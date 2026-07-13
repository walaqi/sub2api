package gift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/shopspring/decimal"

	dbent "github.com/Wei-Shaw/sub2api/ent"
)

// Engine 是赠金子系统对外的唯一入口。
//
// 调用契约：
//   - Grant：发放赠金，自动识别 ctx 中的 ent 事务（dbent.TxFromContext）；amount<=0 早返回
//   - AllocateAndDeduct：在调用方持有的 *sql.Tx 内扣费（usage_billing_repo 主路径）
//   - AllocateAndDeductSimple：内部开短事务的扣费（gateway_service legacy fallback）
//   - DeductFromRechargePool：退款专用，事务内 FOR UPDATE 重校验充值池上限
//   - GetRechargePool / GetGiftBalance：只读查询，无锁
type Engine struct {
	repo *repository
}

// NewEngine 构造引擎实例。entClient 与 sqlDB 必须共用同一连接池。
func NewEngine(entClient *dbent.Client, sqlDB *sql.DB) *Engine {
	if entClient == nil {
		panic("gift.NewEngine: entClient is nil")
	}
	if sqlDB == nil {
		panic("gift.NewEngine: sqlDB is nil")
	}
	return &Engine{repo: newRepository(entClient, sqlDB)}
}

// Grant 发放一笔赠金。amount<=0 时早返回 (nil, nil)，不写表、不动 balance。
//
// 事务策略：
//   - ctx 已通过 dbent.NewTxContext 携带 *ent.Tx：在该事务内插入并 +balance
//   - 否则内部开短事务，函数返回前 commit/rollback
func (e *Engine) Grant(ctx context.Context, in GrantInput) (*UserGift, error) {
	if in.Amount <= 0 {
		return nil, nil
	}
	if err := validateGrantInput(in); err != nil {
		return nil, err
	}

	if existingTx := dbent.TxFromContext(ctx); existingTx != nil {
		return e.repo.insertGiftWithBalance(ctx, existingTx, in)
	}

	tx, err := e.repo.entClient.Tx(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin ent tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	out, err := e.repo.insertGiftWithBalance(ctx, tx, in)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit ent tx: %w", err)
	}
	return out, nil
}

// AllocateBreakdown 是一次扣费的分摊明细，用于持久化到 usage_logs。
// 不变量：GiftCost + RechargeCost = totalCost（订阅扣费路径不调用此引擎，因此两者均为 0）。
type AllocateBreakdown struct {
	GiftCost     float64
	RechargeCost float64
}

// AllocateAndDeduct 在传入的 *sql.Tx 内扣 totalCost。返回新的 users.balance。
//
// 内部步骤：
//  1. 锁读 users + active gifts
//  2. 调 Allocate 计算分摊（纯函数）
//  3. 落库：UPDATE user_gifts × N + UPDATE users
func (e *Engine) AllocateAndDeduct(ctx context.Context, tx *sql.Tx, userID int64, groupID *int64, totalCost float64) (float64, error) {
	newBalance, _, err := e.AllocateAndDeductWithBreakdown(ctx, tx, userID, groupID, totalCost)
	return newBalance, err
}

// AllocateAndDeductWithBreakdown 与 AllocateAndDeduct 等价，额外返回 GiftCost / RechargeCost 分摊明细。
// 调用方（usage_billing_repo）把明细透传给 usage_log 持久化，前端用于"赠金扣减"展示。
//
// groupID 是本次请求的分组（来自 apiKey.GroupID，nil=无分组）。锁到用户的全部 active 赠金后，
// 按 groupID 切成 eligible（group_id IS NULL 或 == groupID）与 ineligible 两份：
// eligible 参与分摊，ineligibleRemaining 从充值池扣除以维持全局余额不变量。
func (e *Engine) AllocateAndDeductWithBreakdown(
	ctx context.Context, tx *sql.Tx, userID int64, groupID *int64, totalCost float64,
) (float64, AllocateBreakdown, error) {
	if tx == nil {
		return 0, AllocateBreakdown{}, errors.New("gift.AllocateAndDeduct: tx is nil")
	}
	if totalCost <= 0 {
		bal, err := e.readBalance(ctx, tx, userID)
		return bal, AllocateBreakdown{}, err
	}
	cost := decimal.NewFromFloat(totalCost)

	balance, gifts, err := e.repo.lockedSnapshot(ctx, tx, userID)
	if err != nil {
		return 0, AllocateBreakdown{}, err
	}

	eligible, ineligibleRemaining := partitionByGroup(gifts, groupID)
	res, err := Allocate(AllocateInput{
		TotalCost:               cost,
		TotalBalance:            balance,
		Gifts:                   eligible,
		IneligibleGiftRemaining: ineligibleRemaining,
	})
	if err != nil {
		return 0, AllocateBreakdown{}, fmt.Errorf("allocate: %w", err)
	}

	newBalance, err := e.repo.applyDeductions(ctx, tx, userID, cost, res)
	if err != nil {
		return 0, AllocateBreakdown{}, err
	}

	// 聚合 breakdown：本次实际扣给用户的赠金 = Σ(gift_deltas)；充值池扣减 = RechargeDelta。
	// 不变量：两者之和守恒等于 totalCost。
	giftSum := decimal.Zero
	for _, d := range res.GiftDeltas {
		giftSum = giftSum.Add(d)
	}
	giftCost, _ := giftSum.Float64()
	rechargeCost, _ := res.RechargeDelta.Float64()

	v, _ := newBalance.Float64()
	return v, AllocateBreakdown{GiftCost: giftCost, RechargeCost: rechargeCost}, nil
}

// AllocateAndDeductSimple 内部开短事务执行扣费，不依赖外部 tx。
// 仅用于 gateway_service.postUsageBilling legacy fallback 路径（无 dedup 保护）。
// groupID 为本次请求分组（apiKey.GroupID，nil=无分组），与主路径同源保证一致的赠金过滤。
func (e *Engine) AllocateAndDeductSimple(ctx context.Context, userID int64, groupID *int64, totalCost float64) error {
	tx, err := e.repo.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := e.AllocateAndDeduct(ctx, tx, userID, groupID, totalCost); err != nil {
		return err
	}
	return tx.Commit()
}

// DeductFromRechargePool 在独立短事务内重新校验充值池上限并按 min(requested, cap) 扣减。
// 仅扣 users.balance，不动赠金。返回真实扣减额。
func (e *Engine) DeductFromRechargePool(ctx context.Context, userID int64, requested float64) (float64, error) {
	if requested <= 0 {
		return 0, nil
	}
	tx, err := e.repo.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	actual, err := e.repo.deductFromRechargePool(ctx, tx, userID, decimal.NewFromFloat(requested))
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	v, _ := actual.Float64()
	return v, nil
}

// GetRechargePool 返回 users.balance - Σ(active gifts.remaining)，用于退款评估阶段。
// 无锁查询；最终一致性读，调用方负责处理评估-执行间的并发（见 DeductFromRechargePool）。
func (e *Engine) GetRechargePool(ctx context.Context, userID int64) (float64, error) {
	user, err := e.repo.entClient.User.Get(ctx, userID)
	if err != nil {
		return 0, fmt.Errorf("get user: %w", err)
	}
	giftSum, err := e.repo.sumActiveGiftRemaining(ctx, userID)
	if err != nil {
		return 0, err
	}
	return user.Balance - giftSum, nil
}

// GetGiftBalance 返回 Σ(active gifts.remaining)，供 Profile API 拆分展示。
func (e *Engine) GetGiftBalance(ctx context.Context, userID int64) (float64, error) {
	return e.repo.sumActiveGiftRemaining(ctx, userID)
}

// GiftExpiringSoonThreshold 是"即将过期"的硬编码阈值。
// Profile UI 在赠金后跟一个橙红色提示数字，提示 < 该阈值的 active 赠金额。
// 改成可配（如管理员/用户级 setting）需要扩展接口；目前一处硬编码。
const GiftExpiringSoonThreshold = 120 * time.Hour

// GetGiftBalanceBreakdown 返回 (gift_balance, expiring_soon)。
// gift_balance = Σ(active gifts.remaining)
// expiring_soon = Σ(remaining WHERE expires_at < NOW() + GiftExpiringSoonThreshold)
// 不变量：expiring_soon ≤ gift_balance。
// 单条 SQL 算两个值，避免两次往返。
func (e *Engine) GetGiftBalanceBreakdown(ctx context.Context, userID int64) (float64, float64, error) {
	return e.repo.giftBalanceBreakdown(ctx, userID, GiftExpiringSoonThreshold)
}

// HasActivePriorityGift 返回用户是否持有至少一笔"当前请求分组可用"的 active 且未过期的
// priority 赠金（remaining > 0）。可用 = group_id IS NULL（全局）或 == groupID（该组专属）。
// 供 billing preflight 使用：当 rechargePool ≤ 0 且无可用 priority 赠金时拦截请求。
// groupID 为本次请求分组（nil=无分组，此时只有全局赠金可用）。只读、不加锁。
func (e *Engine) HasActivePriorityGift(ctx context.Context, userID int64, groupID *int64) (bool, error) {
	return e.repo.hasActivePriorityGift(ctx, userID, groupID)
}

// ListActiveGiftsForDisplay 返回用户当前持有的所有有效赠金（status='active' 且未过期），
// 供 Profile 页面逐条展示。排序与扣费顺序对齐（priority 在前，再按 ratio/到期/id），
// 让用户看到的顺序即实际消耗顺序。ExpiringSoon 用同一 GiftExpiringSoonThreshold 判定，
// 与 GetGiftBalanceBreakdown 保持一致。
func (e *Engine) ListActiveGiftsForDisplay(ctx context.Context, userID int64) ([]GiftDisplayItem, error) {
	if userID <= 0 {
		return nil, errors.New("ListActiveGiftsForDisplay: userID must be positive")
	}
	return e.repo.listActiveGiftsForDisplay(ctx, userID, GiftExpiringSoonThreshold)
}

// RevokeGift 把指定 gift 置 revoked，同步从 users.balance 扣掉它的 remaining。
// 只允许撤销 status='active' 的赠金；非 active 返回 ErrGiftNotRevocable。
// 事务内执行：先锁 users 后锁 gift（与扣费保持加锁顺序一致），杜绝死锁。
func (e *Engine) RevokeGift(ctx context.Context, giftID int64, reason string) error {
	if giftID <= 0 {
		return errors.New("RevokeGift: giftID must be positive")
	}
	return e.repo.revokeOneGift(ctx, giftID, reason)
}

// ListGiftsByUser 列出某用户的赠金，可按 status 过滤（status=="" 表示不过滤）。
// 分页：page 从 1 起，pageSize<=0 时默认 50。返回总数便于前端分页。
func (e *Engine) ListGiftsByUser(ctx context.Context, userID int64, status Status, page, pageSize int) ([]UserGift, int64, error) {
	if userID <= 0 {
		return nil, 0, errors.New("ListGiftsByUser: userID must be positive")
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	return e.repo.listGiftsByUser(ctx, userID, status, page, pageSize)
}

// ListGiftsByUserExpiryAsc 同 ListGiftsByUser，但按过期时间从早到晚排序。
// 用于用户端"我的赠金"页面。
func (e *Engine) ListGiftsByUserExpiryAsc(ctx context.Context, userID int64, status Status, page, pageSize int) ([]UserGift, int64, error) {
	if userID <= 0 {
		return nil, 0, errors.New("ListGiftsByUserExpiryAsc: userID must be positive")
	}
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	return e.repo.listGiftsByUserExpiryAsc(ctx, userID, status, page, pageSize)
}

// GetGiftByID 返回单笔赠金详情（运维侧查询用）。
func (e *Engine) GetGiftByID(ctx context.Context, giftID int64) (*UserGift, error) {
	if giftID <= 0 {
		return nil, errors.New("GetGiftByID: giftID must be positive")
	}
	return e.repo.getGiftByID(ctx, giftID)
}

// ErrGiftNotRevocable 表示尝试撤销一笔非 active 状态的赠金。
var ErrGiftNotRevocable = errors.New("gift is not active and cannot be revoked")

// ErrGiftNotPinnable 表示置顶目标不属于该用户、已过期或已耗尽（不可置顶）。
var ErrGiftNotPinnable = errors.New("gift cannot be pinned (not owned, expired, or exhausted)")

// PinGift 把用户某笔 active 且未过期的赠金置顶（allocator Stage 0 最先消费）。
// 一人至多一条：置顶前先清掉旧置顶。目标不可置顶时返回 ErrGiftNotPinnable。
func (e *Engine) PinGift(ctx context.Context, userID, giftID int64) error {
	if userID <= 0 || giftID <= 0 {
		return errors.New("PinGift: userID and giftID must be positive")
	}
	return e.repo.pinGift(ctx, userID, giftID)
}

// UnpinGift 取消用户某笔赠金的置顶。幂等（未置顶/非本人视为成功）。
func (e *Engine) UnpinGift(ctx context.Context, userID, giftID int64) error {
	if userID <= 0 || giftID <= 0 {
		return errors.New("UnpinGift: userID and giftID must be positive")
	}
	return e.repo.unpinGift(ctx, userID, giftID)
}

// readBalance 在事务内读 users.balance（与 deductUsageBillingBalance 现有语义对齐：扣 0 时也返回当前值）。
func (e *Engine) readBalance(ctx context.Context, tx *sql.Tx, userID int64) (float64, error) {
	var balance float64
	err := tx.QueryRowContext(ctx,
		`SELECT balance FROM users WHERE id = $1 AND deleted_at IS NULL`,
		userID,
	).Scan(&balance)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, fmt.Errorf("user %d not found", userID)
		}
		return 0, err
	}
	return balance, nil
}

func validateGrantInput(in GrantInput) error {
	if in.UserID <= 0 {
		return errors.New("UserID must be positive")
	}
	switch in.Mode {
	case DeductionModePriority:
		if in.RatioRecharge != nil {
			return errors.New("priority gift must not have ratio_recharge")
		}
	case DeductionModeRatio:
		if in.RatioRecharge == nil || *in.RatioRecharge <= 0 {
			return errors.New("ratio gift requires positive ratio_recharge")
		}
	default:
		return fmt.Errorf("unknown deduction mode: %s", in.Mode)
	}
	if in.Source == "" {
		return errors.New("Source must be set")
	}
	return nil
}
