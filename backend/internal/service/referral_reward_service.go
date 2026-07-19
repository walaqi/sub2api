package service

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"math"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
)

// inviterRechargeReader 读取邀请人累计充值额（users.total_recharged），抽成接口便于单测打桩。
type inviterRechargeReader interface {
	TotalRecharged(ctx context.Context, userID int64) (float64, error)
}

// entInviterRechargeReader 通过 ent client 读取 users.total_recharged，tx 感知。
type entInviterRechargeReader struct {
	client *dbent.Client
}

func (r *entInviterRechargeReader) TotalRecharged(ctx context.Context, userID int64) (float64, error) {
	if r == nil || r.client == nil {
		return 0, nil
	}
	var execer interface {
		QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	} = r.client
	if tx := dbent.TxFromContext(ctx); tx != nil {
		execer = tx.Client()
	}
	rows, err := execer.QueryContext(ctx, `SELECT total_recharged::double precision FROM users WHERE id = $1`, userID)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()
	var total float64
	if rows.Next() {
		if err := rows.Scan(&total); err != nil {
			return 0, err
		}
	}
	return total, rows.Err()
}

// ReferralRewardService 实现双向邀请赠金逻辑。
// 实现 InviterBoundHook 接口：被邀请人注册绑定邀请关系后触发。
type ReferralRewardService struct {
	entClient        *dbent.Client
	giftEngine       *gift.Engine
	settingService   *SettingService
	discountRepo     RechargeDiscountRepo  // 用于折扣继承
	rechargeReader   inviterRechargeReader // 用于 recharge 模式资格判定（读累计充值额）
	affiliateService *AffiliateService     // 用于 EnsureUserAffiliate（lazy 创建 aff_code）
}

// NewReferralRewardService 构造 ReferralRewardService。
func NewReferralRewardService(
	entClient *dbent.Client,
	giftEngine *gift.Engine,
	settingService *SettingService,
	discountRepo RechargeDiscountRepo,
	affiliateService *AffiliateService,
) *ReferralRewardService {
	return &ReferralRewardService{
		entClient:        entClient,
		giftEngine:       giftEngine,
		settingService:   settingService,
		discountRepo:     discountRepo,
		rechargeReader:   &entInviterRechargeReader{client: entClient},
		affiliateService: affiliateService,
	}
}

// OnInviterBound 实现 InviterBoundHook。
// 被邀请人注册后绑定邀请关系时由 AffiliateService 异步调用。
// 无论功能开关状态如何，都创建 tracker 行（确保后续开启时能追踪）。
// 仅当 referral_reward_enabled=true 时发放被邀请人赠金和继承折扣。
func (s *ReferralRewardService) OnInviterBound(ctx context.Context, inviterID, inviteeID int64, boundAt time.Time) {
	if s == nil || s.entClient == nil {
		return
	}

	// 获取配置
	cfg := s.settingService.GetReferralRewardConfig(ctx)
	rewardEligible := s.hasInviterRewardEligibilityAtTime(ctx, inviterID, boundAt)

	// 创建 tracker 行（幂等，ON CONFLICT DO NOTHING）
	if err := s.ensureTracker(ctx, inviterID, inviteeID, cfg.SpendThreshold, rewardEligible); err != nil {
		log.Printf("[referral] create tracker for inviter=%d invitee=%d failed: %v", inviterID, inviteeID, err)
		return
	}

	// 功能开关关闭时不发放
	if !s.settingService.IsReferralRewardEnabled(ctx) {
		return
	}

	// 邀请人在绑定时无超级邀请资格 → 绑定关系照常建立（tracker 已建，快照 false），
	// 仅跳过超级邀请奖励：不发被邀请人赠金、不继承折扣。
	// 这防止无资格邀请人用普通返利链接拉人时，被邀请人被按超级邀请逻辑批量发赠金。
	if !rewardEligible {
		return
	}

	// 发放被邀请人赠金
	if err := s.grantInviteeReward(ctx, inviterID, inviteeID, cfg); err != nil {
		log.Printf("[referral] grant invitee reward for invitee=%d failed: %v", inviteeID, err)
	}

	// 继承邀请人的充值折扣
	if err := s.inheritDiscountFromInviter(ctx, inviterID, inviteeID, boundAt); err != nil {
		log.Printf("[referral] inherit discount for invitee=%d from inviter=%d failed: %v", inviteeID, inviterID, err)
	}
}

// TrackSpendAndMaybeGrantInviterReward 每次计费成功后异步调用。
// 累加被邀请人消费额，达标后发放邀请人赠金。
// 幂等：referral_spend_events 唯一索引保证同一 eventID 不重复累加。
//
// 竞态安全：若 tracker 尚未创建（OnInviterBound 异步还没跑完），从 user_affiliates
// 查 inviter 并补建 tracker，然后继续处理当前 spend。不丢失任何 billing event。
func (s *ReferralRewardService) TrackSpendAndMaybeGrantInviterReward(ctx context.Context, inviteeID int64, eventID string, spendAmount float64) error {
	if s == nil || s.entClient == nil || s.giftEngine == nil {
		return nil
	}
	if spendAmount <= 0 {
		return nil
	}

	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin referral spend tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := dbent.NewTxContext(ctx, tx)
	execer := tx.Client()

	// 1. FOR UPDATE 锁 tracker 行
	rows, err := execer.QueryContext(txCtx, `
SELECT id, inviter_id, invitee_spend_tracked, spend_threshold, inviter_reward_granted, inviter_reward_eligible_at_bind
FROM referral_reward_tracker
WHERE invitee_id = $1
FOR UPDATE`, inviteeID)
	if err != nil {
		return fmt.Errorf("query tracker for update: %w", err)
	}

	type trackerRow struct {
		id             int64
		inviterID      int64
		spendTracked   float64
		threshold      float64
		inviterGranted bool
		rewardEligible bool
	}
	var tracker *trackerRow
	if rows.Next() {
		t := &trackerRow{}
		if err := rows.Scan(&t.id, &t.inviterID, &t.spendTracked, &t.threshold, &t.inviterGranted, &t.rewardEligible); err != nil {
			_ = rows.Close()
			return err
		}
		tracker = t
	}
	_ = rows.Close()

	// 无 tracker：尝试从 user_affiliates 查 inviter 并补建
	if tracker == nil {
		affiliate, err := s.lookupInviteeAffiliate(txCtx, execer, inviteeID)
		if err != nil {
			return fmt.Errorf("lookup invitee affiliate: %w", err)
		}
		if affiliate == nil || affiliate.inviterID == 0 {
			// 该用户不是被邀请人，无需追踪
			return nil // defer rollback (无副作用)
		}
		cfg := s.settingService.GetReferralRewardConfig(ctx)
		rewardEligible := s.hasInviterRewardEligibilityAtTime(txCtx, affiliate.inviterID, affiliate.boundAt)
		// 在事务内直接插入 tracker（幂等）
		insertRows, err := execer.QueryContext(txCtx, `
INSERT INTO referral_reward_tracker (inviter_id, invitee_id, spend_threshold, inviter_reward_eligible_at_bind)
VALUES ($1, $2, $3, $4)
ON CONFLICT (inviter_id, invitee_id) DO UPDATE SET updated_at = NOW()
RETURNING id, inviter_id, invitee_spend_tracked, spend_threshold, inviter_reward_granted, inviter_reward_eligible_at_bind`,
			affiliate.inviterID, inviteeID, cfg.SpendThreshold, rewardEligible)
		if err != nil {
			return fmt.Errorf("ensure tracker in tx: %w", err)
		}
		if insertRows.Next() {
			t := &trackerRow{}
			if err := insertRows.Scan(&t.id, &t.inviterID, &t.spendTracked, &t.threshold, &t.inviterGranted, &t.rewardEligible); err != nil {
				_ = insertRows.Close()
				return err
			}
			tracker = t
		}
		_ = insertRows.Close()
		if tracker == nil {
			return nil
		}
	}

	// 2. 事件幂等检查 + 插入（tracker 已锁定/创建，可安全消费 event slot）
	res, err := execer.ExecContext(txCtx,
		`INSERT INTO referral_spend_events (event_id, invitee_id, amount) VALUES ($1, $2, $3) ON CONFLICT (event_id) DO NOTHING`,
		eventID, inviteeID, spendAmount)
	if err != nil {
		return fmt.Errorf("insert spend event: %w", err)
	}
	affected, _ := res.RowsAffected()
	if affected == 0 {
		// 已处理过
		return nil
	}

	// 3. 累加消费
	newTracked := tracker.spendTracked + spendAmount
	_, err = execer.ExecContext(txCtx,
		`UPDATE referral_reward_tracker SET invitee_spend_tracked = $1, updated_at = NOW() WHERE id = $2`,
		newTracked, tracker.id)
	if err != nil {
		return fmt.Errorf("update spend tracked: %w", err)
	}

	// 4. 判断是否达标 + 发放（走唯一发奖入口，复用本事务已持有的 tracker 锁）
	if err := s.grantInviterRewardLocked(txCtx, &lockedInviterTracker{
		id:             tracker.id,
		inviterID:      tracker.inviterID,
		inviteeID:      inviteeID,
		spendTracked:   newTracked,
		threshold:      tracker.threshold,
		granted:        tracker.inviterGranted,
		rewardEligible: tracker.rewardEligible,
	}); err != nil {
		return err
	}

	return tx.Commit()
}

// lockedInviterTracker 是已在事务内 FOR UPDATE 锁定的 tracker 行快照。
type lockedInviterTracker struct {
	id             int64
	inviterID      int64
	inviteeID      int64
	spendTracked   float64
	threshold      float64
	granted        bool
	rewardEligible bool
}

// grantInviterRewardLocked 是唯一的「邀请人达标奖励」发放逻辑（TrackSpend 达标点与充值补发共用）。
//
// 前置条件（调用方保证）：txCtx 是已打开的事务；t 对应的 tracker 行已在本事务内 FOR UPDATE 锁定。
// 内部绝不自开事务、绝不重锁 tracker；仅在配额开关开时再锁 affiliate（锁序恒 tracker→affiliate，无死锁）。
//
// 行为：
//   - gate 不通过（已发/未达标/绑定时无资格/全局开关关）→ 直接返回，不发不改 flag。
//   - 配额开关关 → 直接发（无限行为，== 历史语义），置 granted、清 blocked flag。
//   - 配额开关开且 quota<=0 → 不发、不置 granted，置 blocked_by_quota=true（供弹窗投放 + /referral 展示）。
//   - 配额开关开且 quota>0 → 扣一次机会，发放，置 granted、清 blocked flag，全部同事务原子。
func (s *ReferralRewardService) grantInviterRewardLocked(txCtx context.Context, t *lockedInviterTracker) error {
	if t.granted || t.spendTracked < t.threshold || !t.rewardEligible {
		return nil
	}
	if s.settingService == nil || !s.settingService.IsReferralRewardEnabled(txCtx) {
		return nil
	}
	cfg := s.settingService.GetReferralRewardConfig(txCtx)
	execer := s.execer(txCtx)

	// 配额开关开：先锁 affiliate 行检查/扣减机会（第二把锁，恒在 tracker 之后）。
	if cfg.InviterRewardQuotaEnabled {
		rows, err := execer.QueryContext(txCtx,
			`SELECT inviter_reward_quota FROM user_affiliates WHERE user_id = $1 FOR UPDATE`, t.inviterID)
		if err != nil {
			return fmt.Errorf("lock affiliate for quota: %w", err)
		}
		var quota int
		hasRow := false
		if rows.Next() {
			if scanErr := rows.Scan(&quota); scanErr != nil {
				_ = rows.Close()
				return scanErr
			}
			hasRow = true
		}
		_ = rows.Close()

		if !hasRow || quota <= 0 {
			// 无机会：不发、不置 granted，置 blocked 标志位（pending 待邀请人充值补足或再消费）。
			if _, err := execer.ExecContext(txCtx,
				`UPDATE referral_reward_tracker SET inviter_reward_blocked_by_quota = TRUE, updated_at = NOW() WHERE id = $1`,
				t.id); err != nil {
				return fmt.Errorf("mark blocked by quota: %w", err)
			}
			return nil
		}

		// 有机会：扣减一次。
		if _, err := execer.ExecContext(txCtx,
			`UPDATE user_affiliates SET inviter_reward_quota = inviter_reward_quota - 1, inviter_reward_quota_consumed_total = inviter_reward_quota_consumed_total + 1, updated_at = NOW() WHERE user_id = $1`,
			t.inviterID); err != nil {
			return fmt.Errorf("consume inviter reward quota: %w", err)
		}
	}

	// 发放赠金。
	expiresAt := time.Now().Add(time.Duration(cfg.InviterExpiryDays) * 24 * time.Hour)
	mode := gift.DeductionModePriority
	var ratioRecharge *float64
	if cfg.InviterGiftMode == "ratio" {
		mode = gift.DeductionModeRatio
		ratio := cfg.InviterGiftRatio
		ratioRecharge = &ratio
	}
	grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
		UserID:        t.inviterID,
		Amount:        cfg.InviterAmount,
		Mode:          mode,
		RatioRecharge: ratioRecharge,
		ExpiresAt:     &expiresAt,
		Source:        gift.SourceReferralInviter,
		SourceRef:     referralPtrStr(fmt.Sprintf("invitee:%d", t.inviteeID)),
	})
	if err != nil {
		return fmt.Errorf("grant inviter reward: %w", err)
	}
	if _, err := execer.ExecContext(txCtx,
		`UPDATE referral_reward_tracker SET inviter_reward_granted = TRUE, inviter_reward_gift_id = $1, inviter_reward_at = NOW(), inviter_reward_blocked_by_quota = FALSE, updated_at = NOW() WHERE id = $2`,
		grantResult.ID, t.id); err != nil {
		return fmt.Errorf("mark inviter reward granted: %w", err)
	}
	return nil
}

type inviteeAffiliateSnapshot struct {
	inviterID int64
	boundAt   time.Time
}

// lookupInviteeAffiliate 从 user_affiliates 表查询 invitee 的 inviter 和绑定更新时间。
// 返回 nil 表示该用户不是被邀请人。updated_at 由 BindInviter 写入，用作 lazy 补建时的绑定时间近似。
func (s *ReferralRewardService) lookupInviteeAffiliate(ctx context.Context, execer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}, inviteeID int64) (*inviteeAffiliateSnapshot, error) {
	rows, err := execer.QueryContext(ctx,
		`SELECT inviter_id, COALESCE(inviter_bound_at, updated_at) FROM user_affiliates WHERE user_id = $1 AND inviter_id IS NOT NULL LIMIT 1`,
		inviteeID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	if !rows.Next() {
		return nil, nil
	}
	var snapshot inviteeAffiliateSnapshot
	if err := rows.Scan(&snapshot.inviterID, &snapshot.boundAt); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	return &snapshot, nil
}

// ensureTracker 创建 tracker 行（幂等）。
func (s *ReferralRewardService) ensureTracker(ctx context.Context, inviterID, inviteeID int64, threshold float64, rewardEligible bool) error {
	execer := s.execer(ctx)
	_, err := execer.ExecContext(ctx,
		`INSERT INTO referral_reward_tracker (inviter_id, invitee_id, spend_threshold, inviter_reward_eligible_at_bind) VALUES ($1, $2, $3, $4) ON CONFLICT (inviter_id, invitee_id) DO NOTHING`,
		inviterID, inviteeID, threshold, rewardEligible)
	if err != nil {
		return fmt.Errorf("ensure tracker: %w", err)
	}
	return nil
}

// grantInviteeReward 发放被邀请人注册赠金（幂等）。
// 在事务内 FOR UPDATE 锁 tracker → 检查 invitee_reward_granted → grant → 标记。
// 防止 hook 重放或 "grant 成功但 update tracker 失败" 后重复发放。
func (s *ReferralRewardService) grantInviteeReward(ctx context.Context, inviterID, inviteeID int64, cfg ReferralRewardConfig) error {
	if s.giftEngine == nil || s.entClient == nil {
		return nil
	}

	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin invitee reward tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := dbent.NewTxContext(ctx, tx)
	execer := tx.Client()

	// FOR UPDATE 锁 tracker 行
	rows, err := execer.QueryContext(txCtx, `
SELECT id, invitee_reward_granted
FROM referral_reward_tracker
WHERE inviter_id = $1 AND invitee_id = $2
FOR UPDATE`, inviterID, inviteeID)
	if err != nil {
		return fmt.Errorf("lock tracker for invitee reward: %w", err)
	}

	var trackerID int64
	var alreadyGranted bool
	if rows.Next() {
		if err := rows.Scan(&trackerID, &alreadyGranted); err != nil {
			_ = rows.Close()
			return err
		}
	} else {
		_ = rows.Close()
		return nil // tracker 不存在，跳过
	}
	_ = rows.Close()

	if alreadyGranted {
		return nil // 已发放过，幂等退出
	}

	// 发放赠金
	expiresAt := time.Now().Add(time.Duration(cfg.InviteeExpiryDays) * 24 * time.Hour)
	grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
		UserID:    inviteeID,
		Amount:    cfg.InviteeAmount,
		Mode:      gift.DeductionModePriority,
		ExpiresAt: &expiresAt,
		Source:    gift.SourceReferralInvitee,
		SourceRef: referralPtrStr(fmt.Sprintf("inviter:%d", inviterID)),
	})
	if err != nil {
		return fmt.Errorf("grant invitee reward: %w", err)
	}

	// 标记已发放（同一事务内，原子性保证）
	_, err = execer.ExecContext(txCtx,
		`UPDATE referral_reward_tracker SET invitee_reward_granted = TRUE, invitee_reward_gift_id = $1, invitee_reward_at = NOW(), updated_at = NOW() WHERE id = $2`,
		grantResult.ID, trackerID)
	if err != nil {
		return fmt.Errorf("mark invitee reward granted: %w", err)
	}

	return tx.Commit()
}

// inheritDiscountFromInviter 继承邀请人的最佳活跃充值折扣。
// 使用邀请人的 max_discountable_amount（非 remaining）和可配置的 valid_days。
//
// 折扣继承始终以「邀请人名下的有效充值折扣券」为准，与资格获得方式无关：
// recharge 模式下靠纯充值达标（无券）的邀请人，其被邀请人自然继承不到折扣
// （查券为空即空转），即「有券才继承」。
func (s *ReferralRewardService) inheritDiscountFromInviter(ctx context.Context, inviterID, inviteeID int64, boundAt time.Time) error {
	if s.discountRepo == nil {
		return nil
	}

	discounts, err := s.discountRepo.QueryDiscountsForInheritanceAtTime(ctx, inviterID, boundAt)
	if err != nil || len(discounts) == 0 {
		return err
	}

	best := discounts[0] // 已按 rate DESC 排序

	// 读取可配置有效天数
	discountValidDays := 30
	if s.settingService != nil {
		cfg := s.settingService.GetReferralRewardConfig(ctx)
		if cfg.DiscountValidDays >= 1 {
			discountValidDays = cfg.DiscountValidDays
		}
	}
	validUntil := time.Now().Add(time.Duration(discountValidDays) * 24 * time.Hour)

	sourceRef := fmt.Sprintf("inviter:%d", inviterID)
	_, err = s.discountRepo.CreateDiscount(ctx, CreateRechargeDiscountInput{
		UserID:               inviteeID,
		Source:               "referral_inherit",
		SourceRef:            sourceRef,
		Rate:                 best.DiscountRate,
		MaxAmount:            best.MaxDiscountableAmount,
		ValidFrom:            time.Now(),
		ValidUntil:           &validUntil,
		GiftDeductionMode:    best.GiftDeductionMode,
		GiftRatioRecharge:    best.GiftRatioRecharge,
		GiftExpiryMode:       best.GiftExpiryMode,
		GiftExpiresAfterDays: best.GiftExpiresAfterDays,
	})
	if err != nil {
		return fmt.Errorf("create inherited discount: %w", err)
	}
	return nil
}

// hasInviterRewardEligibility 判断邀请人当前是否有超级邀请达标赠金资格。
func (s *ReferralRewardService) hasInviterRewardEligibility(ctx context.Context, inviterID int64) bool {
	return s.hasInviterRewardEligibilityAtTime(ctx, inviterID, time.Time{})
}

// hasInviterRewardEligibilityAtTime 判断邀请人在指定绑定时间点是否有超级邀请达标赠金资格。
//
// 两种资格获得方式（referral_eligibility_grant_mode）：
//   - recharge：只看邀请人累计充值额（users.total_recharged）是否达到门槛，
//     与「赠金领券」完全无关。atTime 在此模式下被忽略——total_recharged 是单调
//     累加计数器、无历史时点台账，而资格快照本就在 OnInviterBound（绑定后立即
//     异步执行）时算，那一刻的 total_recharged 即绑定时点的值。
//   - bind_key_claim（默认）：看邀请人名下是否有有效的充值折扣券（依赖领券）。
//
// atTime 为零值时表示「当前时点」（用于用户可见状态查询）。
func (s *ReferralRewardService) hasInviterRewardEligibilityAtTime(ctx context.Context, inviterID int64, atTime time.Time) bool {
	cfg := ReferralRewardConfig{EligibilityGrantMode: ReferralEligibilityGrantModeBindKeyClaim}
	if s.settingService != nil {
		cfg = s.settingService.GetReferralRewardConfig(ctx)
	}

	if cfg.EligibilityGrantMode == ReferralEligibilityGrantModeRecharge {
		if s.rechargeReader == nil {
			return false
		}
		minAmount := normalizeReferralEligibilityRechargeMinAmount(cfg.EligibilityRechargeMinAmount)
		total, err := s.rechargeReader.TotalRecharged(ctx, inviterID)
		if err != nil {
			return false
		}
		if minAmount <= 0 {
			// 无金额门槛：只要有过任意充值即算资格。
			return total > 0
		}
		return total >= minAmount
	}

	// bind_key_claim 模式：查有效充值折扣券（依赖领券）。
	if s.discountRepo == nil {
		return false
	}
	var discounts []RechargeDiscountSummary
	var err error
	if atTime.IsZero() {
		discounts, err = s.discountRepo.QueryDiscountsForInheritance(ctx, inviterID)
	} else {
		discounts, err = s.discountRepo.QueryDiscountsForInheritanceAtTime(ctx, inviterID, atTime)
	}
	return err == nil && len(discounts) > 0
}

// eligibilityRechargeRemaining 计算 recharge 模式下用户还需累计充值多少（USD）才能获得超级邀请资格。
// 语义对齐 hasInviterRewardEligibilityAtTime 的 recharge 分支：remaining = minAmount - total_recharged。
// minAmount<=0 时无金额门槛，返回 0。
func (s *ReferralRewardService) eligibilityRechargeRemaining(ctx context.Context, userID int64, minAmount float64) float64 {
	if minAmount <= 0 {
		return 0
	}
	if s.rechargeReader == nil {
		return minAmount
	}
	total, err := s.rechargeReader.TotalRecharged(ctx, userID)
	if err != nil {
		return minAmount
	}
	remaining := minAmount - total
	if remaining < 0 {
		remaining = 0
	}
	return remaining
}

func (s *ReferralRewardService) execer(ctx context.Context) interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
} {
	if tx := dbent.TxFromContext(ctx); tx != nil {
		return tx.Client()
	}
	return s.entClient
}

// 充值赚配额去重来源类型。
const (
	ReferralQuotaSourcePaymentOrder = "payment_order"
	ReferralQuotaSourceRedeemCode   = "redeem_code"
)

// AccrueInviterRewardQuota 在用户充值/兑换入账后累积「邀请人达标奖励」发放机会（best-effort）。
//
// 语义：每充值 step USD 得 per_batch 次机会；carry 跨次累积未凑满一档的余额。
// 幂等：referral_recharge_quota_grants(source_type, source_id) 唯一索引保证每笔充值只赚一次。
// 配额开关关时直接跳过（不赚不影响）。
// 加完 quota 后立即扫描该用户被卡的 pending 奖励并补发（backfill）。
//
// 该方法自开事务，不要求调用方持有任何锁；调用方应忽略返回的 error（仅记审计），不阻断充值主链路。
func (s *ReferralRewardService) AccrueInviterRewardQuota(ctx context.Context, userID int64, sourceType string, sourceID int64, amount float64) error {
	if s == nil || s.entClient == nil {
		return nil
	}
	if amount <= 0 {
		return nil
	}
	cfg := s.settingService.GetReferralRewardConfig(ctx)
	if !cfg.InviterRewardQuotaEnabled {
		return nil
	}
	step := cfg.InviterRewardQuotaRechargeStep
	perBatch := cfg.InviterRewardQuotaPerBatch
	if step <= 0 || perBatch <= 0 {
		return nil
	}

	// === 阶段 1：加 quota（独立事务，先提交）===
	if err := s.accrueQuotaTx(ctx, userID, sourceType, sourceID, amount, step, perBatch); err != nil {
		return err
	}

	// === 阶段 2：补发被卡 pending（每笔独立事务，锁序 tracker→affiliate）===
	// best-effort：补发失败不影响已加的 quota，剩余 pending 由被邀请人下次消费兜底。
	s.backfillPendingInviterRewards(ctx, userID)
	return nil
}

// accrueQuotaTx 在单个事务内幂等地累积配额。
func (s *ReferralRewardService) accrueQuotaTx(ctx context.Context, userID int64, sourceType string, sourceID int64, amount, step float64, perBatch int) error {
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin accrue quota tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := dbent.NewTxContext(ctx, tx)
	execer := tx.Client()

	// 确保 affiliate 行存在（aff_code NOT NULL UNIQUE，不能裸插）。
	if s.affiliateService != nil {
		if _, err := s.affiliateService.EnsureUserAffiliate(txCtx, userID); err != nil {
			return fmt.Errorf("ensure affiliate for quota accrue: %w", err)
		}
	}

	// 计算发放批次前，先用当前 carry + 本次 amount。锁 affiliate 行取 carry。
	rows, err := execer.QueryContext(txCtx,
		`SELECT inviter_reward_recharge_carry FROM user_affiliates WHERE user_id = $1 FOR UPDATE`, userID)
	if err != nil {
		return fmt.Errorf("lock affiliate carry: %w", err)
	}
	var carry float64
	if rows.Next() {
		if scanErr := rows.Scan(&carry); scanErr != nil {
			_ = rows.Close()
			return scanErr
		}
	} else {
		_ = rows.Close()
		return nil // 无 affiliate 行（EnsureUserAffiliate 未配置），跳过
	}
	_ = rows.Close()

	// 幂等：抢 source slot。冲突表示已处理过，直接退出（carry 不动）。
	newCarry := carry + amount
	batches := int(math.Floor(newCarry / step))
	res, err := execer.ExecContext(txCtx,
		`INSERT INTO referral_recharge_quota_grants (user_id, source_type, source_id, order_amount, batches_granted)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (source_type, source_id) DO NOTHING`,
		userID, sourceType, sourceID, amount, batches)
	if err != nil {
		return fmt.Errorf("claim quota grant slot: %w", err)
	}
	if affected, _ := res.RowsAffected(); affected == 0 {
		return nil // 并发/重放已处理
	}

	remainCarry := newCarry - float64(batches)*step
	addQuota := batches * perBatch
	if _, err := execer.ExecContext(txCtx,
		`UPDATE user_affiliates SET inviter_reward_quota = inviter_reward_quota + $1, inviter_reward_recharge_carry = $2, updated_at = NOW() WHERE user_id = $3`,
		addQuota, remainCarry, userID); err != nil {
		return fmt.Errorf("update inviter reward quota: %w", err)
	}

	return tx.Commit()
}

// backfillPendingInviterRewards 扫描邀请人名下被 quota 卡住的 pending 奖励，逐笔立即补发（best-effort）。
// 每个 invitee 独立事务：锁其 tracker 行 → 调唯一发奖入口 grantInviterRewardLocked（锁序 tracker→affiliate）。
// quota 耗尽后 grantInviterRewardLocked 的 quota<=0 分支自然停发，剩余仍 blocked。
//
// 失败处理：backfill 是充值路径上的旁路补偿，不阻断充值；且未补发的 pending 仍由被邀请人
// 下次消费兜底。这里刻意降级为带 REFERRAL_QUOTA_BACKFILL_FAILED 标记的日志（而非支付审计表）——
// 因为本服务不持有支付审计写入器，且 backfill 不绑定单一订单；用统一标记便于 ops 从日志检索。
func (s *ReferralRewardService) backfillPendingInviterRewards(ctx context.Context, inviterID int64) {
	if s == nil || s.entClient == nil || s.giftEngine == nil {
		return
	}

	// 先取待补发的 invitee 列表（命中 partial index）。
	rows, err := s.entClient.QueryContext(ctx,
		`SELECT invitee_id FROM referral_reward_tracker
		 WHERE inviter_id = $1 AND inviter_reward_granted = FALSE AND inviter_reward_blocked_by_quota = TRUE
		 ORDER BY created_at`, inviterID)
	if err != nil {
		log.Printf("[referral] REFERRAL_QUOTA_BACKFILL_FAILED list pending for inviter=%d failed: %v", inviterID, err)
		return
	}
	var inviteeIDs []int64
	for rows.Next() {
		var id int64
		if scanErr := rows.Scan(&id); scanErr != nil {
			_ = rows.Close()
			log.Printf("[referral] REFERRAL_QUOTA_BACKFILL_FAILED scan invitee for inviter=%d failed: %v", inviterID, scanErr)
			return
		}
		inviteeIDs = append(inviteeIDs, id)
	}
	_ = rows.Close()

	for _, inviteeID := range inviteeIDs {
		if err := s.backfillOnePendingReward(ctx, inviteeID); err != nil {
			// best-effort：单笔失败记录后继续，剩余 pending 由下次消费兜底。
			log.Printf("[referral] REFERRAL_QUOTA_BACKFILL_FAILED grant for inviter=%d invitee=%d failed: %v", inviterID, inviteeID, err)
		}
	}
}

// backfillOnePendingReward 在独立事务内补发单个 invitee 的 pending 奖励。
func (s *ReferralRewardService) backfillOnePendingReward(ctx context.Context, inviteeID int64) error {
	tx, err := s.entClient.Tx(ctx)
	if err != nil {
		return fmt.Errorf("begin backfill tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	txCtx := dbent.NewTxContext(ctx, tx)
	execer := tx.Client()

	rows, err := execer.QueryContext(txCtx, `
SELECT id, inviter_id, invitee_spend_tracked, spend_threshold, inviter_reward_granted, inviter_reward_eligible_at_bind
FROM referral_reward_tracker
WHERE invitee_id = $1
FOR UPDATE`, inviteeID)
	if err != nil {
		return fmt.Errorf("lock tracker for backfill: %w", err)
	}
	var t lockedInviterTracker
	found := false
	if rows.Next() {
		if scanErr := rows.Scan(&t.id, &t.inviterID, &t.spendTracked, &t.threshold, &t.granted, &t.rewardEligible); scanErr != nil {
			_ = rows.Close()
			return scanErr
		}
		found = true
	}
	_ = rows.Close()
	if !found {
		return nil
	}
	t.inviteeID = inviteeID

	if err := s.grantInviterRewardLocked(txCtx, &t); err != nil {
		return err
	}
	return tx.Commit()
}

// ReferralStatus 是用户可见的邀请奖励状态。
type ReferralStatus struct {
	Enabled                      bool              `json:"enabled"`
	Eligible                     bool              `json:"eligible"` // 当前用户是否有超级邀请资格
	EligibilityGrantMode         string            `json:"eligibility_grant_mode"`
	EligibilityRechargeMinAmount float64           `json:"eligibility_recharge_min_amount"`
	AffCode                      string            `json:"aff_code"`         // 用户的邀请码（用于生成邀请链接）
	InviteeReward                *InviteeRewardDTO `json:"invitee_reward"`   // 当前用户作为被邀请人的奖励状态（nil=非被邀请人）
	InviterProgress              []InviteeProgress `json:"inviter_progress"` // 当前用户作为邀请人，各被邀请人的消费进度
	// 奖励规则金额（供前端展示"注册即得 X / 消费达标 Y / 你得 Z"）。
	InviteeAmount  float64 `json:"invitee_amount"`  // 被邀请人注册赠金
	InviterAmount  float64 `json:"inviter_amount"`  // 邀请人达标赠金
	SpendThreshold float64 `json:"spend_threshold"` // 被邀请人消费达标阈值
	// EligibilityRechargeRemaining 仅在 recharge 模式且尚未获得资格时有意义：
	// 表示还需累计充值多少（USD）才能成为超级邀请人。0 表示已满足或不适用。
	EligibilityRechargeRemaining float64 `json:"eligibility_recharge_remaining"`
	// 邀请人达标奖励发放次数配额（仅配额开关开时有意义）
	InviterRewardQuotaEnabled bool `json:"inviter_reward_quota_enabled"` // 配额功能是否开启
	InviterRewardQuota        int  `json:"inviter_reward_quota"`         // 剩余可领取达标奖励的机会数
}

type InviteeRewardDTO struct {
	Granted bool    `json:"granted"`
	Amount  float64 `json:"amount"`
}

type InviteeProgress struct {
	InviteeID      int64   `json:"invitee_id"` // 被邀请人 user id（前端用于与返利已邀请列表按 id 关联）
	InviteeName    string  `json:"invitee_name"`
	InviteeEmail   string  `json:"invitee_email"`
	SpendTracked   float64 `json:"spend_tracked"`
	Threshold      float64 `json:"threshold"`
	Granted        bool    `json:"granted"`
	RewardEligible bool    `json:"reward_eligible"`  // 绑定时邀请人是否有资格（false=达标也不发放）
	BlockedByQuota bool    `json:"blocked_by_quota"` // 已达标但因邀请人配额用尽未发（充值补足即可解锁）
}

// GetReferralStatus 查询当前用户的邀请奖励状态。
func (s *ReferralRewardService) GetReferralStatus(ctx context.Context, userID int64) (*ReferralStatus, error) {
	if s == nil || s.entClient == nil {
		return &ReferralStatus{InviterProgress: []InviteeProgress{}}, nil
	}

	execer := s.execer(ctx)
	enabled := false
	if s.settingService != nil {
		enabled = s.settingService.IsReferralRewardEnabled(ctx)
	}

	cfg := ReferralRewardConfig{
		InviteeAmount:                10,
		EligibilityGrantMode:         ReferralEligibilityGrantModeBindKeyClaim,
		EligibilityRechargeMinAmount: 0,
	}
	if s.settingService != nil {
		cfg = s.settingService.GetReferralRewardConfig(ctx)
	}

	status := &ReferralStatus{
		Enabled:                      enabled,
		EligibilityGrantMode:         cfg.EligibilityGrantMode,
		EligibilityRechargeMinAmount: cfg.EligibilityRechargeMinAmount,
		InviteeAmount:                cfg.InviteeAmount,
		InviterAmount:                cfg.InviterAmount,
		SpendThreshold:               cfg.SpendThreshold,
	}
	status.Eligible = s.hasInviterRewardEligibility(ctx, userID)
	status.InviterRewardQuotaEnabled = cfg.InviterRewardQuotaEnabled

	// recharge 模式且尚未获得资格时，计算还需累计充值多少才能成为超级邀请人。
	// 语义对齐资格判定：单笔折扣的累计 applied_amount 达到门槛即算资格，
	// 因此"还需"取所有在有效期内折扣中「距门槛最近」的缺口（缺口最小 = 最容易达标）。
	if enabled && !status.Eligible && cfg.EligibilityGrantMode == ReferralEligibilityGrantModeRecharge {
		minAmount := normalizeReferralEligibilityRechargeMinAmount(cfg.EligibilityRechargeMinAmount)
		status.EligibilityRechargeRemaining = s.eligibilityRechargeRemaining(ctx, userID, minAmount)
	}

	// 0. 获取用户的邀请码（lazy-create：无 user_affiliates 行时自动创建并生成 aff_code）
	if s.affiliateService != nil {
		summary, err := s.affiliateService.EnsureUserAffiliate(ctx, userID)
		if err != nil {
			return nil, fmt.Errorf("ensure user affiliate: %w", err)
		}
		if summary != nil {
			status.AffCode = summary.AffCode
		}
	}

	// 0b. 剩余达标奖励发放机会（仅配额开关开时展示）
	if cfg.InviterRewardQuotaEnabled {
		quotaRows, err := execer.QueryContext(ctx,
			`SELECT inviter_reward_quota FROM user_affiliates WHERE user_id = $1 LIMIT 1`, userID)
		if err != nil {
			return nil, fmt.Errorf("query inviter reward quota: %w", err)
		}
		if quotaRows.Next() {
			var quota int
			if err := quotaRows.Scan(&quota); err != nil {
				_ = quotaRows.Close()
				return nil, fmt.Errorf("scan inviter reward quota: %w", err)
			}
			status.InviterRewardQuota = quota
		}
		_ = quotaRows.Close()
	}

	// 1. 作为被邀请人的奖励状态
	inviteeRows, err := execer.QueryContext(ctx,
		`SELECT invitee_reward_granted FROM referral_reward_tracker WHERE invitee_id = $1 LIMIT 1`, userID)
	if err != nil {
		return nil, fmt.Errorf("query invitee reward: %w", err)
	}
	if inviteeRows.Next() {
		var granted bool
		if err := inviteeRows.Scan(&granted); err != nil {
			_ = inviteeRows.Close()
			return nil, fmt.Errorf("scan invitee reward: %w", err)
		}
		status.InviteeReward = &InviteeRewardDTO{Granted: granted, Amount: cfg.InviteeAmount}
	}
	_ = inviteeRows.Close()

	// 2. 作为邀请人的各被邀请人进度
	progressRows, err := execer.QueryContext(ctx, `
SELECT t.invitee_id, COALESCE(u.username, ''), COALESCE(u.email, ''),
       t.invitee_spend_tracked::double precision, t.spend_threshold::double precision, t.inviter_reward_granted, t.inviter_reward_eligible_at_bind, t.inviter_reward_blocked_by_quota
FROM referral_reward_tracker t
LEFT JOIN users u ON u.id = t.invitee_id
WHERE t.inviter_id = $1
ORDER BY t.created_at DESC
LIMIT 50`, userID)
	if err != nil {
		return nil, fmt.Errorf("query inviter progress: %w", err)
	}
	defer func() { _ = progressRows.Close() }()
	for progressRows.Next() {
		var p InviteeProgress
		if err := progressRows.Scan(&p.InviteeID, &p.InviteeName, &p.InviteeEmail, &p.SpendTracked, &p.Threshold, &p.Granted, &p.RewardEligible, &p.BlockedByQuota); err != nil {
			return nil, fmt.Errorf("scan inviter progress: %w", err)
		}
		status.InviterProgress = append(status.InviterProgress, p)
	}
	if err := progressRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate inviter progress: %w", err)
	}

	if status.InviterProgress == nil {
		status.InviterProgress = []InviteeProgress{}
	}

	return status, nil
}

func referralPtrStr(s string) *string { return &s }
