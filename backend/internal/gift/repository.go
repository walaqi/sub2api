package gift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/shopspring/decimal"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/group"
	"github.com/Wei-Shaw/sub2api/ent/predicate"
	"github.com/Wei-Shaw/sub2api/ent/usergift"
)

// repository 封装 user_gifts / users 的读写。
//
// 项目存在"扣费走 raw SQL、CRUD 走 ent"的既有架构割裂：
//   - Grant 走 ent（与 OAuth/promo 既有 ent 事务模式一致）
//   - AllocateAndDeduct 走 raw SQL（与 usage_billing_repo 共享 *sql.Tx）
//   - 二者持有同一 PG 连接池，不混用事务
type repository struct {
	entClient *dbent.Client
	sqlDB     *sql.DB
}

// newRepository 由 Engine 内部使用。
func newRepository(entClient *dbent.Client, sqlDB *sql.DB) *repository {
	return &repository{entClient: entClient, sqlDB: sqlDB}
}

// ---------- ent 路径：Grant / Get* / 过期清理 ----------

// insertGiftWithBalance 在 ent 事务内插入一笔赠金并把 amount 加进 users.balance。
// 调用方必须传入 tx；上层 Engine 负责按 ctx 中是否已有 tx 决定是否新开。
func (r *repository) insertGiftWithBalance(ctx context.Context, tx *dbent.Tx, in GrantInput) (*UserGift, error) {
	create := tx.UserGift.Create().
		SetUserID(in.UserID).
		SetAmount(in.Amount).
		SetRemaining(in.Amount).
		SetDeductionMode(string(in.Mode)).
		SetSource(string(in.Source)).
		SetStatus(string(StatusActive))
	if in.RatioRecharge != nil {
		create = create.SetRatioRecharge(*in.RatioRecharge)
	}
	if in.ExpiresAt != nil {
		create = create.SetExpiresAt(*in.ExpiresAt)
	}
	if in.SourceRef != nil {
		create = create.SetSourceRef(*in.SourceRef)
	}
	// 绑定分组：在同一事务内 SELECT groups ... FOR UPDATE，与 groupRepository 的
	// DeleteCascade / Delete 抢同一把行锁，序列化 grant 与删组。
	//   - 组仍 active → 落 group_id = 该组；
	//   - 组已被软删（删除赢了竞态）→ 落 group_id = NULL（转全局，与 §3.5 一致）。
	// nil GroupID 无需加锁，直接全局插入。
	if in.GroupID != nil {
		groupStillActive, err := lockGroupIfActive(ctx, tx, *in.GroupID)
		if err != nil {
			return nil, err
		}
		if groupStillActive {
			create = create.SetGroupID(*in.GroupID)
		}
		// groupStillActive == false → 不 SetGroupID，落 NULL（全局）。
	}
	created, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("insert user_gift: %w", err)
	}
	if err := tx.User.UpdateOneID(in.UserID).AddBalance(in.Amount).Exec(ctx); err != nil {
		return nil, fmt.Errorf("add balance: %w", err)
	}
	return entToUserGift(created), nil
}

// lockGroupIfActive 在 ent 事务内对 groups 行加 FOR UPDATE 锁，返回该组是否仍存活
// （未软删除）。与 groupRepository.DeleteCascade / Delete 的同一行锁互斥，
// 保证 grant 与删组严格串行、不留悬挂 scope。
func lockGroupIfActive(ctx context.Context, tx *dbent.Tx, groupID int64) (bool, error) {
	rows, err := tx.QueryContext(ctx,
		`SELECT id FROM groups WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, groupID)
	if err != nil {
		return false, fmt.Errorf("lock group %d: %w", groupID, err)
	}
	defer func() { _ = rows.Close() }()
	active := rows.Next()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("lock group %d rows: %w", groupID, err)
	}
	return active, nil
}

// sumActiveGiftRemaining 返回用户所有 active 且未过期的赠金 remaining 之和。
// 不在事务内时使用；只读，不加锁。
func (r *repository) sumActiveGiftRemaining(ctx context.Context, userID int64) (float64, error) {
	now := time.Now()
	rows, err := r.entClient.UserGift.Query().
		Where(
			usergift.UserID(userID),
			usergift.Status(string(StatusActive)),
			usergift.Or(
				usergift.ExpiresAtIsNil(),
				usergift.ExpiresAtGT(now),
			),
		).
		All(ctx)
	if err != nil {
		return 0, fmt.Errorf("query active gifts: %w", err)
	}
	sum := decimal.Zero
	for _, g := range rows {
		sum = sum.Add(decimal.NewFromFloat(g.Remaining))
	}
	v, _ := sum.Float64()
	return v, nil
}

// ---------- raw SQL 路径：AllocateAndDeduct / DeductFromRechargePool / 过期作废 ----------

// lockedSnapshot 在事务内拿到用户余额 + active 赠金的快照（已加锁）。
// 加锁顺序：先 users 后 user_gifts(id ASC)，杜绝死锁。
func (r *repository) lockedSnapshot(ctx context.Context, tx *sql.Tx, userID int64) (decimal.Decimal, []ActiveGift, error) {
	// 1. 锁 users
	var balanceStr string
	if err := tx.QueryRowContext(ctx,
		`SELECT balance::text FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
		userID,
	).Scan(&balanceStr); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return decimal.Zero, nil, fmt.Errorf("user %d not found", userID)
		}
		return decimal.Zero, nil, fmt.Errorf("lock user: %w", err)
	}
	balance, err := decimal.NewFromString(balanceStr)
	if err != nil {
		return decimal.Zero, nil, fmt.Errorf("parse balance: %w", err)
	}

	// 2. 锁 user_gifts active 行。
	// 注意：**不加 group 过滤**——全局充值池依赖用户的全部 active 赠金求和，
	// 且 ratio 分摊需要一致快照。分组切分（eligible/ineligible）在 Go 内做（partitionByGroup）。
	// 排序维度：⓪ pinned 置顶最前 → ① priority 先于 ratio → ② 分组专属先于全局
	//         → ③ ratio_recharge → 到期 → id。让消费顺序与展示顺序对齐。
	rows, err := tx.QueryContext(ctx, `
		SELECT id, deduction_mode, remaining::text, COALESCE(ratio_recharge::text, '0'), group_id, pinned
		FROM user_gifts
		WHERE user_id = $1 AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY
			pinned DESC,
			CASE deduction_mode WHEN 'priority' THEN 0 ELSE 1 END,
			CASE WHEN group_id IS NOT NULL THEN 0 ELSE 1 END,
			ratio_recharge ASC NULLS LAST,
			expires_at ASC NULLS LAST,
			id ASC
		FOR UPDATE
	`, userID)
	if err != nil {
		return decimal.Zero, nil, fmt.Errorf("lock gifts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var gifts []ActiveGift
	for rows.Next() {
		var g ActiveGift
		var modeStr, remStr, ratioStr string
		var groupID sql.NullInt64
		if err := rows.Scan(&g.ID, &modeStr, &remStr, &ratioStr, &groupID, &g.Pinned); err != nil {
			return decimal.Zero, nil, fmt.Errorf("scan gift: %w", err)
		}
		g.Mode = DeductionMode(modeStr)
		g.Remaining, _ = decimal.NewFromString(remStr)
		g.RatioRecharge, _ = decimal.NewFromString(ratioStr)
		if groupID.Valid {
			v := groupID.Int64
			g.GroupID = &v
		}
		gifts = append(gifts, g)
	}
	if err := rows.Err(); err != nil {
		return decimal.Zero, nil, fmt.Errorf("rows.Err: %w", err)
	}
	return balance, gifts, nil
}

// applyDeductions 把分摊结果落库：多行 UPDATE user_gifts + 一次 UPDATE users。
// 返回新的 users.balance。
func (r *repository) applyDeductions(ctx context.Context, tx *sql.Tx, userID int64, totalCost decimal.Decimal, res AllocateResult) (decimal.Decimal, error) {
	// 1. 多行 UPDATE user_gifts
	for giftID, delta := range res.GiftDeltas {
		if delta.IsZero() {
			continue
		}
		deltaF, _ := delta.Float64()
		if _, err := tx.ExecContext(ctx, `
			UPDATE user_gifts SET
				remaining = remaining - $1,
				status = CASE WHEN remaining - $1 <= 0 THEN 'exhausted' ELSE status END,
				updated_at = NOW()
			WHERE id = $2
		`, deltaF, giftID); err != nil {
			return decimal.Zero, fmt.Errorf("update user_gift %d: %w", giftID, err)
		}
	}

	// 2. UPDATE users.balance（一次扣 totalCost；不变量保证 Σdeltas + recharge = totalCost）
	totalCostF, _ := totalCost.Float64()
	var newBalanceStr string
	if err := tx.QueryRowContext(ctx, `
		UPDATE users SET balance = balance - $1, updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
		RETURNING balance::text
	`, totalCostF, userID).Scan(&newBalanceStr); err != nil {
		return decimal.Zero, fmt.Errorf("update users.balance: %w", err)
	}
	newBalance, _ := decimal.NewFromString(newBalanceStr)
	return newBalance, nil
}

// deductFromRechargePool 在事务内重校验 recharge_pool，按 min(requested, cap) 扣减。
// 仅扣 users.balance，不动赠金。返回真实扣减额。
func (r *repository) deductFromRechargePool(ctx context.Context, tx *sql.Tx, userID int64, requested decimal.Decimal) (decimal.Decimal, error) {
	balance, gifts, err := r.lockedSnapshot(ctx, tx, userID)
	if err != nil {
		return decimal.Zero, err
	}
	giftSum := decimal.Zero
	for _, g := range gifts {
		giftSum = giftSum.Add(g.Remaining)
	}
	cap := balance.Sub(giftSum)
	if cap.Sign() < 0 {
		cap = decimal.Zero
	}
	actual := requested
	if actual.GreaterThan(cap) {
		actual = cap
	}
	if actual.Sign() <= 0 {
		return decimal.Zero, nil
	}
	actualF, _ := actual.Float64()
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET balance = balance - $1, updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`, actualF, userID); err != nil {
		return decimal.Zero, fmt.Errorf("deduct recharge pool: %w", err)
	}
	return actual, nil
}

// ---------- helpers ----------

func entToUserGift(e *dbent.UserGift) *UserGift {
	out := &UserGift{
		ID:        e.ID,
		UserID:    e.UserID,
		Amount:    e.Amount,
		Remaining: e.Remaining,
		Mode:      DeductionMode(e.DeductionMode),
		Source:    Source(e.Source),
		Status:    Status(e.Status),
		CreatedAt: e.CreatedAt,
		UpdatedAt: e.UpdatedAt,
	}
	if e.RatioRecharge != nil {
		v := *e.RatioRecharge
		out.RatioRecharge = &v
	}
	if e.ExpiresAt != nil {
		v := *e.ExpiresAt
		out.ExpiresAt = &v
	}
	if e.SourceRef != nil {
		v := *e.SourceRef
		out.SourceRef = &v
	}
	if e.GroupID != nil {
		v := *e.GroupID
		out.GroupID = &v
	}
	out.Pinned = e.Pinned
	return out
}

// listActiveGiftsForDisplay 返回用户所有 active 且未过期的赠金，供 Profile 逐条展示。
// 排序与 lockedSnapshot 的扣费顺序一致（priority 在前，再按 ratio/到期/id），
// 让用户看到的顺序即实际消耗顺序。expiringSoonWindow 内到期的标记 ExpiringSoon=true。
// 只读、不加锁。
func (r *repository) listActiveGiftsForDisplay(ctx context.Context, userID int64, expiringSoonWindow time.Duration) ([]GiftDisplayItem, error) {
	if expiringSoonWindow < 0 {
		expiringSoonWindow = 0
	}
	now := time.Now()
	cutoff := now.Add(expiringSoonWindow)
	// 用 ent 查询保持方言无关（该展示接口有 SQLite 单测）；分组名走 ent 批量查，
	// 排序在 Go 内完成，与 lockedSnapshot 的消费顺序对齐（pinned → priority → 分组专属
	// → ratio → 到期 → id）。
	rows, err := r.entClient.UserGift.Query().
		Where(
			usergift.UserID(userID),
			usergift.Status(string(StatusActive)),
			usergift.RemainingGT(0),
			usergift.Or(
				usergift.ExpiresAtIsNil(),
				usergift.ExpiresAtGT(now),
			),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active gifts: %w", err)
	}

	// 批量查分组名（仅未软删的组；软删组不返回 → 展示为全局）。
	groupNames, err := r.resolveGroupNames(ctx, rows)
	if err != nil {
		return nil, err
	}

	out := make([]GiftDisplayItem, 0, len(rows))
	for _, g := range rows {
		item := GiftDisplayItem{
			Remaining: g.Remaining,
			Mode:      DeductionMode(g.DeductionMode),
		}
		if g.RatioRecharge != nil {
			v := *g.RatioRecharge
			item.RatioRecharge = &v
		}
		if g.ExpiresAt != nil {
			t := *g.ExpiresAt
			item.ExpiresAt = &t
			item.ExpiringSoon = t.Before(cutoff)
		}
		if g.GroupID != nil {
			v := *g.GroupID
			item.GroupID = &v
			item.GroupName = groupNames[v] // 软删组无名 → ""
		}
		out = append(out, item)
	}
	sortGiftDisplayItems(out)
	return out, nil
}

// resolveGroupNames 批量查 rows 里出现的分组名（仅未软删的组）。软删组不在结果里 → 展示为全局。
func (r *repository) resolveGroupNames(ctx context.Context, rows []*dbent.UserGift) (map[int64]string, error) {
	idset := make(map[int64]struct{})
	for _, g := range rows {
		if g.GroupID != nil {
			idset[*g.GroupID] = struct{}{}
		}
	}
	if len(idset) == 0 {
		return map[int64]string{}, nil
	}
	ids := make([]int64, 0, len(idset))
	for id := range idset {
		ids = append(ids, id)
	}
	groups, err := r.entClient.Group.Query().
		Where(group.IDIn(ids...), group.DeletedAtIsNil()).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("resolve group names: %w", err)
	}
	names := make(map[int64]string, len(groups))
	for _, gr := range groups {
		names[gr.ID] = gr.Name
	}
	return names, nil
}

// sortGiftDisplayItems 按消费顺序排序展示项：pinned 优先字段未在 GiftDisplayItem 暴露，
// 此处按 (priority 先于 ratio) → (分组专属先于全局) → (ratio_recharge 升序) →
// (到期升序) → 稳定顺序。置顶维度由分页查询的 SQL ORDER BY 负责（Profile 卡不含置顶）。
func sortGiftDisplayItems(items []GiftDisplayItem) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		// ① priority 先于 ratio
		if pa, pb := modeRank(a.Mode), modeRank(b.Mode); pa != pb {
			return pa < pb
		}
		// ② 分组专属先于全局
		ga, gb := groupRank(a.GroupID), groupRank(b.GroupID)
		if ga != gb {
			return ga < gb
		}
		// ③ ratio_recharge 升序（nil 视为 +inf 排后）
		ra, rb := ratioValue(a.RatioRecharge), ratioValue(b.RatioRecharge)
		if ra != rb {
			return ra < rb
		}
		// ④ 到期升序（nil=永不过期排后）
		return expiresBefore(a.ExpiresAt, b.ExpiresAt)
	})
}

func modeRank(m DeductionMode) int {
	if m == DeductionModePriority {
		return 0
	}
	return 1
}

func groupRank(g *int64) int {
	if g != nil {
		return 0
	}
	return 1
}

func ratioValue(r *float64) float64 {
	if r == nil {
		return math.Inf(1)
	}
	return *r
}

func expiresBefore(a, b *time.Time) bool {
	switch {
	case a == nil && b == nil:
		return false
	case a == nil:
		return false // a 永不过期 → 排 b 之后
	case b == nil:
		return true
	default:
		return a.Before(*b)
	}
}

// ---------- ops 路径：撤销/列表/查单笔/balance breakdown ----------

// giftBalanceBreakdown 一次 SQL 算出 (gift_balance, expiring_soon)。
// 调用方提供 expiringSoonWindow（如 120h），expiring_soon 仅统计 expires_at 落在 (NOW(), NOW()+window) 的赠金。
// 不变量：expiring_soon ≤ gift_balance。
func (r *repository) giftBalanceBreakdown(ctx context.Context, userID int64, expiringSoonWindow time.Duration) (float64, float64, error) {
	if expiringSoonWindow < 0 {
		expiringSoonWindow = 0
	}
	cutoff := time.Now().Add(expiringSoonWindow)
	var giftBalance, expiringSoon float64
	err := r.sqlDB.QueryRowContext(ctx, `
		SELECT
			COALESCE(SUM(remaining), 0) AS gift_balance,
			COALESCE(SUM(CASE WHEN expires_at IS NOT NULL AND expires_at < $2
			                    THEN remaining END), 0) AS expiring_soon
		FROM user_gifts
		WHERE user_id = $1 AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, userID, cutoff).Scan(&giftBalance, &expiringSoon)
	if err != nil {
		return 0, 0, fmt.Errorf("gift balance breakdown: %w", err)
	}
	return giftBalance, expiringSoon, nil
}

// hasActivePriorityGift 返回用户是否存在至少一笔 active 且未过期、remaining > 0 的 priority 赠金。
// 只读、不加锁；供 billing preflight 判定是否放行。
// 使用 ent query builder 确保跨数据库方言兼容。
func (r *repository) hasActivePriorityGift(ctx context.Context, userID int64, groupID *int64) (bool, error) {
	now := time.Now()
	// 分组可用谓词：全局赠金(group_id IS NULL)恒可用；带分组赠金仅当 == 请求组时可用。
	// 请求无分组(groupID==nil)时只有全局赠金可用。
	var groupPred predicate.UserGift
	if groupID != nil {
		groupPred = usergift.Or(
			usergift.GroupIDIsNil(),
			usergift.GroupIDEQ(*groupID),
		)
	} else {
		groupPred = usergift.GroupIDIsNil()
	}
	count, err := r.entClient.UserGift.Query().
		Where(
			usergift.UserID(userID),
			usergift.Status(string(StatusActive)),
			usergift.DeductionMode(string(DeductionModePriority)),
			usergift.RemainingGT(0),
			usergift.Or(
				usergift.ExpiresAtIsNil(),
				usergift.ExpiresAtGT(now),
			),
			groupPred,
		).
		Limit(1).
		Count(ctx)
	if err != nil {
		return false, fmt.Errorf("has active priority gift: %w", err)
	}
	return count > 0, nil
}

// revokeOneGift 撤销单笔赠金（active → revoked）。事务内：
//  1. 锁 users（与扣费/退款保持加锁顺序）
//  2. 锁该 gift 行；非 active 返回 ErrGiftNotRevocable
//  3. UPDATE user_gifts SET remaining=0, status='revoked'
//  4. UPDATE users SET balance = balance - <prevRemaining>
//
// reason 仅写入日志（不持久化到表里，按 KISS 原则；如需审计可后续扩字段）。
func (r *repository) revokeOneGift(ctx context.Context, giftID int64, reason string) error {
	tx, err := r.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// 先拿到 user_id（无锁），再按 user → gift 顺序加锁
	var userID int64
	if err := tx.QueryRowContext(ctx,
		`SELECT user_id FROM user_gifts WHERE id = $1`, giftID,
	).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("gift %d not found", giftID)
		}
		return fmt.Errorf("read gift: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, userID,
	); err != nil {
		return fmt.Errorf("lock user: %w", err)
	}

	var status, remStr string
	if err := tx.QueryRowContext(ctx, `
		SELECT status, remaining::text FROM user_gifts WHERE id = $1 FOR UPDATE
	`, giftID).Scan(&status, &remStr); err != nil {
		return fmt.Errorf("lock gift: %w", err)
	}
	if Status(status) != StatusActive {
		return ErrGiftNotRevocable
	}
	rem, err := decimal.NewFromString(remStr)
	if err != nil {
		return fmt.Errorf("parse remaining: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE user_gifts SET remaining = 0, status = 'revoked', updated_at = NOW()
		WHERE id = $1
	`, giftID); err != nil {
		return fmt.Errorf("revoke gift: %w", err)
	}
	if rem.Sign() > 0 {
		remF, _ := rem.Float64()
		if _, err := tx.ExecContext(ctx, `
			UPDATE users SET balance = balance - $1, updated_at = NOW()
			WHERE id = $2 AND deleted_at IS NULL
		`, remF, userID); err != nil {
			return fmt.Errorf("subtract balance: %w", err)
		}
	}
	_ = reason // 当前不持久化；调用方可在外层写日志
	return tx.Commit()
}

// pinGift 把某用户的一笔 active 且未过期的赠金置顶。事务内：
//  1. 锁 users 行（与扣费/退款/撤销保持 user→gift 加锁顺序，杜绝死锁；
//     无置顶时只锁当前 pinned 行不足以序列化并发 pin）。
//  2. 清掉该用户已有的置顶（UPDATE ... SET pinned=false WHERE user_id AND pinned）。
//  3. 置顶目标（WHERE id AND user_id AND active AND remaining>0 AND 未过期）。
//     affected==0 → 非本人/已过期/已耗尽 → 返回 ErrGiftNotPinnable，回滚。
//
// 部分唯一索引 user_gifts_one_pin_per_user 作为 defense-in-depth。
func (r *repository) pinGift(ctx context.Context, userID, giftID int64) error {
	tx, err := r.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`, userID,
	); err != nil {
		return fmt.Errorf("lock user: %w", err)
	}

	if _, err := tx.ExecContext(ctx,
		`UPDATE user_gifts SET pinned = false, updated_at = NOW() WHERE user_id = $1 AND pinned`, userID,
	); err != nil {
		return fmt.Errorf("clear old pin: %w", err)
	}

	res, err := tx.ExecContext(ctx, `
		UPDATE user_gifts SET pinned = true, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND status = 'active' AND remaining > 0
		  AND (expires_at IS NULL OR expires_at > NOW())
	`, giftID, userID)
	if err != nil {
		return fmt.Errorf("set pin: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("pin rows affected: %w", err)
	}
	if affected == 0 {
		return ErrGiftNotPinnable
	}
	return tx.Commit()
}

// unpinGift 取消某用户某笔赠金的置顶。只清状态、无需锁 users 行（幂等；不改余额/不改分摊）。
// affected==0（非本人/未置顶）视为幂等成功，不报错。
func (r *repository) unpinGift(ctx context.Context, userID, giftID int64) error {
	if _, err := r.sqlDB.ExecContext(ctx, `
		UPDATE user_gifts SET pinned = false, updated_at = NOW()
		WHERE id = $1 AND user_id = $2 AND pinned
	`, giftID, userID); err != nil {
		return fmt.Errorf("unpin gift: %w", err)
	}
	return nil
}

// listGiftsByUser 列出某用户的赠金，可按 status 过滤。返回总数便于分页。
func (r *repository) listGiftsByUser(ctx context.Context, userID int64, status Status, page, pageSize int) ([]UserGift, int64, error) {
	return r.listGiftsByUserWithSort(ctx, userID, status, page, pageSize, "ug.id DESC")
}

// listGiftsByUserExpiryAsc 同 listGiftsByUser，但按过期时间从早到晚排序。
// 置顶行(pinned)恒排最前，供"我的赠金"分页页展示与消费顺序一致。
func (r *repository) listGiftsByUserExpiryAsc(ctx context.Context, userID int64, status Status, page, pageSize int) ([]UserGift, int64, error) {
	return r.listGiftsByUserWithSort(ctx, userID, status, page, pageSize, "ug.pinned DESC, ug.expires_at ASC NULLS LAST, ug.id ASC")
}

// listGiftsByUserWithSort 分页列出赠金。
// user_gifts 一律别名 ug；orderBy 由调用方以 ug. 限定列传入。
// SELECT 侧 LEFT JOIN groups 带出分组名（软删组过滤 → 无名 → 全局展示）；
// COUNT 侧无需 join。共享的 where 谓词全部 ug. 限定，避免加 join 后列名歧义。
func (r *repository) listGiftsByUserWithSort(ctx context.Context, userID int64, status Status, page, pageSize int, orderBy string) ([]UserGift, int64, error) {
	args := []any{userID}
	where := "ug.user_id = $1"
	if status != "" {
		switch status {
		case StatusActive:
			// 语义过滤：status='active' 且未自然过期（expirer 有延迟，可能还没 sweep）
			where += " AND ug.status = 'active' AND (ug.expires_at IS NULL OR ug.expires_at > NOW())"
		case StatusExpired:
			// 语义过滤：status='expired' 或 status='active' 但已自然过期（expirer 尚未 sweep）
			where += " AND (ug.status = 'expired' OR (ug.status = 'active' AND ug.expires_at IS NOT NULL AND ug.expires_at <= NOW()))"
		default:
			args = append(args, string(status))
			where += " AND ug.status = $2"
		}
	}

	var total int64
	if err := r.sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_gifts ug WHERE `+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count gifts: %w", err)
	}
	if total == 0 {
		return nil, 0, nil
	}

	args = append(args, pageSize, (page-1)*pageSize)
	limitIdx := len(args) - 1
	offsetIdx := len(args)
	rows, err := r.sqlDB.QueryContext(ctx, fmt.Sprintf(`
		SELECT ug.id, ug.user_id, ug.amount::text, ug.remaining::text, ug.deduction_mode,
		       COALESCE(ug.ratio_recharge::text, ''), ug.expires_at,
		       ug.source, COALESCE(ug.source_ref, ''), ug.status, ug.created_at, ug.updated_at,
		       ug.group_id, COALESCE(grp.name, ''), ug.pinned
		FROM user_gifts ug
		LEFT JOIN groups grp ON grp.id = ug.group_id AND grp.deleted_at IS NULL
		WHERE %s
		ORDER BY %s
		LIMIT $%d OFFSET $%d
	`, where, orderBy, limitIdx, offsetIdx), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list gifts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := make([]UserGift, 0, pageSize)
	for rows.Next() {
		g, err := scanUserGift(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("rows.Err: %w", err)
	}
	return out, total, nil
}

// getGiftByID 查单笔（运维接口用）。列与 listGiftsByUserWithSort 对齐（含 group/pinned），
// 共享 scanUserGift，故列数与顺序必须一致。
func (r *repository) getGiftByID(ctx context.Context, giftID int64) (*UserGift, error) {
	row := r.sqlDB.QueryRowContext(ctx, `
		SELECT ug.id, ug.user_id, ug.amount::text, ug.remaining::text, ug.deduction_mode,
		       COALESCE(ug.ratio_recharge::text, ''), ug.expires_at,
		       ug.source, COALESCE(ug.source_ref, ''), ug.status, ug.created_at, ug.updated_at,
		       ug.group_id, COALESCE(grp.name, ''), ug.pinned
		FROM user_gifts ug
		LEFT JOIN groups grp ON grp.id = ug.group_id AND grp.deleted_at IS NULL
		WHERE ug.id = $1
	`, giftID)
	g, err := scanUserGift(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("gift %d not found", giftID)
		}
		return nil, err
	}
	return g, nil
}

// scanUserGift 把一行查询结果映射到 *UserGift。decimal 列以 text 读出再解析。
// 列顺序：id,user_id,amount,remaining,mode,ratio,expires_at,source,source_ref,status,
//
//	created_at,updated_at,group_id,group_name,pinned（listGiftsByUserWithSort 与
//	getGiftByID 两处 SELECT 必须与此一致）。
func scanUserGift(scanner interface{ Scan(dst ...any) error }) (*UserGift, error) {
	var (
		id        int64
		userID    int64
		amountStr string
		remStr    string
		modeStr   string
		ratioStr  string
		expiresAt sql.NullTime
		source    string
		sourceRef string
		statusStr string
		createdAt time.Time
		updatedAt time.Time
		groupID   sql.NullInt64
		groupName string
		pinned    bool
	)
	if err := scanner.Scan(&id, &userID, &amountStr, &remStr, &modeStr, &ratioStr, &expiresAt, &source, &sourceRef, &statusStr, &createdAt, &updatedAt, &groupID, &groupName, &pinned); err != nil {
		return nil, err
	}
	g := &UserGift{
		ID:        id,
		UserID:    userID,
		Mode:      DeductionMode(modeStr),
		Source:    Source(source),
		Status:    Status(statusStr),
		CreatedAt: createdAt,
		UpdatedAt: updatedAt,
		GroupName: groupName,
		Pinned:    pinned,
	}
	if v, err := decimal.NewFromString(amountStr); err == nil {
		g.Amount, _ = v.Float64()
	}
	if v, err := decimal.NewFromString(remStr); err == nil {
		g.Remaining, _ = v.Float64()
	}
	if ratioStr != "" {
		if v, err := decimal.NewFromString(ratioStr); err == nil {
			f, _ := v.Float64()
			g.RatioRecharge = &f
		}
	}
	if expiresAt.Valid {
		t := expiresAt.Time
		g.ExpiresAt = &t
	}
	if sourceRef != "" {
		g.SourceRef = &sourceRef
	}
	if groupID.Valid {
		v := groupID.Int64
		g.GroupID = &v
	}
	return g, nil
}
