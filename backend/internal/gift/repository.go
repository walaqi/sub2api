package gift

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/lib/pq"
	"github.com/shopspring/decimal"

	dbent "github.com/Wei-Shaw/sub2api/ent"
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
	created, err := create.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("insert user_gift: %w", err)
	}
	if err := tx.User.UpdateOneID(in.UserID).AddBalance(in.Amount).Exec(ctx); err != nil {
		return nil, fmt.Errorf("add balance: %w", err)
	}
	return entToUserGift(created), nil
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

	// 2. 锁 user_gifts active 行（按 id ASC）
	rows, err := tx.QueryContext(ctx, `
		SELECT id, deduction_mode, remaining::text, COALESCE(ratio_recharge::text, '0')
		FROM user_gifts
		WHERE user_id = $1 AND status = 'active'
		  AND (expires_at IS NULL OR expires_at > NOW())
		ORDER BY
			CASE deduction_mode WHEN 'priority' THEN 0 ELSE 1 END,
			ratio_recharge ASC NULLS LAST,
			expires_at ASC NULLS LAST,
			id ASC
		FOR UPDATE
	`, userID)
	if err != nil {
		return decimal.Zero, nil, fmt.Errorf("lock gifts: %w", err)
	}
	defer rows.Close()

	var gifts []ActiveGift
	for rows.Next() {
		var g ActiveGift
		var modeStr, remStr, ratioStr string
		if err := rows.Scan(&g.ID, &modeStr, &remStr, &ratioStr); err != nil {
			return decimal.Zero, nil, fmt.Errorf("scan gift: %w", err)
		}
		g.Mode = DeductionMode(modeStr)
		g.Remaining, _ = decimal.NewFromString(remStr)
		g.RatioRecharge, _ = decimal.NewFromString(ratioStr)
		gifts = append(gifts, g)
	}
	if err := rows.Err(); err != nil {
		return decimal.Zero, nil, fmt.Errorf("rows.Err: %w", err)
	}
	return balance, gifts, nil
}

// applyDeductions 把分摊结果落库：多行 UPDATE user_gifts + 一次 UPDATE users。
// 联动作废由调用方根据 res.RevokeRatioGifts 自行处理（独立 SQL）。
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

// revokeRatioGifts 把指定 ratio 赠金集体作废，并把对应 remaining 之和从 users.balance 扣掉。
func (r *repository) revokeRatioGifts(ctx context.Context, tx *sql.Tx, userID int64, giftIDs []int64, totalRemaining decimal.Decimal) error {
	if len(giftIDs) == 0 {
		return nil
	}
	// 把 []int64 转为 PG 数组参数
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_gifts SET remaining = 0, status = 'revoked', updated_at = NOW()
		WHERE id = ANY($1)
	`, pq.Array(giftIDs)); err != nil {
		return fmt.Errorf("revoke gifts: %w", err)
	}
	remF, _ := totalRemaining.Float64()
	if remF <= 0 {
		return nil
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET balance = balance - $1, updated_at = NOW()
		WHERE id = $2 AND deleted_at IS NULL
	`, remF, userID); err != nil {
		return fmt.Errorf("subtract revoked balance: %w", err)
	}
	return nil
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
		Order(
			// priority 先于 ratio：用 deduction_mode 升序时 'priority' < 'ratio'，恰好等价。
			dbent.Asc(usergift.FieldDeductionMode),
			dbent.Asc(usergift.FieldRatioRecharge),
			dbent.Asc(usergift.FieldExpiresAt),
			dbent.Asc(usergift.FieldID),
		).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("list active gifts: %w", err)
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
		out = append(out, item)
	}
	return out, nil
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

// listGiftsByUser 列出某用户的赠金，可按 status 过滤。返回总数便于分页。
func (r *repository) listGiftsByUser(ctx context.Context, userID int64, status Status, page, pageSize int) ([]UserGift, int64, error) {
	args := []any{userID}
	where := "user_id = $1"
	if status != "" {
		args = append(args, string(status))
		where += " AND status = $2"
	}

	var total int64
	if err := r.sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_gifts WHERE `+where, args...,
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
		SELECT id, user_id, amount::text, remaining::text, deduction_mode,
		       COALESCE(ratio_recharge::text, ''), expires_at,
		       source, COALESCE(source_ref, ''), status, created_at, updated_at
		FROM user_gifts
		WHERE %s
		ORDER BY id DESC
		LIMIT $%d OFFSET $%d
	`, where, limitIdx, offsetIdx), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list gifts: %w", err)
	}
	defer rows.Close()

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

// getGiftByID 查单笔（运维接口用）。
func (r *repository) getGiftByID(ctx context.Context, giftID int64) (*UserGift, error) {
	row := r.sqlDB.QueryRowContext(ctx, `
		SELECT id, user_id, amount::text, remaining::text, deduction_mode,
		       COALESCE(ratio_recharge::text, ''), expires_at,
		       source, COALESCE(source_ref, ''), status, created_at, updated_at
		FROM user_gifts
		WHERE id = $1
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
	)
	if err := scanner.Scan(&id, &userID, &amountStr, &remStr, &modeStr, &ratioStr, &expiresAt, &source, &sourceRef, &statusStr, &createdAt, &updatedAt); err != nil {
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
	return g, nil
}
