package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

// groupModelQuota5hRepository 用裸 SQL 访问 user_group_model_quota_5h 表。
// 该表无 ent 实体（避免生成文件 churn），仅一个原子 upsert + 一个读取。
type groupModelQuota5hRepository struct {
	client *dbent.Client
}

// NewGroupModelQuota5hRepository 创建 GroupModelQuota5hRepository 实现。
func NewGroupModelQuota5hRepository(client *dbent.Client) service.GroupModelQuota5hRepository {
	return &groupModelQuota5hRepository{client: client}
}

// GetUsage 查询单条记录；未找到返回 (nil, nil)。
func (r *groupModelQuota5hRepository) GetUsage(ctx context.Context, userID, groupID int64, model string) (*service.GroupModelQuota5hRecord, error) {
	client := clientFromContext(ctx, r.client)
	const query = `SELECT usage_usd, window_start
		FROM user_group_model_quota_5h
		WHERE user_id = $1 AND group_id = $2 AND model_name = $3`
	rows, err := client.QueryContext(ctx, query, userID, groupID, model)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, nil
	}
	rec := &service.GroupModelQuota5hRecord{
		UserID:  userID,
		GroupID: groupID,
		Model:   model,
	}
	if err := rows.Scan(&rec.UsageUSD, &rec.WindowStart); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return rec, nil
}

// IncrementUsageWithReset 原子累加 cost。5h 固定窗口语义：
//   - 记录不存在 → INSERT（usage=cost, window_start=now）
//   - 记录存在但窗口已过期（now - window_start >= 5h）→ 重置为 cost 并推进 window_start=now
//   - 记录存在且窗口未过期 → usage += cost（window_start 不变）
//
// 用单条 ON CONFLICT DO UPDATE 的 CASE 表达式实现，依赖 unique(user_id,group_id,model_name)
// 上的行锁保证并发原子性，无需显式事务（与 Redis 累加脚本的窗口判定同口径）。
func (r *groupModelQuota5hRepository) IncrementUsageWithReset(ctx context.Context, userID, groupID int64, model string, cost float64, now time.Time) error {
	client := clientFromContext(ctx, r.client)
	// $5 = 窗口过期阈值时刻（now - 5h）：existing.window_start <= 该时刻即视为过期。
	windowFloor := now.Add(-service.GroupModelQuota5hWindow)
	const query = `INSERT INTO user_group_model_quota_5h
		(user_id, group_id, model_name, usage_usd, window_start, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $6, $6, $6)
		ON CONFLICT (user_id, group_id, model_name) DO UPDATE SET
			usage_usd = CASE
				WHEN user_group_model_quota_5h.window_start <= $5
				THEN EXCLUDED.usage_usd
				ELSE user_group_model_quota_5h.usage_usd + EXCLUDED.usage_usd
			END,
			window_start = CASE
				WHEN user_group_model_quota_5h.window_start <= $5
				THEN EXCLUDED.window_start
				ELSE user_group_model_quota_5h.window_start
			END,
			updated_at = EXCLUDED.updated_at`
	_, err := client.ExecContext(ctx, query, userID, groupID, model, cost, windowFloor, now)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	return nil
}
