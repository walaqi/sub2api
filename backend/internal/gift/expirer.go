package gift

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/lib/pq"
)

// DefaultExpirerInterval 是过期清理的默认扫描间隔。
// 对账任务复用同一节奏（每 10 分钟），不会显著增加 DB 负载（见 idx_user_gifts_expiry_sweep 部分索引）。
const DefaultExpirerInterval = 10 * time.Minute

// ExpirerService 周期扫描 user_gifts 表，把 expires_at 已到的赠金置 expired 并同步扣减 users.balance。
//
// 不变量：处理后 users.balance ≡ recharge_pool + Σ(active gifts.remaining) 仍然守恒。
// 加锁顺序与 Engine.AllocateAndDeduct 一致：先 users 后 user_gifts(id ASC)，杜绝死锁。
type ExpirerService struct {
	sqlDB    *sql.DB
	interval time.Duration
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// NewExpirerService 构造过期清理服务实例。
// interval ≤ 0 时使用 DefaultExpirerInterval。
func NewExpirerService(sqlDB *sql.DB, interval time.Duration) *ExpirerService {
	if interval <= 0 {
		interval = DefaultExpirerInterval
	}
	return &ExpirerService{
		sqlDB:    sqlDB,
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

// Start 启动后台 ticker。重复调用安全（Stop 后再 Start 视为新实例）。
func (s *ExpirerService) Start() {
	if s == nil || s.sqlDB == nil {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()

		s.runOnce()
		for {
			select {
			case <-ticker.C:
				s.runOnce()
			case <-s.stopCh:
				return
			}
		}
	}()
}

// Stop 停止后台 ticker，等待最后一轮扫描结束。
func (s *ExpirerService) Stop() {
	if s == nil {
		return
	}
	s.stopOnce.Do(func() {
		close(s.stopCh)
	})
	s.wg.Wait()
}

// runOnce 跑一轮过期清理。
// 流程：
//  1. 扫描所有有过期赠金的 user_id（部分索引）
//  2. 按 user_id 串行处理，每个用户单独事务
//  3. 任一用户处理失败不影响其他用户，记录日志后继续
func (s *ExpirerService) runOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	userIDs, err := s.findUsersWithExpiredGifts(ctx)
	if err != nil {
		log.Printf("[GiftExpirer] find users with expired gifts failed: %v", err)
		return
	}
	if len(userIDs) == 0 {
		return
	}

	processed := 0
	for _, uid := range userIDs {
		if err := s.expireForUser(ctx, uid); err != nil {
			log.Printf("[GiftExpirer] expire for user %d failed: %v", uid, err)
			continue
		}
		processed++
	}
	if processed > 0 {
		log.Printf("[GiftExpirer] processed %d users with expired gifts", processed)
	}
}

// findUsersWithExpiredGifts 列出所有"至少有一笔过期未处理赠金"的用户 ID。
// 用 idx_user_gifts_expiry_sweep 部分索引快速扫表。
func (s *ExpirerService) findUsersWithExpiredGifts(ctx context.Context) ([]int64, error) {
	rows, err := s.sqlDB.QueryContext(ctx, `
		SELECT DISTINCT user_id FROM user_gifts
		WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at < NOW()
		LIMIT 1000
	`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// expireForUser 在单事务内把指定用户的过期赠金置 expired，并同步扣 users.balance。
//
// SQL 步骤：
//  1. 锁 users 行（与 AllocateAndDeduct 相同顺序）
//  2. 锁 user_gifts 过期行（按 id ASC）
//  3. 把 remaining 清零、status 置 expired
//  4. UPDATE users 扣掉总 remaining
func (s *ExpirerService) expireForUser(ctx context.Context, userID int64) error {
	tx, err := s.sqlDB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`SELECT id FROM users WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`,
		userID,
	); err != nil {
		return fmt.Errorf("lock user: %w", err)
	}

	// 拿到所有 user 的过期赠金（按 id ASC 加锁）
	rows, err := tx.QueryContext(ctx, `
		SELECT id, remaining FROM user_gifts
		WHERE user_id = $1 AND status = 'active'
		  AND expires_at IS NOT NULL AND expires_at < NOW()
		ORDER BY id ASC
		FOR UPDATE
	`, userID)
	if err != nil {
		return fmt.Errorf("lock expired gifts: %w", err)
	}
	var ids []int64
	var totalRemaining float64
	for rows.Next() {
		var id int64
		var rem float64
		if err := rows.Scan(&id, &rem); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan: %w", err)
		}
		ids = append(ids, id)
		totalRemaining += rem
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows.Err: %w", err)
	}
	if len(ids) == 0 {
		return nil
	}

	// 过期时顺手清置顶（plan.md §3.10 陈旧置顶清理，仅 UI 整洁；正确性不依赖它）。
	if _, err := tx.ExecContext(ctx, `
		UPDATE user_gifts SET remaining = 0, status = 'expired', pinned = false, updated_at = NOW()
		WHERE id = ANY($1)
	`, pq.Array(ids)); err != nil {
		return fmt.Errorf("expire gifts: %w", err)
	}
	if totalRemaining > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE users SET balance = balance - $1, updated_at = NOW()
			WHERE id = $2 AND deleted_at IS NULL
		`, totalRemaining, userID); err != nil {
			return fmt.Errorf("subtract expired balance: %w", err)
		}
	}
	return tx.Commit()
}
