package service

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
)

// ReferralRewardService 实现双向邀请赠金逻辑。
// 实现 InviterBoundHook 接口：被邀请人注册绑定邀请关系后触发。
type ReferralRewardService struct {
	entClient      *dbent.Client
	giftEngine     *gift.Engine
	settingService *SettingService
	discountRepo   RechargeDiscountRepo // 用于折扣继承
}

// NewReferralRewardService 构造 ReferralRewardService。
func NewReferralRewardService(
	entClient *dbent.Client,
	giftEngine *gift.Engine,
	settingService *SettingService,
	discountRepo RechargeDiscountRepo,
) *ReferralRewardService {
	return &ReferralRewardService{
		entClient:      entClient,
		giftEngine:     giftEngine,
		settingService: settingService,
		discountRepo:   discountRepo,
	}
}

// OnInviterBound 实现 InviterBoundHook。
// 被邀请人注册后绑定邀请关系时由 AffiliateService 异步调用。
// 无论功能开关状态如何，都创建 tracker 行（确保后续开启时能追踪）。
// 仅当 referral_reward_enabled=true 时发放被邀请人赠金和继承折扣。
func (s *ReferralRewardService) OnInviterBound(ctx context.Context, inviterID, inviteeID int64) {
	if s == nil || s.entClient == nil {
		return
	}

	// 获取配置
	cfg := s.settingService.GetReferralRewardConfig(ctx)

	// 创建 tracker 行（幂等，ON CONFLICT DO NOTHING）
	if err := s.ensureTracker(ctx, inviterID, inviteeID, cfg.SpendThreshold); err != nil {
		log.Printf("[referral] create tracker for inviter=%d invitee=%d failed: %v", inviterID, inviteeID, err)
		return
	}

	// 功能开关关闭时不发放
	if !s.settingService.IsReferralRewardEnabled(ctx) {
		return
	}

	// 发放被邀请人赠金
	if err := s.grantInviteeReward(ctx, inviterID, inviteeID, cfg); err != nil {
		log.Printf("[referral] grant invitee reward for invitee=%d failed: %v", inviteeID, err)
	}

	// 继承邀请人的充值折扣
	if err := s.inheritDiscountFromInviter(ctx, inviterID, inviteeID); err != nil {
		log.Printf("[referral] inherit discount for invitee=%d from inviter=%d failed: %v", inviteeID, inviterID, err)
	}
}

// TrackSpendAndMaybeGrantInviterReward 每次计费成功后异步调用。
// 累加被邀请人消费额，达标后发放邀请人赠金。
// 幂等：referral_spend_events 唯一索引保证同一 eventID 不重复累加。
//
// 竞态安全：若 tracker 尚未创建（OnInviterBound 异步还没跑完），整个事务 rollback，
// event 不被标记为已处理——下次 billing 事件会自然重试。
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

	// 1. FOR UPDATE 锁 tracker 行（必须先锁再插 event，确保无 tracker 时能安全 rollback）
	rows, err := execer.QueryContext(txCtx, `
SELECT id, inviter_id, invitee_spend_tracked, spend_threshold, inviter_reward_granted
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
	}
	var tracker *trackerRow
	if rows.Next() {
		t := &trackerRow{}
		if err := rows.Scan(&t.id, &t.inviterID, &t.spendTracked, &t.threshold, &t.inviterGranted); err != nil {
			_ = rows.Close()
			return err
		}
		tracker = t
	}
	_ = rows.Close()

	if tracker == nil {
		// tracker 尚未创建 → rollback，不标记 event 为已处理。
		// 后续 billing event 或 OnInviterBound 回填会正常累计。
		return nil // defer rollback
	}

	// 2. 事件幂等检查 + 插入（在锁定 tracker 之后，确保 tracker 存在才消费 event slot）
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

	// 4. 判断是否达标 + 发放
	if !tracker.inviterGranted && newTracked >= tracker.threshold {
		cfg := s.settingService.GetReferralRewardConfig(ctx)
		if s.settingService.IsReferralRewardEnabled(ctx) {
			expiresAt := time.Now().Add(time.Duration(cfg.InviterExpiryDays) * 24 * time.Hour)
			grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
				UserID:    tracker.inviterID,
				Amount:    cfg.InviterAmount,
				Mode:      gift.DeductionModePriority,
				ExpiresAt: &expiresAt,
				Source:    gift.SourceReferralInviter,
				SourceRef: referralPtrStr(fmt.Sprintf("invitee:%d", inviteeID)),
			})
			if err != nil {
				return fmt.Errorf("grant inviter reward: %w", err)
			}
			_, err = execer.ExecContext(txCtx,
				`UPDATE referral_reward_tracker SET inviter_reward_granted = TRUE, inviter_reward_gift_id = $1, inviter_reward_at = NOW(), updated_at = NOW() WHERE id = $2`,
				grantResult.ID, tracker.id)
			if err != nil {
				return fmt.Errorf("mark inviter reward granted: %w", err)
			}
		}
	}

	return tx.Commit()
}

// ensureTracker 创建 tracker 行（幂等）。
func (s *ReferralRewardService) ensureTracker(ctx context.Context, inviterID, inviteeID int64, threshold float64) error {
	execer := s.execer(ctx)
	_, err := execer.ExecContext(ctx,
		`INSERT INTO referral_reward_tracker (inviter_id, invitee_id, spend_threshold) VALUES ($1, $2, $3) ON CONFLICT (inviter_id, invitee_id) DO NOTHING`,
		inviterID, inviteeID, threshold)
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
func (s *ReferralRewardService) inheritDiscountFromInviter(ctx context.Context, inviterID, inviteeID int64) error {
	if s.discountRepo == nil {
		return nil
	}

	// 读取邀请人的活跃折扣
	discounts, err := s.discountRepo.QueryActiveDiscountsReadOnly(ctx, inviterID)
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
	_, err = s.discountRepo.CreateDiscount(ctx, inviteeID, "referral_inherit", sourceRef, nil,
		best.DiscountRate, best.MaxDiscountableAmount, time.Now(), &validUntil)
	if err != nil {
		return fmt.Errorf("create inherited discount: %w", err)
	}
	return nil
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

func referralPtrStr(s string) *string { return &s }
