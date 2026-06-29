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
	entClient        *dbent.Client
	giftEngine       *gift.Engine
	settingService   *SettingService
	discountRepo     RechargeDiscountRepo // 用于折扣继承
	affiliateService *AffiliateService    // 用于 EnsureUserAffiliate（lazy 创建 aff_code）
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

	// 4. 判断是否达标 + 发放
	if !tracker.inviterGranted && newTracked >= tracker.threshold {
		if !tracker.rewardEligible {
			return tx.Commit()
		}
		cfg := s.settingService.GetReferralRewardConfig(ctx)
		if s.settingService.IsReferralRewardEnabled(ctx) {
			expiresAt := time.Now().Add(time.Duration(cfg.InviterExpiryDays) * 24 * time.Hour)
			mode := gift.DeductionModePriority
			var ratioRecharge *float64
			if cfg.InviterGiftMode == "ratio" {
				mode = gift.DeductionModeRatio
				ratio := cfg.InviterGiftRatio
				ratioRecharge = &ratio
			}
			grantResult, err := s.giftEngine.Grant(txCtx, gift.GrantInput{
				UserID:        tracker.inviterID,
				Amount:        cfg.InviterAmount,
				Mode:          mode,
				RatioRecharge: ratioRecharge,
				ExpiresAt:     &expiresAt,
				Source:        gift.SourceReferralInviter,
				SourceRef:     referralPtrStr(fmt.Sprintf("invitee:%d", inviteeID)),
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
func (s *ReferralRewardService) inheritDiscountFromInviter(ctx context.Context, inviterID, inviteeID int64, boundAt time.Time) error {
	if s.discountRepo == nil {
		return nil
	}

	discounts, err := s.queryInviterDiscountsForReferralGrant(ctx, inviterID, &boundAt)
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
	discounts, err := s.queryInviterDiscountsForReferralGrant(ctx, inviterID, nil)
	return err == nil && len(discounts) > 0
}

// hasInviterRewardEligibilityAtTime 判断邀请人在指定绑定时间点是否有超级邀请达标赠金资格。
func (s *ReferralRewardService) hasInviterRewardEligibilityAtTime(ctx context.Context, inviterID int64, atTime time.Time) bool {
	discounts, err := s.queryInviterDiscountsForReferralGrant(ctx, inviterID, &atTime)
	return err == nil && len(discounts) > 0
}

func (s *ReferralRewardService) queryInviterDiscountsForReferralGrant(ctx context.Context, inviterID int64, atTime *time.Time) ([]RechargeDiscountSummary, error) {
	if s == nil || s.discountRepo == nil {
		return nil, nil
	}
	cfg := ReferralRewardConfig{EligibilityGrantMode: ReferralEligibilityGrantModeBindKeyClaim}
	if s.settingService != nil {
		cfg = s.settingService.GetReferralRewardConfig(ctx)
	}
	if cfg.EligibilityGrantMode == ReferralEligibilityGrantModeRecharge {
		minAmount := normalizeReferralEligibilityRechargeMinAmount(cfg.EligibilityRechargeMinAmount)
		if atTime != nil {
			return s.discountRepo.QueryDiscountsForEligibilityAfterRechargeAtTime(ctx, inviterID, *atTime, minAmount)
		}
		return s.discountRepo.QueryDiscountsForEligibilityAfterRecharge(ctx, inviterID, minAmount)
	}
	if atTime != nil {
		return s.discountRepo.QueryDiscountsForInheritanceAtTime(ctx, inviterID, *atTime)
	}
	return s.discountRepo.QueryDiscountsForInheritance(ctx, inviterID)
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

// ReferralStatus 是用户可见的邀请奖励状态。
type ReferralStatus struct {
	Enabled                      bool              `json:"enabled"`
	Eligible                     bool              `json:"eligible"` // 当前用户是否有超级邀请资格
	EligibilityGrantMode         string            `json:"eligibility_grant_mode"`
	EligibilityRechargeMinAmount float64           `json:"eligibility_recharge_min_amount"`
	AffCode                      string            `json:"aff_code"`         // 用户的邀请码（用于生成邀请链接）
	InviteeReward                *InviteeRewardDTO `json:"invitee_reward"`   // 当前用户作为被邀请人的奖励状态（nil=非被邀请人）
	InviterProgress              []InviteeProgress `json:"inviter_progress"` // 当前用户作为邀请人，各被邀请人的消费进度
}

type InviteeRewardDTO struct {
	Granted bool    `json:"granted"`
	Amount  float64 `json:"amount"`
}

type InviteeProgress struct {
	InviteeName    string  `json:"invitee_name"`
	InviteeEmail   string  `json:"invitee_email"`
	SpendTracked   float64 `json:"spend_tracked"`
	Threshold      float64 `json:"threshold"`
	Granted        bool    `json:"granted"`
	RewardEligible bool    `json:"reward_eligible"` // 绑定时邀请人是否有资格（false=达标也不发放）
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
	}
	status.Eligible = s.hasInviterRewardEligibility(ctx, userID)

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
SELECT COALESCE(u.username, ''), COALESCE(u.email, ''),
       t.invitee_spend_tracked::double precision, t.spend_threshold::double precision, t.inviter_reward_granted, t.inviter_reward_eligible_at_bind
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
		if err := progressRows.Scan(&p.InviteeName, &p.InviteeEmail, &p.SpendTracked, &p.Threshold, &p.Granted, &p.RewardEligible); err != nil {
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
