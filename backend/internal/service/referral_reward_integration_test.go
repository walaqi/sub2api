//go:build integration

package service

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupReferralIntegrationDB(t *testing.T) (*dbent.Client, *sql.DB) {
	t.Helper()
	sqlDB, err := sql.Open("postgres", testDSN)
	require.NoError(t, err)
	// 本包无 testcontainers harness，直连外部 PG（本地 5432）。CI 等无 PG 环境
	// 下应跳过而非失败——这些用例覆盖并发返利/赠金逻辑，需真实 PG 才有意义。
	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sqlDB.PingContext(pingCtx); err != nil {
		_ = sqlDB.Close()
		t.Skipf("integration DB unavailable at %s, skipping: %v", testDSN, err)
	}

	client, err := dbent.Open("postgres", testDSN)
	require.NoError(t, err)

	// Clean test data
	_, _ = sqlDB.Exec("DELETE FROM referral_spend_events WHERE invitee_id >= 800000")
	_, _ = sqlDB.Exec("DELETE FROM referral_reward_tracker WHERE invitee_id >= 800000")
	_, _ = sqlDB.Exec("DELETE FROM recharge_discount_applications WHERE user_id >= 800000 AND user_id < 900000")
	_, _ = sqlDB.Exec("DELETE FROM user_recharge_discounts WHERE user_id >= 800000 AND user_id < 900000")
	_, _ = sqlDB.Exec("DELETE FROM referral_recharge_quota_grants WHERE user_id >= 800000 AND user_id < 900000")
	_, _ = sqlDB.Exec("DELETE FROM user_affiliates WHERE user_id >= 800000 AND user_id < 900000")

	t.Cleanup(func() {
		_, _ = sqlDB.Exec("DELETE FROM referral_spend_events WHERE invitee_id >= 800000")
		_, _ = sqlDB.Exec("DELETE FROM referral_reward_tracker WHERE invitee_id >= 800000")
		_, _ = sqlDB.Exec("DELETE FROM recharge_discount_applications WHERE user_id >= 800000 AND user_id < 900000")
		_, _ = sqlDB.Exec("DELETE FROM user_recharge_discounts WHERE user_id >= 800000 AND user_id < 900000")
		_, _ = sqlDB.Exec("DELETE FROM referral_recharge_quota_grants WHERE user_id >= 800000 AND user_id < 900000")
		_, _ = sqlDB.Exec("DELETE FROM user_gifts WHERE user_id >= 800000")
		_, _ = sqlDB.Exec("DELETE FROM user_affiliates WHERE user_id >= 800000 AND user_id < 900000")
		_, _ = sqlDB.Exec("DELETE FROM users WHERE id >= 800000 AND id < 900000")
		_ = client.Close()
		_ = sqlDB.Close()
	})
	return client, sqlDB
}

func ensureTestUser(t *testing.T, db *sql.DB, userID int64) {
	t.Helper()
	var exists bool
	_ = db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)", userID).Scan(&exists)
	if !exists {
		_, err := db.Exec(`INSERT INTO users (id, email, password_hash, role, balance, status, username, concurrency, total_recharged) VALUES ($1, $2, '', 'user', 100, 'active', $3, 5, 0)`,
			userID, fmt.Sprintf("referral_test_%d@test.local", userID), fmt.Sprintf("referral_test_%d", userID))
		require.NoError(t, err)
	}
}

// setTotalRecharged 直接设置 users.total_recharged（USD）。
// recharge 模式资格判定读的正是这一列（见 referral_reward_service.go 的
// entInviterRechargeReader），与折扣券/领券完全解耦（PR#63）。
func setTotalRecharged(t *testing.T, db *sql.DB, userID int64, amount float64) {
	t.Helper()
	_, err := db.Exec(`UPDATE users SET total_recharged = $2 WHERE id = $1`, userID, amount)
	require.NoError(t, err)
}

func ensureAffiliateRelation(t *testing.T, db *sql.DB, inviteeID, inviterID int64) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO user_affiliates (user_id, inviter_id, aff_code, aff_count, aff_quota, aff_history_quota)
		VALUES ($1, $2, $3, 0, 0, 0)
		ON CONFLICT (user_id) DO UPDATE SET inviter_id = $2, updated_at = NOW()`,
		inviteeID, inviterID, fmt.Sprintf("referral_test_%d", inviteeID))
	require.NoError(t, err)
}

func insertTracker(t *testing.T, db *sql.DB, inviterID, inviteeID int64, threshold float64) int64 {
	t.Helper()
	var id int64
	err := db.QueryRow(`INSERT INTO referral_reward_tracker (inviter_id, invitee_id, spend_threshold) VALUES ($1, $2, $3) RETURNING id`,
		inviterID, inviteeID, threshold).Scan(&id)
	require.NoError(t, err)
	return id
}

func insertRechargeDiscount(t *testing.T, db *sql.DB, userID int64, sourceRef string, totalDiscounted, maxAmount float64, validFrom, validUntil string) {
	t.Helper()
	_, err := db.Exec(`
INSERT INTO user_recharge_discounts (user_id, source, source_ref, discount_rate, max_discountable_amount, total_discounted, valid_from, valid_until)
VALUES ($1, 'bind_key', $2, 0.1, $3, $4, $5::timestamptz, $6::timestamptz)
ON CONFLICT (user_id, source, source_ref) DO UPDATE SET
    max_discountable_amount = EXCLUDED.max_discountable_amount,
    total_discounted = EXCLUDED.total_discounted,
    valid_from = EXCLUDED.valid_from,
    valid_until = EXCLUDED.valid_until`,
		userID, sourceRef, maxAmount, totalDiscounted, validFrom, validUntil)
	require.NoError(t, err)
}

func buildReferralService(t *testing.T, client *dbent.Client, db *sql.DB, enabled bool) *ReferralRewardService {
	t.Helper()
	giftEngine := gift.NewEngine(client, db)
	discountRepo := NewRechargeDiscountRepoAdapter(client)

	// Use a real SettingService with the test DB
	settingRepo := &integrationSettingRepoStub{enabled: enabled}
	settingSvc := &SettingService{settingRepo: settingRepo}

	// affiliateService=nil is safe: integration tests focus on TrackSpend,
	// not GetReferralStatus which uses affiliateService for EnsureUserAffiliate.
	return NewReferralRewardService(client, giftEngine, settingSvc, discountRepo, nil)
}

// integrationSettingRepoStub implements the minimal SettingRepository for integration tests
type integrationSettingRepoStub struct {
	enabled          bool
	inviterGiftMode  string
	inviterGiftRatio string
	// 邀请人达标奖励发放次数配额（默认关闭，行为不变）
	quotaEnabled      bool
	quotaRechargeStep string // 空=默认 50
	quotaPerBatch     string // 空=默认 10
	// 资格获得方式：空=默认 bind_key_claim；设为 "recharge" 走充值达标模式
	eligibilityGrantMode   string
	eligibilityRechargeMin string // 空=默认 0
}

func (s *integrationSettingRepoStub) Get(_ context.Context, key string) (*Setting, error) {
	v, err := s.GetValue(context.Background(), key)
	if err != nil {
		return nil, err
	}
	return &Setting{Key: key, Value: v}, nil
}

func (s *integrationSettingRepoStub) GetValue(_ context.Context, key string) (string, error) {
	switch key {
	case SettingKeyReferralRewardEnabled:
		if s.enabled {
			return "true", nil
		}
		return "false", nil
	case SettingKeyReferralInviteeAmount:
		return "10", nil
	case SettingKeyReferralInviteeExpiryDays:
		return "2", nil
	case SettingKeyReferralInviterAmount:
		return "10", nil
	case SettingKeyReferralInviterExpiryDays:
		return "30", nil
	case SettingKeyReferralInviterGiftMode:
		if s.inviterGiftMode != "" {
			return s.inviterGiftMode, nil
		}
		return "priority", nil
	case SettingKeyReferralInviterGiftRatioRecharge:
		if s.inviterGiftRatio != "" {
			return s.inviterGiftRatio, nil
		}
		return "0.5", nil
	case SettingKeyReferralSpendThreshold:
		return "10", nil
	case SettingKeyReferralDiscountValidDays:
		return "30", nil
	case SettingKeyReferralInviterRewardQuotaEnabled:
		if s.quotaEnabled {
			return "true", nil
		}
		return "false", nil
	case SettingKeyReferralInviterRewardQuotaRechargeStep:
		if s.quotaRechargeStep != "" {
			return s.quotaRechargeStep, nil
		}
		return "50", nil
	case SettingKeyReferralInviterRewardQuotaPerBatch:
		if s.quotaPerBatch != "" {
			return s.quotaPerBatch, nil
		}
		return "10", nil
	case SettingKeyReferralEligibilityGrantMode:
		if s.eligibilityGrantMode != "" {
			return s.eligibilityGrantMode, nil
		}
		return ReferralEligibilityGrantModeBindKeyClaim, nil
	case SettingKeyReferralEligibilityRechargeMin:
		if s.eligibilityRechargeMin != "" {
			return s.eligibilityRechargeMin, nil
		}
		return "0", nil
	}
	return "", fmt.Errorf("key not found: %s", key)
}

func (s *integrationSettingRepoStub) Set(_ context.Context, _ string, _ string) error { return nil }
func (s *integrationSettingRepoStub) GetMultiple(_ context.Context, _ []string) (map[string]string, error) {
	return nil, nil
}
func (s *integrationSettingRepoStub) SetMultiple(_ context.Context, _ map[string]string) error {
	return nil
}
func (s *integrationSettingRepoStub) GetAll(_ context.Context) (map[string]string, error) {
	return nil, nil
}
func (s *integrationSettingRepoStub) Delete(_ context.Context, _ string) error { return nil }

// ==========================================================================
// Test 1: TrackSpend 基本事务路径 — 有 tracker、累加消费
// ==========================================================================

func TestIntegration_Referral_TrackSpend_BasicAccumulation(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800001)
	inviteeID := int64(800002)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	insertTracker(t, db, inviterID, inviteeID, 10)

	// First spend: $3
	err := svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:req1:key1", 3.0)
	require.NoError(t, err)

	// Verify spend tracked
	var tracked float64
	err = db.QueryRow("SELECT invitee_spend_tracked::double precision FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&tracked)
	require.NoError(t, err)
	assert.Equal(t, 3.0, tracked)

	// Second spend: $4
	err = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:req2:key1", 4.0)
	require.NoError(t, err)

	err = db.QueryRow("SELECT invitee_spend_tracked::double precision FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&tracked)
	require.NoError(t, err)
	assert.Equal(t, 7.0, tracked)

	// Inviter reward not yet granted (below threshold)
	var granted bool
	err = db.QueryRow("SELECT inviter_reward_granted FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&granted)
	require.NoError(t, err)
	assert.False(t, granted)
}

// ==========================================================================
// Test 2: 事件幂等 — 同一 eventID 不重复累加
// ==========================================================================

func TestIntegration_Referral_TrackSpend_EventIdempotent(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800003)
	inviteeID := int64(800004)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	insertTracker(t, db, inviterID, inviteeID, 10)

	eventID := "billing:req_dup:key1"

	// First call
	err := svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, eventID, 5.0)
	require.NoError(t, err)

	// Same eventID again — should be idempotent
	err = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, eventID, 5.0)
	require.NoError(t, err)

	// Verify only accumulated once
	var tracked float64
	err = db.QueryRow("SELECT invitee_spend_tracked::double precision FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&tracked)
	require.NoError(t, err)
	assert.Equal(t, 5.0, tracked) // NOT 10.0

	// Verify only one event row
	var eventCount int
	err = db.QueryRow("SELECT COUNT(*) FROM referral_spend_events WHERE event_id = $1", eventID).Scan(&eventCount)
	require.NoError(t, err)
	assert.Equal(t, 1, eventCount)
}

// ==========================================================================
// Test 3: 达标发放 — 消费达阈值后邀请人获得赠金
// ==========================================================================

func TestIntegration_Referral_TrackSpend_ThresholdGrant(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800005)
	inviteeID := int64(800006)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	insertTracker(t, db, inviterID, inviteeID, 10)

	// Spend $6 first
	err := svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:t3_req1:key1", 6.0)
	require.NoError(t, err)

	// Spend $5 more → total $11 > threshold $10
	err = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:t3_req2:key1", 5.0)
	require.NoError(t, err)

	// Verify inviter reward granted
	var granted bool
	var giftID sql.NullInt64
	err = db.QueryRow("SELECT inviter_reward_granted, inviter_reward_gift_id FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&granted, &giftID)
	require.NoError(t, err)
	assert.True(t, granted)
	assert.True(t, giftID.Valid)
	assert.Greater(t, giftID.Int64, int64(0))

	// Verify gift was actually created for inviter
	var giftAmount float64
	var giftSource string
	err = db.QueryRow("SELECT amount, source FROM user_gifts WHERE id = $1", giftID.Int64).Scan(&giftAmount, &giftSource)
	require.NoError(t, err)
	assert.Equal(t, 10.0, giftAmount)
	assert.Equal(t, "referral_inviter", giftSource)
}

func TestIntegration_Referral_TrackSpend_ThresholdGrant_RatioMode(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	giftEngine := gift.NewEngine(client, db)
	discountRepo := NewRechargeDiscountRepoAdapter(client)
	settingSvc := &SettingService{settingRepo: &integrationSettingRepoStub{
		enabled:          true,
		inviterGiftMode:  "ratio",
		inviterGiftRatio: "0.75",
	}}
	svc := NewReferralRewardService(client, giftEngine, settingSvc, discountRepo, nil)
	ctx := context.Background()

	inviterID := int64(800016)
	inviteeID := int64(800017)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	insertTracker(t, db, inviterID, inviteeID, 10)

	err := svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:ratio_mode:key1", 12.0)
	require.NoError(t, err)

	var giftID sql.NullInt64
	err = db.QueryRow("SELECT inviter_reward_gift_id FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&giftID)
	require.NoError(t, err)
	require.True(t, giftID.Valid)

	var mode string
	var ratio sql.NullFloat64
	err = db.QueryRow("SELECT deduction_mode, ratio_recharge::double precision FROM user_gifts WHERE id = $1", giftID.Int64).Scan(&mode, &ratio)
	require.NoError(t, err)
	assert.Equal(t, "ratio", mode)
	require.True(t, ratio.Valid)
	assert.InDelta(t, 0.75, ratio.Float64, 0.0001)
}

// ==========================================================================
// Test 4: 并发只发一次 — 多个 goroutine 同时达标，邀请人只得一次奖励
// ==========================================================================

func TestIntegration_Referral_ConcurrentSpend_OnlyOneGrant(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800007)
	inviteeID := int64(800008)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)

	// Start with $9 tracked (just below $10 threshold)
	trackerID := insertTracker(t, db, inviterID, inviteeID, 10)
	_, err := db.Exec("UPDATE referral_reward_tracker SET invitee_spend_tracked = 9 WHERE id = $1", trackerID)
	require.NoError(t, err)

	// 10 goroutines each trying to push over the threshold simultaneously
	const goroutines = 10
	var grantCount atomic.Int32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		eventID := fmt.Sprintf("billing:concurrent_%d:key1", i)
		go func(eid string) {
			defer wg.Done()
			_ = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, eid, 2.0)
		}(eventID)
	}
	wg.Wait()

	// Verify exactly one grant
	var granted bool
	err = db.QueryRow("SELECT inviter_reward_granted FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&granted)
	require.NoError(t, err)
	assert.True(t, granted)

	// Count inviter gifts with source referral_inviter for this inviter
	var giftCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id = $1 AND source = 'referral_inviter'", inviterID).Scan(&giftCount)
	require.NoError(t, err)
	assert.Equal(t, 1, giftCount, "inviter should receive exactly one gift regardless of concurrent events")

	// All events should be recorded (each unique)
	var eventCount int
	err = db.QueryRow("SELECT COUNT(*) FROM referral_spend_events WHERE invitee_id = $1", inviteeID).Scan(&eventCount)
	require.NoError(t, err)
	assert.Equal(t, goroutines, eventCount)

	// Verify total tracked = 9 (initial) + 10 * 2 = 29
	var tracked float64
	err = db.QueryRow("SELECT invitee_spend_tracked::double precision FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&tracked)
	require.NoError(t, err)
	// Due to serialization, all events are accumulated
	assert.InDelta(t, 9.0+float64(goroutines)*2.0, tracked, 0.01)

	t.Logf("concurrent spend: %d events processed, inviter got %d gift(s), total tracked=%.2f",
		eventCount, giftCount, tracked)
	_ = grantCount
}

// ==========================================================================
// Test 5: 无 tracker 时自动补建 — 从 user_affiliates 查 inviter 并创建 tracker
// ==========================================================================

func TestIntegration_Referral_TrackSpend_NoTracker_AutoCreates(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800009)
	inviteeID := int64(800010)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)

	// Set up affiliate relation but NO tracker (simulates race: billing fires before OnInviterBound)
	ensureAffiliateRelation(t, db, inviteeID, inviterID)

	// Verify no tracker exists
	var trackerExists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM referral_reward_tracker WHERE invitee_id = $1)", inviteeID).Scan(&trackerExists)
	require.NoError(t, err)
	assert.False(t, trackerExists)

	// TrackSpend should auto-create tracker and accumulate
	err = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:no_tracker_1:key1", 5.0)
	require.NoError(t, err)

	// Verify tracker was created
	var tracked float64
	var createdInviterID int64
	err = db.QueryRow("SELECT inviter_id, invitee_spend_tracked::double precision FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&createdInviterID, &tracked)
	require.NoError(t, err)
	assert.Equal(t, inviterID, createdInviterID)
	assert.Equal(t, 5.0, tracked)

	// Verify event was recorded
	var eventCount int
	err = db.QueryRow("SELECT COUNT(*) FROM referral_spend_events WHERE invitee_id = $1", inviteeID).Scan(&eventCount)
	require.NoError(t, err)
	assert.Equal(t, 1, eventCount)
}

// ==========================================================================
// Test 6: 非被邀请人（无 affiliate 关系）→ 安全退出无副作用
// ==========================================================================

func TestIntegration_Referral_TrackSpend_NotInvitee_NoOp(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	// User with no affiliate relation
	loneUserID := int64(800011)
	ensureTestUser(t, db, loneUserID)

	err := svc.TrackSpendAndMaybeGrantInviterReward(ctx, loneUserID, "billing:lone_1:key1", 100.0)
	require.NoError(t, err)

	// No tracker created
	var trackerExists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM referral_reward_tracker WHERE invitee_id = $1)", loneUserID).Scan(&trackerExists)
	require.NoError(t, err)
	assert.False(t, trackerExists)

	// No events recorded
	var eventCount int
	err = db.QueryRow("SELECT COUNT(*) FROM referral_spend_events WHERE invitee_id = $1", loneUserID).Scan(&eventCount)
	require.NoError(t, err)
	assert.Equal(t, 0, eventCount)
}

// ==========================================================================
// Test 7: tracker 快照为 false 时，达标只累计消费，不发邀请人赠金
// ==========================================================================

func TestIntegration_Referral_TrackSpend_RewardIneligibleAtBind_DoesNotGrantInviter(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800012)
	inviteeID := int64(800013)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)

	trackerID := insertTracker(t, db, inviterID, inviteeID, 10)
	_, err := db.Exec("UPDATE referral_reward_tracker SET inviter_reward_eligible_at_bind = FALSE WHERE id = $1", trackerID)
	require.NoError(t, err)

	err = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:ineligible:key1", 12.0)
	require.NoError(t, err)

	var tracked float64
	var granted bool
	err = db.QueryRow("SELECT invitee_spend_tracked::double precision, inviter_reward_granted FROM referral_reward_tracker WHERE id = $1", trackerID).Scan(&tracked, &granted)
	require.NoError(t, err)
	assert.Equal(t, 12.0, tracked)
	assert.False(t, granted)

	var giftCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id = $1 AND source = 'referral_inviter'", inviterID).Scan(&giftCount)
	require.NoError(t, err)
	assert.Equal(t, 0, giftCount)
}

// ==========================================================================
// Test 8: lazy 补建 tracker 使用 user_affiliates.inviter_bound_at/updated_at 还原绑定时资格
// ==========================================================================

func TestIntegration_Referral_TrackSpend_NoTracker_UsesBindTimeEligibility(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800014)
	inviteeID := int64(800015)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	ensureAffiliateRelation(t, db, inviteeID, inviterID)

	_, err := db.Exec("UPDATE user_affiliates SET updated_at = '2026-01-10T00:00:00Z'::timestamptz WHERE user_id = $1", inviteeID)
	require.NoError(t, err)
	insertRechargeDiscount(t, db, inviterID, "api_key:lazy_bind_window", 100, 100, "2026-01-01T00:00:00Z", "2026-01-20T00:00:00Z")

	err = svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:lazy_bind:key1", 5.0)
	require.NoError(t, err)

	var rewardEligible bool
	err = db.QueryRow("SELECT inviter_reward_eligible_at_bind FROM referral_reward_tracker WHERE invitee_id = $1", inviteeID).Scan(&rewardEligible)
	require.NoError(t, err)
	assert.True(t, rewardEligible)
}

// ==========================================================================
// Test 9: OnInviterBound — 邀请人资格为 false 时不发被邀请人赠金（修复 bug）
// ==========================================================================

func TestIntegration_Referral_OnInviterBound_IneligibleInviter_NoInviteeGift(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800018)
	inviteeID := int64(800019)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)

	// 邀请人886无折扣（无资格）
	boundAt := time.Now()

	// 直接调用 OnInviterBound 模拟被邀请人绑定
	svc.OnInviterBound(ctx, inviterID, inviteeID, boundAt)

	// 验证 tracker 被创建且快照为 false
	var trackerID int64
	var rewardEligible bool
	var inviteeRewardGranted bool
	err := db.QueryRow(
		"SELECT id, inviter_reward_eligible_at_bind, invitee_reward_granted FROM referral_reward_tracker WHERE inviter_id = $1 AND invitee_id = $2",
		inviterID, inviteeID).Scan(&trackerID, &rewardEligible, &inviteeRewardGranted)
	require.NoError(t, err)
	assert.False(t, rewardEligible, "邀请人无资格，快照应为 false")
	assert.False(t, inviteeRewardGranted, "资格为 false 时不应发放被邀请人赠金")

	// 验证被邀请人没有获得赠金
	var giftCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id = $1 AND source = 'referral_invitee'", inviteeID).Scan(&giftCount)
	require.NoError(t, err)
	assert.Equal(t, 0, giftCount, "邀请人无资格时被邀请人不应获得赠金")

	// 验证被邀请人也没有继承折扣
	var discountCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_recharge_discounts WHERE user_id = $1 AND source = 'referral_inherit'", inviteeID).Scan(&discountCount)
	require.NoError(t, err)
	assert.Equal(t, 0, discountCount, "邀请人无资格时不应继承折扣")
}

// ==========================================================================
// Test 10: OnInviterBound — 邀请人资格为 true 时发被邀请人赠金
// ==========================================================================

func TestIntegration_Referral_OnInviterBound_EligibleInviter_GrantsInviteeGift(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800020)
	inviteeID := int64(800021)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)

	boundAt := time.Now()

	// 邀请人在绑定时刻有有效折扣（资格=true）
	validUntil := time.Now().Add(30 * 24 * time.Hour)
	insertRechargeDiscount(t, db, inviterID, "api_key:eligible", 100, 100,
		boundAt.Add(-1*time.Hour).Format(time.RFC3339),
		validUntil.Format(time.RFC3339))

	svc.OnInviterBound(ctx, inviterID, inviteeID, boundAt)

	// 验证快照为 true
	var trackerID int64
	var rewardEligible bool
	var inviteeRewardGranted bool
	err := db.QueryRow(
		"SELECT id, inviter_reward_eligible_at_bind, invitee_reward_granted FROM referral_reward_tracker WHERE inviter_id = $1 AND invitee_id = $2",
		inviterID, inviteeID).Scan(&trackerID, &rewardEligible, &inviteeRewardGranted)
	require.NoError(t, err)
	assert.True(t, rewardEligible, "邀请人有资格，快照应为 true")
	assert.True(t, inviteeRewardGranted, "资格为 true 时应发放被邀请人赠金")

	// 验证被邀请人获得赠金
	var giftAmount float64
	var giftSource string
	err = db.QueryRow("SELECT amount, source FROM user_gifts WHERE user_id = $1 AND source = 'referral_invitee'", inviteeID).Scan(&giftAmount, &giftSource)
	require.NoError(t, err)
	assert.Equal(t, 10.0, giftAmount)
	assert.Equal(t, "referral_invitee", giftSource)

	// 验证被邀请人继承折扣
	var inheritDiscountCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_recharge_discounts WHERE user_id = $1 AND source = 'referral_inherit'", inviteeID).Scan(&inheritDiscountCount)
	require.NoError(t, err)
	assert.Equal(t, 1, inheritDiscountCount, "资格为 true 时应继承折扣")
}

// ensureAffiliateRow 为用户建一个独立 user_affiliates 行（无 inviter），供配额赚/花测试用。
func ensureAffiliateRow(t *testing.T, db *sql.DB, userID int64) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO user_affiliates (user_id, aff_code, aff_count, aff_quota, aff_history_quota)
		VALUES ($1, $2, 0, 0, 0)
		ON CONFLICT (user_id) DO NOTHING`,
		userID, fmt.Sprintf("referral_test_%d", userID))
	require.NoError(t, err)
}

// buildReferralServiceRecharge 构建 recharge 资格模式的服务，minAmount 为达标门槛（USD）。
func buildReferralServiceRecharge(t *testing.T, client *dbent.Client, db *sql.DB, minAmount string) *ReferralRewardService {
	t.Helper()
	giftEngine := gift.NewEngine(client, db)
	discountRepo := NewRechargeDiscountRepoAdapter(client)
	settingSvc := &SettingService{settingRepo: &integrationSettingRepoStub{
		enabled:                true,
		eligibilityGrantMode:   ReferralEligibilityGrantModeRecharge,
		eligibilityRechargeMin: minAmount,
	}}
	return NewReferralRewardService(client, giftEngine, settingSvc, discountRepo, nil)
}

func buildReferralServiceWithQuota(t *testing.T, client *dbent.Client, db *sql.DB, step, perBatch string) *ReferralRewardService {
	t.Helper()
	giftEngine := gift.NewEngine(client, db)
	discountRepo := NewRechargeDiscountRepoAdapter(client)
	settingSvc := &SettingService{settingRepo: &integrationSettingRepoStub{
		enabled:           true,
		quotaEnabled:      true,
		quotaRechargeStep: step,
		quotaPerBatch:     perBatch,
	}}
	return NewReferralRewardService(client, giftEngine, settingSvc, discountRepo, nil)
}

// ==========================================================================
// Quota Test A: 充值赚配额 — carry 跨次累积
// ==========================================================================

func TestIntegration_Referral_QuotaAccrual_CarryAccumulates(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800030)
	ensureTestUser(t, db, inviterID)
	ensureAffiliateRow(t, db, inviterID)

	// 充值 70 → floor(70/50)=1 批 → +10 机会，carry=20
	require.NoError(t, svc.AccrueInviterRewardQuota(ctx, inviterID, ReferralQuotaSourcePaymentOrder, 900001, 70))
	var quota int
	var carry float64
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota, inviter_reward_recharge_carry::double precision FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota, &carry))
	assert.Equal(t, 10, quota)
	assert.InDelta(t, 20.0, carry, 0.001)

	// 再充值 30 → carry=50 → floor(50/50)=1 批 → +10 机会（共20），carry=0
	require.NoError(t, svc.AccrueInviterRewardQuota(ctx, inviterID, ReferralQuotaSourcePaymentOrder, 900002, 30))
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota, inviter_reward_recharge_carry::double precision FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota, &carry))
	assert.Equal(t, 20, quota)
	assert.InDelta(t, 0.0, carry, 0.001)
}

// ==========================================================================
// Quota Test B: 赚配额幂等 — 同一 source 重放不重复赚
// ==========================================================================

func TestIntegration_Referral_QuotaAccrual_Idempotent(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800031)
	ensureTestUser(t, db, inviterID)
	ensureAffiliateRow(t, db, inviterID)

	require.NoError(t, svc.AccrueInviterRewardQuota(ctx, inviterID, ReferralQuotaSourcePaymentOrder, 900010, 100))
	require.NoError(t, svc.AccrueInviterRewardQuota(ctx, inviterID, ReferralQuotaSourcePaymentOrder, 900010, 100)) // 同 source 重放

	var quota int
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota))
	assert.Equal(t, 20, quota, "重放不应重复赚（应只 +20 而非 +40）")

	var grantCount int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM referral_recharge_quota_grants WHERE source_type=$1 AND source_id=$2", ReferralQuotaSourcePaymentOrder, 900010).Scan(&grantCount))
	assert.Equal(t, 1, grantCount)
}

// ==========================================================================
// Quota Test C: quota=0 达标 → 不发、置 blocked flag
// ==========================================================================

func TestIntegration_Referral_QuotaZero_BlocksAndFlagsPending(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800032)
	inviteeID := int64(800033)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	ensureAffiliateRow(t, db, inviterID) // quota=0
	insertTracker(t, db, inviterID, inviteeID, 10)

	// 达标（$12 > $10）但 quota=0 → 不发、置 blocked
	require.NoError(t, svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:qzero:key1", 12.0))

	var granted, blocked bool
	require.NoError(t, db.QueryRow("SELECT inviter_reward_granted, inviter_reward_blocked_by_quota FROM referral_reward_tracker WHERE invitee_id=$1", inviteeID).Scan(&granted, &blocked))
	assert.False(t, granted, "quota=0 时不应发放")
	assert.True(t, blocked, "quota=0 时应置 blocked flag")

	var giftCount int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id=$1 AND source='referral_inviter'", inviterID).Scan(&giftCount))
	assert.Equal(t, 0, giftCount)
}

// ==========================================================================
// Quota Test D: quota>0 达标 → 发放、扣一次机会、清 blocked
// ==========================================================================

func TestIntegration_Referral_QuotaAvailable_GrantsAndConsumes(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800034)
	inviteeID := int64(800035)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	ensureAffiliateRow(t, db, inviterID)
	// 预置 quota=3
	_, err := db.Exec("UPDATE user_affiliates SET inviter_reward_quota=3 WHERE user_id=$1", inviterID)
	require.NoError(t, err)
	insertTracker(t, db, inviterID, inviteeID, 10)

	require.NoError(t, svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:qavail:key1", 12.0))

	var granted, blocked bool
	require.NoError(t, db.QueryRow("SELECT inviter_reward_granted, inviter_reward_blocked_by_quota FROM referral_reward_tracker WHERE invitee_id=$1", inviteeID).Scan(&granted, &blocked))
	assert.True(t, granted)
	assert.False(t, blocked)

	var quota, consumed int
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota, inviter_reward_quota_consumed_total FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota, &consumed))
	assert.Equal(t, 2, quota, "应扣一次机会")
	assert.Equal(t, 1, consumed)

	var giftCount int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id=$1 AND source='referral_inviter'", inviterID).Scan(&giftCount))
	assert.Equal(t, 1, giftCount)
}

// ==========================================================================
// Quota Test E: 充值后立即补发被卡 pending
// ==========================================================================

func TestIntegration_Referral_RechargeBackfillsPending(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800036)
	inviteeID := int64(800037)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	ensureAffiliateRow(t, db, inviterID) // quota=0
	insertTracker(t, db, inviterID, inviteeID, 10)

	// 达标但 quota=0 → pending blocked
	require.NoError(t, svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:bf1:key1", 12.0))
	var blocked, granted bool
	require.NoError(t, db.QueryRow("SELECT inviter_reward_blocked_by_quota, inviter_reward_granted FROM referral_reward_tracker WHERE invitee_id=$1", inviteeID).Scan(&blocked, &granted))
	require.True(t, blocked)
	require.False(t, granted)

	// 邀请人充值 50 → +10 机会 → 立即补发
	require.NoError(t, svc.AccrueInviterRewardQuota(ctx, inviterID, ReferralQuotaSourcePaymentOrder, 900020, 50))

	require.NoError(t, db.QueryRow("SELECT inviter_reward_blocked_by_quota, inviter_reward_granted FROM referral_reward_tracker WHERE invitee_id=$1", inviteeID).Scan(&blocked, &granted))
	assert.True(t, granted, "充值后应立即补发")
	assert.False(t, blocked, "补发后清 blocked flag")

	var giftCount int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id=$1 AND source='referral_inviter'", inviterID).Scan(&giftCount))
	assert.Equal(t, 1, giftCount)

	// 补发消耗一次机会：quota 10 → 9
	var quota int
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota))
	assert.Equal(t, 9, quota)
}

// ==========================================================================
// Quota Test F: 补发受 quota 数量限制 — 机会不足时部分补发，剩余仍 blocked
// ==========================================================================

func TestIntegration_Referral_BackfillLimitedByQuota(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800038)
	ensureTestUser(t, db, inviterID)
	ensureAffiliateRow(t, db, inviterID)

	// 3 个被邀请人全部达标但 quota=0 → 全部 blocked
	inviteeIDs := []int64{800039, 800040, 800041}
	for i, invID := range inviteeIDs {
		ensureTestUser(t, db, invID)
		insertTracker(t, db, inviterID, invID, 10)
		require.NoError(t, svc.TrackSpendAndMaybeGrantInviterReward(ctx, invID, fmt.Sprintf("billing:bl_%d:key1", i), 12.0))
	}
	var blockedCount int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM referral_reward_tracker WHERE inviter_id=$1 AND inviter_reward_blocked_by_quota=TRUE", inviterID).Scan(&blockedCount))
	require.Equal(t, 3, blockedCount)

	// 手动只给 2 次机会（模拟 step/perBatch 下不足以覆盖全部），走 backfill
	_, err := db.Exec("UPDATE user_affiliates SET inviter_reward_quota=2 WHERE user_id=$1", inviterID)
	require.NoError(t, err)
	svc.backfillPendingInviterRewards(ctx, inviterID)

	var grantedCount, stillBlocked int
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM referral_reward_tracker WHERE inviter_id=$1 AND inviter_reward_granted=TRUE", inviterID).Scan(&grantedCount))
	require.NoError(t, db.QueryRow("SELECT COUNT(*) FROM referral_reward_tracker WHERE inviter_id=$1 AND inviter_reward_granted=FALSE AND inviter_reward_blocked_by_quota=TRUE", inviterID).Scan(&stillBlocked))
	assert.Equal(t, 2, grantedCount, "只应补发 2 笔（机会数）")
	assert.Equal(t, 1, stillBlocked, "剩余 1 笔仍 blocked")

	var quota int
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota))
	assert.Equal(t, 0, quota)
}

// ==========================================================================
// Quota Test G: 开关关闭时行为不变（无限发放，不赚不花）
// ==========================================================================

func TestIntegration_Referral_QuotaDisabled_UnlimitedGrant(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true) // 配额开关关（默认）
	ctx := context.Background()

	inviterID := int64(800042)
	inviteeID := int64(800043)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)
	ensureAffiliateRow(t, db, inviterID) // quota=0，但开关关时不看 quota
	insertTracker(t, db, inviterID, inviteeID, 10)

	// 开关关：即使 quota=0 也应发放（无限行为）
	require.NoError(t, svc.TrackSpendAndMaybeGrantInviterReward(ctx, inviteeID, "billing:qdis:key1", 12.0))

	var granted, blocked bool
	require.NoError(t, db.QueryRow("SELECT inviter_reward_granted, inviter_reward_blocked_by_quota FROM referral_reward_tracker WHERE invitee_id=$1", inviteeID).Scan(&granted, &blocked))
	assert.True(t, granted, "开关关时无限发放")
	assert.False(t, blocked)

	// quota 不被消耗（仍 0），carry 不变
	var quota, consumed int
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota, inviter_reward_quota_consumed_total FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota, &consumed))
	assert.Equal(t, 0, quota)
	assert.Equal(t, 0, consumed)
}

// ==========================================================================
// Quota Test H: 支付订单 redeem 级被 ContextSkipRedeemReferralQuota 抑制，不与订单级双计
// ==========================================================================

func TestIntegration_Referral_RedeemSkipContext_SuppressesQuotaAccrual(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	referralSvc := buildReferralServiceWithQuota(t, client, db, "50", "10")
	ctx := context.Background()

	inviterID := int64(800044)
	ensureTestUser(t, db, inviterID)
	ensureAffiliateRow(t, db, inviterID)

	redeemSvc := &RedeemService{referralReward: referralSvc}

	// 带 skip context（模拟支付订单触发的 redeem）→ 不赚配额
	redeemSvc.tryAccrueReferralQuotaForRedeem(ContextSkipRedeemReferralQuota(ctx), inviterID, 900030, 100)
	var quota int
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota))
	assert.Equal(t, 0, quota, "带 skip context 时不应赚配额（订单级已处理）")

	// 不带 skip context（直接兑换码）→ 正常赚配额
	redeemSvc.tryAccrueReferralQuotaForRedeem(ctx, inviterID, 900031, 100)
	require.NoError(t, db.QueryRow("SELECT inviter_reward_quota FROM user_affiliates WHERE user_id=$1", inviterID).Scan(&quota))
	assert.Equal(t, 20, quota, "直接兑换码应正常赚配额")
}

// ==========================================================================
// Test 11: OnInviterBound 重放/并发 — 只产生一个 referral_invitee 赠金
// ==========================================================================

func TestIntegration_Referral_OnInviterBound_ConcurrentReplay_OneInviteeGift(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralService(t, client, db, true)
	ctx := context.Background()

	inviterID := int64(800022)
	inviteeID := int64(800023)
	ensureTestUser(t, db, inviterID)
	ensureTestUser(t, db, inviteeID)

	boundAt := time.Now()

	// 邀请人在绑定时刻有有效折扣（资格=true）
	validUntil := time.Now().Add(30 * 24 * time.Hour)
	insertRechargeDiscount(t, db, inviterID, "api_key:concurrent_replay", 100, 100,
		boundAt.Add(-1*time.Hour).Format(time.RFC3339),
		validUntil.Format(time.RFC3339))

	// 10 个 goroutine 同时重放 OnInviterBound，模拟 hook 重放/并发触发
	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			svc.OnInviterBound(ctx, inviterID, inviteeID, boundAt)
		}()
	}
	wg.Wait()

	// 只应产生一个被邀请人赠金
	var giftCount int
	err := db.QueryRow("SELECT COUNT(*) FROM user_gifts WHERE user_id = $1 AND source = 'referral_invitee'", inviteeID).Scan(&giftCount)
	require.NoError(t, err)
	assert.Equal(t, 1, giftCount, "重放/并发下被邀请人赠金只应发一次")

	// tracker 标记已发放且引用该赠金
	var granted bool
	var giftID sql.NullInt64
	err = db.QueryRow("SELECT invitee_reward_granted, invitee_reward_gift_id FROM referral_reward_tracker WHERE inviter_id = $1 AND invitee_id = $2", inviterID, inviteeID).Scan(&granted, &giftID)
	require.NoError(t, err)
	assert.True(t, granted)
	assert.True(t, giftID.Valid)

	// 折扣继承也应只有一条（source_ref 唯一约束保证幂等）
	var inheritDiscountCount int
	err = db.QueryRow("SELECT COUNT(*) FROM user_recharge_discounts WHERE user_id = $1 AND source = 'referral_inherit'", inviteeID).Scan(&inheritDiscountCount)
	require.NoError(t, err)
	assert.Equal(t, 1, inheritDiscountCount, "重放/并发下折扣继承只应有一条")
}

// ==========================================================================
// Test 12: GetReferralStatus — recharge 模式下 EligibilityRechargeRemaining
// 语义（PR#63）：recharge 资格纯看 users.total_recharged >= 门槛，与折扣券无关。
// remaining = 门槛 - total_recharged，随充值单调递减，达标后归 0。
// ==========================================================================

func TestIntegration_Referral_GetReferralStatus_RechargeRemaining(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	// 门槛 100 USD
	svc := buildReferralServiceRecharge(t, client, db, "100")
	ctx := context.Background()

	userID := int64(800050)
	ensureTestUser(t, db, userID)

	// 尚无任何充值 → 未达标，还需全额 100
	status, err := svc.GetReferralStatus(ctx, userID)
	require.NoError(t, err)
	assert.False(t, status.Eligible)
	assert.InDelta(t, 100.0, status.EligibilityRechargeRemaining, 0.001)

	// 累计充值 40 → 还需 60
	setTotalRecharged(t, db, userID, 40)
	status, err = svc.GetReferralStatus(ctx, userID)
	require.NoError(t, err)
	assert.False(t, status.Eligible)
	assert.InDelta(t, 60.0, status.EligibilityRechargeRemaining, 0.001)

	// 再充到累计 110（≥ 100）→ 达标，remaining 归 0
	setTotalRecharged(t, db, userID, 110)
	status, err = svc.GetReferralStatus(ctx, userID)
	require.NoError(t, err)
	assert.True(t, status.Eligible)
	assert.InDelta(t, 0.0, status.EligibilityRechargeRemaining, 0.001)
}

// ==========================================================================
// Test 13: GetReferralStatus — total_recharged 恰好等于门槛即达标（边界）
// 边界语义：total_recharged >= 门槛（含等于）→ eligible=true、remaining=0。
// ==========================================================================

func TestIntegration_Referral_GetReferralStatus_RechargeRemaining_ExactThreshold(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceRecharge(t, client, db, "100")
	ctx := context.Background()

	userID := int64(800051)
	ensureTestUser(t, db, userID)

	// 差一点点：99.99 < 100 → 未达标，remaining ≈ 0.01
	setTotalRecharged(t, db, userID, 99.99)
	status, err := svc.GetReferralStatus(ctx, userID)
	require.NoError(t, err)
	assert.False(t, status.Eligible, "低于门槛 → 未达标")
	assert.InDelta(t, 0.01, status.EligibilityRechargeRemaining, 0.001)

	// 恰好等于门槛：100 >= 100 → 达标，remaining 归 0
	setTotalRecharged(t, db, userID, 100)
	status, err = svc.GetReferralStatus(ctx, userID)
	require.NoError(t, err)
	assert.True(t, status.Eligible, "恰好等于门槛 → 达标")
	assert.InDelta(t, 0.0, status.EligibilityRechargeRemaining, 0.001)
}

// ==========================================================================
// Test 14: GetReferralStatus — 超额充值 remaining 夹到 0，不为负
// eligibilityRechargeRemaining 对 minAmount - total_recharged < 0 的情况钳到 0。
// ==========================================================================

func TestIntegration_Referral_GetReferralStatus_RechargeRemaining_OvershootClampsToZero(t *testing.T) {
	client, db := setupReferralIntegrationDB(t)
	svc := buildReferralServiceRecharge(t, client, db, "100")
	ctx := context.Background()

	userID := int64(800052)
	ensureTestUser(t, db, userID)

	// 大幅超额：500 >> 100 → 达标，remaining 钳到 0（不为负）
	setTotalRecharged(t, db, userID, 500)
	status, err := svc.GetReferralStatus(ctx, userID)
	require.NoError(t, err)
	assert.True(t, status.Eligible)
	assert.InDelta(t, 0.0, status.EligibilityRechargeRemaining, 0.001)
	assert.GreaterOrEqual(t, status.EligibilityRechargeRemaining, 0.0, "remaining 不应为负")
}
