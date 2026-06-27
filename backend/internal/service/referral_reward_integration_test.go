//go:build integration

package service

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

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
	require.NoError(t, sqlDB.Ping())

	client, err := dbent.Open("postgres", testDSN)
	require.NoError(t, err)

	// Clean test data
	_, _ = sqlDB.Exec("DELETE FROM referral_spend_events WHERE invitee_id >= 800000")
	_, _ = sqlDB.Exec("DELETE FROM referral_reward_tracker WHERE invitee_id >= 800000")

	t.Cleanup(func() {
		_, _ = sqlDB.Exec("DELETE FROM referral_spend_events WHERE invitee_id >= 800000")
		_, _ = sqlDB.Exec("DELETE FROM referral_reward_tracker WHERE invitee_id >= 800000")
		_, _ = sqlDB.Exec("DELETE FROM user_gifts WHERE user_id >= 800000")
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

func ensureAffiliateRelation(t *testing.T, db *sql.DB, inviteeID, inviterID int64) {
	t.Helper()
	_, _ = db.Exec(`INSERT INTO user_affiliates (user_id, inviter_id, aff_code, aff_count, aff_quota, aff_frozen_quota, aff_history_quota)
		VALUES ($1, $2, '', 0, 0, 0, 0) ON CONFLICT (user_id) DO UPDATE SET inviter_id = $2`, inviteeID, inviterID)
}

func insertTracker(t *testing.T, db *sql.DB, inviterID, inviteeID int64, threshold float64) int64 {
	t.Helper()
	var id int64
	err := db.QueryRow(`INSERT INTO referral_reward_tracker (inviter_id, invitee_id, spend_threshold) VALUES ($1, $2, $3) RETURNING id`,
		inviterID, inviteeID, threshold).Scan(&id)
	require.NoError(t, err)
	return id
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
	enabled bool
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
	case SettingKeyReferralSpendThreshold:
		return "10", nil
	case SettingKeyReferralDiscountValidDays:
		return "30", nil
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
