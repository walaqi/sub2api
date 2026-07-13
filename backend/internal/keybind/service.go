// Package keybind provides a self-contained feature for users to claim
// pre-provisioned API keys from a pool. The pool is identified by a
// configured "pool user" (admin or placeholder account that owns all
// claimable keys until someone binds them).
//
// This package is deliberately decoupled from the rest of the codebase
// to keep upstream merges easy: it only depends on the ent client, the
// redis client, and the user repository's GetByEmail method.
package keybind

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/apikey"
	"github.com/Wei-Shaw/sub2api/ent/bindkeygiftsetting"
	"github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"

	"github.com/redis/go-redis/v9"
)

const (
	reservationTTL          = 5 * time.Minute
	maxKeysPerReserve       = 200
	balanceRemainingMinimum = 0.5 // require > 50% remaining quota

	redisLockedKeyPrefix      = "bindkey:locked:"      // bindkey:locked:<api_key_id> -> reservation_id
	redisReservationKeyPrefix = "bindkey:reservation:" // bindkey:reservation:<reservation_id> -> api_key_id (string)
	// redisActivityHoldPrefix gates one in-flight reservation per (activity, user):
	// bindkey:activity_hold:<activity_id>:<user_id> -> reservation_id.
	// Prevents a user from reserving multiple activity keys via repeated or
	// concurrent signups before the first reservation is committed.
	redisActivityHoldPrefix = "bindkey:activity_hold:"
)

// Errors mapped to HTTP responses via the project's infraerrors package.
var (
	ErrPoolUserNotConfigured = infraerrors.ServiceUnavailable("BIND_KEY_DISABLED", "key binding feature is not configured")
	ErrEmptyKeyList          = infraerrors.BadRequest("BIND_KEY_EMPTY", "no keys provided")
	ErrTooManyKeys           = infraerrors.BadRequest("BIND_KEY_TOO_MANY", "too many keys in one request")
	ErrNoEligibleKey         = infraerrors.NotFound("BIND_KEY_NO_ELIGIBLE", "no eligible key found in the provided list")
	ErrNoActivityKey         = infraerrors.NotFound("BIND_KEY_NO_ACTIVITY_KEY", "no claimable key is available for this activity")
	ErrReservationExpired    = infraerrors.NotFound("BIND_KEY_RESERVATION_EXPIRED", "reservation has expired or does not exist")
	ErrPoolKeyAlreadyClaimed = infraerrors.Conflict("BIND_KEY_RACE", "key has already been claimed by another user")
	ErrAlreadyParticipated   = infraerrors.Forbidden("BIND_KEY_ALREADY_PARTICIPATED", "you have already bound a key this month")
	ErrRegistrationWindow    = infraerrors.Forbidden("BIND_KEY_REGISTRATION_WINDOW", "your account registration date is outside the allowed window for this key")
)

// ReservationResult is returned to the client after a successful Reserve.
type ReservationResult struct {
	ReservationID   string  `json:"reservation_id"`
	MaskedKey       string  `json:"masked_key"`
	RemainingQuota  float64 `json:"remaining_quota"`
	QuotaLimit      float64 `json:"quota_limit"`
	ExpiresAtUnixMs int64   `json:"expires_at_unix_ms"`
}

// CommitResult is returned after a successful Commit.
type CommitResult struct {
	APIKeyID  int64            `json:"api_key_id"`
	MaskedKey string           `json:"masked_key"`
	Gift      *GrantedGift     `json:"gift,omitempty"`
	Discount  *GrantedDiscount `json:"discount,omitempty"`
}

// GrantedDiscount describes a recharge discount created during bind.
type GrantedDiscount struct {
	DiscountRate          float64  `json:"discount_rate"`
	MaxDiscountableAmount float64  `json:"max_discountable_amount"`
	ValidDays             int      `json:"valid_days"`
	GiftDeductionMode     string   `json:"gift_deduction_mode"`
	GiftRatioRecharge     *float64 `json:"gift_ratio_recharge,omitempty"`
	GiftExpiryMode        string   `json:"gift_expiry_mode"`
	GiftExpiresAfterDays  *int     `json:"gift_expires_after_days,omitempty"`
}

// EligibilityResult tells the UI whether the caller may participate this
// month and, if not, when the next natural-month reset happens so it can
// render a countdown.
type EligibilityResult struct {
	Eligible            bool   `json:"eligible"`
	AlreadyParticipated bool   `json:"already_participated"`
	NextResetUnixMs     int64  `json:"next_reset_unix_ms"`
	Reason              string `json:"reason,omitempty"`
}

// Service implements the bind-key feature.
type Service struct {
	client        *ent.Client
	redis         *redis.Client
	poolUserID    int64 // 0 if not configured (feature disabled)
	configErrMsg  string
	participation *ParticipationStore

	// giftSettingResolver 读表 A（bind_key_gift_settings）的 per-key 配置，
	// 用于注册时间窗口校验。client 为 nil 时该 resolver 为 nil（降级为不限制）。
	giftSettingResolver BindKeyGiftSettingResolver

	// 可选依赖：用于绑定成功后赠送余额并失效相关缓存。
	// 任意字段为 nil 时降级为"该能力关闭"，但 key 仍会正常转移。
	userBalanceUpdater UserBalanceUpdater
	authCacheInval     APIKeyAuthCacheInvalidator
	billingCacheInval  BillingBalanceInvalidator

	// 可选依赖：绑定成功后创建充值折扣记录。nil 时不创建。
	discountCreator RechargeDiscountCreator
}

// NewService constructs a Service. It resolves the pool user once at
// startup by looking up the configured email in the users table. If the
// email is empty or the lookup fails, the service is constructed in a
// "disabled" state where every call returns ErrPoolUserNotConfigured.
// This keeps the feature's failure mode isolated from server startup.
func NewService(ctx context.Context, client *ent.Client, redisClient *redis.Client, poolUserEmail string, dataDir string, opts ...Option) *Service {
	svc := &Service{
		client:              client,
		redis:               redisClient,
		participation:       NewParticipationStore(dataDir),
		giftSettingResolver: NewBindKeyGiftSettingResolver(client),
	}

	email := strings.TrimSpace(strings.ToLower(poolUserEmail))
	if email == "" {
		svc.configErrMsg = "BIND_KEY_POOL_USER_EMAIL not set"
		applyOptions(svc, opts)
		return svc
	}
	if client == nil {
		svc.configErrMsg = "ent client not provided"
		applyOptions(svc, opts)
		return svc
	}

	row, err := client.User.Query().
		Where(user.EmailEQ(email)).
		Only(ctx)
	if err != nil || row == nil {
		svc.configErrMsg = fmt.Sprintf("pool user %q not found", email)
		applyOptions(svc, opts)
		return svc
	}
	svc.poolUserID = row.ID
	applyOptions(svc, opts)
	return svc
}

func applyOptions(s *Service, opts []Option) {
	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}
}

// Enabled reports whether the feature is operational.
func (s *Service) Enabled() bool {
	return s != nil && s.poolUserID > 0
}

// CheckEligibility reports whether userID can bind a key this month.
// Anonymous callers (userID <= 0) are reported as eligible; the actual
// monthly-limit gate runs at Commit time once JWT identifies the user.
func (s *Service) CheckEligibility(ctx context.Context, userID int64) (*EligibilityResult, error) {
	res := &EligibilityResult{
		NextResetUnixMs: s.participation.NextResetUnixMs(),
	}
	if !s.Enabled() {
		res.Eligible = false
		res.Reason = "feature_disabled"
		return res, nil
	}
	if userID <= 0 {
		res.Eligible = true
		return res, nil
	}
	already, err := s.participation.HasParticipated(ctx, userID)
	if err != nil {
		return nil, err
	}
	res.AlreadyParticipated = already
	if !already {
		res.Eligible = true
		return res, nil
	}
	// User participated this month, but if any pool key is unlimited they
	// can still bind — the monthly gate is skipped for unlimited keys.
	if s.hasUnlimitedPoolKeys(ctx) {
		res.Eligible = true
		return res, nil
	}
	res.Eligible = false
	return res, nil
}

// checkRegistrationWindow enforces a key's optional registration-time window.
// Returns nil when the key has no window configured / it's disabled, or when
// the user's account age falls inside [MinDays, MaxDays]. Returns
// ErrRegistrationWindow (carrying min/max metadata for the UI) otherwise.
//
// Failures resolving the per-key setting are propagated so we never silently
// admit a user a key meant to exclude; failures looking up the user collapse
// to a rejection for the same reason.
func (s *Service) checkRegistrationWindow(ctx context.Context, userID, keyID int64) error {
	if s.giftSettingResolver == nil || keyID <= 0 {
		return nil
	}
	setting, err := s.giftSettingResolver.Resolve(ctx, keyID)
	if err != nil {
		return fmt.Errorf("resolve bind-key setting: %w", err)
	}
	if setting == nil || setting.RegistrationWindow == nil || !setting.RegistrationWindow.Enabled {
		return nil
	}
	win := setting.RegistrationWindow

	row, err := s.client.User.Query().
		Where(user.IDEQ(userID)).
		Select(user.FieldCreatedAt).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			return s.registrationWindowErr(win)
		}
		return fmt.Errorf("query user created_at: %w", err)
	}

	age := time.Since(row.CreatedAt)
	minAge := time.Duration(win.MinDays) * 24 * time.Hour
	maxAge := time.Duration(win.MaxDays) * 24 * time.Hour
	if age < minAge || age > maxAge {
		return s.registrationWindowErr(win)
	}
	return nil
}

// registrationWindowErr attaches the configured window bounds so the client
// can render a precise "registered between X and Y days" message.
func (s *Service) registrationWindowErr(win *domain.BindKeyRegistrationWindow) error {
	return ErrRegistrationWindow.WithMetadata(map[string]string{
		"min_days": strconv.Itoa(win.MinDays),
		"max_days": strconv.Itoa(win.MaxDays),
	})
}

// Reserve walks the input keys top-to-bottom and reserves the first one that:
//   - exists in api_keys
//   - is owned by the pool user (claimable)
//   - has status == active and is not soft-deleted
//   - has remaining quota > 50% of its quota
//   - is not already locked by another in-flight reservation
//
// On success the matched key is locked in Redis for reservationTTL.
func (s *Service) Reserve(ctx context.Context, keys []string) (*ReservationResult, error) {
	if !s.Enabled() {
		return nil, s.disabledErr()
	}

	cleaned := normalizeKeys(keys)
	if len(cleaned) == 0 {
		return nil, ErrEmptyKeyList
	}
	if len(cleaned) > maxKeysPerReserve {
		return nil, ErrTooManyKeys
	}

	for _, k := range cleaned {
		row, err := s.client.APIKey.Query().
			Where(
				apikey.KeyEQ(k),
				apikey.UserIDEQ(s.poolUserID),
				apikey.StatusEQ(domain.StatusActive),
				apikey.DeletedAtIsNil(),
			).
			Only(ctx)
		if err != nil {
			if ent.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("query api_key: %w", err)
		}

		if !hasSufficientRemaining(row.Quota, row.QuotaUsed) {
			continue
		}
		res, locked, err := s.lockAndBuildReservation(ctx, row)
		if err != nil {
			return nil, err
		}
		if !locked {
			// another reservation already holds this key
			continue
		}
		return res, nil
	}

	return nil, ErrNoEligibleKey
}

// lockAndBuildReservation attempts to lock a single pool key row in Redis and,
// on success, returns the ReservationResult the client needs to later Commit.
//
// The (nil, false, nil) return means the key is already held by another
// in-flight reservation — the caller should skip it and try the next candidate.
// Shared by both the paste-driven Reserve and the activity-driven
// ReserveForActivity so the lock/TTL protocol stays in one place.
func (s *Service) lockAndBuildReservation(ctx context.Context, row *ent.APIKey) (*ReservationResult, bool, error) {
	reservationID, err := newReservationID()
	if err != nil {
		return nil, false, fmt.Errorf("generate reservation id: %w", err)
	}

	lockKey := redisLockedKeyPrefix + intToStr(row.ID)
	ok, err := s.redis.SetNX(ctx, lockKey, reservationID, reservationTTL).Result()
	if err != nil {
		return nil, false, fmt.Errorf("redis setnx: %w", err)
	}
	if !ok {
		return nil, false, nil
	}

	// Bind reservation_id -> api_key_id with same TTL.
	if err := s.redis.Set(ctx, redisReservationKeyPrefix+reservationID, intToStr(row.ID), reservationTTL).Err(); err != nil {
		// best-effort cleanup
		_ = s.redis.Del(ctx, lockKey).Err()
		return nil, false, fmt.Errorf("redis set reservation: %w", err)
	}

	expiresAt := time.Now().Add(reservationTTL)
	return &ReservationResult{
		ReservationID:   reservationID,
		MaskedKey:       maskKey(row.Key),
		RemainingQuota:  row.Quota - row.QuotaUsed,
		QuotaLimit:      row.Quota,
		ExpiresAtUnixMs: expiresAt.UnixMilli(),
	}, true, nil
}

// activityKeyScanBatch bounds the size of each api_keys lookup while walking an
// activity's candidate keys. Claimed keys keep their bind_key_gift_settings row
// (activity_id is immutable on claim), so an activity that has handed out many
// keys can have a long prefix of already-claimed candidates; batching lets us
// scan past them to reach a still-claimable key instead of giving up after a
// fixed window.
const activityKeyScanBatch = 500

// ReserveForActivity finds one claimable pool key tied to activityID, locks it
// in Redis, and returns the reservation the client uses to Commit — mirroring
// the paste-driven Reserve but selecting the key by activity instead of by a
// user-supplied list.
//
// A key is claimable when it is (still) owned by the pool user, active,
// not soft-deleted, has > 50% remaining quota, and carries a
// bind_key_gift_settings row whose activity_id == activityID. Ownership
// transfers away on Commit, so an already-claimed key naturally drops out of
// this query — no separate "assigned" flag is needed.
//
// Per-user idempotency: a (activity, user) hold in Redis ensures one user can
// hold only one in-flight activity reservation. Repeated or concurrent signups
// by the same user before committing return the SAME reservation rather than
// locking additional keys — closing the race where UserHasClaimedActivityKey
// (which only sees committed claims) reports false twice.
//
// Returns ErrNoActivityKey when the activity has no free key left. The caller
// (activity signup) still short-circuits on already-committed claims via
// UserHasClaimedActivityKey before calling this.
func (s *Service) ReserveForActivity(ctx context.Context, activityID, userID int64) (*ReservationResult, error) {
	if !s.Enabled() {
		return nil, s.disabledErr()
	}
	if activityID <= 0 || userID <= 0 {
		return nil, ErrNoActivityKey
	}

	holdKey := activityHoldKey(activityID, userID)

	// Idempotent fast path: this user already holds an in-flight reservation for
	// the activity → return it instead of locking a second key.
	if existing, err := s.redis.Get(ctx, holdKey).Result(); err == nil && existing != "" {
		if res, ok := s.rebuildReservation(ctx, existing); ok {
			return res, nil
		}
		// Stale hold (its reservation expired/was consumed) — clear and continue.
		_ = s.redis.Del(ctx, holdKey).Err()
	}

	res, err := s.reserveOneActivityKey(ctx, activityID)
	if err != nil {
		return nil, err
	}

	// Claim the per-user hold. SetNX so a concurrent signup by the same user
	// cannot also win: the loser releases the key it just locked and returns the
	// winner's reservation, so the user ends up with exactly one.
	ok, setErr := s.redis.SetNX(ctx, holdKey, res.ReservationID, reservationTTL).Result()
	if setErr != nil {
		// The per-user hold IS the invariant this method exists to enforce
		// ("one in-flight activity reservation per user"). If we can't write it
		// we must NOT hand back an unguarded reservation — a repeat/concurrent
		// signup could then lock a second key (the very race we're fixing).
		// Fail closed: release the key we just locked and report no key. The
		// caller degrades this to a plain signup (no gift), never a double grant.
		s.releaseReservation(ctx, res.ReservationID)
		return nil, ErrNoActivityKey
	}
	if !ok {
		s.releaseReservation(ctx, res.ReservationID)
		if winner, err := s.redis.Get(ctx, holdKey).Result(); err == nil && winner != "" {
			if r, ok := s.rebuildReservation(ctx, winner); ok {
				return r, nil
			}
		}
		return nil, ErrNoActivityKey
	}
	return res, nil
}

// reserveOneActivityKey walks the activity's candidate keys in a deterministic
// order (ascending api_key_id) and returns the first one it can lock. Claimed
// keys are filtered out by the pool-ownership predicate, so scanning continues
// past them across batches instead of stopping at a fixed window.
func (s *Service) reserveOneActivityKey(ctx context.Context, activityID int64) (*ReservationResult, error) {
	keyIDs, err := s.client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.ActivityIDEQ(activityID)).
		Order(ent.Asc(bindkeygiftsetting.FieldAPIKeyID)).
		Select(bindkeygiftsetting.FieldAPIKeyID).
		Ints(ctx)
	if err != nil {
		return nil, fmt.Errorf("query activity key settings: %w", err)
	}
	if len(keyIDs) == 0 {
		return nil, ErrNoActivityKey
	}

	for start := 0; start < len(keyIDs); start += activityKeyScanBatch {
		end := start + activityKeyScanBatch
		if end > len(keyIDs) {
			end = len(keyIDs)
		}
		batch := make([]int64, 0, end-start)
		for _, id := range keyIDs[start:end] {
			batch = append(batch, int64(id))
		}

		rows, err := s.client.APIKey.Query().
			Where(
				apikey.IDIn(batch...),
				apikey.UserIDEQ(s.poolUserID),
				apikey.StatusEQ(domain.StatusActive),
				apikey.DeletedAtIsNil(),
			).
			Order(ent.Asc(apikey.FieldID)).
			All(ctx)
		if err != nil {
			return nil, fmt.Errorf("query activity pool keys: %w", err)
		}

		for _, row := range rows {
			if !hasSufficientRemaining(row.Quota, row.QuotaUsed) {
				continue
			}
			res, locked, err := s.lockAndBuildReservation(ctx, row)
			if err != nil {
				return nil, err
			}
			if !locked {
				continue
			}
			return res, nil
		}
	}

	return nil, ErrNoActivityKey
}

// activityHoldKey builds the per-(activity,user) hold key.
func activityHoldKey(activityID, userID int64) string {
	return redisActivityHoldPrefix + intToStr(activityID) + ":" + intToStr(userID)
}

// rebuildReservation reconstructs a ReservationResult from a reservation id by
// looking up its key. Returns (nil, false) when the reservation or its key is
// gone (expired/consumed/deleted), so callers can treat the hold as stale.
func (s *Service) rebuildReservation(ctx context.Context, reservationID string) (*ReservationResult, bool) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return nil, false
	}
	keyIDStr, err := s.redis.Get(ctx, redisReservationKeyPrefix+reservationID).Result()
	if err != nil || keyIDStr == "" {
		return nil, false
	}
	keyID, err := strToInt(keyIDStr)
	if err != nil {
		return nil, false
	}
	row, err := s.client.APIKey.Get(ctx, keyID)
	if err != nil {
		return nil, false
	}
	// Reflect the lock's remaining TTL as the reservation expiry so the UI
	// countdown stays honest across the idempotent re-fetch.
	expiresAt := time.Now().Add(reservationTTL)
	if ttl, err := s.redis.TTL(ctx, redisLockedKeyPrefix+intToStr(keyID)).Result(); err == nil && ttl > 0 {
		expiresAt = time.Now().Add(ttl)
	}
	return &ReservationResult{
		ReservationID:   reservationID,
		MaskedKey:       maskKey(row.Key),
		RemainingQuota:  row.Quota - row.QuotaUsed,
		QuotaLimit:      row.Quota,
		ExpiresAtUnixMs: expiresAt.UnixMilli(),
	}, true
}

// releaseReservation drops a reservation and frees its key lock. Best-effort:
// used when a concurrent per-user hold loser gives up its freshly-locked key.
func (s *Service) releaseReservation(ctx context.Context, reservationID string) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return
	}
	resKey := redisReservationKeyPrefix + reservationID
	if keyIDStr, err := s.redis.Get(ctx, resKey).Result(); err == nil && keyIDStr != "" {
		_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+keyIDStr).Err()
		return
	}
	_ = s.redis.Del(ctx, resKey).Err()
}

// UserHasClaimedActivityKey reports whether userID already owns a key tied to
// activityID. After a successful Commit the key's ownership moves from the pool
// user to the claimer while its bind_key_gift_settings.activity_id stays put,
// so this doubles as the "already participated in this activity" check without
// a dedicated column on activity_signups.
func (s *Service) UserHasClaimedActivityKey(ctx context.Context, userID, activityID int64) (bool, error) {
	if !s.Enabled() {
		return false, s.disabledErr()
	}
	if userID <= 0 || activityID <= 0 {
		return false, nil
	}

	keyIDs, err := s.client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.ActivityIDEQ(activityID)).
		Select(bindkeygiftsetting.FieldAPIKeyID).
		Ints(ctx)
	if err != nil {
		return false, fmt.Errorf("query activity key settings: %w", err)
	}
	if len(keyIDs) == 0 {
		return false, nil
	}

	ids := make([]int64, 0, len(keyIDs))
	for _, id := range keyIDs {
		ids = append(ids, int64(id))
	}

	exists, err := s.client.APIKey.Query().
		Where(
			apikey.IDIn(ids...),
			apikey.UserIDEQ(userID),
			apikey.DeletedAtIsNil(),
		).
		Exist(ctx)
	if err != nil {
		return false, fmt.Errorf("check user activity key: %w", err)
	}
	return exists, nil
}

// Commit finalizes a reservation by transferring the key's ownership to userID.
// The reservation is consumed regardless of outcome on success path; on
// transient failures the Redis entries are left intact so the user can retry
// before TTL.
func (s *Service) Commit(ctx context.Context, userID int64, reservationID string) (*CommitResult, error) {
	if !s.Enabled() {
		return nil, s.disabledErr()
	}
	if userID <= 0 {
		return nil, infraerrors.Unauthorized("BIND_KEY_NO_USER", "authentication required")
	}
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return nil, ErrReservationExpired
	}

	resKey := redisReservationKeyPrefix + reservationID
	keyIDStr, err := s.redis.Get(ctx, resKey).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrReservationExpired
		}
		return nil, fmt.Errorf("redis get reservation: %w", err)
	}
	keyID, err := strToInt(keyIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid reservation payload: %w", err)
	}

	// Resolve per-key config to determine whether monthly-limit applies.
	// unlimit: nil or true → no monthly limit; only explicit false → enforce.
	unlimited := s.isKeyUnlimited(ctx, keyID)

	// Monthly-limit gate: enforced here because anonymous /reserve cannot
	// know the caller's identity. We drop the reservation so a queued key
	// is freed up for someone else; the lock entry expires naturally.
	if !unlimited {
		already, err := s.participation.HasParticipated(ctx, userID)
		if err != nil {
			return nil, err
		}
		if already {
			_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
			return nil, ErrAlreadyParticipated
		}
	}

	// Per-key registration-window gate: a key may restrict claims to users
	// whose account age falls inside a rolling [min,max] day window. Enforced
	// here (not at the anonymous /reserve) since it needs both the user's
	// created_at and the chosen key. Drop the reservation on rejection so the
	// queued key is freed for someone eligible.
	if err := s.checkRegistrationWindow(ctx, userID, keyID); err != nil {
		if errors.Is(err, ErrRegistrationWindow) {
			_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
		}
		return nil, err
	}

	// 先把池 key 拉出来一次，用于赠送余额（quota - quota_used）。
	// 这一步同时充当"是否仍属于池用户/active/未删除"的预检；下面 TOCTOU
	// 更新仍然校验同一组 where 条件，确保并发场景下不会双发余额。
	poolKey, err := s.client.APIKey.Query().
		Where(
			apikey.IDEQ(keyID),
			apikey.UserIDEQ(s.poolUserID),
			apikey.StatusEQ(domain.StatusActive),
			apikey.DeletedAtIsNil(),
		).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
			return nil, ErrPoolKeyAlreadyClaimed
		}
		return nil, fmt.Errorf("query pool key: %w", err)
	}

	giftAmount := poolKey.Quota - poolKey.QuotaUsed
	if poolKey.Quota <= 0 || giftAmount < 0 {
		giftAmount = 0
	}

	// TOCTOU guard: only update if the row is still owned by the pool user
	// and still matches the active/non-deleted invariants. group_id 随 key 一
	// 起转移到新 owner（不再调用 ClearGroupID），运营保证池 key 不在排他分组。
	//
	// claim-time group pin（plan.md §3.2/S6）：把上面读到的 poolKey.GroupID 固化进
	// transfer WHERE。若管理员在 read 与 update 之间改了池 key 的分组，affected==0
	// 触发重试，保证转移的 key 行与随后 Grant 用的 groupID 一致。
	transferUpdate := s.client.APIKey.Update().
		Where(
			apikey.IDEQ(keyID),
			apikey.UserIDEQ(s.poolUserID),
			apikey.StatusEQ(domain.StatusActive),
			apikey.DeletedAtIsNil(),
		)
	if poolKey.GroupID != nil {
		transferUpdate = transferUpdate.Where(apikey.GroupIDEQ(*poolKey.GroupID))
	} else {
		transferUpdate = transferUpdate.Where(apikey.GroupIDIsNil())
	}
	affected, err := transferUpdate.
		SetUserID(userID).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("update api_key user: %w", err)
	}
	if affected == 0 {
		// Either the key was already claimed, deleted, or disabled between
		// reserve and commit. Clean up the reservation so the user retries.
		_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
		return nil, ErrPoolKeyAlreadyClaimed
	}

	// 赠送余额（Bug 1 修复）。失败仅记日志，不回滚——key 已转移成功，
	// "拿到 key 但没赠送" 比 "拿不到 key 也没赠送" 体验更好；运营可手工补。
	// Phase 3：把 apiKeyID 一并传下去，由 updater 读表 A 决定 mode/ratio_recharge/expires_after_days。
	var grantedGift *GrantedGift
	if giftAmount > 0 && s.userBalanceUpdater != nil {
		// 传 poolKey.GroupID：绑分组的池 key → 发一笔绑该组的赠金（只能在该组消费）；
		// 无分组池 key → 全局赠金（与现状一致）。见 plan.md §3.2。
		g, err := s.userBalanceUpdater.GrantForBindKey(ctx, userID, giftAmount, keyID, poolKey.GroupID)
		if err != nil {
			log.Printf("[keybind] grant balance %.4f to user %d failed: %v", giftAmount, userID, err)
		} else {
			grantedGift = g
			// 余额改了必须失效缓存，否则中间件读到旧 balance=0 仍然 403。
			if s.authCacheInval != nil {
				s.authCacheInval.InvalidateAuthCacheByUserID(ctx, userID)
			}
			if s.billingCacheInval != nil {
				cacheCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				_ = s.billingCacheInval.InvalidateUserBalance(cacheCtx, userID)
				cancel()
			}
			log.Printf("[keybind] granted %.4f USD to user %d (key %d remaining quota)", giftAmount, userID, keyID)
		}
	}

	// 创建充值折扣记录（如果 key 配置了 RechargeDiscount）。
	// 与赠金分开处理：折扣创建失败仅记日志，不影响 key 转移和赠金。
	var grantedDiscount *GrantedDiscount
	if s.discountCreator != nil && s.giftSettingResolver != nil {
		if setting, err := s.giftSettingResolver.Resolve(ctx, keyID); err == nil && setting != nil {
			if cfg := s.resolveRechargeDiscountConfig(setting); cfg != nil {
				if _, err := s.discountCreator.CreateBindKeyDiscount(ctx, userID, keyID, cfg.DiscountRate, cfg.MaxDiscountableAmount, cfg.ValidDays, cfg.GiftDeductionMode, cfg.GiftRatioRecharge, cfg.GiftExpiryMode, cfg.GiftExpiresAfterDays); err != nil {
					log.Printf("[keybind] create recharge discount for user %d key %d failed: %v", userID, keyID, err)
				} else {
					log.Printf("[keybind] created recharge discount for user %d (key %d, rate=%.2f, max=%.2f, days=%d, mode=%s, gift_expiry=%s)", userID, keyID, cfg.DiscountRate, cfg.MaxDiscountableAmount, cfg.ValidDays, cfg.GiftDeductionMode, cfg.GiftExpiryMode)
					grantedDiscount = &GrantedDiscount{
						DiscountRate:          cfg.DiscountRate,
						MaxDiscountableAmount: cfg.MaxDiscountableAmount,
						ValidDays:             cfg.ValidDays,
						GiftDeductionMode:     cfg.GiftDeductionMode,
						GiftRatioRecharge:     cfg.GiftRatioRecharge,
						GiftExpiryMode:        cfg.GiftExpiryMode,
						GiftExpiresAfterDays:  cfg.GiftExpiresAfterDays,
					}
				}
			}
		}
	}

	// Record participation (only when monthly limit is enforced).
	if !unlimited {
		if err := s.participation.MarkParticipated(ctx, userID); err != nil {
			log.Printf("[keybind] mark participation failed for user %d: %v", userID, err)
		}
	}

	// Fetch the now-claimed row for the response. Lookup error is non-fatal.
	row, err := s.client.APIKey.Get(ctx, keyID)
	if err != nil {
		// The transfer succeeded; degrade gracefully.
		_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
		return &CommitResult{APIKeyID: keyID, MaskedKey: "", Gift: grantedGift, Discount: grantedDiscount}, nil
	}

	// Consume reservation atomically (best-effort; TTL also cleans them up).
	_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()

	return &CommitResult{APIKeyID: row.ID, MaskedKey: maskKey(row.Key), Gift: grantedGift, Discount: grantedDiscount}, nil
}

func (s *Service) disabledErr() error {
	if s.configErrMsg != "" {
		return ErrPoolUserNotConfigured.WithMetadata(map[string]string{"reason": s.configErrMsg})
	}
	return ErrPoolUserNotConfigured
}

// resolveRechargeDiscountConfig 从 per-key 配置中提取充值折扣参数。
// 返回 nil 表示该 key 未配置或未启用充值折扣。
// 同时归一化 gift 扣除策略：空/未知 mode → priority；非法 ratio 配置 → 视为未配置（nil）。
func (s *Service) resolveRechargeDiscountConfig(setting *BindKeyGiftSetting) *domain.BindKeyRechargeDiscount {
	if setting == nil || setting.RechargeDiscount == nil {
		return nil
	}
	cfg := setting.RechargeDiscount
	if !cfg.Enabled {
		return nil
	}
	if cfg.DiscountRate <= 0 || cfg.DiscountRate > 10 || cfg.MaxDiscountableAmount <= 0 || cfg.ValidDays < 1 {
		return nil
	}
	// 归一化赠金策略：非法配置直接拒绝该折扣（避免发放时才报错阻塞充值）。
	mode, ratio, err := domain.NormalizeGiftDeduction(cfg.GiftDeductionMode, cfg.GiftRatioRecharge)
	if err != nil {
		return nil
	}
	expiryMode, expiryDays, err := domain.NormalizeGiftExpiry(cfg.GiftExpiryMode, cfg.GiftExpiresAfterDays)
	if err != nil {
		return nil
	}
	normalized := *cfg
	normalized.GiftDeductionMode = mode
	normalized.GiftRatioRecharge = ratio
	normalized.GiftExpiryMode = expiryMode
	normalized.GiftExpiresAfterDays = expiryDays
	return &normalized
}

// isKeyUnlimited resolves the per-key config and returns whether the monthly
// participation limit should be skipped. Only explicit *Unlimit == true skips
// the monthly limit; all other cases (nil, false, missing config, resolver
// error) enforce the limit by default.
func (s *Service) isKeyUnlimited(ctx context.Context, keyID int64) bool {
	if s.giftSettingResolver == nil || keyID <= 0 {
		return false
	}
	setting, err := s.giftSettingResolver.Resolve(ctx, keyID)
	if err != nil || setting == nil {
		return false
	}
	if setting.Unlimit == nil {
		return false
	}
	return *setting.Unlimit
}

// hasUnlimitedPoolKeys returns true if the pool contains at least one active
// key whose config has explicit unlimit == true. Called by CheckEligibility so
// the UI doesn't block users who can still claim unlimited keys.
func (s *Service) hasUnlimitedPoolKeys(ctx context.Context) bool {
	if s.giftSettingResolver == nil {
		return false
	}
	ids, err := s.client.APIKey.Query().
		Where(
			apikey.UserIDEQ(s.poolUserID),
			apikey.StatusEQ(domain.StatusActive),
			apikey.DeletedAtIsNil(),
		).
		IDs(ctx)
	if err != nil || len(ids) == 0 {
		return false
	}
	for _, id := range ids {
		if s.isKeyUnlimited(ctx, id) {
			return true
		}
	}
	return false
}

func hasSufficientRemaining(quota, used float64) bool {
	if quota <= 0 {
		// quota == 0 means unlimited; treat as eligible.
		return true
	}
	remaining := quota - used
	if remaining <= 0 {
		return false
	}
	return remaining/quota > balanceRemainingMinimum
}

func normalizeKeys(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, raw := range in {
		k := strings.TrimSpace(raw)
		if k == "" {
			continue
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	return out
}

func newReservationID() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// maskKey returns a privacy-preserving rendering of the key for UI display.
// Keeps the prefix (e.g. sk-) and the last 4 chars.
func maskKey(k string) string {
	if len(k) <= 8 {
		return strings.Repeat("*", len(k))
	}
	prefixEnd := strings.IndexByte(k, '-')
	prefix := ""
	tail := k
	if prefixEnd > 0 && prefixEnd < len(k)-1 {
		prefix = k[:prefixEnd+1]
		tail = k[prefixEnd+1:]
	}
	if len(tail) <= 4 {
		return prefix + strings.Repeat("*", len(tail))
	}
	return prefix + strings.Repeat("*", len(tail)-4) + tail[len(tail)-4:]
}

func intToStr(v int64) string {
	return fmt.Sprintf("%d", v)
}

func strToInt(s string) (int64, error) {
	var v int64
	_, err := fmt.Sscanf(s, "%d", &v)
	if err != nil {
		return 0, err
	}
	return v, nil
}
