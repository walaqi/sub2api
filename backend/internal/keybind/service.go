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
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/apikey"
	"github.com/Wei-Shaw/sub2api/ent/user"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	infraerrors "github.com/Wei-Shaw/sub2api/internal/pkg/errors"

	"github.com/redis/go-redis/v9"
)

const (
	reservationTTL          = 5 * time.Minute
	maxKeysPerReserve       = 50
	balanceRemainingMinimum = 0.5 // require > 50% remaining quota

	redisLockedKeyPrefix      = "bindkey:locked:"      // bindkey:locked:<api_key_id> -> reservation_id
	redisReservationKeyPrefix = "bindkey:reservation:" // bindkey:reservation:<reservation_id> -> api_key_id (string)
)

// Errors mapped to HTTP responses via the project's infraerrors package.
var (
	ErrPoolUserNotConfigured = infraerrors.ServiceUnavailable("BIND_KEY_DISABLED", "key binding feature is not configured")
	ErrEmptyKeyList          = infraerrors.BadRequest("BIND_KEY_EMPTY", "no keys provided")
	ErrTooManyKeys           = infraerrors.BadRequest("BIND_KEY_TOO_MANY", "too many keys in one request")
	ErrNoEligibleKey         = infraerrors.NotFound("BIND_KEY_NO_ELIGIBLE", "no eligible key found in the provided list")
	ErrReservationExpired    = infraerrors.NotFound("BIND_KEY_RESERVATION_EXPIRED", "reservation has expired or does not exist")
	ErrPoolKeyAlreadyClaimed = infraerrors.Conflict("BIND_KEY_RACE", "key has already been claimed by another user")
	ErrAlreadyParticipated   = infraerrors.Forbidden("BIND_KEY_ALREADY_PARTICIPATED", "you have already bound a key this month")
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
	APIKeyID  int64        `json:"api_key_id"`
	MaskedKey string       `json:"masked_key"`
	Gift      *GrantedGift `json:"gift,omitempty"`
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

	// 可选依赖：用于绑定成功后赠送余额并失效相关缓存。
	// 任意字段为 nil 时降级为"该能力关闭"，但 key 仍会正常转移。
	userBalanceUpdater UserBalanceUpdater
	authCacheInval     APIKeyAuthCacheInvalidator
	billingCacheInval  BillingBalanceInvalidator
}

// NewService constructs a Service. It resolves the pool user once at
// startup by looking up the configured email in the users table. If the
// email is empty or the lookup fails, the service is constructed in a
// "disabled" state where every call returns ErrPoolUserNotConfigured.
// This keeps the feature's failure mode isolated from server startup.
func NewService(ctx context.Context, client *ent.Client, redisClient *redis.Client, poolUserEmail string, dataDir string, opts ...Option) *Service {
	svc := &Service{
		client:        client,
		redis:         redisClient,
		participation: NewParticipationStore(dataDir),
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
	res.Eligible = !already
	return res, nil
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

		reservationID, err := newReservationID()
		if err != nil {
			return nil, fmt.Errorf("generate reservation id: %w", err)
		}

		lockKey := redisLockedKeyPrefix + intToStr(row.ID)
		ok, err := s.redis.SetNX(ctx, lockKey, reservationID, reservationTTL).Result()
		if err != nil {
			return nil, fmt.Errorf("redis setnx: %w", err)
		}
		if !ok {
			// another reservation already holds this key
			continue
		}

		// Bind reservation_id -> api_key_id with same TTL.
		if err := s.redis.Set(ctx, redisReservationKeyPrefix+reservationID, intToStr(row.ID), reservationTTL).Err(); err != nil {
			// best-effort cleanup
			_ = s.redis.Del(ctx, lockKey).Err()
			return nil, fmt.Errorf("redis set reservation: %w", err)
		}

		expiresAt := time.Now().Add(reservationTTL)
		return &ReservationResult{
			ReservationID:   reservationID,
			MaskedKey:       maskKey(row.Key),
			RemainingQuota:  row.Quota - row.QuotaUsed,
			QuotaLimit:      row.Quota,
			ExpiresAtUnixMs: expiresAt.UnixMilli(),
		}, nil
	}

	return nil, ErrNoEligibleKey
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

	// Monthly-limit gate: enforced here because anonymous /reserve cannot
	// know the caller's identity. We drop the reservation so a queued key
	// is freed up for someone else; the lock entry expires naturally.
	already, err := s.participation.HasParticipated(ctx, userID)
	if err != nil {
		return nil, err
	}
	if already {
		_ = s.redis.Del(ctx, resKey).Err()
		return nil, ErrAlreadyParticipated
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
	affected, err := s.client.APIKey.Update().
		Where(
			apikey.IDEQ(keyID),
			apikey.UserIDEQ(s.poolUserID),
			apikey.StatusEQ(domain.StatusActive),
			apikey.DeletedAtIsNil(),
		).
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
		g, err := s.userBalanceUpdater.GrantForBindKey(ctx, userID, giftAmount, keyID)
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

	// Record participation. Lenient on failure: the key is already
	// transferred, so refusing the response would be a worse UX than the
	// (rare) case of a user slipping through twice in a month.
	if err := s.participation.MarkParticipated(ctx, userID); err != nil {
		log.Printf("[keybind] mark participation failed for user %d: %v", userID, err)
	}

	// Fetch the now-claimed row for the response. Lookup error is non-fatal.
	row, err := s.client.APIKey.Get(ctx, keyID)
	if err != nil {
		// The transfer succeeded; degrade gracefully.
		_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()
		return &CommitResult{APIKeyID: keyID, MaskedKey: "", Gift: grantedGift}, nil
	}

	// Consume reservation atomically (best-effort; TTL also cleans them up).
	_ = s.redis.Del(ctx, resKey, redisLockedKeyPrefix+intToStr(keyID)).Err()

	return &CommitResult{APIKeyID: row.ID, MaskedKey: maskKey(row.Key), Gift: grantedGift}, nil
}

func (s *Service) disabledErr() error {
	if s.configErrMsg != "" {
		return ErrPoolUserNotConfigured.WithMetadata(map[string]string{"reason": s.configErrMsg})
	}
	return ErrPoolUserNotConfigured
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
