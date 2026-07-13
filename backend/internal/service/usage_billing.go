package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var ErrUsageBillingRequestIDRequired = errors.New("usage billing request_id is required")
var ErrUsageBillingRequestConflict = errors.New("usage billing request fingerprint conflict")

// UsageBillingCommand describes one billable request that must be applied at most once.
type UsageBillingCommand struct {
	RequestID          string
	APIKeyID           int64
	RequestFingerprint string
	RequestPayloadHash string

	UserID              int64
	AccountID           int64
	SubscriptionID      *int64
	AccountType         string
	Model               string
	ServiceTier         string
	ReasoningEffort     string
	BillingType         int8
	InputTokens         int
	OutputTokens        int
	CacheCreationTokens int
	CacheReadTokens     int
	ImageCount          int
	MediaType           string

	BalanceCost         float64
	SubscriptionCost    float64
	APIKeyQuotaCost     float64
	APIKeyRateLimitCost float64
	AccountQuotaCost    float64

	// GroupID 是本次请求分组（apiKey.GroupID，nil=无分组）。用于赠金按组扣费，
	// 同时纳入 v2 指纹以区分"同请求改组后重试"（见 FingerprintVersion）。
	GroupID *int64

	// FingerprintVersion 决定 Normalize 用哪版公式计算指纹：
	//   1（默认/legacy）：不含 group_id，与历史行兼容；
	//   2：含 group_id。两阶段发布下由 config 开关控制新写入用哪版（见 plan.md §3.6）。
	// dedup 表持久化该版本，比对时按存储版本选公式，避免混版误判冲突。
	FingerprintVersion int16
}

// UsageBillingFingerprintV1 / V2 是指纹公式版本号。
// V1：历史公式（不含 group_id）；V2：追加 group_id。
const (
	UsageBillingFingerprintV1 int16 = 1
	UsageBillingFingerprintV2 int16 = 2
)

func (c *UsageBillingCommand) Normalize() {
	if c == nil {
		return
	}
	c.RequestID = strings.TrimSpace(c.RequestID)
	if c.FingerprintVersion == 0 {
		c.FingerprintVersion = UsageBillingFingerprintV1
	}
	if strings.TrimSpace(c.RequestFingerprint) == "" {
		c.RequestFingerprint = buildUsageBillingFingerprint(c, c.FingerprintVersion)
	}
}

// buildUsageBillingFingerprint 按 version 计算指纹。
// V1 与历史逐字节一致（不含 group_id）；V2 在 payloadHash 之后追加 group_id 段，
// 使仅 group 不同的两请求得到不同 hash、而不影响 V1 存量行的重算比对。
func buildUsageBillingFingerprint(c *UsageBillingCommand, version int16) string {
	if c == nil {
		return ""
	}
	raw := fmt.Sprintf(
		"%d|%d|%d|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%s|%d|%0.10f|%0.10f|%0.10f|%0.10f|%0.10f",
		c.UserID,
		c.AccountID,
		c.APIKeyID,
		strings.TrimSpace(c.AccountType),
		strings.TrimSpace(c.Model),
		strings.TrimSpace(c.ServiceTier),
		strings.TrimSpace(c.ReasoningEffort),
		c.BillingType,
		c.InputTokens,
		c.OutputTokens,
		c.CacheCreationTokens,
		c.CacheReadTokens,
		c.ImageCount,
		strings.TrimSpace(c.MediaType),
		valueOrZero(c.SubscriptionID),
		c.BalanceCost,
		c.SubscriptionCost,
		c.APIKeyQuotaCost,
		c.APIKeyRateLimitCost,
		c.AccountQuotaCost,
	)
	if payloadHash := strings.TrimSpace(c.RequestPayloadHash); payloadHash != "" {
		raw += "|" + payloadHash
	}
	if version >= UsageBillingFingerprintV2 {
		// V2 追加 group 段；V1 完全不含此段，与历史行逐字节一致。
		raw += fmt.Sprintf("|g:%d", valueOrZero(c.GroupID))
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// FingerprintForVersion 用指定版本公式重算本命令的指纹，供 dedup 比对：
// 存储行标注 version=1 → 用 V1 重算比对（即使本命令是 V2 写入），避免混版误判冲突。
func (c *UsageBillingCommand) FingerprintForVersion(version int16) string {
	return buildUsageBillingFingerprint(c, version)
}

func HashUsageRequestPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func valueOrZero(v *int64) int64 {
	if v == nil {
		return 0
	}
	return *v
}

// AccountQuotaState holds the post-increment quota state returned by the DB transaction.
// All values are post-update (i.e., already include the increment).
type AccountQuotaState struct {
	TotalUsed   float64
	TotalLimit  float64
	DailyUsed   float64
	DailyLimit  float64
	WeeklyUsed  float64
	WeeklyLimit float64
}

type UsageBillingApplyResult struct {
	Applied              bool
	APIKeyQuotaExhausted bool
	NewBalance           *float64           // post-deduction balance (nil = no balance deduction)
	QuotaState           *AccountQuotaState // post-increment quota state (nil = no quota increment)
	// GiftCost / RechargeCost 是赠金引擎本次扣费的分摊明细（仅 BalanceCost > 0 时填充）。
	// 用于把"赠金扣减 / 充值池扣减"持久化到 usage_logs。
	// 不变量：GiftCost + RechargeCost = BalanceCost（订阅扣费路径下两者均为 0）。
	GiftCost     *float64
	RechargeCost *float64
}

type UsageBillingRepository interface {
	Apply(ctx context.Context, cmd *UsageBillingCommand) (*UsageBillingApplyResult, error)
}
