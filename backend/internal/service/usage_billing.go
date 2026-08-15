package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/shopspring/decimal"
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

	// rawFingerprintV1 / V2 缓存首次 Normalize 时基于原始金额生成的指纹。
	// 金额随后会被量化，因此跨版本 dedup 比对不能再从已量化字段重算。
	rawFingerprintV1 string
	rawFingerprintV2 string
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
	if c.rawFingerprintV1 == "" {
		c.rawFingerprintV1 = buildUsageBillingFingerprint(c, UsageBillingFingerprintV1)
	}
	if c.rawFingerprintV2 == "" {
		c.rawFingerprintV2 = buildUsageBillingFingerprint(c, UsageBillingFingerprintV2)
	}
	if strings.TrimSpace(c.RequestFingerprint) == "" {
		c.RequestFingerprint = c.rawFingerprintForVersion(c.FingerprintVersion)
	}
	// 量化必须在指纹计算之后：指纹是请求幂等键，保持由原始金额派生可以避免
	// 升级前后同一 request_id 的重试算出不同指纹而被判为 fingerprint conflict。
	c.quantizeMonetaryFields()
}

// UsageBillingMonetaryScale 是所有计费金额的规范小数位数，
// 对齐 users.balance / api_keys.quota_used 的 NUMERIC(20,8)。
const UsageBillingMonetaryScale = 8

// quantizeMonetaryFields 把命令中的金额统一量化到 NUMERIC(20,8)。
//
// 不量化时，同一笔 ActualCost 会在两条方向相反的 SQL 上被 PostgreSQL 分别舍入：
//
//	balance    = balance - $1      // 存剩余额度，舍入的是「减法结果」
//	quota_used = quota_used + $1   // 存累计用量，舍入的是「加法结果」
//
// PostgreSQL 对 NUMERIC 采用 half-away-from-zero。当金额在第 9 位出现 half 边界
// （例：10 输入 token × 0.00000125 + 5 输出 token × 0.00001000，再乘分组倍率
// 1.25 = 0.000078125）时：
//
//	balance:    10000 - 0.000078125 = 9999.999921875 → 9999.99992188（delta 0.00007812）
//	quota_used:     0 + 0.000078125 =     0.000078125 →     0.00007813（delta 0.00007813）
//
// 两个 delta 相差 1e-8，且方向相反——余额少扣、Key 配额多记，随请求量线性累积，
// 使余额、API Key 配额与用量记录无法精确对账（需要 epsilon 比较才能勉强吻合）。
//
// 在参数进入 SQL 之前量化一次，两条语句就都拿到已经落在 8 位刻度上的同一个金额，
// 存储阶段不再发生任何舍入，delta 精确相等。
func (c *UsageBillingCommand) quantizeMonetaryFields() {
	c.BalanceCost = QuantizeUsageBillingAmount(c.BalanceCost)
	c.SubscriptionCost = QuantizeUsageBillingAmount(c.SubscriptionCost)
	c.APIKeyQuotaCost = QuantizeUsageBillingAmount(c.APIKeyQuotaCost)
	c.APIKeyRateLimitCost = QuantizeUsageBillingAmount(c.APIKeyRateLimitCost)
	c.AccountQuotaCost = QuantizeUsageBillingAmount(c.AccountQuotaCost)
}

// QuantizeUsageBillingAmount 把金额舍入到 UsageBillingMonetaryScale 位小数，
// 采用与 PostgreSQL NUMERIC 一致的 half-away-from-zero 规则。
//
// 走 decimal 而不是 math.Round(v*1e8)/1e8：后者在乘除过程中会引入额外的二进制
// 误差，边界值可能被推到错误的一侧。decimal.NewFromFloat 取 float64 的最短十进制
// 表示，正是 PostgreSQL 把 float8 参数转成 numeric 时所用的表示。
func QuantizeUsageBillingAmount(v float64) float64 {
	if v == 0 || math.IsNaN(v) || math.IsInf(v, 0) {
		return v
	}
	quantized, _ := decimal.NewFromFloat(v).Round(UsageBillingMonetaryScale).Float64()
	return quantized
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
	if c == nil {
		return ""
	}
	if fingerprint := c.rawFingerprintForVersion(version); fingerprint != "" {
		return fingerprint
	}
	return buildUsageBillingFingerprint(c, version)
}

func (c *UsageBillingCommand) rawFingerprintForVersion(version int16) string {
	if version >= UsageBillingFingerprintV2 {
		return c.rawFingerprintV2
	}
	return c.rawFingerprintV1
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
	BalanceOverdrafted   bool               // true when the sufficient-balance guard missed and debt was still recorded
	QuotaState           *AccountQuotaState // post-increment quota state (nil = no quota increment)
	// GiftCost / RechargeCost 是赠金引擎本次扣费的分摊明细（仅 BalanceCost > 0 时填充）。
	// 用于把"赠金扣减 / 充值池扣减"持久化到 usage_logs。
	// 不变量：GiftCost + RechargeCost = BalanceCost（订阅扣费路径下两者均为 0）。
	GiftCost     *float64
	RechargeCost *float64
}

// BatchImageBalanceHoldCommand describes an idempotent balance hold operation.
type BatchImageBalanceHoldCommand struct {
	RequestID          string
	APIKeyID           int64
	RequestFingerprint string
	RequestPayloadHash string
	UserID             int64
	BatchID            string
	HoldAmount         float64
	ActualAmount       float64
}

func (c *BatchImageBalanceHoldCommand) Normalize() {
	if c == nil {
		return
	}
	c.RequestID = strings.TrimSpace(c.RequestID)
	c.BatchID = strings.TrimSpace(c.BatchID)
	if strings.TrimSpace(c.RequestFingerprint) == "" {
		c.RequestFingerprint = buildBatchImageBalanceHoldFingerprint(c)
	}
}

func buildBatchImageBalanceHoldFingerprint(c *BatchImageBalanceHoldCommand) string {
	if c == nil {
		return ""
	}
	raw := fmt.Sprintf(
		"%d|%d|%s|%0.10f|%0.10f",
		c.UserID,
		c.APIKeyID,
		strings.TrimSpace(c.BatchID),
		c.HoldAmount,
		c.ActualAmount,
	)
	if payloadHash := strings.TrimSpace(c.RequestPayloadHash); payloadHash != "" {
		raw += "|" + payloadHash
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

type BatchImageBalanceHoldResult struct {
	Applied       bool
	NewBalance    *float64
	FrozenBalance *float64
}

type UsageBillingRepository interface {
	Apply(ctx context.Context, cmd *UsageBillingCommand) (*UsageBillingApplyResult, error)
	ReserveBatchImageBalance(ctx context.Context, cmd *BatchImageBalanceHoldCommand) (*BatchImageBalanceHoldResult, error)
	CaptureBatchImageBalance(ctx context.Context, cmd *BatchImageBalanceHoldCommand) (*BatchImageBalanceHoldResult, error)
	ReleaseBatchImageBalance(ctx context.Context, cmd *BatchImageBalanceHoldCommand) (*BatchImageBalanceHoldResult, error)
}
