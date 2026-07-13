package keybind

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/gift"
)

// GrantedGift 是 Commit 回应里"刚发出的赠金"快照，足够前端渲染：
//   - 金额（display "$xx"）
//   - 扣费模式 + ratio_recharge（priority 不需 ratio；ratio 必带）
//   - 过期时间（nil 表示永不过期）
type GrantedGift struct {
	Amount          float64            `json:"amount"`
	DeductionMode   gift.DeductionMode `json:"deduction_mode"`
	RatioRecharge   *float64           `json:"ratio_recharge,omitempty"`
	ExpiresAtUnixMs *int64             `json:"expires_at_unix_ms,omitempty"`
}

// UserBalanceUpdater 抽象出"绑 key 成功后给用户发放赠金"的最小动作。
//
// 历史：早期实现叫 AddBalanceAndTotalRecharged，把赠金错记进 total_recharged（commit 32df9534）。
// Phase 1 改为通过 gift.Engine.Grant 发放 priority 类赠金，不再动 total_recharged。
// Phase 3 进一步把 api_key_id 一起传下来，由实现读表 A 决定 mode/ratio_recharge/expires_after_days。
// 返回 *GrantedGift 让 service 层把赠金详情透传到前端；amount<=0 时返回 (nil, nil)。
type UserBalanceUpdater interface {
	// groupID 为池 key 携带的分组（nil=无分组）。非 nil 时发一笔绑该组的赠金
	// （只能在该组消费）；Grant 内部在事务里锁 groups 行校验，组已删则落全局。
	GrantForBindKey(ctx context.Context, userID int64, amount float64, apiKeyID int64, groupID *int64) (*GrantedGift, error)
}

// APIKeyAuthCacheInvalidator 与 service.APIKeyAuthCacheInvalidator 结构等价。
// 这里只声明 keybind 真正用到的方法；router.go 通过 structural typing 注入 *service.APIKeyService。
type APIKeyAuthCacheInvalidator interface {
	InvalidateAuthCacheByUserID(ctx context.Context, userID int64)
}

// BillingBalanceInvalidator 与 service.BillingCacheService 上的方法签名一致。
// 当前 router 不注入此实例（避免 http.go 签名变更），保留接口以便后续扩展。
type BillingBalanceInvalidator interface {
	InvalidateUserBalance(ctx context.Context, userID int64) error
}

// Option 用 functional options 给 Service 注入可选依赖。
type Option func(*Service)

// WithBalanceGift 配置"绑定成功后赠送余额并失效相关缓存"。
// 任意参数为 nil 表示对应能力关闭：
//   - updater 为 nil → 不赠送余额（key 仍转移）
//   - authCache 为 nil → 不失效 auth 缓存（首请求需等 TTL 自然过期）
//   - billing 为 nil → 不失效 billing 余额缓存（同上）
func WithBalanceGift(updater UserBalanceUpdater, authCache APIKeyAuthCacheInvalidator, billing BillingBalanceInvalidator) Option {
	return func(s *Service) {
		s.userBalanceUpdater = updater
		s.authCacheInval = authCache
		s.billingCacheInval = billing
	}
}

// RechargeDiscountCreator 抽象出"绑 key 成功后创建充值折扣记录"的最小动作。
// keybind 不直接依赖 repository 包，通过接口注入实现。
type RechargeDiscountCreator interface {
	// CreateBindKeyDiscount 为用户创建 bind_key 来源的充值折扣记录。
	// 由调用方从 BindKeyGiftSetting 的 RechargeDiscount 配置中提取参数。
	// giftDeductionMode/giftRatioRecharge/giftExpiryMode/giftExpiresAfterDays
	// 固化该折扣发放赠金的策略（空 mode 由实现层归一化为默认值）。
	// 返回值：created discount ID（0 表示未创建，如幂等冲突或无需创建）。
	CreateBindKeyDiscount(ctx context.Context, userID, apiKeyID int64, rate, maxAmount float64, validDays int, giftDeductionMode string, giftRatioRecharge *float64, giftExpiryMode string, giftExpiresAfterDays *int) (int64, error)
}

// WithRechargeDiscountCreator 注入"绑定成功后创建充值折扣记录"的能力。
func WithRechargeDiscountCreator(creator RechargeDiscountCreator) Option {
	return func(s *Service) {
		s.discountCreator = creator
	}
}

// giftEngineUpdater 通过 gift.Engine 发放赠金。
// 实际发放参数（mode / ratio_recharge / expires_at）由 resolver 按 api_key_id 查表 A 决定。
// 表中无对应行 → 走默认 priority、永不过期。
type giftEngineUpdater struct {
	engine   *gift.Engine
	resolver BindKeyGiftSettingResolver
}

// NewGiftEngineUpdater 返回基于 gift.Engine + 表 A resolver 的赠金更新器。
// resolver 可以为 nil（等同于"全部走默认 priority + 永不过期"）。
func NewGiftEngineUpdater(engine *gift.Engine, resolver BindKeyGiftSettingResolver) UserBalanceUpdater {
	if engine == nil {
		return nil
	}
	return &giftEngineUpdater{engine: engine, resolver: resolver}
}

// NewEntUserBalanceUpdater 是历史命名，保留以避免破坏调用点（已无生产使用）。
//
// Deprecated: use NewGiftEngineUpdater(engine, resolver).
func NewEntUserBalanceUpdater(_ *ent.Client) UserBalanceUpdater {
	return nil
}

func (u *giftEngineUpdater) GrantForBindKey(ctx context.Context, userID int64, amount float64, apiKeyID int64, groupID *int64) (*GrantedGift, error) {
	if amount <= 0 {
		return nil, nil
	}
	if u == nil || u.engine == nil {
		return nil, errors.New("giftEngineUpdater: engine is nil")
	}

	// 默认 priority、永不过期。groupID 非 nil 时该赠金绑定分组（仅该组可消费）；
	// Grant 内部在事务里锁 groups 行，若该组已删则落全局（group_id=NULL）。
	input := gift.GrantInput{
		UserID:  userID,
		Amount:  amount,
		Mode:    gift.DeductionModePriority,
		Source:  gift.SourceKeybind,
		GroupID: groupID,
	}
	if ref := apiKeyRef(apiKeyID); ref != "" {
		input.SourceRef = &ref
	}

	// 查表 A 覆盖默认参数
	if u.resolver != nil && apiKeyID > 0 {
		setting, err := u.resolver.Resolve(ctx, apiKeyID)
		if err != nil {
			return nil, err
		}
		if setting != nil {
			input.Mode = setting.DeductionMode
			input.RatioRecharge = setting.RatioRecharge
			if setting.ExpiresAfterDays != nil && *setting.ExpiresAfterDays > 0 {
				exp := time.Now().Add(time.Duration(*setting.ExpiresAfterDays) * 24 * time.Hour)
				input.ExpiresAt = &exp
			}
		}
	}

	granted, err := u.engine.Grant(ctx, input)
	if err != nil {
		return nil, err
	}
	if granted == nil {
		return nil, nil
	}

	out := &GrantedGift{
		Amount:        granted.Amount,
		DeductionMode: granted.Mode,
		RatioRecharge: granted.RatioRecharge,
	}
	if granted.ExpiresAt != nil {
		ms := granted.ExpiresAt.UnixMilli()
		out.ExpiresAtUnixMs = &ms
	}
	return out, nil
}

// apiKeyRef 把 api_key_id 编码为 gift.source_ref，便于后续审计/对账。
func apiKeyRef(apiKeyID int64) string {
	if apiKeyID <= 0 {
		return ""
	}
	return "api_key:" + strconv.FormatInt(apiKeyID, 10)
}
