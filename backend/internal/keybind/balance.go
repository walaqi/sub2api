package keybind

import (
	"context"

	"github.com/Wei-Shaw/sub2api/ent"
	dbuser "github.com/Wei-Shaw/sub2api/ent/user"
)

// UserBalanceUpdater 抽象出"给用户加余额并同步累加 total_recharged"的最小动作。
// 由 keybind 包内的 entUserBalanceUpdater 实现，避免 keybind 反向依赖 repository/service。
type UserBalanceUpdater interface {
	AddBalanceAndTotalRecharged(ctx context.Context, userID int64, amount float64) error
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

// entUserBalanceUpdater 直接走 ent.Client，单条 UPDATE 同时改 balance 与 total_recharged。
type entUserBalanceUpdater struct {
	client *ent.Client
}

// NewEntUserBalanceUpdater 返回基于 *ent.Client 的默认实现。
func NewEntUserBalanceUpdater(client *ent.Client) UserBalanceUpdater {
	return &entUserBalanceUpdater{client: client}
}

func (u *entUserBalanceUpdater) AddBalanceAndTotalRecharged(ctx context.Context, userID int64, amount float64) error {
	if amount <= 0 {
		return nil
	}
	_, err := u.client.User.Update().
		Where(dbuser.IDEQ(userID)).
		AddBalance(amount).
		AddTotalRecharged(amount).
		Save(ctx)
	return err
}
