package keybind

import (
	"context"
	"errors"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/bindkeygiftsetting"
	"github.com/Wei-Shaw/sub2api/internal/domain"
	"github.com/Wei-Shaw/sub2api/internal/gift"
)

// BindKeyGiftSetting 是一个 api_key_id 对应的发放预设。
// 表 A 中没有该 api_key_id 的行 → Resolver 返回 nil → 调用方走默认 priority + 永不过期。
type BindKeyGiftSetting struct {
	APIKeyID         int64
	DeductionMode    gift.DeductionMode
	RatioRecharge    *float64
	ExpiresAfterDays *int
	// Unlimit 来自表 A config JSONB（config.unlimit）。
	// nil 或 true → 不限次数；仅 *false 才执行每月一次限制。
	Unlimit *bool
	// RegistrationWindow 来自表 A 的 config JSONB（config.registration_window）。
	// nil 表示未配置窗口；由调用方按"不限制注册时间"处理。
	RegistrationWindow *domain.BindKeyRegistrationWindow
}

// BindKeyGiftSettingResolver 抽象出"按 api_key_id 查表 A"的最小动作。
// 接口便于单测与后续替换为缓存实现。
type BindKeyGiftSettingResolver interface {
	Resolve(ctx context.Context, apiKeyID int64) (*BindKeyGiftSetting, error)
}

// entBindKeyGiftSettingResolver 走 ent.Client 查 bind_key_gift_settings 表。
type entBindKeyGiftSettingResolver struct {
	client *dbent.Client
}

// NewBindKeyGiftSettingResolver 返回基于 ent 的默认实现。client 为 nil 时返回 nil。
func NewBindKeyGiftSettingResolver(client *dbent.Client) BindKeyGiftSettingResolver {
	if client == nil {
		return nil
	}
	return &entBindKeyGiftSettingResolver{client: client}
}

// Resolve 查询单条配置。表中无对应行返回 (nil, nil)，由调用方按默认 priority 处理。
func (r *entBindKeyGiftSettingResolver) Resolve(ctx context.Context, apiKeyID int64) (*BindKeyGiftSetting, error) {
	if r == nil || r.client == nil {
		return nil, nil
	}
	row, err := r.client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(apiKeyID)).
		Only(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	mode := gift.DeductionMode(row.DeductionMode)
	if mode != gift.DeductionModePriority && mode != gift.DeductionModeRatio {
		return nil, errors.New("bind_key_gift_settings: unknown deduction_mode " + row.DeductionMode)
	}
	out := &BindKeyGiftSetting{
		APIKeyID:      row.APIKeyID,
		DeductionMode: mode,
	}
	if row.RatioRecharge != nil {
		v := *row.RatioRecharge
		out.RatioRecharge = &v
	}
	if row.ExpiresAfterDays != nil {
		v := *row.ExpiresAfterDays
		out.ExpiresAfterDays = &v
	}
	if row.Config != nil && row.Config.RegistrationWindow != nil {
		w := *row.Config.RegistrationWindow
		out.RegistrationWindow = &w
	}
	if row.Config != nil && row.Config.Unlimit != nil {
		v := *row.Config.Unlimit
		out.Unlimit = &v
	}
	return out, nil
}
