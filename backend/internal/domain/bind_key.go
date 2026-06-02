package domain

// BindKeyConfig 是表 A bind_key_gift_settings 的可扩展 per-key 配置，
// 序列化进 bind_key_gift_settings.config (JSONB)。
//
// 设计意图：新增 per-key 选项时往这里加字段即可，无需再迁移 schema。
// 所有字段 omitempty，未设置的子配置不写入 JSON，保持向后兼容。
type BindKeyConfig struct {
	// RegistrationWindow 限制只有"注册时长"落在窗口内的用户才能领取该 key。
	// nil 或 Enabled=false 表示不限制（仅保留每月一次的全局规则）。
	RegistrationWindow *BindKeyRegistrationWindow `json:"registration_window,omitempty"`
}

// BindKeyRegistrationWindow 是滚动相对注册窗口（单位：天，相对当前时间计算）。
//
// 条件：MinDays*24h <= (now - user.created_at) <= MaxDays*24h。
//   - MinDays: 最小注册时长，>= 0，0 表示对下界不设限（含刚注册的新用户）。
//   - MaxDays: 最大注册时长，>= 1，且必须 >= MinDays。
type BindKeyRegistrationWindow struct {
	Enabled bool `json:"enabled"`
	MinDays int  `json:"min_days"`
	MaxDays int  `json:"max_days"`
}
