package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"
	"github.com/Wei-Shaw/sub2api/internal/domain"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// BindKeyGiftSetting 是表 A：每条池 key 在绑定时发放赠金的参数预设。
//
// 不挂 edge 到 APIKey/User —— 与 api_keys 解耦。绑定后所有权转移，配置可由运维独立清理。
// 详见 /home/chris/.claude/plans/wobbly-herding-waffle.md Phase 3 §1。
type BindKeyGiftSetting struct {
	ent.Schema
}

func (BindKeyGiftSetting) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "bind_key_gift_settings"},
	}
}

func (BindKeyGiftSetting) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (BindKeyGiftSetting) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("api_key_id").Unique(),
		field.String("deduction_mode").MaxLen(16),
		field.Float("ratio_recharge").
			SchemaType(map[string]string{dialect.Postgres: "decimal(20,8)"}).
			Optional().
			Nillable(),
		field.Int("expires_after_days").
			Optional().
			Nillable(),
		// activity_id 关联该池 key 所属的活动（activity_events.id）。
		// nil 表示该 key 不隶属任何活动（普通推广 key，仅走 /bind-key 手动领取）。
		// 用于活动报名时按活动查出未被领走的池 key —— 建独立索引列（而非塞进
		// config JSONB），才能高效过滤 "某活动的所有 key"。
		field.Int64("activity_id").
			Optional().
			Nillable(),
		// 可扩展 per-key 配置（首个使用方：registration_window）。
		// 新增 per-key 选项往 domain.BindKeyConfig 加字段即可，避免再迁移 schema。
		field.JSON("config", &domain.BindKeyConfig{}).
			Optional(),
	}
}

func (BindKeyGiftSetting) Edges() []ent.Edge {
	return nil
}

func (BindKeyGiftSetting) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("api_key_id").Unique(),
		// 活动报名时按 activity_id 过滤该活动下的池 key，需索引。
		index.Fields("activity_id"),
	}
}
