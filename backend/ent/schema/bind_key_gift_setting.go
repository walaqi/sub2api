package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

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
	}
}

func (BindKeyGiftSetting) Edges() []ent.Edge {
	return nil
}

func (BindKeyGiftSetting) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("api_key_id").Unique(),
	}
}
