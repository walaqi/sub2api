package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// UserGift 赠金子账本：每行 = 一笔赠金。
// 详见设计稿 /home/chris/.claude/plans/wobbly-herding-waffle.md。
//
// 不变量：users.balance ≡ recharge_pool + Σ(active gifts.remaining)
type UserGift struct {
	ent.Schema
}

func (UserGift) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "user_gifts"},
	}
}

func (UserGift) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (UserGift) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("user_id"),
		field.Float("amount").
			SchemaType(map[string]string{dialect.Postgres: "decimal(20,8)"}),
		field.Float("remaining").
			SchemaType(map[string]string{dialect.Postgres: "decimal(20,8)"}),
		field.String("deduction_mode").
			MaxLen(16),
		field.Float("ratio_recharge").
			SchemaType(map[string]string{dialect.Postgres: "decimal(20,8)"}).
			Optional().
			Nillable(),
		field.Time("expires_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{dialect.Postgres: "timestamptz"}),
		field.String("source").
			MaxLen(32),
		field.String("source_ref").
			MaxLen(128).
			Optional().
			Nillable(),
		field.String("status").
			MaxLen(16).
			Default("active"),
	}
}

func (UserGift) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Ref("gifts").
			Field("user_id").
			Required().
			Unique(),
	}
}

func (UserGift) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("user_id"),
		index.Fields("expires_at"),
	}
}
