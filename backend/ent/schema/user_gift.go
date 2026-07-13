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
		// group_id：赠金绑定的分组。NULL = 全局通用（任意分组可花）。
		// 领取带分组的池 key 时固化为该组；分组被删除时置回 NULL（转全局）。
		field.Int64("group_id").
			Optional().
			Nillable(),
		// pinned：用户置顶的赠金。至多一条（部分唯一索引保证）。
		// 置顶后只要满足使用条件即被 allocator Stage 0 最先消费（绝对第一）。
		field.Bool("pinned").
			Default(false),
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
		// 扣费快照按 (user_id, group_id) 过滤。
		index.Fields("user_id", "group_id"),
		// 分组删除按 group_id 清扫；(user_id,group_id) 复合索引无法高效服务
		// WHERE group_id = $1，单列偏索引仅覆盖有分组的赠金。
		index.Fields("group_id").
			Annotations(entsql.IndexWhere("group_id IS NOT NULL")),
		// 一人至多一条置顶：部分唯一索引在 DB 层强约束。
		// StorageKey 避免与上面 index.Fields("user_id") 的默认名 usergift_user_id 冲突。
		index.Fields("user_id").
			Annotations(entsql.IndexWhere("pinned")).
			StorageKey("user_gifts_one_pin_per_user").
			Unique(),
	}
}
