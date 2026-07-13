package gift

import (
	"errors"

	"github.com/shopspring/decimal"
)

// 算法精度：所有 decimal 计算保留 8 位小数（与 PG decimal(20,8) 列对齐）。
const decimalScale = 8

// AllocateInput 分摊算法的入参（纯函数）。
type AllocateInput struct {
	TotalCost    decimal.Decimal // 本次扣费总额
	TotalBalance decimal.Decimal // users.balance 当前值
	// Gifts 仅含"当前请求分组可用"的赠金（group_id IS NULL 或 == 请求组），
	// 已由调用方按 (pinned DESC, mode, group, ratio, expiry, id) 预排序。
	Gifts []ActiveGift
	// IneligibleGiftRemaining 是"当前请求分组不可用"的赠金 remaining 之和
	// （绑定了别的分组的赠金）。它不参与本次分摊，但必须从充值池里扣除，
	// 否则会被误当成可花的真金。见 plan.md §3.3。
	IneligibleGiftRemaining decimal.Decimal
}

// ActiveGift 参与分摊的赠金快照。
type ActiveGift struct {
	ID            int64
	Mode          DeductionMode
	Remaining     decimal.Decimal
	RatioRecharge decimal.Decimal // priority 模式忽略；ratio 模式必为正
	// GroupID 绑定分组：非 nil 时仅限该分组消费；nil = 全局。用于 partitionByGroup 切分。
	GroupID *int64
	// Pinned 表示用户置顶了这笔赠金。置顶赠金在 Stage 0 无视 priority/ratio 分阶段
	// 被最先消费（绝对第一）。至多一条（DB 部分唯一索引保证）。
	Pinned bool
	// SortKey 字段供 ratio 模式 tie-break：值小的先扣（消耗更快、对用户更划算）。
	// 由调用方按 (pinned DESC, mode, group, ratio_recharge ASC, expires_at ASC, id ASC) 预排序后传入。
}

// partitionByGroup 把锁到的全部 active 赠金按当前请求分组切成两份：
//   - eligible：group_id IS NULL 或 == reqGroupID 的赠金（保留传入顺序）；
//   - ineligibleRemaining：其余（绑定别的分组）赠金的 remaining 之和。
//
// reqGroupID == nil（请求无分组）时，只有全局赠金 eligible，所有带分组的赠金归入 ineligible。
// 纯函数，供 AllocateAndDeduct 在 lockedSnapshot 之后调用。
func partitionByGroup(gifts []ActiveGift, reqGroupID *int64) (eligible []ActiveGift, ineligibleRemaining decimal.Decimal) {
	ineligibleRemaining = decimal.Zero
	for _, g := range gifts {
		usable := g.GroupID == nil || (reqGroupID != nil && *g.GroupID == *reqGroupID)
		if usable {
			eligible = append(eligible, g)
		} else {
			ineligibleRemaining = ineligibleRemaining.Add(g.Remaining)
		}
	}
	return eligible, ineligibleRemaining
}

// AllocateResult 分摊结果。
type AllocateResult struct {
	// GiftDeltas 每笔赠金本次的扣减量（正数）。未参与扣减的赠金不出现在 map 里。
	GiftDeltas map[int64]decimal.Decimal
	// RechargeDelta 充值池本次的扣减量（正数；可能 > recharge_pool 表示透支）。
	RechargeDelta decimal.Decimal
}

// Allocate 是赠金扣费的核心纯函数：根据当前赠金快照与待扣总额，计算各笔赠金减量与充值池减量。
//
// 算法分三阶段：
//  1. 优先扣 priority 赠金（按调用方传入顺序）
//  2. 比例扣 ratio 赠金（按调用方传入顺序，约定 ratio_recharge 小者在前）
//     T 单位扣费分摊：gift_part = T·r/(1+r), recharge_part = T/(1+r)
//  3. 剩余扣 recharge_pool（可透支）
//
// ratio 赠金在 rechargePool ≤ 0 时不参与消费（比例配对需要充值余额），
// 但不会被作废——用户后续充值后 ratio 赠金自然恢复配对消费。
//
// 不变量：Σ(GiftDeltas) + RechargeDelta ≡ TotalCost（精确相等，舍入误差归在链尾）。
func Allocate(in AllocateInput) (AllocateResult, error) {
	if in.TotalCost.IsNegative() {
		return AllocateResult{}, errors.New("totalCost must be non-negative")
	}

	res := AllocateResult{GiftDeltas: map[int64]decimal.Decimal{}}
	if in.TotalCost.IsZero() {
		return res, nil
	}

	// 拆 pinned / priority / ratio 三组，保留入参顺序。
	// pinned 至多一条（DB 部分唯一索引保证）；取第一条置顶项交给 Stage 0，
	// 并把它从 priority/ratio 组里排除，避免重复计数。
	var pinned *ActiveGift
	var priority, ratio []ActiveGift
	totalActive := decimal.Zero
	for i := range in.Gifts {
		g := in.Gifts[i]
		totalActive = totalActive.Add(g.Remaining)
		if g.Pinned && pinned == nil {
			gc := g
			pinned = &gc
			continue
		}
		switch g.Mode {
		case DeductionModePriority:
			priority = append(priority, g)
		case DeductionModeRatio:
			ratio = append(ratio, g)
		}
	}

	// 充值池 = total_balance − Σ(eligible active gifts) − Σ(ineligible gifts)
	//        = total_balance − Σ(所有 active gifts) → 真·全局充值池。
	// 若不减 IneligibleGiftRemaining，绑定别组的赠金会被误当可花真金而透支。
	rechargePool := in.TotalBalance.Sub(totalActive).Sub(in.IneligibleGiftRemaining)
	remaining := in.TotalCost

	// Stage 0: pinned 赠金（绝对第一），按其自身 mode 处理。
	// 分组不匹配的置顶赠金不在 in.Gifts（eligible 子集）里 → 天然被忽略。
	if pinned != nil && remaining.Sign() > 0 {
		switch pinned.Mode {
		case DeductionModePriority:
			take := decimalMin(pinned.Remaining, remaining)
			if take.Sign() > 0 {
				res.GiftDeltas[pinned.ID] = roundScale(take)
				remaining = remaining.Sub(take)
			}
		case DeductionModeRatio:
			giftPart, rechargePart, T := takeRatio(pinned, remaining, rechargePool)
			if T.Sign() > 0 {
				res.GiftDeltas[pinned.ID] = roundScale(giftPart)
				rechargePool = rechargePool.Sub(rechargePart)
				remaining = remaining.Sub(T)
			}
		}
	}

	// Stage 1: priority（已排除 pinned）
	for i := range priority {
		if remaining.Sign() <= 0 {
			break
		}
		g := &priority[i]
		take := decimalMin(g.Remaining, remaining)
		if take.Sign() > 0 {
			res.GiftDeltas[g.ID] = roundScale(take)
			g.Remaining = g.Remaining.Sub(take)
			remaining = remaining.Sub(take)
		}
	}

	// Stage 2: ratio（已排除 pinned；按调用方传入顺序：ratio_recharge ASC）
	for i := range ratio {
		if remaining.Sign() <= 0 {
			break
		}
		g := &ratio[i]
		if g.Remaining.Sign() <= 0 {
			continue
		}
		giftPart, rechargePart, T := takeRatio(g, remaining, rechargePool)
		if T.Sign() <= 0 {
			continue
		}

		// 累加 g 的减量（同一笔 gift 在 ratio 阶段最多被处理一次，无需累加）
		res.GiftDeltas[g.ID] = roundScale(giftPart)
		g.Remaining = g.Remaining.Sub(giftPart)
		rechargePool = rechargePool.Sub(rechargePart)
		remaining = remaining.Sub(T)
	}

	// Stage 3: 剩余压充值池（允许透支）
	if remaining.Sign() > 0 {
		res.RechargeDelta = remaining
		// NOTE: rechargePool 不再被后续使用（联动作废逻辑已移除，见 PR#31）。
		// 旧代码在此处更新 rechargePool 后用于判定是否 revoke ratio gifts，
		// 现在 ratio gifts 在 rechargePool≤0 时保持 active 休眠，不再作废。
	}

	// 舍入收口：保证 Σ(GiftDeltas) + RechargeDelta ≡ TotalCost。
	// roundScale 后可能产生微小误差，用 RechargeDelta 吸收。
	sum := res.RechargeDelta
	for _, d := range res.GiftDeltas {
		sum = sum.Add(d)
	}
	if !sum.Equal(in.TotalCost) {
		diff := in.TotalCost.Sub(sum)
		res.RechargeDelta = res.RechargeDelta.Add(diff)
	}
	res.RechargeDelta = roundScale(res.RechargeDelta)

	return res, nil
}

// takeRatio 计算一笔 ratio 赠金在本步能承担的分摊：
// 每扣 1 单位充值池 → 同步扣 r 单位赠金。设这一段总扣 T，
// 则 gift_part = T·r/(1+r), recharge_part = T/(1+r)。
// 受三个上限约束：① g.Remaining 用尽对应的 T；② rechargePool 可承担的 T
// （比例阶段不主动透支，透支留给 Stage 3，故 rechargePool≤0 时休眠取 0）；
// ③ 本次还需扣的 remaining。返回 (giftPart, rechargePart, T)。
func takeRatio(g *ActiveGift, remaining, rechargePool decimal.Decimal) (giftPart, rechargePart, T decimal.Decimal) {
	r := g.RatioRecharge
	if r.Sign() <= 0 {
		// 防御：ratio 模式必须有正比例，否则不扣。
		return decimal.Zero, decimal.Zero, decimal.Zero
	}
	one := decimal.NewFromInt(1)
	onePlusR := one.Add(r)

	capByGift := g.Remaining.Mul(onePlusR).Div(r)
	var capByRecharge decimal.Decimal
	if rechargePool.Sign() > 0 {
		capByRecharge = rechargePool.Mul(onePlusR)
	} else {
		capByRecharge = decimal.Zero
	}
	T = decimalMin(remaining, decimalMin(capByGift, capByRecharge))
	if T.Sign() <= 0 {
		return decimal.Zero, decimal.Zero, decimal.Zero
	}
	giftPart = T.Mul(r).Div(onePlusR)
	rechargePart = T.Sub(giftPart)
	return giftPart, rechargePart, T
}

// roundScale 把 decimal 截到固定精度（8 位），避免 Mul/Div 引入的尾数。
func roundScale(d decimal.Decimal) decimal.Decimal {
	return d.Round(decimalScale)
}

func decimalMin(a, b decimal.Decimal) decimal.Decimal {
	if a.LessThan(b) {
		return a
	}
	return b
}
