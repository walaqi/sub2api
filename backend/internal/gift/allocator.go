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
	Gifts        []ActiveGift    // 用户当前所有 active 且未过期的赠金，已加锁读取
}

// ActiveGift 参与分摊的赠金快照。
type ActiveGift struct {
	ID            int64
	Mode          DeductionMode
	Remaining     decimal.Decimal
	RatioRecharge decimal.Decimal // priority 模式忽略；ratio 模式必为正
	// SortKey 字段供 ratio 模式 tie-break：值小的先扣（消耗更快、对用户更划算）。
	// 由调用方按 (ratio_recharge ASC, expires_at ASC, id ASC) 预排序后传入。
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

	// 拆 priority / ratio 两组，保留入参顺序
	var priority, ratio []ActiveGift
	totalActive := decimal.Zero
	for _, g := range in.Gifts {
		totalActive = totalActive.Add(g.Remaining)
		switch g.Mode {
		case DeductionModePriority:
			priority = append(priority, g)
		case DeductionModeRatio:
			ratio = append(ratio, g)
		}
	}

	// 当前充值池 = total_balance - 所有 active 赠金 remaining 之和
	rechargePool := in.TotalBalance.Sub(totalActive)
	remaining := in.TotalCost

	// Stage 1: priority
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

	// Stage 2: ratio（按调用方传入顺序：ratio_recharge ASC）
	for i := range ratio {
		if remaining.Sign() <= 0 {
			break
		}
		g := &ratio[i]
		if g.Remaining.Sign() <= 0 {
			continue
		}
		r := g.RatioRecharge
		if r.Sign() <= 0 {
			// 防御：ratio 模式必须有正比例，否则跳过
			continue
		}

		// 这一段使用 g 时：
		// 每扣 1 单位充值池 → 同步扣 r 单位赠金。
		// 设这一段总扣 T，则 gift_part = T·r/(1+r), recharge_part = T/(1+r)。
		one := decimal.NewFromInt(1)
		onePlusR := one.Add(r)

		// 上限 1：g.Remaining 用尽时对应的 T
		capByGift := g.Remaining.Mul(onePlusR).Div(r)
		// 上限 2：rechargePool 在此步剩余可承担的 T（rechargePool 允许透支，但本算法在比例阶段
		// 不主动透支：透支留给 stage 3）
		var capByRecharge decimal.Decimal
		if rechargePool.Sign() > 0 {
			capByRecharge = rechargePool.Mul(onePlusR)
		} else {
			capByRecharge = decimal.Zero
		}
		// 上限 3：本次还需要扣的总额
		T := decimalMin(remaining, decimalMin(capByGift, capByRecharge))
		if T.Sign() <= 0 {
			continue
		}

		giftPart := T.Mul(r).Div(onePlusR)
		rechargePart := T.Sub(giftPart)

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
