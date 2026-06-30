package service

import (
	"context"
	"time"
)

// InviterBoundHook 在邀请关系绑定成功后触发。
// 实现方通常是 ReferralRewardService，用于发放被邀请人赠金和继承折扣。
// 接口设计为小接口以避免 AffiliateService → ReferralRewardService 的直接循环依赖。
type InviterBoundHook interface {
	OnInviterBound(ctx context.Context, inviterID, inviteeID int64, boundAt time.Time)
}
