//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// fp 返回 float64 指针，简化定价字面量构造。
func fp(v float64) *float64 { return &v }

// newCatalogChannelService 构造一个 ChannelService，使其 ListAvailable 返回基于
// 给定 channels + activeGroups 的聚合视图。pricingService 传入以便补充元数据/回落定价。
func newCatalogChannelService(channels []Channel, activeGroups []Group, pricing *PricingService) *ChannelService {
	repo := &mockChannelRepository{
		listAllFn: func(ctx context.Context) ([]Channel, error) { return channels, nil },
	}
	groupRepo := &stubGroupRepoForAvailable{activeGroups: activeGroups}
	return NewChannelService(repo, groupRepo, nil, pricing)
}

// catalogChannel 构造一个带定价的渠道，便于在测试里声明「平台 + 模型 + 定价」。
func catalogChannel(id int64, name string, groupIDs []int64, platform, model string, pricing *ChannelModelPricing) Channel {
	p := *pricing
	p.Platform = platform
	p.Models = []string{model}
	return Channel{
		ID:           id,
		Name:         name,
		Status:       StatusActive,
		GroupIDs:     groupIDs,
		ModelPricing: []ChannelModelPricing{p},
	}
}

func TestModelCatalog_StandardPricePremultipliesRechargeMultiplier(t *testing.T) {
	channels := []Channel{
		catalogChannel(1, "chA", []int64{10}, "anthropic", "claude-opus-4-5",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5), OutputPrice: fp(2e-5)}),
	}
	groups := []Group{
		{ID: 10, Name: "public", Platform: "anthropic", RateMultiplier: 1.5, IsExclusive: false, Status: StatusActive},
	}
	chSvc := newCatalogChannelService(channels, groups, nil)
	// rechargeMult 来自 paymentConfigService；nil 时回退 1.0。这里用 nil 验证默认。
	svc := NewModelCatalogService(chSvc, nil, nil, nil)

	cat, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	require.Len(t, cat.Models, 1)
	require.InDelta(t, 1.0, cat.RechargeMultiplier, 1e-12)

	m := cat.Models[0]
	require.Equal(t, "claude-opus-4-5", m.Name)
	require.Equal(t, "anthropic", m.Platform)
	// rechargeMult=1.0 → 标准价 == 基础价
	require.NotNil(t, m.StandardInputPrice)
	require.InDelta(t, 1e-5, *m.StandardInputPrice, 1e-12)
	require.NotNil(t, m.StandardOutputPrice)
	require.InDelta(t, 2e-5, *m.StandardOutputPrice, 1e-12)
	require.Equal(t, []int64{10}, m.GroupIDs)

	// 公开分组应出现在 Groups，倍率透传给前端用于算充值价
	require.Len(t, cat.Groups, 1)
	require.Equal(t, int64(10), cat.Groups[0].ID)
	require.InDelta(t, 1.5, cat.Groups[0].RateMultiplier, 1e-12)
}

func TestModelCatalog_ExcludesModelsOnlyOnExclusiveGroups(t *testing.T) {
	channels := []Channel{
		// 渠道只挂在专属分组上 → 它的模型不进广场（决策 #7）
		catalogChannel(1, "chExclusive", []int64{20}, "anthropic", "claude-secret",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
		// 渠道挂在公开分组上 → 可见
		catalogChannel(2, "chPublic", []int64{10}, "anthropic", "claude-public",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
	}
	groups := []Group{
		{ID: 10, Name: "public", Platform: "anthropic", RateMultiplier: 1, IsExclusive: false, Status: StatusActive},
		{ID: 20, Name: "exclusive", Platform: "anthropic", RateMultiplier: 1, IsExclusive: true, Status: StatusActive},
	}
	chSvc := newCatalogChannelService(channels, groups, nil)
	svc := NewModelCatalogService(chSvc, nil, nil, nil)

	cat, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	require.Len(t, cat.Models, 1)
	require.Equal(t, "claude-public", cat.Models[0].Name)
	// 只有公开分组进 Groups
	require.Len(t, cat.Groups, 1)
	require.Equal(t, int64(10), cat.Groups[0].ID)
}

func TestModelCatalog_ModelOnBothExclusiveAndPublicVisibleWithPublicGroupOnly(t *testing.T) {
	// 同一渠道同时挂公开+专属分组：模型可见，但只用公开分组算价（GroupIDs 只含公开分组）。
	channels := []Channel{
		catalogChannel(1, "chMixed", []int64{10, 20}, "anthropic", "claude-mixed",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
	}
	groups := []Group{
		{ID: 10, Name: "public", Platform: "anthropic", RateMultiplier: 1, IsExclusive: false, Status: StatusActive},
		{ID: 20, Name: "exclusive", Platform: "anthropic", RateMultiplier: 1, IsExclusive: true, Status: StatusActive},
	}
	chSvc := newCatalogChannelService(channels, groups, nil)
	svc := NewModelCatalogService(chSvc, nil, nil, nil)

	cat, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	require.Len(t, cat.Models, 1)
	require.Equal(t, []int64{10}, cat.Models[0].GroupIDs)
}

func TestModelCatalog_MergesSameModelAcrossChannels(t *testing.T) {
	// 两个渠道在不同公开分组提供同一平台同名模型 → 聚合为一条，GroupIDs 取并集。
	channels := []Channel{
		catalogChannel(1, "chA", []int64{10}, "anthropic", "claude-shared",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
		catalogChannel(2, "chB", []int64{11}, "anthropic", "claude-shared",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
	}
	groups := []Group{
		{ID: 10, Name: "p1", Platform: "anthropic", RateMultiplier: 1, Status: StatusActive},
		{ID: 11, Name: "p2", Platform: "anthropic", RateMultiplier: 2, Status: StatusActive},
	}
	chSvc := newCatalogChannelService(channels, groups, nil)
	svc := NewModelCatalogService(chSvc, nil, nil, nil)

	cat, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	require.Len(t, cat.Models, 1)
	require.Equal(t, []int64{10, 11}, cat.Models[0].GroupIDs)
	require.Len(t, cat.Groups, 2)
}

func TestModelCatalog_SkipsInactiveChannels(t *testing.T) {
	ch := catalogChannel(1, "chDown", []int64{10}, "anthropic", "claude-down",
		&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)})
	ch.Status = "inactive"
	channels := []Channel{ch}
	groups := []Group{{ID: 10, Name: "public", Platform: "anthropic", Status: StatusActive}}
	chSvc := newCatalogChannelService(channels, groups, nil)
	svc := NewModelCatalogService(chSvc, nil, nil, nil)

	cat, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	require.Empty(t, cat.Models)
}

func TestModelCatalog_PricingMetadataFromLiteLLM(t *testing.T) {
	channels := []Channel{
		catalogChannel(1, "chA", []int64{10}, "anthropic", "claude-meta",
			&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
	}
	groups := []Group{{ID: 10, Name: "public", Platform: "anthropic", Status: StatusActive}}
	pricing := &PricingService{
		pricingData: map[string]*LiteLLMModelPricing{
			"claude-meta": {
				MaxInputTokens:          200000,
				MaxOutputTokens:         8192,
				SupportsFunctionCalling: true,
				SupportsVision:          true,
				SupportsPromptCaching:   true,
			},
		},
	}
	chSvc := newCatalogChannelService(channels, groups, pricing)
	svc := NewModelCatalogService(chSvc, pricing, nil, nil)

	cat, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	require.Len(t, cat.Models, 1)
	m := cat.Models[0]
	require.Equal(t, 200000, m.ContextLength)
	require.Equal(t, 8192, m.MaxOutputTokens)
	require.Contains(t, m.Capabilities, "function_calling")
	require.Contains(t, m.Capabilities, "vision")
	require.Contains(t, m.Capabilities, "prompt_caching")
	require.Contains(t, m.InputModalities, "text")
	require.Contains(t, m.InputModalities, "image")
}

func TestModelCatalog_CachesWithinTTL(t *testing.T) {
	var listAllCalls int
	repo := &mockChannelRepository{
		listAllFn: func(ctx context.Context) ([]Channel, error) {
			listAllCalls++
			return []Channel{
				catalogChannel(1, "chA", []int64{10}, "anthropic", "claude-cache",
					&ChannelModelPricing{BillingMode: BillingModeToken, InputPrice: fp(1e-5)}),
			}, nil
		},
	}
	groupRepo := &stubGroupRepoForAvailable{
		activeGroups: []Group{{ID: 10, Name: "public", Platform: "anthropic", Status: StatusActive}},
	}
	chSvc := NewChannelService(repo, groupRepo, nil, nil)
	svc := NewModelCatalogService(chSvc, nil, nil, nil)

	_, err := svc.GetCatalog(context.Background())
	require.NoError(t, err)
	_, err = svc.GetCatalog(context.Background())
	require.NoError(t, err)

	// 第二次调用应命中缓存，不再触达 channelRepo.ListAll
	require.Equal(t, 1, listAllCalls)
}

func TestModelCatalog_DeriveModalitiesImageOutput(t *testing.T) {
	lp := &LiteLLMModelPricing{Mode: "image_generation"}
	in, out := deriveModelModalities(lp)
	require.Equal(t, []string{"text"}, in)
	require.Contains(t, out, "image")
}
