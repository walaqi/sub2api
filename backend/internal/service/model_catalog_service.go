package service

import (
	"context"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sync/singleflight"
)

// modelCatalogCacheTTL 模型广场聚合结果的进程内缓存有效期。
// 第一版用 1 分钟 time-based TTL，不做 invalidate hook（见模型广场决策 #10）。
const modelCatalogCacheTTL = time.Minute

// CatalogGroup 是模型广场中可选的公开分组概要。
//
// 仅暴露非专属（公开）分组：模型广场面向未登录访客，专属分组的倍率不应外泄。
// 前端用 RateMultiplier 计算充值价（recharge = standard × RateMultiplier）。
type CatalogGroup struct {
	ID             int64   `json:"id"`
	Name           string  `json:"name"`
	Platform       string  `json:"platform"`
	RateMultiplier float64 `json:"rate_multiplier"`
}

// CatalogModel 是模型广场中的一个模型条目（按 platform + 模型名聚合）。
//
// 标准价 = 基础价 × 余额充值倍率（recharge_mult），已在后端预乘好，按 token 计。
// 充值价由前端根据所选分组计算：recharge = standard × group.rate_multiplier。
// 价格字段为 nil 表示该项未配置（前端展示为 "-"）。
type CatalogModel struct {
	Name             string   `json:"name"`
	Platform         string   `json:"platform"`
	ContextLength    int      `json:"context_length"`
	MaxOutputTokens  int      `json:"max_output_tokens"`
	Capabilities     []string `json:"capabilities"`
	InputModalities  []string `json:"input_modalities"`
	OutputModalities []string `json:"output_modalities"`
	BillingMode      string   `json:"billing_mode"`

	StandardInputPrice       *float64 `json:"standard_input_price"`
	StandardOutputPrice      *float64 `json:"standard_output_price"`
	StandardCacheReadPrice   *float64 `json:"standard_cache_read_price"`
	StandardCacheWritePrice  *float64 `json:"standard_cache_write_price"`
	StandardPerRequestPrice  *float64 `json:"standard_per_request_price"`
	StandardImageOutputPrice *float64 `json:"standard_image_output_price"`

	// GroupIDs 是提供该模型的公开分组 ID（platform 与本模型一致）。
	GroupIDs []int64 `json:"group_ids"`
}

// ModelCatalog 是模型广场的聚合结果。
type ModelCatalog struct {
	Models             []CatalogModel `json:"models"`
	Groups             []CatalogGroup `json:"groups"`
	RechargeMultiplier float64        `json:"recharge_multiplier"`
	// DefaultGroupID 是「系统设置 → 用户默认值 → 默认订阅列表」第一个落在公开分组里的项；
	// 没有命中时为 0，前端回退到 Groups 的第一项。
	DefaultGroupID int64 `json:"default_group_id"`
}

// ModelCatalogService 聚合「模型广场」展示数据：复用 ChannelService.ListAvailable
// 的渠道 × 分组 × 支持模型聚合，叠加 PricingService 的模型元数据，并按公开分组过滤可见性。
type ModelCatalogService struct {
	channelService       *ChannelService
	pricingService       *PricingService
	paymentConfigService *PaymentConfigService
	settingService       *SettingService

	cache   atomic.Value // *modelCatalogCache
	cacheSF singleflight.Group
}

type modelCatalogCache struct {
	catalog  *ModelCatalog
	loadedAt time.Time
}

// NewModelCatalogService 创建模型广场聚合服务。
// pricingService 可为 nil（元数据缺省为空）；paymentConfigService 可为 nil（充值倍率回退默认 1.0）；
// settingService 可为 nil（默认分组回退 0）。
func NewModelCatalogService(
	channelService *ChannelService,
	pricingService *PricingService,
	paymentConfigService *PaymentConfigService,
	settingService *SettingService,
) *ModelCatalogService {
	return &ModelCatalogService{
		channelService:       channelService,
		pricingService:       pricingService,
		paymentConfigService: paymentConfigService,
		settingService:       settingService,
	}
}

// GetCatalog 返回模型广场聚合结果，带 1 分钟进程内缓存 + singleflight 防击穿。
//
// 返回的 *ModelCatalog 为共享缓存对象，调用方只读、不得修改。
func (s *ModelCatalogService) GetCatalog(ctx context.Context) (*ModelCatalog, error) {
	if cached, ok := s.cache.Load().(*modelCatalogCache); ok && cached != nil {
		if time.Since(cached.loadedAt) < modelCatalogCacheTTL {
			return cached.catalog, nil
		}
	}

	v, err, _ := s.cacheSF.Do("catalog", func() (any, error) {
		// double-check：等待 singleflight 期间可能已有别的 goroutine 刷新过缓存
		if cached, ok := s.cache.Load().(*modelCatalogCache); ok && cached != nil {
			if time.Since(cached.loadedAt) < modelCatalogCacheTTL {
				return cached.catalog, nil
			}
		}
		catalog, err := s.buildCatalog(ctx)
		if err != nil {
			return nil, err
		}
		s.cache.Store(&modelCatalogCache{catalog: catalog, loadedAt: time.Now()})
		return catalog, nil
	})
	if err != nil {
		return nil, err
	}
	catalog, _ := v.(*ModelCatalog)
	return catalog, nil
}

// buildCatalog 执行实际聚合（无缓存）。
func (s *ModelCatalogService) buildCatalog(ctx context.Context) (*ModelCatalog, error) {
	channels, err := s.channelService.ListAvailable(ctx)
	if err != nil {
		return nil, err
	}

	rechargeMult := defaultBalanceRechargeMultiplier
	if s.paymentConfigService != nil {
		if cfg, cfgErr := s.paymentConfigService.GetPaymentConfig(ctx); cfgErr == nil && cfg != nil {
			rechargeMult = normalizeBalanceRechargeMultiplier(cfg.BalanceRechargeMultiplier)
		}
	}

	type modelAgg struct {
		model    *CatalogModel
		groupIDs map[int64]struct{}
	}
	models := make(map[string]*modelAgg)
	publicGroups := make(map[int64]CatalogGroup)

	for ci := range channels {
		ch := &channels[ci]
		if ch.Status != StatusActive {
			continue
		}

		// 该渠道的公开分组按 platform 索引（专属分组不进广场，见决策 #7）
		publicByPlatform := make(map[string][]int64)
		for _, g := range ch.Groups {
			if g.IsExclusive {
				continue
			}
			publicByPlatform[g.Platform] = append(publicByPlatform[g.Platform], g.ID)
			publicGroups[g.ID] = CatalogGroup{
				ID:             g.ID,
				Name:           g.Name,
				Platform:       g.Platform,
				RateMultiplier: g.RateMultiplier,
			}
		}
		if len(publicByPlatform) == 0 {
			continue
		}

		for smi := range ch.SupportedModels {
			sm := ch.SupportedModels[smi]
			groupIDs, ok := publicByPlatform[sm.Platform]
			if !ok {
				continue // 该模型平台没有公开分组 → 不可见
			}
			key := sm.Platform + "\x00" + strings.ToLower(sm.Name)
			agg, exists := models[key]
			if !exists {
				cm := s.buildCatalogModel(sm, rechargeMult)
				agg = &modelAgg{model: &cm, groupIDs: make(map[int64]struct{})}
				models[key] = agg
			}
			for _, gid := range groupIDs {
				agg.groupIDs[gid] = struct{}{}
			}
		}
	}

	out := &ModelCatalog{
		RechargeMultiplier: rechargeMult,
		Models:             make([]CatalogModel, 0, len(models)),
		Groups:             make([]CatalogGroup, 0, len(publicGroups)),
	}
	for _, agg := range models {
		ids := make([]int64, 0, len(agg.groupIDs))
		for id := range agg.groupIDs {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		agg.model.GroupIDs = ids
		out.Models = append(out.Models, *agg.model)
	}
	sort.SliceStable(out.Models, func(i, j int) bool {
		if out.Models[i].Platform != out.Models[j].Platform {
			return out.Models[i].Platform < out.Models[j].Platform
		}
		return strings.ToLower(out.Models[i].Name) < strings.ToLower(out.Models[j].Name)
	})

	for _, g := range publicGroups {
		out.Groups = append(out.Groups, g)
	}
	sort.SliceStable(out.Groups, func(i, j int) bool {
		if out.Groups[i].Platform != out.Groups[j].Platform {
			return out.Groups[i].Platform < out.Groups[j].Platform
		}
		return out.Groups[i].Name < out.Groups[j].Name
	})

	out.DefaultGroupID = s.resolveDefaultGroupID(ctx, publicGroups)
	return out, nil
}

// buildCatalogModel 从单条 SupportedModel 构造广场模型条目：价格预乘充值倍率，
// 元数据从全局 LiteLLM 数据补充。
func (s *ModelCatalogService) buildCatalogModel(sm SupportedModel, rechargeMult float64) CatalogModel {
	cm := CatalogModel{
		Name:     sm.Name,
		Platform: sm.Platform,
	}
	if sm.Pricing != nil {
		cm.BillingMode = string(sm.Pricing.BillingMode)
		cm.StandardInputPrice = scaleStandardPrice(sm.Pricing.InputPrice, rechargeMult)
		cm.StandardOutputPrice = scaleStandardPrice(sm.Pricing.OutputPrice, rechargeMult)
		cm.StandardCacheReadPrice = scaleStandardPrice(sm.Pricing.CacheReadPrice, rechargeMult)
		cm.StandardCacheWritePrice = scaleStandardPrice(sm.Pricing.CacheWritePrice, rechargeMult)
		cm.StandardPerRequestPrice = scaleStandardPrice(sm.Pricing.PerRequestPrice, rechargeMult)
		cm.StandardImageOutputPrice = scaleStandardPrice(sm.Pricing.ImageOutputPrice, rechargeMult)
	}
	if cm.BillingMode == "" {
		cm.BillingMode = string(BillingModeToken)
	}

	if s.pricingService != nil {
		if lp := s.pricingService.GetModelPricing(sm.Name); lp != nil {
			cm.ContextLength = lp.MaxInputTokens
			cm.MaxOutputTokens = lp.MaxOutputTokens
			cm.Capabilities = deriveModelCapabilities(lp)
			cm.InputModalities, cm.OutputModalities = deriveModelModalities(lp)
		}
	}
	return cm
}

// resolveDefaultGroupID 返回管理员在「系统设置 → 模型广场」配置的默认分组。
// 该分组必须仍是公开分组才生效；未配置（0）或已失效/转专属时返回 0，
// 由前端回退到第一个公开分组。不再依赖默认订阅列表。
func (s *ModelCatalogService) resolveDefaultGroupID(ctx context.Context, publicGroups map[int64]CatalogGroup) int64 {
	if s.settingService == nil {
		return 0
	}
	configured := s.settingService.GetModelsPlazaRuntime(ctx).DefaultGroupID
	if configured <= 0 {
		return 0
	}
	if _, ok := publicGroups[configured]; ok {
		return configured
	}
	return 0
}

// scaleStandardPrice 把基础价乘以充值倍率得到标准价；入参为 nil 时返回 nil。
func scaleStandardPrice(base *float64, mult float64) *float64 {
	if base == nil {
		return nil
	}
	v := *base * mult
	return &v
}

// deriveModelCapabilities 从 LiteLLM 的 supports_* 字段映射到展示用 capability 列表。
func deriveModelCapabilities(lp *LiteLLMModelPricing) []string {
	if lp == nil {
		return nil
	}
	caps := make([]string, 0, 12)
	add := func(cond bool, name string) {
		if cond {
			caps = append(caps, name)
		}
	}
	add(lp.SupportsFunctionCalling, "function_calling")
	add(lp.SupportsVision, "vision")
	add(lp.SupportsPromptCaching, "prompt_caching")
	add(lp.SupportsReasoning, "reasoning")
	add(lp.SupportsResponseSchema, "response_schema")
	add(lp.SupportsToolChoice, "tool_choice")
	add(lp.SupportsWebSearch, "web_search")
	add(lp.SupportsPDFInput, "pdf_input")
	add(lp.SupportsComputerUse, "computer_use")
	add(lp.SupportsAssistantPrefill, "assistant_prefill")
	add(lp.SupportsAudioInput, "audio_input")
	add(lp.SupportsAudioOutput, "audio_output")
	if len(caps) == 0 {
		return nil
	}
	return caps
}

// deriveModelModalities 从 mode + supports_* 推断输入/输出模态。
// 文本恒为基础模态；图像/文件/音频按对应 supports_* 字段叠加。
func deriveModelModalities(lp *LiteLLMModelPricing) (input []string, output []string) {
	if lp == nil {
		return nil, nil
	}
	input = []string{"text"}
	if lp.SupportsVision {
		input = append(input, "image")
	}
	if lp.SupportsPDFInput {
		input = append(input, "file")
	}
	if lp.SupportsAudioInput {
		input = append(input, "audio")
	}

	output = []string{"text"}
	if lp.Mode == "image_generation" || lp.OutputCostPerImage > 0 || lp.OutputCostPerImageToken > 0 {
		output = append(output, "image")
	}
	if lp.SupportsAudioOutput {
		output = append(output, "audio")
	}
	return input, output
}
