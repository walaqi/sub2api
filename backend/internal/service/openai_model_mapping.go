package service

import "strings"

// resolveOpenAIForwardModel 解析 OpenAI 兼容转发使用的模型。
// defaultMappedModel 只服务于 /v1/messages 的 Claude 系列显式调度映射，
// 不作为普通 OpenAI 请求的未知模型兜底。
func resolveOpenAIForwardModel(account *Account, requestedModel, defaultMappedModel string) string {
	billingModel, _ := resolveOpenAIForwardModelDetailed(account, requestedModel, defaultMappedModel)
	return billingModel
}

// resolveOpenAIForwardModelDetailed 与 resolveOpenAIForwardModel 相同，额外返回
// explicitlyMapped：账号级 model_mapping 是否命中（精确或通配符）。命中时表示
// 转发模型来自管理员显式配置，上游模型归一化据此尊重配置，不将未知 gpt-5* 目标
// 兜底改写为 gpt-5.4。Claude 系列调度默认映射（defaultMappedModel）不视为显式映射。
func resolveOpenAIForwardModelDetailed(account *Account, requestedModel, defaultMappedModel string) (billingModel string, explicitlyMapped bool) {
	if account == nil {
		if defaultMappedModel != "" && claudeMessagesDispatchFamily(requestedModel) != "" {
			return defaultMappedModel, false
		}
		return requestedModel, false
	}

	mappedModel, matched := account.ResolveMappedModel(requestedModel)
	if !matched && defaultMappedModel != "" && claudeMessagesDispatchFamily(requestedModel) != "" {
		return defaultMappedModel, false
	}
	return mappedModel, matched
}

// resolveOpenAICompactForwardModel determines the compact-only upstream model
// for /responses/compact requests. It never affects normal /responses traffic.
// When no compact-specific mapping matches, the input model is returned as-is.
func resolveOpenAICompactForwardModel(account *Account, model string) string {
	trimmedModel := strings.TrimSpace(model)
	if trimmedModel == "" || account == nil {
		return trimmedModel
	}

	mappedModel, matched := account.ResolveCompactMappedModel(trimmedModel)
	if !matched {
		return trimmedModel
	}
	if trimmedMapped := strings.TrimSpace(mappedModel); trimmedMapped != "" {
		return trimmedMapped
	}
	return trimmedModel
}
