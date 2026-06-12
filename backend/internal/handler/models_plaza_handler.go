package handler

import (
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// ModelsPlazaHandler 处理「模型广场」的公开查询。
//
// 模型广场不需要登录（见模型广场决策 #2），endpoint 直接挂在公开 /settings 同级。
// 行为按 SettingKeyModelsPlazaEnabled 开关 gate：未启用时返回空目录，
// 不暴露任何模型/分组信息。
type ModelsPlazaHandler struct {
	catalogService *service.ModelCatalogService
	settingService *service.SettingService
}

// NewModelsPlazaHandler 创建模型广场 handler。
func NewModelsPlazaHandler(
	catalogService *service.ModelCatalogService,
	settingService *service.SettingService,
) *ModelsPlazaHandler {
	return &ModelsPlazaHandler{
		catalogService: catalogService,
		settingService: settingService,
	}
}

// featureEnabled 返回 models-plaza 开关是否启用。默认关闭（opt-in）。
func (h *ModelsPlazaHandler) featureEnabled(c *gin.Context) bool {
	if h.settingService == nil {
		return false
	}
	return h.settingService.GetModelsPlazaRuntime(c.Request.Context()).Enabled
}

// emptyCatalog 是 feature 未启用时返回的空目录（避免前端拿到 null）。
func emptyCatalog() *service.ModelCatalog {
	return &service.ModelCatalog{
		Models:             []service.CatalogModel{},
		Groups:             []service.CatalogGroup{},
		RechargeMultiplier: 1.0,
	}
}

// Catalog 返回模型广场聚合目录。
// GET /api/v1/models-plaza/catalog
//
// 公开 endpoint，无需认证。feature 未启用时返回空目录。
func (h *ModelsPlazaHandler) Catalog(c *gin.Context) {
	if !h.featureEnabled(c) {
		response.Success(c, emptyCatalog())
		return
	}

	catalog, err := h.catalogService.GetCatalog(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, catalog)
}
