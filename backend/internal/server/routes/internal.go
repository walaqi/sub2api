package routes

import (
	"github.com/Wei-Shaw/sub2api/internal/handler"
	"github.com/Wei-Shaw/sub2api/internal/server/middleware"

	"github.com/gin-gonic/gin"
)

// RegisterInternalRoutes 注册 service-to-service 内部端点（/internal/*）。
//
// 这些端点供 image-studio 后端按 userID 解析可出图的渠道凭证，由
// InternalSecretMiddleware（X-Internal-Secret 共享密钥）保护。
//
// ⚠️ 安全前提：/internal/* 绝不能经公网反代暴露。nginx 不应为 /internal/ 配
// location（或显式 deny），仅容器内网/localhost 可达。详见
// docs/comments-from-mother.md §C.2 部署提醒。/internal/ 已加入
// shouldBypassEmbeddedFrontend，避免被内嵌 SPA 兜底吞掉。
func RegisterInternalRoutes(
	r *gin.Engine,
	h *handler.Handlers,
	internalSecret middleware.InternalSecretMiddleware,
) {
	internal := r.Group("/internal")
	internal.Use(gin.HandlerFunc(internalSecret))
	{
		// 凭证解析（两段式，见 §C.1）
		cred := internal.Group("/cred")
		{
			// 取明文：GET /internal/cred?uid=<userID>&key_id=<id>
			cred.GET("", h.ImageStudio.ResolveImageCred)
			// 列候选：GET /internal/cred/keys?uid=<userID>
			cred.GET("/keys", h.ImageStudio.ListImageKeys)
		}
	}
}
