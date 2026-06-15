package middleware

import (
	"crypto/subtle"
	"strings"

	"github.com/gin-gonic/gin"
)

// InternalSecretMiddleware 是 /internal/* 内部端点的 service-to-service 鉴权中间件类型。
type InternalSecretMiddleware gin.HandlerFunc

// internalSecretHeader 是携带共享密钥的请求头名称。
const internalSecretHeader = "X-Internal-Secret"

// NewInternalSecretMiddleware 创建内部密钥认证中间件。
//
// 用于 /internal/cred 等 service-to-service 端点：调用方（image-studio 后端）
// 必须在 X-Internal-Secret 头携带与配置一致的共享密钥。校验用常量时间比较，
// 避免计时侧信道。密钥来源是配置（image_studio.internal_secret），见
// docs/comments-from-mother.md §C.2。
//
// 安全前提：该端点绝不能经公网反代暴露（nginx 不为 /internal/ 配 location 或显式
// deny），仅在容器内网/localhost 可达，见 §C.2 部署提醒。
func NewInternalSecretMiddleware(secret string) InternalSecretMiddleware {
	trimmedSecret := strings.TrimSpace(secret)
	return InternalSecretMiddleware(func(c *gin.Context) {
		// 未配置密钥时一律拒绝（避免空密钥导致端点裸奔）。
		if trimmedSecret == "" {
			AbortWithError(c, 401, "INVALID_INTERNAL_SECRET", "Invalid internal secret")
			return
		}
		provided := c.GetHeader(internalSecretHeader)
		if provided == "" || subtle.ConstantTimeCompare([]byte(provided), []byte(trimmedSecret)) != 1 {
			AbortWithError(c, 401, "INVALID_INTERNAL_SECRET", "Invalid internal secret")
			return
		}
		c.Next()
	})
}
