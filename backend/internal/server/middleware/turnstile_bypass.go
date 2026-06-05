package middleware

import (
	"crypto/subtle"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
)

// AppBypassHeader 受信任的服务端客户端用于携带 Turnstile 绕过共享密钥的请求头名称。
const AppBypassHeader = "X-App-Bypass-Token"

// TurnstileBypassGuard 返回一个中间件：当请求携带的 X-App-Bypass-Token 与配置的共享密钥
// （turnstile.app_bypass_secret）精确匹配时，在请求上下文中打上"跳过 Turnstile 校验"标记。
// 下游所有汇聚到 AuthService.VerifyTurnstile 的入口都会因此自动跳过人机验证。
//
// 当 secret 为空时（默认），该中间件不做任何事——无论请求带不带头都不会绕过。
// 使用常量时间比较以避免时序侧信道。该密钥仅用于受信任的服务端到服务端调用，
// 不应分发到可被逆向的客户端。
func TurnstileBypassGuard(secret string) gin.HandlerFunc {
	secret = strings.TrimSpace(secret)
	return func(c *gin.Context) {
		if secret == "" {
			c.Next()
			return
		}
		provided := strings.TrimSpace(c.GetHeader(AppBypassHeader))
		if provided != "" && subtle.ConstantTimeCompare([]byte(provided), []byte(secret)) == 1 {
			c.Request = c.Request.WithContext(service.ContextWithTurnstileBypass(c.Request.Context()))
		}
		c.Next()
	}
}
