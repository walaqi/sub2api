//go:build unit

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func runBypassGuard(t *testing.T, secret, headerVal string) bool {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	var bypassed bool
	router.POST("/test", TurnstileBypassGuard(secret), func(c *gin.Context) {
		bypassed = service.IsTurnstileBypassRequested(c.Request.Context())
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	if headerVal != "" {
		req.Header.Set(AppBypassHeader, headerVal)
	}
	router.ServeHTTP(httptest.NewRecorder(), req)
	return bypassed
}

func TestTurnstileBypassGuard_MatchingSecret(t *testing.T) {
	require.True(t, runBypassGuard(t, "super-secret", "super-secret"))
}

func TestTurnstileBypassGuard_WrongSecret(t *testing.T) {
	require.False(t, runBypassGuard(t, "super-secret", "nope"))
}

func TestTurnstileBypassGuard_EmptySecretNeverBypasses(t *testing.T) {
	// 即使客户端发了头，未配置密钥时也绝不绕过。
	require.False(t, runBypassGuard(t, "", "anything"))
}

func TestTurnstileBypassGuard_NoHeader(t *testing.T) {
	require.False(t, runBypassGuard(t, "super-secret", ""))
}

func TestTurnstileBypassGuard_SecretWithSurroundingWhitespace(t *testing.T) {
	// 配置侧密钥含空白时会被裁剪；客户端需发送裁剪后的值。
	require.True(t, runBypassGuard(t, "  super-secret  ", "super-secret"))
}
