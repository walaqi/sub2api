package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupThrottleTest(t *testing.T) (*gin.Engine, *miniredis.Miniredis, *redis.Client) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	mr, err := miniredis.Run()
	require.NoError(t, err)
	t.Cleanup(mr.Close)

	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	r := gin.New()
	return r, mr, rc
}

// simulateAuthSubject injects a fake AuthSubject into gin context.
func simulateAuthSubject(userID int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(string(ContextKeyUser), AuthSubject{UserID: userID, Concurrency: 1})
		c.Next()
	}
}

// simulateUpstreamError sets upstream error context keys (mimics gateway behavior after c.Next).
func simulateUpstreamError(statusCode int, message string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(service.OpsUpstreamStatusCodeKey, statusCode)
		c.Set(service.OpsUpstreamErrorMessageKey, message)
		c.Status(http.StatusBadGateway)
	}
}

func TestClientErrorThrottle_NoBlockBelowThreshold(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(100))
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1/responses", simulateUpstreamError(400, "Invalid call_id: empty string"))

	// Send 19 requests (below threshold of 20) — all should pass
	for i := 0; i < 19; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadGateway, w.Code, "request %d should not be throttled", i+1)
	}
}

func TestClientErrorThrottle_BlocksAtThreshold(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(200))
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1/responses", simulateUpstreamError(400, "Invalid call_id: empty string"))

	// Send 20 requests to hit the threshold
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadGateway, w.Code, "request %d should pass through", i+1)
	}

	// 21st request should be throttled (OpenAI format for /v1/responses)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/responses", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Contains(t, w.Body.String(), "rate_limit_error")
	assert.NotContains(t, w.Body.String(), `"type":"error"`) // OpenAI format has no top-level "type"
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestClientErrorThrottle_CooldownExpires(t *testing.T) {
	r, mr, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(300))
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1/responses", simulateUpstreamError(400, "Invalid call_id: empty string"))

	// Trigger cooldown
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
	}

	// Confirm blocked
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/responses", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Fast-forward past cooldown
	mr.FastForward(clientErrorThrottleCooldown + time.Second)

	// Should pass again
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/v1/responses", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestClientErrorThrottle_DifferentErrorsDontCombine(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(400))
	r.Use(ClientErrorThrottle(rc))
	// Handler alternates between two different error messages
	callCount := 0
	r.POST("/v1/responses", func(c *gin.Context) {
		callCount++
		if callCount%2 == 0 {
			c.Set(service.OpsUpstreamStatusCodeKey, 400)
			c.Set(service.OpsUpstreamErrorMessageKey, "Error type A: something wrong")
		} else {
			c.Set(service.OpsUpstreamStatusCodeKey, 400)
			c.Set(service.OpsUpstreamErrorMessageKey, "Error type B: something else wrong")
		}
		c.Status(http.StatusBadGateway)
	})

	// 38 requests (19 of each type) — neither reaches 20
	for i := 0; i < 38; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadGateway, w.Code, "request %d should not be throttled", i+1)
	}
}

func TestClientErrorThrottle_DifferentUsersDontCombine(t *testing.T) {
	_, _, rc := setupThrottleTest(t)

	// Two separate routers for two different users
	for _, userID := range []int64{500, 501} {
		r := gin.New()
		r.Use(simulateAuthSubject(userID))
		r.Use(ClientErrorThrottle(rc))
		r.POST("/v1/responses", simulateUpstreamError(400, "same error message"))

		for i := 0; i < 15; i++ {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/v1/responses", nil)
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadGateway, w.Code)
		}
	}

	// Neither user should be blocked (15 < 20)
	for _, userID := range []int64{500, 501} {
		r := gin.New()
		r.Use(simulateAuthSubject(userID))
		r.Use(ClientErrorThrottle(rc))
		r.POST("/v1/responses", simulateUpstreamError(400, "same error message"))

		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadGateway, w.Code, "user %d should not be throttled", userID)
	}
}

func TestClientErrorThrottle_IgnoresNon400(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(600))
	r.Use(ClientErrorThrottle(rc))
	// Upstream returns 429, not 400
	r.POST("/v1/responses", simulateUpstreamError(429, "rate limited"))

	// Even 50 requests should not trigger the throttle
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadGateway, w.Code)
	}
}

func TestClientErrorThrottle_NilRedis_PassesThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(simulateAuthSubject(700))
	r.Use(ClientErrorThrottle(nil))
	r.POST("/v1/responses", simulateUpstreamError(400, "error"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/responses", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestClientErrorThrottle_NoAuthSubject_PassesThrough(t *testing.T) {
	_, _, rc := setupThrottleTest(t)
	r := gin.New()
	// No auth subject middleware
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1/responses", simulateUpstreamError(400, "error"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/responses", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadGateway, w.Code)
}

func TestErrorFingerprint_TruncatesLongMessages(t *testing.T) {
	longMsg := ""
	for i := 0; i < 200; i++ {
		longMsg += "x"
	}
	fp1 := errorFingerprint(400, longMsg)
	fp2 := errorFingerprint(400, longMsg[:80])
	assert.Equal(t, fp1, fp2, "messages longer than 80 chars should produce the same fingerprint")
}

func TestErrorFingerprint_DifferentStatusCodes(t *testing.T) {
	fp1 := errorFingerprint(400, "same message")
	fp2 := errorFingerprint(500, "same message")
	assert.NotEqual(t, fp1, fp2)
}

func TestClientErrorThrottle_RetryAfterHeader(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(800))
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1/responses", simulateUpstreamError(400, "error msg"))

	// Trigger cooldown
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/responses", nil)
		r.ServeHTTP(w, req)
	}

	// Throttled request should have Retry-After
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/responses", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	retryAfter := w.Header().Get("Retry-After")
	assert.NotEmpty(t, retryAfter)
	seconds, err := strconv.Atoi(retryAfter)
	require.NoError(t, err)
	assert.True(t, seconds > 0 && seconds <= 60)
}

func TestClientErrorThrottle_AnthropicFormat(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(900))
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1/messages", simulateUpstreamError(400, "error msg"))

	// Trigger cooldown
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1/messages", nil)
		r.ServeHTTP(w, req)
	}

	// Throttled: should return Anthropic format with top-level "type":"error"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1/messages", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"type":"error"`)
	assert.Contains(t, body, `"rate_limit_error"`)
}

func TestClientErrorThrottle_GeminiFormat(t *testing.T) {
	r, _, rc := setupThrottleTest(t)

	r.Use(simulateAuthSubject(901))
	r.Use(ClientErrorThrottle(rc))
	r.POST("/v1beta/models/gemini:generateContent", simulateUpstreamError(400, "error msg"))

	// Trigger cooldown
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/v1beta/models/gemini:generateContent", nil)
		r.ServeHTTP(w, req)
	}

	// Throttled: should return Google format with "status":"RESOURCE_EXHAUSTED"
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/v1beta/models/gemini:generateContent", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	body := w.Body.String()
	assert.Contains(t, body, `"RESOURCE_EXHAUSTED"`)
	assert.Contains(t, body, `"code"`)
}
