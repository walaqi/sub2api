package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

const (
	// clientErrorThrottleWindow is the sliding window for counting repeated upstream errors.
	clientErrorThrottleWindow = 5 * time.Minute
	// clientErrorThrottleThreshold is the max upstream 400 errors (same fingerprint) before cooldown.
	clientErrorThrottleThreshold = 20
	// clientErrorThrottleCooldown is how long a user is blocked after exceeding the threshold.
	clientErrorThrottleCooldown = 60 * time.Second

	clientErrorThrottleCounterPrefix  = "client_err_throttle:"
	clientErrorThrottleCooldownPrefix = "client_err_cd:"
)

// ClientErrorThrottle returns a middleware that rate-limits users who repeatedly
// trigger the same upstream 400 error. This protects upstream accounts from being
// flooded by clients stuck in a broken retry loop.
//
// Mechanism:
//   - Pre-request: if a per-user cooldown key exists in Redis, reject with 429.
//   - Post-request: if the upstream returned 400, compute an error fingerprint
//     (status + first 80 chars of error message), increment a per-user+fingerprint
//     counter. If it exceeds the threshold, set a per-user cooldown key.
func ClientErrorThrottle(redisClient *redis.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		if redisClient == nil {
			c.Next()
			return
		}

		// Identify the user from auth context (set by apiKeyAuth middleware)
		subject, ok := GetAuthSubjectFromContext(c)
		if !ok {
			c.Next()
			return
		}
		userID := subject.UserID

		// Pre-check: is this user in cooldown?
		cooldownKey := clientErrorThrottleCooldownPrefix + strconv.FormatInt(userID, 10)
		ctx := c.Request.Context()
		if exists, err := redisClient.Exists(ctx, cooldownKey).Result(); err == nil && exists > 0 {
			ttl, _ := redisClient.TTL(ctx, cooldownKey).Result()
			retryAfter := int(ttl.Seconds())
			if retryAfter <= 0 {
				retryAfter = int(clientErrorThrottleCooldown.Seconds())
			}
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			writeThrottleError(c)
			return
		}

		// Process the request
		c.Next()

		// Post-check: did the upstream return 400?
		upstreamStatus := getUpstreamStatusCodeFromContext(c)
		if upstreamStatus != http.StatusBadRequest {
			return
		}

		// Compute error fingerprint from upstream error message
		upstreamMsg := getUpstreamErrorMessageFromContext(c)
		fp := errorFingerprint(upstreamStatus, upstreamMsg)

		// Increment counter
		counterKey := clientErrorThrottleCounterPrefix + strconv.FormatInt(userID, 10) + ":" + fp
		count, err := incrWithExpiry(ctx, redisClient, counterKey, clientErrorThrottleWindow)
		if err != nil {
			// Redis error: fail open, don't block users
			return
		}

		// Threshold exceeded: set cooldown
		if count >= clientErrorThrottleThreshold {
			_ = redisClient.Set(ctx, cooldownKey, "1", clientErrorThrottleCooldown).Err()
		}
	}
}

// errorFingerprint produces a short hash from upstream status code + error message prefix.
func errorFingerprint(statusCode int, message string) string {
	// Use first 80 chars of error message for grouping
	msg := message
	if len(msg) > 80 {
		msg = msg[:80]
	}
	raw := fmt.Sprintf("%d:%s", statusCode, msg)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:8]) // 16 hex chars
}

// incrWithExpiry atomically increments a key and sets expiry on first write.
func incrWithExpiry(ctx context.Context, client *redis.Client, key string, window time.Duration) (int64, error) {
	pipe := client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return incrCmd.Val(), nil
}

// getUpstreamStatusCodeFromContext reads the upstream status code set by gateway services.
func getUpstreamStatusCodeFromContext(c *gin.Context) int {
	v, ok := c.Get(service.OpsUpstreamStatusCodeKey)
	if !ok {
		return 0
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	}
	return 0
}

// getUpstreamErrorMessageFromContext reads the upstream error message set by gateway services.
func getUpstreamErrorMessageFromContext(c *gin.Context) string {
	v, ok := c.Get(service.OpsUpstreamErrorMessageKey)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

const clientErrorThrottleMessage = "Too many repeated invalid requests. Please fix the request and retry after cooldown."

// writeThrottleError writes a 429 error response in the format matching the
// inbound API protocol (Anthropic, OpenAI, or Google).
func writeThrottleError(c *gin.Context) {
	path := c.Request.URL.Path

	switch {
	case strings.Contains(path, "/v1beta/"):
		// Google/Gemini format
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error": gin.H{
				"code":    http.StatusTooManyRequests,
				"message": clientErrorThrottleMessage,
				"status":  "RESOURCE_EXHAUSTED",
			},
		})
	case strings.Contains(path, "/v1/messages"):
		// Anthropic format
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"type": "error",
			"error": gin.H{
				"type":    "rate_limit_error",
				"message": clientErrorThrottleMessage,
			},
		})
	default:
		// OpenAI format (responses, chat/completions, embeddings, images, etc.)
		c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
			"error": gin.H{
				"type":    "rate_limit_error",
				"message": clientErrorThrottleMessage,
			},
		})
	}
}
