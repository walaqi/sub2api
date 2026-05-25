package keybind

import (
	"context"
	"log"
	"os"

	"github.com/Wei-Shaw/sub2api/ent"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// PoolUserEmailEnv overrides the hard-coded default at runtime, in case
// the operator wants to point at a different placeholder account without
// rebuilding the binary.
const PoolUserEmailEnv = "BIND_KEY_POOL_USER_EMAIL"

// DefaultPoolUserEmail is the fallback email used when the env var is not
// set. Edit this constant to point at the placeholder/admin account that
// owns all claimable keys in your deployment. Keeping it here (rather than
// in config.yaml) avoids touching the shared Config struct so upstream
// merges stay clean.
const DefaultPoolUserEmail = "keypool@atai8.cc"

// RegisterRoutes wires the bind-key endpoints into the supplied router group.
// This is the only entry point used by the host application; everything else
// is internal to the keybind package.
//
// If the pool user cannot be resolved (e.g. the email is not in the users
// table), routes are still registered but every request returns 503
// ErrPoolUserNotConfigured. This keeps the failure mode isolated.
func RegisterRoutes(
	v1 *gin.RouterGroup,
	client *ent.Client,
	redisClient *redis.Client,
	jwtAuth servermiddleware.JWTAuthMiddleware,
) {
	if client == nil || redisClient == nil {
		log.Printf("[keybind] disabled: missing ent client or redis client")
		return
	}

	poolEmail := os.Getenv(PoolUserEmailEnv)
	if poolEmail == "" {
		poolEmail = DefaultPoolUserEmail
	}
	svc := NewService(context.Background(), client, redisClient, poolEmail)
	if !svc.Enabled() {
		log.Printf("[keybind] feature is disabled (pool user %q not found; create the user or override via %s)", poolEmail, PoolUserEmailEnv)
	} else {
		log.Printf("[keybind] feature enabled (pool user %q resolved)", poolEmail)
	}

	h := NewHandler(svc)
	g := v1.Group("/bind-key")
	g.POST("/reserve", h.Reserve)                         // public
	g.POST("/commit", gin.HandlerFunc(jwtAuth), h.Commit) // requires JWT
}
