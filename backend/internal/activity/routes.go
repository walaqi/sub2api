package activity

import (
	"log"

	"github.com/Wei-Shaw/sub2api/ent"
	servermiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"

	"github.com/gin-gonic/gin"
)

func RegisterRoutes(
	v1 *gin.RouterGroup,
	client *ent.Client,
	jwtAuth servermiddleware.JWTAuthMiddleware,
	adminAuth servermiddleware.AdminAuthMiddleware,
) {
	if client == nil {
		log.Printf("[activity] disabled: missing ent client")
		return
	}

	repo := NewRepository(client)
	svc := NewService(repo)
	h := NewHandler(svc)

	g := v1.Group("/activity")
	{
		user := g.Group("")
		user.Use(gin.HandlerFunc(jwtAuth))
		user.GET("/events/active", h.ListActiveEvents)
		user.POST("/events/:id/signups", h.Signup)

		// Backward-compatible ops path. It uses the existing admin JWT auth;
		// no separate activity secret is required.
		legacyOps := g.Group("/ops")
		legacyOps.Use(gin.HandlerFunc(adminAuth))
		legacyOps.POST("/events", h.CreateEvent)
		legacyOps.PUT("/events/:id", h.UpdateEvent)
		legacyOps.GET("/events/:id/signups", h.ListSignups)
	}

	adminOps := v1.Group("/admin/ops/activity")
	adminOps.Use(gin.HandlerFunc(adminAuth))
	adminOps.POST("/events", h.CreateEvent)
	adminOps.PUT("/events/:id", h.UpdateEvent)
	adminOps.GET("/events/:id/signups", h.ListSignups)
}
