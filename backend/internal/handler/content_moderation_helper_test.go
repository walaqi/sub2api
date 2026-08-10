package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestContentModerationWSDedupeMatchesOnlySameTurnAndRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(contentModerationWSTurnContextKey, 2)
	input := service.ContentModerationCheckInput{
		Protocol: service.ContentModerationProtocolOpenAIResponses,
		Model:    "gpt-test",
	}
	body := []byte(`{"type":"response.create","input":"same turn"}`)
	allow := &service.ContentModerationDecision{Allowed: true, Action: service.ContentModerationActionAllow}

	cacheContentModerationWSDecision(c, input, body, allow)
	require.Equal(t, allow, cachedContentModerationWSDecision(c, input, body))

	c.Set(contentModerationWSTurnContextKey, 3)
	require.Nil(t, cachedContentModerationWSDecision(c, input, body))
	c.Set(contentModerationWSTurnContextKey, 2)
	require.Nil(t, cachedContentModerationWSDecision(c, input, []byte(`{"type":"response.create","input":"changed"}`)))
	changedModel := input
	changedModel.Model = "gpt-other"
	require.Nil(t, cachedContentModerationWSDecision(c, changedModel, body))
}

func TestContentModerationWSDedupeDoesNotCacheRiskDecisions(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(contentModerationWSTurnContextKey, 2)
	input := service.ContentModerationCheckInput{Protocol: service.ContentModerationProtocolOpenAIResponses, Model: "gpt-test"}
	body := []byte(`{"type":"response.create","input":"review"}`)

	for _, decision := range []*service.ContentModerationDecision{
		{Allowed: true, Flagged: true, Action: service.ContentModerationActionAllow},
		{Blocked: true, Action: service.ContentModerationActionBlock},
		{Allowed: true, Action: service.ContentModerationActionError},
	} {
		cacheContentModerationWSDecision(c, input, body, decision)
		_, exists := c.Get(contentModerationWSDedupeContextKey)
		require.False(t, exists)
	}
}
