package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	middleware2 "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
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

func TestRunContentModerationLogsWebSocketChecksAndCacheHits(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var checks atomic.Int64
	moderationServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		checks.Add(1)
		_, _ = w.Write([]byte(`{"results":[{"category_scores":{"sexual":0}}]}`))
	}))
	defer moderationServer.Close()

	cfg := &service.ContentModerationConfig{
		Enabled: true, Mode: service.ContentModerationModePreBlock,
		BaseURL: moderationServer.URL, Model: "omni-moderation-latest",
		APIKeys: []string{"sk-test"}, SampleRate: 100, AllGroups: true,
	}
	rawCfg, err := json.Marshal(cfg)
	require.NoError(t, err)
	svc := service.NewContentModerationService(
		&contentModerationHandlerSettingRepo{values: map[string]string{
			service.SettingKeyRiskControlEnabled:      "true",
			service.SettingKeyContentModerationConfig: string(rawCfg),
		}},
		&contentModerationHandlerTestRepo{}, nil, nil, nil, nil, nil, nil,
	)

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	c.Set(contentModerationWSTurnContextKey, 2)
	core, logs := observer.New(zap.InfoLevel)
	reqLog := zap.New(core)
	payload := []byte(`{"type":"response.create","input":[{"type":"message","role":"user","content":[{"type":"input_text","text":"same turn"}]}]}`)

	first := runContentModeration(c, reqLog, svc, nil, middleware2.AuthSubject{UserID: 7}, service.ContentModerationProtocolOpenAIResponses, "gpt-test", payload)
	second := runContentModeration(c, reqLog, svc, nil, middleware2.AuthSubject{UserID: 7}, service.ContentModerationProtocolOpenAIResponses, "gpt-test", payload)

	require.NotNil(t, first)
	require.True(t, first.Allowed)
	require.Equal(t, first, second)
	require.Equal(t, int64(1), checks.Load())
	startLogs := logs.FilterMessage("content_moderation.gateway_check_start").All()
	require.Len(t, startLogs, 1)
	require.Equal(t, false, startLogs[0].ContextMap()["cached"])
	doneLogs := logs.FilterMessage("content_moderation.gateway_check_done").All()
	require.Len(t, doneLogs, 2)
	require.Equal(t, false, doneLogs[0].ContextMap()["cached"])
	require.Equal(t, true, doneLogs[1].ContextMap()["cached"])
}
