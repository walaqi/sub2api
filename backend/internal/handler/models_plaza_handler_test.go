//go:build unit

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

// TestModelsPlaza_FeatureDisabled_ReturnsEmptyCatalog 验证开关关闭（默认 opt-in）时
// 返回空目录，且不触达 catalogService（这里传 nil，若被调用会 panic）。
func TestModelsPlaza_FeatureDisabled_ReturnsEmptyCatalog(t *testing.T) {
	gin.SetMode(gin.TestMode)

	repo := &settingHandlerPublicRepoStub{
		values: map[string]string{
			service.SettingKeyModelsPlazaEnabled: "false",
		},
	}
	settingSvc := service.NewSettingService(repo, &config.Config{})
	// catalogService 为 nil：feature 关闭路径不应调用它。
	h := NewModelsPlazaHandler(nil, settingSvc)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/models-plaza/catalog", nil)

	h.Catalog(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp response.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]any)
	require.True(t, ok)

	models, ok := data["models"].([]any)
	require.True(t, ok)
	require.Empty(t, models)

	groups, ok := data["groups"].([]any)
	require.True(t, ok)
	require.Empty(t, groups)
}

// TestModelsPlaza_NilSettingService_FailsClosed 验证 settingService 为 nil 时
// fail-closed：返回空目录而非 panic。
func TestModelsPlaza_NilSettingService_FailsClosed(t *testing.T) {
	gin.SetMode(gin.TestMode)

	h := NewModelsPlazaHandler(nil, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/models-plaza/catalog", nil)

	h.Catalog(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp response.Response
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	data, ok := resp.Data.(map[string]any)
	require.True(t, ok)
	models, ok := data["models"].([]any)
	require.True(t, ok)
	require.Empty(t, models)
}
