//go:build unit

package admin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/bindkeygiftsetting"
	"github.com/Wei-Shaw/sub2api/ent/enttest"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"entgo.io/ent/dialect"
	entsql "entgo.io/ent/dialect/sql"
	_ "modernc.org/sqlite"
)

var giftOpsDBSeq atomic.Int64

func newGiftOpsTestClient(t *testing.T) *dbent.Client {
	t.Helper()
	dsn := fmt.Sprintf("file:gift_ops_window_%d?mode=memory&cache=shared&_fk=1", giftOpsDBSeq.Add(1))
	db, err := sql.Open("sqlite", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec("PRAGMA foreign_keys = ON")
	require.NoError(t, err)
	drv := entsql.OpenDB(dialect.SQLite, db)
	client := enttest.NewClient(t, enttest.WithOptions(dbent.Driver(drv)))
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func setupGiftOpsRouter(client *dbent.Client) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewGiftOpsHandler(nil, nil, client)
	g := r.Group("/api/v1/admin/ops/bind-key-gifts")
	g.POST("", h.UpsertBindKeyGiftSetting)
	g.GET("/:api_key_id", h.GetBindKeyGiftSetting)
	g.PUT("/:api_key_id/registration-window", h.SetBindKeyRegistrationWindow)
	g.DELETE("/:api_key_id/registration-window", h.DeleteBindKeyRegistrationWindow)
	return r
}

func doJSON(t *testing.T, r *gin.Engine, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(rec, req)
	return rec
}

func TestSetBindKeyRegistrationWindow_CreatesRow(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)

	rec := doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/77/registration-window",
		`{"enabled":true,"min_days":0,"max_days":30}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	row, err := client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(77)).Only(context.Background())
	require.NoError(t, err)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.RegistrationWindow)
	require.True(t, row.Config.RegistrationWindow.Enabled)
	require.Equal(t, 30, row.Config.RegistrationWindow.MaxDays)
	// Placeholder row uses priority so gift behavior matches "no row".
	require.Equal(t, "priority", row.DeductionMode)
}

func TestSetBindKeyRegistrationWindow_Validation(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)

	for _, body := range []string{
		`{"enabled":true,"min_days":-1,"max_days":30}`,
		`{"enabled":true,"min_days":0,"max_days":0}`,
		`{"enabled":true,"min_days":20,"max_days":10}`,
	} {
		rec := doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/5/registration-window", body)
		require.Equal(t, http.StatusBadRequest, rec.Code, body)
	}
}

func TestGiftAndWindowAreIndependent(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)
	ctx := context.Background()
	const keyID = "88"

	// 1. Configure a ratio gift first.
	rec := doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":88,"deduction_mode":"ratio","ratio_recharge":2.0,"expires_after_days":7}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 2. Add a registration window; gift fields must survive.
	rec = doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/"+keyID+"/registration-window",
		`{"enabled":true,"min_days":3,"max_days":14}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	row, err := client.BindKeyGiftSetting.Query().Where(bindkeygiftsetting.APIKeyIDEQ(88)).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "ratio", row.DeductionMode)
	require.NotNil(t, row.RatioRecharge)
	require.InDelta(t, 2.0, *row.RatioRecharge, 1e-9)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.RegistrationWindow)
	require.Equal(t, 3, row.Config.RegistrationWindow.MinDays)

	// 3. Update the gift again; window must survive (upsert never touches config).
	rec = doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":88,"deduction_mode":"priority"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	row, err = client.BindKeyGiftSetting.Query().Where(bindkeygiftsetting.APIKeyIDEQ(88)).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "priority", row.DeductionMode)
	require.Nil(t, row.RatioRecharge)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.RegistrationWindow, "window must survive a gift update")

	// 4. Delete the window; gift fields must survive.
	rec = doJSON(t, r, http.MethodDelete, "/api/v1/admin/ops/bind-key-gifts/"+keyID+"/registration-window", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	row, err = client.BindKeyGiftSetting.Query().Where(bindkeygiftsetting.APIKeyIDEQ(88)).Only(ctx)
	require.NoError(t, err)
	require.Equal(t, "priority", row.DeductionMode)
	require.True(t, row.Config == nil || row.Config.RegistrationWindow == nil)
}

func TestGetBindKeyGiftSetting_ReturnsWindow(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)

	rec := doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/9/registration-window",
		`{"enabled":true,"min_days":1,"max_days":5}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = doJSON(t, r, http.MethodGet, "/api/v1/admin/ops/bind-key-gifts/9", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var resp struct {
		Data BindKeyGiftSettingResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotNil(t, resp.Data.Config)
	require.NotNil(t, resp.Data.Config.RegistrationWindow)
	require.Equal(t, 5, resp.Data.Config.RegistrationWindow.MaxDays)
}

func TestDeleteRegistrationWindow_NoRowIsNoop(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)
	rec := doJSON(t, r, http.MethodDelete, "/api/v1/admin/ops/bind-key-gifts/12345/registration-window", "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
}

func TestUpsertBindKeyGiftSetting_UnlimitWritesConfig(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)
	ctx := context.Background()

	// Create with unlimit=true
	rec := doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":100,"deduction_mode":"ratio","ratio_recharge":2.0,"unlimit":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	row, err := client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(100)).Only(ctx)
	require.NoError(t, err)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.Unlimit)
	require.True(t, *row.Config.Unlimit)
}

func TestUpsertBindKeyGiftSetting_UnlimitPreservesWindow(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)
	ctx := context.Background()

	// 1. Create with a registration window first.
	rec := doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/200/registration-window",
		`{"enabled":true,"min_days":0,"max_days":60}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 2. Upsert the gift with unlimit=true — window must survive.
	rec = doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":200,"deduction_mode":"priority","unlimit":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	row, err := client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(200)).Only(ctx)
	require.NoError(t, err)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.Unlimit)
	require.True(t, *row.Config.Unlimit)
	require.NotNil(t, row.Config.RegistrationWindow, "window must survive unlimit upsert")
	require.Equal(t, 60, row.Config.RegistrationWindow.MaxDays)
}

func TestUpsertBindKeyGiftSetting_WindowPreservesUnlimit(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)
	ctx := context.Background()

	// 1. Create with unlimit=true.
	rec := doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":300,"deduction_mode":"priority","unlimit":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 2. Add a registration window — unlimit must survive.
	rec = doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/300/registration-window",
		`{"enabled":true,"min_days":1,"max_days":90}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	row, err := client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(300)).Only(ctx)
	require.NoError(t, err)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.Unlimit, "unlimit must survive window update")
	require.True(t, *row.Config.Unlimit)
	require.NotNil(t, row.Config.RegistrationWindow)
	require.Equal(t, 90, row.Config.RegistrationWindow.MaxDays)
}

func TestUpsertBindKeyGiftSetting_NoUnlimitDoesNotTouchConfig(t *testing.T) {
	client := newGiftOpsTestClient(t)
	r := setupGiftOpsRouter(client)
	ctx := context.Background()

	// 1. Create with unlimit + window.
	rec := doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":400,"deduction_mode":"priority","unlimit":true}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	rec = doJSON(t, r, http.MethodPut, "/api/v1/admin/ops/bind-key-gifts/400/registration-window",
		`{"enabled":true,"min_days":0,"max_days":7}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 2. Update without unlimit field — config must remain unchanged.
	rec = doJSON(t, r, http.MethodPost, "/api/v1/admin/ops/bind-key-gifts",
		`{"api_key_id":400,"deduction_mode":"ratio","ratio_recharge":1.5}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	row, err := client.BindKeyGiftSetting.Query().
		Where(bindkeygiftsetting.APIKeyIDEQ(400)).Only(ctx)
	require.NoError(t, err)
	require.NotNil(t, row.Config)
	require.NotNil(t, row.Config.Unlimit, "unlimit must survive when field is absent from payload")
	require.True(t, *row.Config.Unlimit)
	require.NotNil(t, row.Config.RegistrationWindow)
}
