package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const previousResponseUnavailableMessage = "previous_response_id is not available for this user"

func previousResponseErrorResponse(status int, message string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(fmt.Sprintf(`{"error":{"message":%q,"type":"invalid_request_error"}}`, message))),
	}
}

func TestOpenAICompatPreviousResponseUnavailableRecognitionIsStrict(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		status  int
		message string
		want    bool
	}{
		{"unavailable", http.StatusBadRequest, previousResponseUnavailableMessage, true},
		{"normalized", http.StatusBadRequest, "  PREVIOUS_RESPONSE_ID IS NOT AVAILABLE FOR THIS USER  ", true},
		{"forbidden", http.StatusForbidden, previousResponseUnavailableMessage, false},
		{"not_found_status", http.StatusNotFound, previousResponseUnavailableMessage, false},
		{"permission", http.StatusBadRequest, "permission is not available for this user", false},
		{"project", http.StatusBadRequest, "previous_response_id is not available for this project", false},
		{"extra_text", http.StatusBadRequest, previousResponseUnavailableMessage + " permissions", false},
		{"legacy_not_found", http.StatusNotFound, "previous_response_not_found", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, isOpenAICompatPreviousResponseNotFound(tc.status, tc.message, nil))
			body, err := io.ReadAll(previousResponseErrorResponse(tc.status, tc.message).Body)
			require.NoError(t, err)
			require.Equal(t, tc.want, isOpenAICompatPreviousResponseNotFound(tc.status, "", body))
		})
	}
}

func TestForwardAsAnthropic_ReplaysFullToolHistoryWhenPreviousResponseUnavailable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream_%t", stream), func(t *testing.T) {
			upstream := &httpUpstreamRecorder{responses: []*http.Response{
				openAICompatSSECompletedResponse("resp_first", "gpt-5.3-codex"),
				previousResponseErrorResponse(http.StatusBadRequest, previousResponseUnavailableMessage),
				openAICompatSSECompletedResponse("resp_replayed", "gpt-5.3-codex"),
				openAICompatSSECompletedResponse("resp_next", "gpt-5.3-codex"),
			}}
			svc, account := newContinuationTestService(upstream)
			forward := func(body []byte) *OpenAIForwardResult {
				rec := httptest.NewRecorder()
				c, _ := gin.CreateTestContext(rec)
				c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
				result, err := svc.ForwardAsAnthropic(context.Background(), c, account, body, "stable-cache-key", "gpt-5.3-codex")
				require.NoError(t, err)
				require.Equal(t, http.StatusOK, rec.Code)
				require.NotNil(t, result)
				return result
			}
			forward([]byte(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"first"}]}`))
			messages := []string{`{"role":"user","content":"first"}`,
				`{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"lookup","input":{"q":"first"}}]}`,
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"found"}]}`}
			for i := 0; i < openAICompatAnthropicReplayMaxTailMessages+2; i++ {
				role := "assistant"
				if i%2 == 1 {
					role = "user"
				}
				messages = append(messages, fmt.Sprintf(`{"role":%q,"content":"message-%02d"}`, role, i))
			}
			body := []byte(fmt.Sprintf(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[%s],"tools":[{"name":"lookup","input_schema":{"type":"object"}}],"stream":%t}`, strings.Join(messages, ","), stream))
			require.Equal(t, "resp_replayed", forward(body).ResponseID)
			require.Len(t, upstream.requests, 3)
			require.Equal(t, "resp_first", gjson.GetBytes(upstream.bodies[1], "previous_response_id").String())
			require.Equal(t, int64(2), gjson.GetBytes(upstream.bodies[1], "input.#").Int())
			replayed := upstream.bodies[2]
			require.False(t, gjson.GetBytes(replayed, "previous_response_id").Exists())
			require.Equal(t, int64(len(messages)+1), gjson.GetBytes(replayed, "input.#").Int())
			require.Equal(t, "developer", gjson.GetBytes(replayed, "input.0.role").String())
			require.Equal(t, "first", gjson.GetBytes(replayed, "input.1.content.0.text").String())
			require.Equal(t, "function_call", gjson.GetBytes(replayed, "input.2.type").String())
			require.Equal(t, "call_1", gjson.GetBytes(replayed, "input.2.call_id").String())
			require.Equal(t, "function_call_output", gjson.GetBytes(replayed, "input.3.type").String())
			require.Equal(t, "call_1", gjson.GetBytes(replayed, "input.3.call_id").String())
			require.Equal(t, "found", gjson.GetBytes(replayed, "input.3.output").String())
			for i := 0; i < openAICompatAnthropicReplayMaxTailMessages+2; i++ {
				require.Equal(t, fmt.Sprintf("message-%02d", i), gjson.GetBytes(replayed, fmt.Sprintf("input.%d.content.0.text", i+4)).String())
			}
			require.Equal(t, "resp_next", forward(body).ResponseID)
			require.Equal(t, "resp_replayed", gjson.GetBytes(upstream.bodies[3], "previous_response_id").String())
		})
	}
}

func TestForwardAsAnthropic_PreviousResponseUnavailableRetryIsBounded(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, tc := range []struct {
		name    string
		bindID  bool
		retried bool
		status  int
		message string
		calls   int
	}{
		{"retry_failure", true, false, http.StatusBadRequest, previousResponseUnavailableMessage, 2},
		{"without_id", false, false, http.StatusBadRequest, previousResponseUnavailableMessage, 1},
		{"rebound_id_after_retry", true, true, http.StatusBadRequest, previousResponseUnavailableMessage, 1},
		{"permission", true, false, http.StatusBadRequest, "permission is not available for this user", 1},
		{"forbidden", true, false, http.StatusForbidden, previousResponseUnavailableMessage, 1},
		{"not_found_status", true, false, http.StatusNotFound, previousResponseUnavailableMessage, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := &httpUpstreamRecorder{responses: []*http.Response{
				previousResponseErrorResponse(tc.status, tc.message),
				previousResponseErrorResponse(tc.status, tc.message),
			}}
			svc, account := newContinuationTestService(upstream)
			if tc.bindID {
				svc.bindOpenAICompatSessionResponseID(context.Background(), nil, account, "stable-cache-key", "resp_missing")
			}
			body := []byte(`{"model":"claude-sonnet-4-5","max_tokens":16,"messages":[{"role":"user","content":"hello"}]}`)
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(body))
			ctx := context.Background()
			if tc.retried {
				ctx = markOpenAICompatContinuationRetried(ctx)
			}
			_, err := svc.ForwardAsAnthropic(ctx, c, account, body, "stable-cache-key", "gpt-5.3-codex")
			require.Error(t, err)
			require.Len(t, upstream.requests, tc.calls)
			require.Equal(t, tc.bindID && !tc.retried, gjson.GetBytes(upstream.bodies[0], "previous_response_id").Exists())
			if tc.calls == 2 {
				require.False(t, gjson.GetBytes(upstream.bodies[1], "previous_response_id").Exists())
				require.Empty(t, svc.getOpenAICompatSessionResponseID(context.Background(), nil, account, "stable-cache-key"))
			}
		})
	}
}

func newContinuationTestService(upstream *httpUpstreamRecorder) (*OpenAIGatewayService, *Account) {
	return &OpenAIGatewayService{
		httpUpstream: upstream,
		cfg:          &config.Config{Security: config.SecurityConfig{URLAllowlist: config.URLAllowlistConfig{Enabled: false}}},
	}, &Account{
		ID: 1, Platform: PlatformOpenAI, Type: AccountTypeAPIKey, Concurrency: 1,
		Credentials: map[string]any{"api_key": "sk-test", "base_url": "https://api.openai.com/v1"},
	}
}
