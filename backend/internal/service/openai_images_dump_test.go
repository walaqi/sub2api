package service

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/gin-gonic/gin"
)

func newDumpTestContext(reqID string) *gin.Context {
	c, _ := gin.CreateTestContext(nil)
	req, _ := http.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	if reqID != "" {
		req = req.WithContext(context.WithValue(req.Context(), ctxkey.RequestID, reqID))
	}
	c.Request = req
	return c
}

// 门控：未设置环境变量时，tee 不改变 body、不写任何文件。
func TestOpenAIImageDump_DisabledByDefault(t *testing.T) {
	t.Setenv(openAIImageDumpDirEnv, "")

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("hello-body")),
	}
	c := newDumpTestContext("req-1")
	openAIImageDumpTeeBody(c, resp, "test")

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != "hello-body" {
		t.Fatalf("body changed when dump disabled: %q", string(got))
	}
}

// 启用：目录不存在时自动创建（含多级父目录），tee 把原始字节同步写盘，
// 且 handler 侧读取到的 body 完全不变。
func TestOpenAIImageDump_TeeWritesRawBytesAndCreatesDir(t *testing.T) {
	base := t.TempDir()
	dumpDir := filepath.Join(base, "nested", "dump") // 故意多级、尚不存在
	t.Setenv(openAIImageDumpDirEnv, dumpDir)

	const payload = `data: {"type":"response.completed","response":{"output":[]}}` + "\n\n"
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"X-Request-Id": []string{"up-123"}, "Content-Type": []string{"text/event-stream"}},
		Body:       io.NopCloser(strings.NewReader(payload)),
	}
	c := newDumpTestContext("req-abc")
	openAIImageDumpTeeBody(c, resp, "oauth_responses_2xx")

	// handler 照常读取——内容必须原样。
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("tee altered body: %q", string(got))
	}
	// 关闭触发文件落盘 flush。
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// 目录已被自动创建。
	if _, err := os.Stat(dumpDir); err != nil {
		t.Fatalf("dump dir not created: %v", err)
	}
	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		t.Fatalf("read dump dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 dump file, got %d", len(entries))
	}
	name := entries[0].Name()
	if !strings.Contains(name, "req-abc") || !strings.Contains(name, "oauth_responses_2xx") {
		t.Fatalf("dump filename missing request id / tag: %q", name)
	}
	content, err := os.ReadFile(filepath.Join(dumpDir, name))
	if err != nil {
		t.Fatalf("read dump file: %v", err)
	}
	cs := string(content)
	if !strings.Contains(cs, payload) {
		t.Fatalf("dump file missing raw body; got:\n%s", cs)
	}
	if !strings.Contains(cs, "up-123") || !strings.Contains(cs, "status: 200") {
		t.Fatalf("dump header missing upstream meta; got:\n%s", cs)
	}
}

// 直接转储已在内存的 body（>=400 错误分支用）。
func TestOpenAIImageDump_Bytes(t *testing.T) {
	dumpDir := t.TempDir()
	t.Setenv(openAIImageDumpDirEnv, dumpDir)

	resp := &http.Response{
		StatusCode: 429,
		Header:     http.Header{"X-Request-Id": []string{"up-err"}},
	}
	c := newDumpTestContext("req-err")
	openAIImageDumpBytes(c, resp, []byte(`{"error":{"message":"rate limited"}}`), "oauth_responses_4xx")

	entries, err := os.ReadDir(dumpDir)
	if err != nil {
		t.Fatalf("read dump dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 dump file, got %d", len(entries))
	}
	content, err := os.ReadFile(filepath.Join(dumpDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("read dump file: %v", err)
	}
	cs := string(content)
	if !strings.Contains(cs, "rate limited") || !strings.Contains(cs, "status: 429") {
		t.Fatalf("dump bytes missing content/status; got:\n%s", cs)
	}
}

// 文件名片段净化：含路径分隔符的 request_id 不得污染文件名。
func TestSanitizeOpenAIImageDumpComponent(t *testing.T) {
	cases := map[string]string{
		"":                "unknown",
		"abc-123":         "abc-123",
		"a/b\\c":          "a_b_c",
		"req id\twith ws": "req_id_with_ws",
	}
	for in, want := range cases {
		if got := sanitizeOpenAIImageDumpComponent(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
