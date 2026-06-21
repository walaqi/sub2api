package service

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/gin-gonic/gin"
)

// openAIImageDumpDirEnv 是「转储上游图片响应原始内容」的开关兼目标目录。
//
// 设为一个非空目录路径时，网关会把每一次 /v1/images/generations 转发的**完整原始
// 上游响应体**（无论成功或失败）写到该目录，供离线排障——尤其是上游回 200 却既无
// 图片输出、也不是可识别错误事件（被 collectOpenAIImagesFromResponsesBody 判成 0 张图）
// 这种「黑盒」情形。未设置（空字符串）= 关闭，零开销。
//
// 注意：成功响应里含 base64 图片数据，转储文件可能很大；这是有意的（要「全部」内容），
// 故默认关闭、仅排障时按需开启。
const openAIImageDumpDirEnv = "SUB2API_DUMP_OPENAI_IMAGE_DIR"

// openAIImageDumpEnabled 返回转储目录（已 trim）与是否启用。
// 每次调用即时读环境变量——简单、无初始化顺序问题；改值后重启进程即生效。
func openAIImageDumpEnabled() (string, bool) {
	dir := strings.TrimSpace(os.Getenv(openAIImageDumpDirEnv))
	return dir, dir != ""
}

// openAIImageDumpCreateFile 在转储目录下创建一个新文件用于本次转储。
// 它负责用户要求的三步：判断目录是否设置、目录是否存在、不存在则创建（MkdirAll）。
// 任一步失败只记一行日志并返回 ok=false（绝不影响正常转发流程）。
func openAIImageDumpCreateFile(c *gin.Context, tag string) (*os.File, bool) {
	dir, ok := openAIImageDumpEnabled()
	if !ok {
		return nil, false
	}
	// 目录不存在则创建（含多级父目录）。已存在则 MkdirAll 直接返回 nil。
	if err := os.MkdirAll(dir, 0o755); err != nil {
		logger.LegacyPrintf("service.openai_gateway", "[OpenAI] image dump: mkdir %q failed: %v", dir, err)
		return nil, false
	}
	name := openAIImageDumpFileName(c, tag)
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		logger.LegacyPrintf("service.openai_gateway", "[OpenAI] image dump: create %q failed: %v", path, err)
		return nil, false
	}
	logger.LegacyPrintf("service.openai_gateway", "[OpenAI] image dump → %s", path)
	return f, true
}

// openAIImageDumpFileName 生成形如 20060102T150405.000_<requestID>_<tag>.txt 的文件名。
func openAIImageDumpFileName(c *gin.Context, tag string) string {
	reqID := sanitizeOpenAIImageDumpComponent(openAIImageDumpRequestID(c))
	ts := time.Now().Format("20060102T150405.000")
	return fmt.Sprintf("%s_%s_%s.txt", ts, reqID, sanitizeOpenAIImageDumpComponent(tag))
}

// openAIImageDumpRequestID 从 gin 请求上下文取服务端 request_id（与日志字段一致）。
func openAIImageDumpRequestID(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}
	if v, _ := c.Request.Context().Value(ctxkey.RequestID).(string); strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

// sanitizeOpenAIImageDumpComponent 把文件名片段里的非白名单字符替换为下划线，
// 避免 request_id 等带上路径分隔符或控制字符污染文件名。
func sanitizeOpenAIImageDumpComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			_, _ = b.WriteRune(r)
		default:
			_, _ = b.WriteRune('_')
		}
	}
	return b.String()
}

// writeOpenAIImageDumpHeader 在 body 前写一段元信息头，便于排障定位。
func writeOpenAIImageDumpHeader(f *os.File, resp *http.Response, tag string) {
	fmt.Fprintf(f, "=== sub2api openai image upstream dump ===\n")
	fmt.Fprintf(f, "tag: %s\n", tag)
	fmt.Fprintf(f, "time: %s\n", time.Now().Format(time.RFC3339Nano))
	if resp != nil {
		fmt.Fprintf(f, "status: %d\n", resp.StatusCode)
		fmt.Fprintf(f, "upstream-request-id: %s\n", resp.Header.Get("x-request-id"))
		fmt.Fprintf(f, "content-type: %s\n", resp.Header.Get("Content-Type"))
	}
	fmt.Fprintf(f, "=== body ===\n")
}

// openAIImageDumpTeeBody 在转储启用时，用 io.TeeReader 包住 resp.Body：handler 照常
// 逐字节读取的同时，原始字节被同步写入转储文件。覆盖流式/非流式两种消费方式，捕获的是
// **原始上游字节**（不依赖解析是否成功）。转储文件随 resp.Body 一起关闭。
// 未启用时原样返回、零开销。
func openAIImageDumpTeeBody(c *gin.Context, resp *http.Response, tag string) {
	if resp == nil || resp.Body == nil {
		return
	}
	f, ok := openAIImageDumpCreateFile(c, tag)
	if !ok {
		return
	}
	writeOpenAIImageDumpHeader(f, resp, tag)
	resp.Body = &openAIImageDumpTeeReadCloser{
		reader:  io.TeeReader(resp.Body, f),
		closers: []io.Closer{resp.Body, f},
	}
}

// openAIImageDumpBytes 直接把一段已在内存里的 body（如 >=400 错误响应已 ReadAll）转储。
func openAIImageDumpBytes(c *gin.Context, resp *http.Response, body []byte, tag string) {
	f, ok := openAIImageDumpCreateFile(c, tag)
	if !ok {
		return
	}
	defer func() { _ = f.Close() }()
	writeOpenAIImageDumpHeader(f, resp, tag)
	_, _ = f.Write(body)
}

// openAIImageDumpTeeReadCloser 让 tee 后的 reader 同时满足 io.ReadCloser：
// 读走 TeeReader，关闭时依次关闭底层 body 与转储文件。
type openAIImageDumpTeeReadCloser struct {
	reader  io.Reader
	closers []io.Closer
}

func (t *openAIImageDumpTeeReadCloser) Read(p []byte) (int, error) {
	return t.reader.Read(p)
}

func (t *openAIImageDumpTeeReadCloser) Close() error {
	var firstErr error
	for _, c := range t.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
