package service

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"

	"github.com/golang-jwt/jwt/v5"
)

// ImageStudioService 负责为 ChatGpt-Image-Studio 子应用签发入口票据（entry ticket）。
//
// 票据是一张 RS256、短有效期、一次性的 JWT：母系统持私钥签发，image-studio 仅持
// 对应公钥验签。image-studio 验签后在自己域下换发会话 cookie，之后所有请求走 cookie。
// 母系统在 claim 里塞 jti 以支持「一次性」语义，但是否记录 jti 防重放由 image-studio
// 验签侧决定（见 docs/comments-from-mother.md §B.5：母系统塞、不兜底）。
type ImageStudioService struct {
	cfg        *config.Config
	privateKey *rsa.PrivateKey
}

// EntryTicket 是签发结果。
type EntryTicket struct {
	// Ticket 是签名后的 JWT 字符串。
	Ticket string `json:"ticket"`
	// ExpiresAt 是票据过期的 Unix 秒级时间戳。
	ExpiresAt int64 `json:"expires_at"`
}

// NewImageStudioService 构造 service。
//
// 当 image_studio.enabled=true 时，解析配置中的 RSA 私钥 PEM；解析失败直接返回 error，
// 让 Wire 在启动期 fail-fast（避免运行时才发现密钥无效）。当 enabled=false 时，
// privateKey 留空，MintTicket 会返回 ErrImageStudioDisabled。
func NewImageStudioService(cfg *config.Config) (*ImageStudioService, error) {
	svc := &ImageStudioService{cfg: cfg}
	if !cfg.ImageStudio.Enabled {
		return svc, nil
	}
	pem := strings.TrimSpace(cfg.ImageStudio.JWTPrivateKeyPEM)
	if pem == "" {
		return nil, fmt.Errorf("image_studio enabled but private key PEM is empty")
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pem))
	if err != nil {
		return nil, fmt.Errorf("parse image_studio RSA private key: %w", err)
	}
	svc.privateKey = key
	return svc, nil
}

// ErrImageStudioDisabled 表示功能未启用或私钥缺失。
var ErrImageStudioDisabled = fmt.Errorf("image studio is not enabled")

// Enabled 返回功能是否可用。
func (s *ImageStudioService) Enabled() bool {
	return s.cfg.ImageStudio.Enabled && s.privateKey != nil
}

// MintTicket 为指定 userID 签发一张入口票据。
func (s *ImageStudioService) MintTicket(userID int64) (*EntryTicket, error) {
	if !s.Enabled() {
		return nil, ErrImageStudioDisabled
	}
	now := time.Now()
	ttl := time.Duration(s.cfg.ImageStudio.TicketTTLSeconds) * time.Second
	exp := now.Add(ttl)

	jti, err := newJTI()
	if err != nil {
		return nil, fmt.Errorf("generate ticket jti: %w", err)
	}

	claims := jwt.MapClaims{
		"sub": strconv.FormatInt(userID, 10), // image-studio store 列为 TEXT，userID 字符串化
		"iss": s.cfg.ImageStudio.JWTIssuer,
		"aud": s.cfg.ImageStudio.JWTAudience,
		"iat": now.Unix(),
		"exp": exp.Unix(),
		"jti": jti,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign image studio ticket: %w", err)
	}
	return &EntryTicket{Ticket: signed, ExpiresAt: exp.Unix()}, nil
}

// newJTI 生成 16 字节随机 jti（hex 编码）。
func newJTI() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
