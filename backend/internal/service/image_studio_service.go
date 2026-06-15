package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"

	"github.com/golang-jwt/jwt/v5"
)

// ImageStudioService 负责为 ChatGpt-Image-Studio 子应用签发入口票据（entry ticket），
// 并通过内部端点按 userID 解析可出图的渠道凭证。
//
// 票据是一张 RS256、短有效期、一次性的 JWT：母系统持私钥签发，image-studio 仅持
// 对应公钥验签。image-studio 验签后在自己域下换发会话 cookie，之后所有请求走 cookie。
// 母系统在 claim 里塞 jti 以支持「一次性」语义，但是否记录 jti 防重放由 image-studio
// 验签侧决定（见 docs/comments-from-mother.md §B.5：母系统塞、不兜底）。
//
// 凭证选取策略：用户自选 + 记住 + 兜底自建（见 §C.4）。母系统侧只读不铸：
// 列出用户「能出图」的 key 供 image-studio 渲染选择器，并按 key_id 解析明文凭证。
type ImageStudioService struct {
	cfg        *config.Config
	apiKeyRepo APIKeyRepository
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
func NewImageStudioService(cfg *config.Config, apiKeyRepo APIKeyRepository) (*ImageStudioService, error) {
	svc := &ImageStudioService{cfg: cfg, apiKeyRepo: apiKeyRepo}
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

// ImageKeyCandidate 是「能出图」的 key 候选（不含明文 key）。
type ImageKeyCandidate struct {
	KeyID     int64   `json:"key_id"`
	Name      string  `json:"name"`
	Quota     float64 `json:"quota"`      // 0 = unlimited
	QuotaUsed float64 `json:"quota_used"` // 已用额度
	ExpiresAt *int64  `json:"expires_at"` // Unix 秒；nil = 永不过期
	GroupID   int64   `json:"group_id"`
	GroupName string  `json:"group_name"`
}

// ImageKeyList 是列候选的返回结构。
type ImageKeyList struct {
	Keys []ImageKeyCandidate `json:"keys"`
	// CanCreate 表示是否存在可供「兜底自建」绑定的图片专用 group。
	CanCreate bool `json:"can_create"`
	// ImageGroupID 是兜底自建时该绑定的 group（<=0 表示未配置，此时 CanCreate=false）。
	ImageGroupID int64 `json:"image_group_id"`
}

// Credential 是取明文返回的真正凭证。
type Credential struct {
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url"`
	Model   string `json:"model"`
}

// ErrNoImageCapableKey 表示按 key_id 解析时该 key 不存在/不归属/已不满足出图条件。
var ErrNoImageCapableKey = fmt.Errorf("no image-capable key for the given selection")

// keyAllowsImageGeneration 判定一把 key 当前是否「能出图」。
//
// 三道门槛（见 docs/comments-from-mother.md §C.4）：
//  1. 平台门槛：/v1/images/generations 仅 OpenAI 平台放行（非 OpenAI 直接 404）。
//  2. 分组放行：group 必须开 AllowImageGeneration。
//     注意：未分组的 key 在网关侧虽放行，但拿不到 OpenAI 平台归属、也无图片定价，
//     无法稳定出图，故此处要求 key 必须分组且该 group 满足条件。
//  3. 可用性：active、未过期、配额未耗尽。
//
// 门槛 3（渠道映射 gpt-image-* → 真实上游）无法在母系统侧静态判定，依赖部署前提
// （admin 预配好图片专用 group 的账号映射），见 §C.4 部署提醒。
func keyAllowsImageGeneration(k *APIKey) bool {
	if k == nil || k.Group == nil {
		return false
	}
	if k.Group.Platform != PlatformOpenAI {
		return false
	}
	if !GroupAllowsImageGeneration(k.Group) {
		return false
	}
	if !k.IsActive() || k.IsExpired() || k.IsQuotaExhausted() {
		return false
	}
	return true
}

// ListImageCapableKeys 返回该用户当前「能出图」的 key 列表（不含明文），
// 供 image-studio 渲染选择器。
func (s *ImageStudioService) ListImageCapableKeys(ctx context.Context, userID int64) (*ImageKeyList, error) {
	imageGroupID := s.cfg.ImageStudio.ImageGroupID
	out := &ImageKeyList{
		Keys:         []ImageKeyCandidate{},
		ImageGroupID: imageGroupID,
		CanCreate:    imageGroupID > 0,
	}

	// 拉该用户全部 key（带 group hydrate），逐把按门槛过滤。
	params := pagination.PaginationParams{Page: 1, PageSize: 1000}
	keys, _, err := s.apiKeyRepo.ListByUserID(ctx, userID, params, APIKeyListFilters{})
	if err != nil {
		return nil, fmt.Errorf("list user api keys: %w", err)
	}

	for i := range keys {
		k := &keys[i]
		if !keyAllowsImageGeneration(k) {
			continue
		}
		candidate := ImageKeyCandidate{
			KeyID:     k.ID,
			Name:      k.Name,
			Quota:     k.Quota,
			QuotaUsed: k.QuotaUsed,
			GroupName: k.Group.Name,
		}
		if k.GroupID != nil {
			candidate.GroupID = *k.GroupID
		}
		if k.ExpiresAt != nil {
			exp := k.ExpiresAt.Unix()
			candidate.ExpiresAt = &exp
		}
		out.Keys = append(out.Keys, candidate)
	}
	return out, nil
}

// ResolveImageCred 按用户选定的 keyID 返回真正凭证。
// 返回前再校验一次归属（key 属于该 userID）、未过期、有额度、仍满足出图条件。
func (s *ImageStudioService) ResolveImageCred(ctx context.Context, userID int64, keyID int64) (*Credential, error) {
	params := pagination.PaginationParams{Page: 1, PageSize: 1000}
	keys, _, err := s.apiKeyRepo.ListByUserID(ctx, userID, params, APIKeyListFilters{})
	if err != nil {
		return nil, fmt.Errorf("list user api keys: %w", err)
	}

	for i := range keys {
		k := &keys[i]
		if k.ID != keyID {
			continue
		}
		// 找到了，但必须仍满足出图条件（归属已由 ListByUserID(userID) 保证）。
		if !keyAllowsImageGeneration(k) {
			return nil, ErrNoImageCapableKey
		}
		return &Credential{
			APIKey:  k.Key,
			BaseURL: s.cfg.ImageStudio.GatewayBaseURL,
			Model:   s.cfg.ImageStudio.ImageModel,
		}, nil
	}
	return nil, ErrNoImageCapableKey
}
