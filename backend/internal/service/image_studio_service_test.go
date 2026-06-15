//go:build unit

package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strconv"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"

	"github.com/golang-jwt/jwt/v5"
)

// generateTestRSAKeyPEM 生成一对测试用 RSA 私钥，返回 PKCS#8 PEM 与对应公钥。
func generateTestRSAKeyPEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal PKCS8: %v", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block)), &key.PublicKey
}

func newImageStudioConfig(pemKey string) *config.Config {
	cfg := &config.Config{}
	cfg.ImageStudio.Enabled = true
	cfg.ImageStudio.JWTPrivateKeyPEM = pemKey
	cfg.ImageStudio.JWTIssuer = "sub2api"
	cfg.ImageStudio.JWTAudience = "image-studio"
	cfg.ImageStudio.TicketTTLSeconds = 60
	return cfg
}

func TestImageStudioMintTicketVerifiesWithPublicKey(t *testing.T) {
	pemKey, pubKey := generateTestRSAKeyPEM(t)
	svc, err := NewImageStudioService(newImageStudioConfig(pemKey))
	if err != nil {
		t.Fatalf("NewImageStudioService: %v", err)
	}
	if !svc.Enabled() {
		t.Fatalf("service should be enabled")
	}

	const userID int64 = 12345
	before := time.Now().Unix()
	ticket, err := svc.MintTicket(userID)
	if err != nil {
		t.Fatalf("MintTicket: %v", err)
	}
	if ticket.Ticket == "" {
		t.Fatalf("ticket string is empty")
	}

	claims := jwt.MapClaims{}
	parsed, err := jwt.ParseWithClaims(ticket.Ticket, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return pubKey, nil
	})
	if err != nil {
		t.Fatalf("verify ticket with public key: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("parsed token is not valid")
	}

	if got := claims["sub"]; got != strconv.FormatInt(userID, 10) {
		t.Fatalf("sub = %v, want %d", got, userID)
	}
	if got := claims["iss"]; got != "sub2api" {
		t.Fatalf("iss = %v, want sub2api", got)
	}
	if got := claims["aud"]; got != "image-studio" {
		t.Fatalf("aud = %v, want image-studio", got)
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Fatalf("jti is empty")
	}

	expFloat, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp claim missing or wrong type")
	}
	exp := int64(expFloat)
	if exp < before+59 || exp > before+62 {
		t.Fatalf("exp = %d, want ~%d+60s", exp, before)
	}
}

func TestImageStudioMintTicketJTIUnique(t *testing.T) {
	seen := make(map[string]struct{}, 50)
	for i := 0; i < 50; i++ {
		jti, err := newJTI()
		if err != nil {
			t.Fatalf("newJTI: %v", err)
		}
		if _, dup := seen[jti]; dup {
			t.Fatalf("duplicate jti generated: %s", jti)
		}
		seen[jti] = struct{}{}
	}
}

func TestImageStudioDisabledReturnsError(t *testing.T) {
	cfg := &config.Config{}
	cfg.ImageStudio.Enabled = false
	svc, err := NewImageStudioService(cfg)
	if err != nil {
		t.Fatalf("NewImageStudioService (disabled): %v", err)
	}
	if svc.Enabled() {
		t.Fatalf("service should be disabled")
	}
	if _, err := svc.MintTicket(1); err != ErrImageStudioDisabled {
		t.Fatalf("MintTicket err = %v, want ErrImageStudioDisabled", err)
	}
}

func TestImageStudioEnabledWithBadPEMFails(t *testing.T) {
	cfg := &config.Config{}
	cfg.ImageStudio.Enabled = true
	cfg.ImageStudio.JWTPrivateKeyPEM = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key\n-----END PRIVATE KEY-----"
	if _, err := NewImageStudioService(cfg); err == nil {
		t.Fatalf("expected error for invalid PEM, got nil")
	}
}
