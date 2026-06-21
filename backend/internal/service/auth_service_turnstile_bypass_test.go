//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/stretchr/testify/require"
)

func newAuthServiceForBypassTest(settings map[string]string, verifier TurnstileVerifier) *AuthService {
	cfg := &config.Config{
		Server:    config.ServerConfig{Mode: "release"},
		Turnstile: config.TurnstileConfig{Required: true},
	}
	settingService := NewSettingService(&settingRepoStub{values: settings}, cfg)
	turnstileService := NewTurnstileService(settingService, verifier)
	return NewAuthService(
		nil, &userRepoStub{}, nil, nil, cfg, settingService,
		nil, turnstileService, nil, nil, nil, nil, nil, nil,
	)
}

// 当上下文带有 bypass 标记时，VerifyTurnstile 直接放行，且不调用底层 verifier。
func TestVerifyTurnstile_BypassFromContext(t *testing.T) {
	verifier := &turnstileVerifierSpy{}
	svc := newAuthServiceForBypassTest(map[string]string{
		SettingKeyTurnstileEnabled:   "true",
		SettingKeyTurnstileSecretKey: "secret",
	}, verifier)

	ctx := ContextWithTurnstileBypass(context.Background())
	err := svc.VerifyTurnstile(ctx, "", "127.0.0.1")
	require.NoError(t, err)
	require.Equal(t, 0, verifier.called)
}

// 注册路径（VerifyTurnstileForRegister → VerifyTurnstile）同样受 bypass 标记覆盖。
func TestVerifyTurnstileForRegister_BypassFromContext(t *testing.T) {
	verifier := &turnstileVerifierSpy{}
	svc := newAuthServiceForBypassTest(map[string]string{
		SettingKeyEmailVerifyEnabled: "false",
		SettingKeyTurnstileEnabled:   "true",
		SettingKeyTurnstileSecretKey: "secret",
	}, verifier)

	ctx := ContextWithTurnstileBypass(context.Background())
	err := svc.VerifyTurnstileForRegister(ctx, "", "127.0.0.1", "")
	require.NoError(t, err)
	require.Equal(t, 0, verifier.called)
}

// 没有 bypass 标记时，仍按原逻辑校验（此处缺少有效 token 应失败）。
func TestVerifyTurnstile_NoBypassStillVerifies(t *testing.T) {
	verifier := &turnstileVerifierSpy{}
	svc := newAuthServiceForBypassTest(map[string]string{
		SettingKeyTurnstileEnabled:   "true",
		SettingKeyTurnstileSecretKey: "secret",
	}, verifier)

	err := svc.VerifyTurnstile(context.Background(), "", "127.0.0.1")
	require.ErrorIs(t, err, ErrTurnstileVerificationFailed)
	require.Equal(t, 0, verifier.called)
}

func TestIsTurnstileBypassRequested(t *testing.T) {
	require.False(t, IsTurnstileBypassRequested(context.Background()))
	require.True(t, IsTurnstileBypassRequested(ContextWithTurnstileBypass(context.Background())))
}
