//go:build unit

package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ctxkey"
	"github.com/stretchr/testify/require"
)

// recordUsageGiftDeductStub / giftDeducterFromUserRepo 定义在无 build tag 的
// openai_gateway_record_usage_test.go，供本文件（unit tag）与该文件共用。

func newGatewayRecordUsageServiceForTest(usageRepo UsageLogRepository, userRepo UserRepository, subRepo UserSubscriptionRepository) *GatewayService {
	// 用 simple 模式构造以合法通过"标准模式 giftEngine 非空"硬校验（构造期 fail-fast），
	// 构造后翻回 standard 并注入兜底扣费依赖 —— 使 RecordUsage 走计费路径且可断言扣费发生。
	cfg := &config.Config{}
	cfg.RunMode = config.RunModeSimple
	cfg.Default.RateMultiplier = 1.1
	svc := NewGatewayService(
		nil,
		nil,
		usageRepo,
		nil,
		userRepo,
		subRepo,
		nil,
		nil,
		cfg,
		nil,
		nil,
		NewBillingService(cfg, nil),
		nil,
		&BillingCacheService{},
		nil,
		nil,
		&DeferredService{},
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil, // userPlatformQuotaRepo
		nil, // giftEngine
	)
	cfg.RunMode = config.RunModeStandard
	svc.giftEngine = giftDeducterFromUserRepo(userRepo)
	return svc
}

func newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo UsageLogRepository, billingRepo UsageBillingRepository, userRepo UserRepository, subRepo UserSubscriptionRepository) *GatewayService {
	svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, subRepo)
	svc.usageBillingRepo = billingRepo
	return svc
}

type openAIRecordUsageBestEffortLogRepoStub struct {
	UsageLogRepository

	bestEffortErr   error
	createErr       error
	bestEffortCalls int
	createCalls     int
	lastLog         *UsageLog
	lastCtxErr      error
}

func (s *openAIRecordUsageBestEffortLogRepoStub) CreateBestEffort(ctx context.Context, log *UsageLog) error {
	s.bestEffortCalls++
	s.lastLog = log
	s.lastCtxErr = ctx.Err()
	return s.bestEffortErr
}

func (s *openAIRecordUsageBestEffortLogRepoStub) Create(ctx context.Context, log *UsageLog) (bool, error) {
	s.createCalls++
	s.lastLog = log
	s.lastCtxErr = ctx.Err()
	return false, s.createErr
}

func TestGatewayServiceRecordUsage_BillingUsesDetachedContext(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: false, err: context.DeadlineExceeded}
	userRepo := &openAIRecordUsageUserRepoStub{}
	subRepo := &openAIRecordUsageSubRepoStub{}
	quotaSvc := &openAIRecordUsageAPIKeyQuotaStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, subRepo)

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := svc.RecordUsage(reqCtx, &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gateway_detached_ctx",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey: &APIKey{
			ID:    501,
			Quota: 100,
		},
		User:          &User{ID: 601},
		Account:       &Account{ID: 701},
		APIKeyService: quotaSvc,
	})

	require.NoError(t, err)
	require.Equal(t, 1, usageRepo.calls)
	// 兜底扣费已改道赠金引擎（不再直扣 userRepo）：断言 stub 在 detached ctx 内被调用。
	// 兜底扣费改道赠金引擎，但 userRepo stub 实现了 giftBalanceDeducter 并计进同一
	// deductCalls/lastCtxErr，故断言语义不变（"在 detached ctx 内扣费一次"）。
	require.Equal(t, 1, userRepo.deductCalls)
	require.NoError(t, userRepo.lastCtxErr)
	require.Equal(t, 1, quotaSvc.quotaCalls)
	require.NoError(t, quotaSvc.lastQuotaCtxErr)
}

func TestGatewayServiceRecordUsage_BillingFingerprintIncludesRequestPayloadHash(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{Applied: true}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo, billingRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	payloadHash := HashUsageRequestPayload([]byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gateway_payload_hash",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:             &APIKey{ID: 501, Quota: 100},
		User:               &User{ID: 601},
		Account:            &Account{ID: 701},
		RequestPayloadHash: payloadHash,
	})
	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.Equal(t, payloadHash, billingRepo.lastCmd.RequestPayloadHash)
}

func TestGatewayServiceRecordUsage_Gemini36FlashPricingFlowsThroughGiftAllocation(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	giftCost := 4.15
	rechargeCost := 5.0
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{
		Applied:      true,
		GiftCost:     &giftCost,
		RechargeCost: &rechargeCost,
	}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(
		usageRepo,
		billingRepo,
		&openAIRecordUsageUserRepoStub{},
		&openAIRecordUsageSubRepoStub{},
	)
	svc.cfg.Default.RateMultiplier = 1
	groupID := int64(42)

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gemini-36-flash-gift-allocation",
			Usage: ClaudeUsage{
				InputTokens:          1_000_000,
				OutputTokens:         1_000_000,
				CacheReadInputTokens: 1_000_000,
			},
			Model:    "gemini-3.6-flash-low",
			Duration: time.Second,
		},
		APIKey: &APIKey{
			ID:      501,
			GroupID: &groupID,
		},
		User:    &User{ID: 601},
		Account: &Account{ID: 701, Platform: PlatformAntigravity},
	})

	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.InDelta(t, 9.15, billingRepo.lastCmd.BalanceCost, 1e-12)
	require.Equal(t, &groupID, billingRepo.lastCmd.GroupID)
	require.NotNil(t, usageRepo.lastLog)
	require.InDelta(t, 9.15, usageRepo.lastLog.ActualCost, 1e-12)
	require.InDelta(t, giftCost, usageRepo.lastLog.GiftCost, 1e-12)
	require.InDelta(t, rechargeCost, usageRepo.lastLog.RechargeCost, 1e-12)
	require.InDelta(t, usageRepo.lastLog.ActualCost, usageRepo.lastLog.GiftCost+usageRepo.lastLog.RechargeCost, 1e-12)
}

func TestGatewayServiceRecordUsage_CodexAutoReviewPricingFlowsThroughGiftAllocation(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	giftCost := 0.42
	rechargeCost := 1.0
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{
		Applied:      true,
		GiftCost:     &giftCost,
		RechargeCost: &rechargeCost,
	}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(
		usageRepo,
		billingRepo,
		&openAIRecordUsageUserRepoStub{},
		&openAIRecordUsageSubRepoStub{},
	)
	svc.cfg.Default.RateMultiplier = 1
	pricingJSON, err := os.ReadFile(filepath.Join("..", "..", "resources", "model-pricing", "model_prices_and_context_window.json"))
	require.NoError(t, err)
	pricingSvc := &PricingService{}
	pricingData, err := pricingSvc.parsePricingData(pricingJSON)
	require.NoError(t, err)
	pricingSvc.pricingData = pricingData
	svc.billingService = NewBillingService(svc.cfg, pricingSvc)
	groupID := int64(43)

	err = svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "codex-auto-review-gift-allocation",
			Usage: ClaudeUsage{
				InputTokens:          1_000_000,
				OutputTokens:         1_000_000,
				CacheReadInputTokens: 1_000_000,
			},
			Model:    "codex-auto-review",
			Duration: time.Second,
		},
		APIKey: &APIKey{
			ID:      502,
			GroupID: &groupID,
		},
		User:    &User{ID: 602},
		Account: &Account{ID: 702, Platform: PlatformOpenAI},
	})

	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.InDelta(t, 1.42, billingRepo.lastCmd.BalanceCost, 1e-12)
	require.Equal(t, &groupID, billingRepo.lastCmd.GroupID)
	require.NotNil(t, usageRepo.lastLog)
	require.InDelta(t, 1.42, usageRepo.lastLog.ActualCost, 1e-12)
	require.InDelta(t, giftCost, usageRepo.lastLog.GiftCost, 1e-12)
	require.InDelta(t, rechargeCost, usageRepo.lastLog.RechargeCost, 1e-12)
	require.InDelta(t, usageRepo.lastLog.ActualCost, usageRepo.lastLog.GiftCost+usageRepo.lastLog.RechargeCost, 1e-12)
}

func TestGatewayServiceRecordUsage_BillingFingerprintFallsBackToContextRequestID(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{Applied: true}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo, billingRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	ctx := context.WithValue(context.Background(), ctxkey.RequestID, "req-local-123")
	err := svc.RecordUsage(ctx, &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gateway_payload_fallback",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 501, Quota: 100},
		User:    &User{ID: 601},
		Account: &Account{ID: 701},
	})
	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.Equal(t, "local:req-local-123", billingRepo.lastCmd.RequestPayloadHash)
}

func TestGatewayServiceRecordUsage_PreservesRequestedAndUpstreamModels(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})
	mappedModel := "claude-sonnet-4-20250514"

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID:     "gateway_models_split",
			Usage:         ClaudeUsage{InputTokens: 10, OutputTokens: 6},
			Model:         "claude-sonnet-4",
			UpstreamModel: mappedModel,
			Duration:      time.Second,
		},
		APIKey:  &APIKey{ID: 501, Quota: 100},
		User:    &User{ID: 601},
		Account: &Account{ID: 701},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, "claude-sonnet-4", usageRepo.lastLog.Model)
	require.Equal(t, "claude-sonnet-4", usageRepo.lastLog.RequestedModel)
	require.NotNil(t, usageRepo.lastLog.UpstreamModel)
	require.Equal(t, mappedModel, *usageRepo.lastLog.UpstreamModel)
}

func TestGatewayServiceRecordUsage_ExtractsDeviceIDFromMetadataUserID(t *testing.T) {
	deviceHex := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sessionUUID := "11111111-1111-1111-1111-111111111111"

	cases := []struct {
		name           string
		metadataUserID string
		parsedReq      bool
		wantDeviceID   *string
	}{
		{
			name:           "legacy_format_populates_device_id",
			metadataUserID: "user_" + deviceHex + "_account__session_" + sessionUUID,
			parsedReq:      true,
			wantDeviceID:   &deviceHex,
		},
		{
			name:           "json_format_populates_device_id",
			metadataUserID: `{"device_id":"` + deviceHex + `","account_uuid":"","session_id":"` + sessionUUID + `"}`,
			parsedReq:      true,
			wantDeviceID:   &deviceHex,
		},
		{
			name:           "unparseable_metadata_leaves_device_id_nil",
			metadataUserID: "not-a-valid-user-id",
			parsedReq:      true,
			wantDeviceID:   nil,
		},
		{
			name:           "no_parsed_request_leaves_device_id_nil",
			metadataUserID: "",
			parsedReq:      false,
			wantDeviceID:   nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
			svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

			input := &RecordUsageInput{
				Result: &ForwardResult{
					RequestID: "gateway_device_id_" + tc.name,
					Usage:     ClaudeUsage{InputTokens: 10, OutputTokens: 6},
					Model:     "claude-sonnet-4",
					Duration:  time.Second,
				},
				APIKey:  &APIKey{ID: 501, Quota: 100},
				User:    &User{ID: 601},
				Account: &Account{ID: 701},
			}
			if tc.parsedReq {
				input.MetadataUserID = tc.metadataUserID
			}

			err := svc.RecordUsage(context.Background(), input)
			require.NoError(t, err)
			require.NotNil(t, usageRepo.lastLog)
			if tc.wantDeviceID == nil {
				require.Nil(t, usageRepo.lastLog.DeviceID)
			} else {
				require.NotNil(t, usageRepo.lastLog.DeviceID)
				require.Equal(t, *tc.wantDeviceID, *usageRepo.lastLog.DeviceID)
			}
		})
	}
}

func TestGatewayServiceRecordUsage_PersistsClientFingerprint(t *testing.T) {
	cases := []struct {
		name        string
		fingerprint string
		wantPtr     *string
	}{
		{
			name:        "non_empty_fingerprint_is_persisted",
			fingerprint: "fp-deadbeef",
			wantPtr:     ptrString("fp-deadbeef"),
		},
		{
			name:        "whitespace_only_fingerprint_leaves_nil",
			fingerprint: "   ",
			wantPtr:     nil,
		},
		{
			name:        "empty_fingerprint_leaves_nil",
			fingerprint: "",
			wantPtr:     nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
			svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

			input := &RecordUsageInput{
				Result: &ForwardResult{
					RequestID: "gateway_client_fp_" + tc.name,
					Usage:     ClaudeUsage{InputTokens: 10, OutputTokens: 6},
					Model:     "claude-sonnet-4",
					Duration:  time.Second,
				},
				APIKey:            &APIKey{ID: 501, Quota: 100},
				User:              &User{ID: 601},
				Account:           &Account{ID: 701},
				ClientFingerprint: tc.fingerprint,
			}

			err := svc.RecordUsage(context.Background(), input)
			require.NoError(t, err)
			require.NotNil(t, usageRepo.lastLog)
			if tc.wantPtr == nil {
				require.Nil(t, usageRepo.lastLog.ClientFingerprint)
			} else {
				require.NotNil(t, usageRepo.lastLog.ClientFingerprint)
				require.Equal(t, *tc.wantPtr, *usageRepo.lastLog.ClientFingerprint)
			}
		})
	}
}

func TestGatewayServiceRecordUsage_PreservesChannelMappedUpstreamModel(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID:     "gateway_channel_mapping_models",
			Usage:         ClaudeUsage{InputTokens: 10, OutputTokens: 6},
			Model:         "gpt-5.6-terra",
			UpstreamModel: "gpt-5.6-terra",
			Duration:      time.Second,
		},
		APIKey:  &APIKey{ID: 501, Quota: 100},
		User:    &User{ID: 601},
		Account: &Account{ID: 701},
		ChannelUsageFields: ChannelUsageFields{
			OriginalModel:      "gpt-5.6-sol",
			ChannelMappedModel: "gpt-5.6-terra",
		},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, "gpt-5.6-sol", usageRepo.lastLog.RequestedModel)
	require.Equal(t, "gpt-5.6-terra", usageRepo.lastLog.Model)
	require.NotNil(t, usageRepo.lastLog.UpstreamModel)
	require.Equal(t, "gpt-5.6-terra", *usageRepo.lastLog.UpstreamModel)
}

func TestGatewayServiceRecordUsage_PreservesLoopedChannelAndAccountUpstreamModel(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID:     "gateway_looped_mapping_models",
			Usage:         ClaudeUsage{InputTokens: 10, OutputTokens: 6},
			Model:         "gpt-5.6-terra",
			UpstreamModel: "gpt-5.6-sol",
			Duration:      time.Second,
		},
		APIKey:  &APIKey{ID: 501, Quota: 100},
		User:    &User{ID: 601},
		Account: &Account{ID: 701},
		ChannelUsageFields: ChannelUsageFields{
			OriginalModel:      "gpt-5.6-sol",
			ChannelMappedModel: "gpt-5.6-terra",
		},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, "gpt-5.6-sol", usageRepo.lastLog.RequestedModel)
	require.Equal(t, "gpt-5.6-terra", usageRepo.lastLog.Model)
	require.NotNil(t, usageRepo.lastLog.UpstreamModel)
	require.Equal(t, "gpt-5.6-sol", *usageRepo.lastLog.UpstreamModel)
}

func TestGatewayServiceRecordUsage_EmptyImageSizeDefaultsBeforeBillingAndPersistence(t *testing.T) {
	imagePrice2K := 0.19
	groupID := int64(901)
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID:      "gateway_image_default_size",
			Model:          "gemini-image",
			ImageCount:     1,
			ImageInputSize: "auto",
			Duration:       time.Second,
		},
		APIKey: &APIKey{
			ID:      801,
			GroupID: i64p(groupID),
			Group: &Group{
				ID:             groupID,
				RateMultiplier: 1.0,
				ImagePrice2K:   &imagePrice2K,
			},
		},
		User:    &User{ID: 601},
		Account: &Account{ID: 701},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, 1, usageRepo.lastLog.ImageCount)
	require.NotNil(t, usageRepo.lastLog.ImageSize)
	require.Equal(t, ImageBillingSize2K, *usageRepo.lastLog.ImageSize)
	require.NotNil(t, usageRepo.lastLog.ImageInputSize)
	require.Equal(t, "auto", *usageRepo.lastLog.ImageInputSize)
	require.NotNil(t, usageRepo.lastLog.ImageSizeSource)
	require.Equal(t, ImageSizeSourceDefault, *usageRepo.lastLog.ImageSizeSource)
	require.InDelta(t, 0.19, usageRepo.lastLog.TotalCost, 1e-12)
	require.InDelta(t, 0.19, usageRepo.lastLog.ActualCost, 1e-12)
}

func TestGatewayServiceRecordUsage_PeakRateAffectsTokenModeImageOutputTokens(t *testing.T) {
	groupID := int64(902)
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
	userRepo := &openAIRecordUsageUserRepoStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, &openAIRecordUsageSubRepoStub{})
	svc.resolver = newOpenAITokenImageChannelPricingResolverForTest(t, groupID, "gemini-image")

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID:  "gateway_peak_image_tokens",
			Model:      "gemini-image",
			ImageCount: 1,
			Usage: ClaudeUsage{
				InputTokens:       1000,
				OutputTokens:      600,
				ImageOutputTokens: 100,
			},
			Duration: time.Second,
		},
		APIKey: &APIKey{
			ID:      802,
			GroupID: i64p(groupID),
			Group: &Group{
				ID:                 groupID,
				RateMultiplier:     1.0,
				SubscriptionType:   SubscriptionTypeSubscription,
				PeakRateEnabled:    true,
				PeakStart:          "00:00",
				PeakEnd:            "23:59",
				PeakRateMultiplier: 3.0,
			},
		},
		User:    &User{ID: 602},
		Account: &Account{ID: 702},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.NotNil(t, usageRepo.lastLog.BillingMode)
	require.Equal(t, string(BillingModeToken), *usageRepo.lastLog.BillingMode)
	require.Equal(t, 3.0, usageRepo.lastLog.RateMultiplier)

	textInput := 1000 * 3e-6
	textOutput := 500 * 15e-6
	imageOutput := 100 * 15e-6
	expectedActual := (textInput + textOutput + imageOutput) * 3.0

	require.InDelta(t, textInput+textOutput+imageOutput, usageRepo.lastLog.TotalCost, 1e-12)
	require.InDelta(t, imageOutput, usageRepo.lastLog.ImageOutputCost, 1e-12)
	require.InDelta(t, expectedActual, usageRepo.lastLog.ActualCost, 1e-12)
	require.InDelta(t, expectedActual, userRepo.lastAmount, 1e-12)
}

func TestGatewayServiceRecordUsage_UsesExplicitPricingAtForPeakRate(t *testing.T) {
	for _, platform := range []string{PlatformAnthropic, PlatformGemini, PlatformGrok, PlatformAntigravity} {
		t.Run(platform, func(t *testing.T) {
			groupID := int64(903)
			usageRepo := &openAIRecordUsageLogRepoStub{inserted: true}
			userRepo := &openAIRecordUsageUserRepoStub{}
			svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, &openAIRecordUsageSubRepoStub{})
			svc.resolver = newOpenAITokenImageChannelPricingResolverForTest(t, groupID, "gemini-image")

			pricingAt := time.Date(2026, time.January, 1, 0, 30, 0, 0, time.UTC)
			err := svc.RecordUsage(context.Background(), &RecordUsageInput{
				Result: &ForwardResult{
					RequestID:  "gateway_explicit_pricing_at_" + platform,
					Model:      "gemini-image",
					ImageCount: 1,
					Usage: ClaudeUsage{
						InputTokens:       1000,
						OutputTokens:      600,
						ImageOutputTokens: 100,
					},
				},
				APIKey: &APIKey{
					ID:      803,
					GroupID: i64p(groupID),
					Group: &Group{
						ID:                 groupID,
						Platform:           platform,
						RateMultiplier:     1.0,
						SubscriptionType:   SubscriptionTypeSubscription,
						PeakRateEnabled:    true,
						PeakStart:          "00:00",
						PeakEnd:            "01:00",
						PeakRateMultiplier: 3.0,
					},
				},
				User:      &User{ID: 603},
				Account:   &Account{ID: 703, Platform: platform},
				PricingAt: pricingAt,
			})

			require.NoError(t, err)
			require.NotNil(t, usageRepo.lastLog)
			require.Equal(t, 3.0, usageRepo.lastLog.RateMultiplier)
		})
	}
}

func TestGatewayServiceRecordUsage_PricingAtFlowsThroughGiftAllocation(t *testing.T) {
	groupID := int64(904)
	giftCost := 0.014
	rechargeCost := 0.022
	usageRepo := &openAIRecordUsageLogRepoStub{}
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{
		Applied:      true,
		GiftCost:     &giftCost,
		RechargeCost: &rechargeCost,
	}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(
		usageRepo,
		billingRepo,
		&openAIRecordUsageUserRepoStub{},
		&openAIRecordUsageSubRepoStub{},
	)
	svc.resolver = newOpenAITokenImageChannelPricingResolverForTest(t, groupID, "gemini-image")

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID:  "gateway_pricing_at_gift_allocation",
			Model:      "gemini-image",
			ImageCount: 1,
			Usage: ClaudeUsage{
				InputTokens:       1000,
				OutputTokens:      600,
				ImageOutputTokens: 100,
			},
		},
		APIKey: &APIKey{
			ID:      804,
			GroupID: i64p(groupID),
			Group: &Group{
				ID:                 groupID,
				Platform:           PlatformAnthropic,
				RateMultiplier:     1.0,
				SubscriptionType:   SubscriptionTypeSubscription,
				PeakRateEnabled:    true,
				PeakStart:          "00:00",
				PeakEnd:            "01:00",
				PeakRateMultiplier: 3.0,
			},
		},
		User:      &User{ID: 604},
		Account:   &Account{ID: 704, Platform: PlatformAnthropic},
		PricingAt: time.Date(2026, time.January, 1, 0, 30, 0, 0, time.UTC),
	})

	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.InDelta(t, 0.036, billingRepo.lastCmd.BalanceCost, 1e-12)
	require.Equal(t, &groupID, billingRepo.lastCmd.GroupID)
	require.NotNil(t, usageRepo.lastLog)
	require.InDelta(t, 0.036, usageRepo.lastLog.ActualCost, 1e-12)
	require.InDelta(t, giftCost, usageRepo.lastLog.GiftCost, 1e-12)
	require.InDelta(t, rechargeCost, usageRepo.lastLog.RechargeCost, 1e-12)
	require.InDelta(t, usageRepo.lastLog.ActualCost, usageRepo.lastLog.GiftCost+usageRepo.lastLog.RechargeCost, 1e-12)
}

func TestGatewayServiceRecordUsage_UsageLogWriteErrorDoesNotSkipBilling(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: false, err: MarkUsageLogCreateNotPersisted(context.Canceled)}
	userRepo := &openAIRecordUsageUserRepoStub{}
	subRepo := &openAIRecordUsageSubRepoStub{}
	quotaSvc := &openAIRecordUsageAPIKeyQuotaStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, subRepo)

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gateway_not_persisted",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey: &APIKey{
			ID:    503,
			Quota: 100,
		},
		User:          &User{ID: 603},
		Account:       &Account{ID: 703},
		APIKeyService: quotaSvc,
	})

	require.NoError(t, err)
	require.Equal(t, 1, usageRepo.calls)
	require.Equal(t, 1, userRepo.deductCalls)
	require.Equal(t, 1, quotaSvc.quotaCalls)
}

func TestGatewayServiceRecordUsageWithLongContext_BillingUsesDetachedContext(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{inserted: false, err: context.DeadlineExceeded}
	userRepo := &openAIRecordUsageUserRepoStub{}
	subRepo := &openAIRecordUsageSubRepoStub{}
	quotaSvc := &openAIRecordUsageAPIKeyQuotaStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, subRepo)

	reqCtx, cancel := context.WithCancel(context.Background())
	cancel()

	err := svc.RecordUsageWithLongContext(reqCtx, &RecordUsageLongContextInput{
		Result: &ForwardResult{
			RequestID: "gateway_long_context_detached_ctx",
			Usage: ClaudeUsage{
				InputTokens:  12,
				OutputTokens: 8,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey: &APIKey{
			ID:    502,
			Quota: 100,
		},
		User:                  &User{ID: 602},
		Account:               &Account{ID: 702},
		LongContextThreshold:  200000,
		LongContextMultiplier: 2,
		APIKeyService:         quotaSvc,
	})

	require.NoError(t, err)
	require.Equal(t, 1, usageRepo.calls)
	require.Equal(t, 1, userRepo.deductCalls)
	require.NoError(t, userRepo.lastCtxErr)
	require.Equal(t, 1, quotaSvc.quotaCalls)
	require.NoError(t, quotaSvc.lastQuotaCtxErr)
}

func TestGatewayServiceRecordUsage_UsesFallbackRequestIDForUsageLog(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	userRepo := &openAIRecordUsageUserRepoStub{}
	subRepo := &openAIRecordUsageSubRepoStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, userRepo, subRepo)

	ctx := context.WithValue(context.Background(), ctxkey.RequestID, "gateway-local-fallback")
	err := svc.RecordUsage(ctx, &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 504},
		User:    &User{ID: 604},
		Account: &Account{ID: 704},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, "local:gateway-local-fallback", usageRepo.lastLog.RequestID)
}

func TestGatewayServiceRecordUsage_PrefersClientRequestIDOverUpstreamRequestID(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{Applied: true}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo, billingRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	ctx := context.WithValue(context.Background(), ctxkey.ClientRequestID, "client-stable-123")
	ctx = context.WithValue(ctx, ctxkey.RequestID, "req-local-ignored")
	err := svc.RecordUsage(ctx, &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "upstream-volatile-456",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 506},
		User:    &User{ID: 606},
		Account: &Account{ID: 706},
	})

	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.Equal(t, "client:client-stable-123", billingRepo.lastCmd.RequestID)
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, "client:client-stable-123", usageRepo.lastLog.RequestID)
}

func TestGatewayServiceRecordUsage_GeneratesRequestIDWhenAllSourcesMissing(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{Applied: true}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo, billingRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 507},
		User:    &User{ID: 607},
		Account: &Account{ID: 707},
	})

	require.NoError(t, err)
	require.NotNil(t, billingRepo.lastCmd)
	require.True(t, strings.HasPrefix(billingRepo.lastCmd.RequestID, "generated:"))
	require.NotNil(t, usageRepo.lastLog)
	require.Equal(t, billingRepo.lastCmd.RequestID, usageRepo.lastLog.RequestID)
}

func TestGatewayServiceRecordUsage_DroppedUsageLogFallsBackToSyncCreate(t *testing.T) {
	// 计费成功后 best-effort 写入被丢弃（队列超时）时必须同步兜底，
	// 否则出现“已扣费但无 usage_log”的对账缺口（issue #3656）。
	usageRepo := &openAIRecordUsageBestEffortLogRepoStub{
		bestEffortErr: MarkUsageLogCreateDropped(errors.New("usage log best-effort queue full")),
	}
	billingRepo := &openAIRecordUsageBillingRepoStub{result: &UsageBillingApplyResult{Applied: true}}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo, billingRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gateway_drop_usage_log",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 508},
		User:    &User{ID: 608},
		Account: &Account{ID: 708},
	})

	require.NoError(t, err)
	require.Equal(t, 1, usageRepo.bestEffortCalls)
	require.Equal(t, 1, usageRepo.createCalls)
	// 兜底调用使用的 ctx 必须仍然存活，不能带着已死的 ctx 走过场。
	require.NoError(t, usageRepo.lastCtxErr)
}

func TestGatewayServiceRecordUsage_BillingErrorSkipsUsageLogWrite(t *testing.T) {
	usageRepo := &openAIRecordUsageLogRepoStub{}
	billingRepo := &openAIRecordUsageBillingRepoStub{err: context.DeadlineExceeded}
	userRepo := &openAIRecordUsageUserRepoStub{}
	subRepo := &openAIRecordUsageSubRepoStub{}
	svc := newGatewayRecordUsageServiceWithBillingRepoForTest(usageRepo, billingRepo, userRepo, subRepo)

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "gateway_billing_fail",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 6,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 505},
		User:    &User{ID: 605},
		Account: &Account{ID: 705},
	})

	require.Error(t, err)
	require.Equal(t, 1, billingRepo.calls)
	require.Equal(t, 0, usageRepo.calls)
}

func TestGatewayServiceRecordUsage_ReasoningEffortPersisted(t *testing.T) {
	usageRepo := &openAIRecordUsageBestEffortLogRepoStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	effort := "max"
	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "effort_test",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 5,
			},
			Model:           "claude-opus-4-6",
			Duration:        time.Second,
			ReasoningEffort: &effort,
		},
		APIKey:  &APIKey{ID: 1},
		User:    &User{ID: 1},
		Account: &Account{ID: 1},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.NotNil(t, usageRepo.lastLog.ReasoningEffort)
	require.Equal(t, "max", *usageRepo.lastLog.ReasoningEffort)
}

func TestGatewayServiceRecordUsage_ReasoningEffortNil(t *testing.T) {
	usageRepo := &openAIRecordUsageBestEffortLogRepoStub{}
	svc := newGatewayRecordUsageServiceForTest(usageRepo, &openAIRecordUsageUserRepoStub{}, &openAIRecordUsageSubRepoStub{})

	err := svc.RecordUsage(context.Background(), &RecordUsageInput{
		Result: &ForwardResult{
			RequestID: "no_effort_test",
			Usage: ClaudeUsage{
				InputTokens:  10,
				OutputTokens: 5,
			},
			Model:    "claude-sonnet-4",
			Duration: time.Second,
		},
		APIKey:  &APIKey{ID: 1},
		User:    &User{ID: 1},
		Account: &Account{ID: 1},
	})

	require.NoError(t, err)
	require.NotNil(t, usageRepo.lastLog)
	require.Nil(t, usageRepo.lastLog.ReasoningEffort)
}
