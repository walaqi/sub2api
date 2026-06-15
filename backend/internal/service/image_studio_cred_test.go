//go:build unit

package service

import (
	"context"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/pagination"
)

// imageCredRepoStub 只实现 ListByUserID，其余方法继承自嵌入的（nil）接口。
// byUser 按 userID 返回预置的 key 列表，从而验证「能出图」过滤与跨用户归属。
type imageCredRepoStub struct {
	APIKeyRepository
	byUser map[int64][]APIKey
}

func (s *imageCredRepoStub) ListByUserID(_ context.Context, userID int64, _ pagination.PaginationParams, _ APIKeyListFilters) ([]APIKey, *pagination.PaginationResult, error) {
	keys := s.byUser[userID]
	return keys, &pagination.PaginationResult{Total: int64(len(keys))}, nil
}

// imageGroupListerStub 按 userID 返回预置的可绑定分组，用于验证「兜底自建」的动态发现。
type imageGroupListerStub struct {
	byUser map[int64][]Group
}

func (s *imageGroupListerStub) GetAvailableGroups(_ context.Context, userID int64) ([]Group, error) {
	return s.byUser[userID], nil
}

func newImageCredService(repo APIKeyRepository) *ImageStudioService {
	return newImageCredServiceWithLister(repo, nil)
}

func newImageCredServiceWithLister(repo APIKeyRepository, lister imageGroupLister) *ImageStudioService {
	cfg := &config.Config{}
	cfg.ImageStudio.Enabled = true
	cfg.ImageStudio.GatewayBaseURL = "http://localhost:8080/v1"
	cfg.ImageStudio.ImageModel = "gpt-image-2"
	return &ImageStudioService{cfg: cfg, apiKeyRepo: repo, groupLister: lister}
}

// imageOKGroup 返回一个满足出图门槛的 group。
func imageOKGroup(id int64) *Group {
	return &Group{ID: id, Name: "图片专用", Platform: PlatformOpenAI, AllowImageGeneration: true, Status: StatusActive}
}

func TestListImageCapableKeysFiltersByGate(t *testing.T) {
	gid := int64(7)
	okGroup := imageOKGroup(gid)
	nonOpenAIGroup := &Group{ID: 8, Name: "claude", Platform: PlatformAnthropic, AllowImageGeneration: true}
	noImageGroup := &Group{ID: 9, Name: "openai-noimg", Platform: PlatformOpenAI, AllowImageGeneration: false}

	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{
		1: {
			// 通过：OpenAI + allow + active + 有额度
			{ID: 100, UserID: 1, Key: "sk-ok", Name: "ok", Status: StatusActive, GroupID: &gid, Group: okGroup, Quota: 10, QuotaUsed: 2},
			// 拒：非 OpenAI 平台
			{ID: 101, UserID: 1, Key: "sk-claude", Name: "claude", Status: StatusActive, Group: nonOpenAIGroup},
			// 拒：group 未开 allow_image_generation
			{ID: 102, UserID: 1, Key: "sk-noimg", Name: "noimg", Status: StatusActive, Group: noImageGroup},
			// 拒：未分组
			{ID: 103, UserID: 1, Key: "sk-nogroup", Name: "nogroup", Status: StatusActive},
			// 拒：配额耗尽
			{ID: 104, UserID: 1, Key: "sk-exhausted", Name: "exhausted", Status: StatusActive, GroupID: &gid, Group: okGroup, Quota: 5, QuotaUsed: 5},
			// 拒：非 active
			{ID: 105, UserID: 1, Key: "sk-disabled", Name: "disabled", Status: "disabled", GroupID: &gid, Group: okGroup},
		},
	}}

	svc := newImageCredServiceWithLister(repo, &imageGroupListerStub{byUser: map[int64][]Group{
		1: {*okGroup}, // 用户可绑该 openai+作图分组 → 兜底自建可用
	}})
	list, err := svc.ListImageCapableKeys(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListImageCapableKeys: %v", err)
	}
	if len(list.Keys) != 1 {
		t.Fatalf("expected 1 capable key, got %d: %+v", len(list.Keys), list.Keys)
	}
	if list.Keys[0].KeyID != 100 {
		t.Fatalf("expected key 100, got %d", list.Keys[0].KeyID)
	}
	// 候选不含明文 key（结构体里就没有该字段，这里顺带断言元数据）。
	if list.Keys[0].GroupID != gid {
		t.Fatalf("expected group_id %d, got %d", gid, list.Keys[0].GroupID)
	}
	if !list.CanCreate || list.ImageGroupID != gid {
		t.Fatalf("expected CanCreate=true ImageGroupID=%d, got %v/%d", gid, list.CanCreate, list.ImageGroupID)
	}
}

func TestListImageCapableKeysExpiredExcluded(t *testing.T) {
	gid := int64(7)
	past := time.Now().Add(-time.Hour)
	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{
		1: {
			{ID: 200, UserID: 1, Key: "sk-expired", Name: "expired", Status: StatusActive, GroupID: &gid, Group: imageOKGroup(gid), ExpiresAt: &past},
		},
	}}
	svc := newImageCredService(repo)
	list, err := svc.ListImageCapableKeys(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListImageCapableKeys: %v", err)
	}
	if len(list.Keys) != 0 {
		t.Fatalf("expected expired key excluded, got %d", len(list.Keys))
	}
}

func TestListImageCapableKeysNoAvailableImageGroup(t *testing.T) {
	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{1: {}}}
	// 无 lister（等价于该用户没有任何可绑定的 openai+作图分组：系统里没有，
	// 或有但用户无权限/未订阅）→ 兜底自建不可用。前端据此统一提示
	//「您当前没有可用的绘图分组（或没有权限），请联系客服处理」。
	svc := newImageCredService(repo)
	list, err := svc.ListImageCapableKeys(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListImageCapableKeys: %v", err)
	}
	if list.CanCreate {
		t.Fatalf("expected CanCreate=false when no available image group")
	}
	if list.ImageGroupID != 0 {
		t.Fatalf("expected ImageGroupID=0, got %d", list.ImageGroupID)
	}
}

// 用户有可绑定的 openai+作图分组，但当前没有该分组的 key：仍应能发现分组、
// 引导自建（这正是动态发现相对配置写死的价值——不依赖用户已有 key）。
func TestListImageCapableKeysDiscoversGroupWithoutExistingKey(t *testing.T) {
	gid := int64(7)
	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{1: {}}} // 无任何 key
	svc := newImageCredServiceWithLister(repo, &imageGroupListerStub{byUser: map[int64][]Group{
		1: {*imageOKGroup(gid)},
	}})
	list, err := svc.ListImageCapableKeys(context.Background(), 1)
	if err != nil {
		t.Fatalf("ListImageCapableKeys: %v", err)
	}
	if len(list.Keys) != 0 {
		t.Fatalf("expected 0 keys, got %d", len(list.Keys))
	}
	if !list.CanCreate || list.ImageGroupID != gid {
		t.Fatalf("expected CanCreate=true ImageGroupID=%d (discovered without existing key), got %v/%d", gid, list.CanCreate, list.ImageGroupID)
	}
}

func TestResolveImageCredReturnsPlaintext(t *testing.T) {
	gid := int64(7)
	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{
		1: {{ID: 100, UserID: 1, Key: "sk-ok", Name: "ok", Status: StatusActive, GroupID: &gid, Group: imageOKGroup(gid), Quota: 10, QuotaUsed: 1}},
	}}
	svc := newImageCredService(repo)
	cred, err := svc.ResolveImageCred(context.Background(), 1, 100)
	if err != nil {
		t.Fatalf("ResolveImageCred: %v", err)
	}
	if cred.APIKey != "sk-ok" {
		t.Fatalf("api_key = %q, want sk-ok", cred.APIKey)
	}
	if cred.BaseURL != "http://localhost:8080/v1" {
		t.Fatalf("base_url = %q", cred.BaseURL)
	}
	if cred.Model != "gpt-image-2" {
		t.Fatalf("model = %q", cred.Model)
	}
}

// 越权：userA 选 userB 的 key_id，应被拒（B 的 key 不在 A 的列表里）。
func TestResolveImageCredCrossUserDenied(t *testing.T) {
	gid := int64(7)
	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{
		1: {{ID: 100, UserID: 1, Key: "sk-a", Status: StatusActive, GroupID: &gid, Group: imageOKGroup(gid), Quota: 10}},
		2: {{ID: 200, UserID: 2, Key: "sk-b", Status: StatusActive, GroupID: &gid, Group: imageOKGroup(gid), Quota: 10}},
	}}
	svc := newImageCredService(repo)
	// userA(1) 试图解析 userB 的 key 200。
	if _, err := svc.ResolveImageCred(context.Background(), 1, 200); err != ErrNoImageCapableKey {
		t.Fatalf("cross-user resolve err = %v, want ErrNoImageCapableKey", err)
	}
}

// 选了一把不再满足出图条件的 key（如配额耗尽），取明文应被拒。
func TestResolveImageCredNoLongerCapableDenied(t *testing.T) {
	gid := int64(7)
	repo := &imageCredRepoStub{byUser: map[int64][]APIKey{
		1: {{ID: 100, UserID: 1, Key: "sk-ok", Status: StatusActive, GroupID: &gid, Group: imageOKGroup(gid), Quota: 5, QuotaUsed: 5}},
	}}
	svc := newImageCredService(repo)
	if _, err := svc.ResolveImageCred(context.Background(), 1, 100); err != ErrNoImageCapableKey {
		t.Fatalf("exhausted resolve err = %v, want ErrNoImageCapableKey", err)
	}
}
