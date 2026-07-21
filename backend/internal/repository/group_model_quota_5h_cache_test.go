//go:build unit

package repository

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestGroupModelQuota5hCache_GetMiss(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	entry, ok, err := c.GetGroupModelQuota5hCache(context.Background(), 1, 7, "m")
	if err != nil {
		t.Fatal(err)
	}
	if ok || entry != nil {
		t.Errorf("expected miss, got ok=%v entry=%v", ok, entry)
	}
}

func TestGroupModelQuota5hCache_SetThenGet(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	ws := time.Date(2026, 7, 21, 10, 0, 0, 0, time.UTC)
	in := &service.GroupModelQuota5hCacheEntry{
		UsageUSD:      2.5,
		WindowStart:   &ws,
		SchemaVersion: service.GroupModelQuota5hCacheSchemaV1,
	}
	if err := c.SetGroupModelQuota5hCache(ctx, 1, 7, "m", in, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.GetGroupModelQuota5hCache(ctx, 1, 7, "m")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	if got.UsageUSD != 2.5 {
		t.Errorf("usage = %v, want 2.5", got.UsageUSD)
	}
	if got.WindowStart == nil || !got.WindowStart.Equal(ws) {
		t.Errorf("windowStart = %v, want %v", got.WindowStart, ws)
	}
	if got.SchemaVersion != service.GroupModelQuota5hCacheSchemaV1 {
		t.Errorf("schemaVersion = %v", got.SchemaVersion)
	}
}

// 新 key（不存在）第一次累加 → 建立窗口，usage = cost。
func TestGroupModelQuota5hCache_IncrCreatesWindow(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	if err := c.IncrGroupModelQuota5hUsageCache(ctx, 1, 7, "m", 1.5, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, ok, err := c.GetGroupModelQuota5hCache(ctx, 1, 7, "m")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	if got.UsageUSD != 1.5 {
		t.Errorf("usage = %v, want 1.5", got.UsageUSD)
	}
	if got.WindowStart == nil {
		t.Error("window_start should be set after first incr")
	}
}

// 同窗口内多次累加 → 相加。
func TestGroupModelQuota5hCache_IncrAccumulatesWithinWindow(t *testing.T) {
	c, _ := newMiniRedisCache(t)
	ctx := context.Background()
	_ = c.IncrGroupModelQuota5hUsageCache(ctx, 1, 7, "m", 1.0, time.Hour)
	_ = c.IncrGroupModelQuota5hUsageCache(ctx, 1, 7, "m", 0.5, time.Hour)
	_ = c.IncrGroupModelQuota5hUsageCache(ctx, 1, 7, "m", 0.25, time.Hour)
	got, ok, err := c.GetGroupModelQuota5hCache(ctx, 1, 7, "m")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	if got.UsageUSD != 1.75 {
		t.Errorf("usage = %v, want 1.75 (accumulated)", got.UsageUSD)
	}
}

// 窗口过期 → 累加时重置为本次 cost，window_start 推进。
func TestGroupModelQuota5hCache_IncrResetsAfterWindowExpiry(t *testing.T) {
	c, mr := newMiniRedisCache(t)
	ctx := context.Background()

	// 先累加建立窗口。
	_ = c.IncrGroupModelQuota5hUsageCache(ctx, 1, 7, "m", 2.0, time.Hour)

	// 手动把 window_start 改到 6 小时前（超过 5h 窗口），模拟窗口过期。
	key := groupModelQuota5hCacheKey(1, 7, "m")
	oldStart := strconv.FormatInt(time.Now().Add(-6*time.Hour).Unix(), 10)
	mr.HSet(key, "window_start", oldStart)

	// 再累加：应重置为本次 cost 而非累加。
	_ = c.IncrGroupModelQuota5hUsageCache(ctx, 1, 7, "m", 0.3, time.Hour)

	got, ok, err := c.GetGroupModelQuota5hCache(ctx, 1, 7, "m")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	if got.UsageUSD != 0.3 {
		t.Errorf("usage = %v, want 0.3 (reset after expiry, not accumulated)", got.UsageUSD)
	}
	// window_start 应推进到近期（不再是 6h 前）。
	if got.WindowStart == nil || time.Since(*got.WindowStart) > time.Minute {
		t.Errorf("window_start should advance to now after reset, got %v", got.WindowStart)
	}
}
