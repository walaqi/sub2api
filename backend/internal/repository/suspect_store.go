package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/service"
	"github.com/redis/go-redis/v9"
)

// 多账户限流疑似名单 Redis 实现。
//
// 设计说明：
//   - key 形式：throttle:suspect:{userID}，值为 SuspectMeta 的 JSON。
//   - 每个 user 独立 TTL（SET ... EX），命中即续期，行为停止后分钟级自然消散（R5）。
//   - IsSuspect 是 checkRPM 命中名单时的一次 GET（fail-open 由调用方处理）。
//   - List 用 SCAN 汇总（管理端 R8 可观测性），避免 KEYS 阻塞。
const suspectThrottleKeyPrefix = "throttle:suspect:"

type suspectStoreImpl struct {
	rdb *redis.Client
}

// NewSuspectStore 创建多账户限流疑似名单存储。
func NewSuspectStore(rdb *redis.Client) service.SuspectStore {
	return &suspectStoreImpl{rdb: rdb}
}

func suspectKey(userID int64) string {
	return suspectThrottleKeyPrefix + strconv.FormatInt(userID, 10)
}

func (c *suspectStoreImpl) Mark(ctx context.Context, userID int64, meta service.SuspectMeta, ttl time.Duration) error {
	if userID <= 0 {
		return nil
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal suspect meta: %w", err)
	}
	if err := c.rdb.Set(ctx, suspectKey(userID), data, ttl).Err(); err != nil {
		return fmt.Errorf("suspect mark: %w", err)
	}
	return nil
}

func (c *suspectStoreImpl) IsSuspect(ctx context.Context, userID int64) (bool, error) {
	if userID <= 0 {
		return false, nil
	}
	n, err := c.rdb.Exists(ctx, suspectKey(userID)).Result()
	if err != nil {
		return false, fmt.Errorf("suspect exists: %w", err)
	}
	return n > 0, nil
}

func (c *suspectStoreImpl) List(ctx context.Context) ([]service.SuspectEntry, error) {
	entries := make([]service.SuspectEntry, 0)
	var cursor uint64
	pattern := suspectThrottleKeyPrefix + "*"
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return nil, fmt.Errorf("suspect scan: %w", err)
		}
		for _, key := range keys {
			entry, ok := c.readEntry(ctx, key)
			if ok {
				entries = append(entries, entry)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return entries, nil
}

// readEntry loads one suspect key into a SuspectEntry; skips keys that expired
// mid-scan or whose value is unparseable.
func (c *suspectStoreImpl) readEntry(ctx context.Context, key string) (service.SuspectEntry, bool) {
	idStr := strings.TrimPrefix(key, suspectThrottleKeyPrefix)
	userID, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return service.SuspectEntry{}, false
	}

	val, err := c.rdb.Get(ctx, key).Result()
	if err == redis.Nil {
		return service.SuspectEntry{}, false
	}
	if err != nil {
		logger.LegacyPrintf("repository.suspect_store", "suspect get %s failed: %v", key, err)
		return service.SuspectEntry{}, false
	}

	entry := service.SuspectEntry{UserID: userID}
	var meta service.SuspectMeta
	if json.Unmarshal([]byte(val), &meta) == nil {
		entry.Dimensions = meta.Dimensions
		entry.MarkedAt = meta.MarkedAt
	}

	if ttl, err := c.rdb.TTL(ctx, key).Result(); err == nil && ttl > 0 {
		entry.TTLSeconds = int64(ttl.Seconds())
	}
	return entry, true
}

func (c *suspectStoreImpl) Clear(ctx context.Context) (int, error) {
	cleared := 0
	var cursor uint64
	pattern := suspectThrottleKeyPrefix + "*"
	for {
		keys, next, err := c.rdb.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return cleared, fmt.Errorf("suspect scan: %w", err)
		}
		if len(keys) > 0 {
			n, err := c.rdb.Del(ctx, keys...).Result()
			if err != nil {
				return cleared, fmt.Errorf("suspect del: %w", err)
			}
			cleared += int(n)
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return cleared, nil
}
