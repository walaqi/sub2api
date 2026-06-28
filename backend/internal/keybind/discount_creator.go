package keybind

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/internal/domain"
)

// entDiscountCreator 通过 ent client 直接写 user_recharge_discounts 表。
// 在 keybind 包内使用原始 SQL 避免跨包导入 service/repository。
type entDiscountCreator struct {
	client *dbent.Client
}

// NewEntDiscountCreator 返回基于 ent client 的折扣创建器。
func NewEntDiscountCreator(client *dbent.Client) RechargeDiscountCreator {
	if client == nil {
		return nil
	}
	return &entDiscountCreator{client: client}
}

func (c *entDiscountCreator) CreateBindKeyDiscount(ctx context.Context, userID, apiKeyID int64, rate, maxAmount float64, validDays int, giftDeductionMode string, giftRatioRecharge *float64) (int64, error) {
	if rate <= 0 || rate > 10 || maxAmount <= 0 || validDays < 1 {
		return 0, fmt.Errorf("invalid discount params: rate=%f max=%f days=%d", rate, maxAmount, validDays)
	}

	// 归一化扣除策略（写入边界兜底，与 DB check 双重保障）。
	mode, ratio, err := domain.NormalizeGiftDeduction(giftDeductionMode, giftRatioRecharge)
	if err != nil {
		return 0, fmt.Errorf("invalid gift deduction config: %w", err)
	}
	var ratioArg any
	if ratio != nil {
		ratioArg = *ratio
	}

	now := time.Now()
	validUntil := now.Add(time.Duration(validDays) * 24 * time.Hour)
	sourceRef := "api_key:" + strconv.FormatInt(apiKeyID, 10)

	execer := c.execer(ctx)
	rows, err := execer.QueryContext(ctx, `
INSERT INTO user_recharge_discounts (user_id, source, source_ref, origin_api_key_id, discount_rate, max_discountable_amount, valid_from, valid_until, gift_deduction_mode, gift_ratio_recharge)
VALUES ($1, 'bind_key', $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (user_id, source, source_ref) DO NOTHING
RETURNING id`, userID, sourceRef, apiKeyID, rate, maxAmount, now, validUntil, mode, ratioArg)
	if err != nil {
		return 0, fmt.Errorf("insert user_recharge_discounts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var id int64
	if rows.Next() {
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		return id, rows.Close()
	}
	return 0, rows.Close() // ON CONFLICT → already exists
}

func (c *entDiscountCreator) execer(ctx context.Context) interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
} {
	if tx := dbent.TxFromContext(ctx); tx != nil {
		return tx.Client()
	}
	return c.client
}
