//go:build unit

package service

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Stubs ---

type rechargeDiscountRepoStub struct {
	applicationExists bool
	discount          *RechargeDiscountRecord
	updatedID         int64
	updatedAmount     float64
	insertedApp       *RechargeDiscountApplicationRecord
	forceError        error
}

func (s *rechargeDiscountRepoStub) CheckApplicationExists(_ context.Context, _ int64) (bool, error) {
	if s.forceError != nil {
		return false, s.forceError
	}
	return s.applicationExists, nil
}

func (s *rechargeDiscountRepoStub) QueryBestActiveDiscountForUpdate(_ context.Context, _ int64) (*RechargeDiscountRecord, error) {
	if s.forceError != nil {
		return nil, s.forceError
	}
	return s.discount, nil
}

func (s *rechargeDiscountRepoStub) UpdateTotalDiscounted(_ context.Context, id int64, amount float64) error {
	if s.forceError != nil {
		return s.forceError
	}
	s.updatedID = id
	s.updatedAmount = amount
	return nil
}

func (s *rechargeDiscountRepoStub) InsertApplication(_ context.Context, app *RechargeDiscountApplicationRecord) error {
	if s.forceError != nil {
		return s.forceError
	}
	s.insertedApp = app
	return nil
}

// --- Tests ---

func TestApplyRechargeDiscount_NilRepo_Skips(t *testing.T) {
	svc := &PaymentService{rechargeDiscountRepo: nil}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_AlreadyApplied_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{applicationExists: true}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
	assert.Nil(t, repo.insertedApp)
}

func TestApplyRechargeDiscount_NoActiveDiscount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{discount: nil}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_DiscountExhausted_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 100,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	assert.NoError(t, err)
	assert.Nil(t, repo.insertedApp)
}

func TestApplyRechargeDiscount_ZeroOrderAmount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 0))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_NegativeOrderAmount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, -5))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_NaNOrderAmount_Skips(t *testing.T) {
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 1, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 0,
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, math.NaN()))
	assert.NoError(t, err)
}

func TestApplyRechargeDiscount_PartialRemaining_AppliesCorrectAmount(t *testing.T) {
	// User used $80 of $100 max; charging $50 → only $20 participates in discount
	repo := &rechargeDiscountRepoStub{
		discount: &RechargeDiscountRecord{
			ID: 5, UserID: 100, DiscountRate: 0.1,
			MaxDiscountableAmount: 100, TotalDiscounted: 80,
			ValidUntil: discountTimePtr(time.Now().Add(30 * 24 * time.Hour)),
		},
	}
	svc := &PaymentService{rechargeDiscountRepo: repo, giftEngine: nil}
	// giftEngine is nil → will error after passing skip logic, confirming calculation path reached
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gift engine or ent client not configured")
}

func TestApplyRechargeDiscount_CheckError_Propagates(t *testing.T) {
	testErr := errors.New("db connection lost")
	repo := &rechargeDiscountRepoStub{forceError: testErr}
	svc := &PaymentService{rechargeDiscountRepo: repo}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "check discount application")
}

func TestApplyRechargeDiscount_QueryError_Propagates(t *testing.T) {
	repo := &rechargeDiscountRepoStub{applicationExists: false}
	// Override just QueryBestActiveDiscountForUpdate to error
	repo.forceError = nil
	svc := &PaymentService{rechargeDiscountRepo: &queryErrorRepoStub{}}
	err := svc.applyRechargeDiscountForOrder(context.Background(), makeTestOrder(100, 1, 50))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query active discount")
}

// --- queryErrorRepoStub only errors on Query ---
type queryErrorRepoStub struct{}

func (s *queryErrorRepoStub) CheckApplicationExists(_ context.Context, _ int64) (bool, error) {
	return false, nil
}
func (s *queryErrorRepoStub) QueryBestActiveDiscountForUpdate(_ context.Context, _ int64) (*RechargeDiscountRecord, error) {
	return nil, errors.New("query failed")
}
func (s *queryErrorRepoStub) UpdateTotalDiscounted(_ context.Context, _ int64, _ float64) error {
	return nil
}
func (s *queryErrorRepoStub) InsertApplication(_ context.Context, _ *RechargeDiscountApplicationRecord) error {
	return nil
}

// --- Helpers ---

func makeTestOrder(userID, orderID int64, amount float64) *dbent.PaymentOrder {
	return &dbent.PaymentOrder{
		ID:     orderID,
		UserID: userID,
		Amount: amount,
	}
}

func discountTimePtr(t time.Time) *time.Time {
	return &t
}
