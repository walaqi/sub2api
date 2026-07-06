//go:build unit

package activity

import (
	"context"
	"errors"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/keybind"
	"github.com/stretchr/testify/require"
)

// fakeKeyReserver is a hand-rolled KeyReserver for exercising the activity
// service's key-grant orchestration without a live keybind/Redis stack.
type fakeKeyReserver struct {
	enabled        bool
	claimed        bool
	claimedErr     error
	reservation    *keybind.ReservationResult
	reserveErr     error
	reserveCalled  int
	claimedCalled  int
	lastReserveAct int64
}

func (f *fakeKeyReserver) Enabled() bool { return f.enabled }

func (f *fakeKeyReserver) UserHasClaimedActivityKey(_ context.Context, _, _ int64) (bool, error) {
	f.claimedCalled++
	return f.claimed, f.claimedErr
}

func (f *fakeKeyReserver) ReserveForActivity(_ context.Context, activityID int64) (*keybind.ReservationResult, error) {
	f.reserveCalled++
	f.lastReserveAct = activityID
	return f.reservation, f.reserveErr
}

func TestReserveActivityKey(t *testing.T) {
	ctx := context.Background()

	t.Run("nil reserver -> disabled, no calls", func(t *testing.T) {
		s := &Service{keys: nil}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusDisabled, status)
		require.Nil(t, res)
	})

	t.Run("disabled reserver -> disabled", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: false}
		s := &Service{keys: f}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusDisabled, status)
		require.Nil(t, res)
		require.Zero(t, f.claimedCalled)
		require.Zero(t, f.reserveCalled)
	})

	t.Run("already claimed -> no reserve attempt", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: true, claimed: true}
		s := &Service{keys: f}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusAlreadyClaimed, status)
		require.Nil(t, res)
		require.Equal(t, 1, f.claimedCalled)
		require.Zero(t, f.reserveCalled, "must not reserve when already claimed")
	})

	t.Run("claimed check errors -> degrade to no key, no reserve", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: true, claimedErr: errors.New("db down")}
		s := &Service{keys: f}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusNoKeyAvailable, status)
		require.Nil(t, res)
		require.Zero(t, f.reserveCalled)
	})

	t.Run("reserve success -> reserved with reservation", func(t *testing.T) {
		want := &keybind.ReservationResult{ReservationID: "abc", MaskedKey: "sk-***1234"}
		f := &fakeKeyReserver{enabled: true, reservation: want}
		s := &Service{keys: f}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusReserved, status)
		require.Same(t, want, res)
		require.Equal(t, int64(7), f.lastReserveAct)
	})

	t.Run("no key available -> no_key_available", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: true, reserveErr: keybind.ErrNoActivityKey}
		s := &Service{keys: f}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusNoKeyAvailable, status)
		require.Nil(t, res)
	})

	t.Run("unexpected reserve error -> degrade to no_key_available", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: true, reserveErr: errors.New("redis boom")}
		s := &Service{keys: f}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusNoKeyAvailable, status)
		require.Nil(t, res)
	})
}

func TestNewSignupResponse(t *testing.T) {
	t.Run("nil result", func(t *testing.T) {
		out := newSignupResponse(nil)
		require.Empty(t, out.KeyStatus)
		require.Nil(t, out.Reservation)
	})

	t.Run("reserved carries reservation dto", func(t *testing.T) {
		out := newSignupResponse(&SignupResult{
			Signup:    &Signup{ID: 1},
			KeyStatus: KeyStatusReserved,
			Reservation: &keybind.ReservationResult{
				ReservationID:   "rid",
				MaskedKey:       "sk-***9",
				ExpiresAtUnixMs: 123,
				RemainingQuota:  50,
			},
		})
		require.Equal(t, KeyStatusReserved, out.KeyStatus)
		require.NotNil(t, out.Reservation)
		require.Equal(t, "rid", out.Reservation.ReservationID)
		require.Equal(t, int64(123), out.Reservation.ExpiresAtUnixMs)
	})

	t.Run("no key -> no reservation dto", func(t *testing.T) {
		out := newSignupResponse(&SignupResult{
			Signup:    &Signup{ID: 2},
			KeyStatus: KeyStatusNoKeyAvailable,
		})
		require.Equal(t, KeyStatusNoKeyAvailable, out.KeyStatus)
		require.Nil(t, out.Reservation)
	})
}
