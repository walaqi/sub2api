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
	enabled         bool
	claimed         bool
	claimedErr      error
	reservation     *keybind.ReservationResult
	reserveErr      error
	reserveCalled   int
	claimedCalled   int
	lastReserveAct  int64
	lastReserveUser int64
}

func (f *fakeKeyReserver) Enabled() bool { return f.enabled }

func (f *fakeKeyReserver) UserHasClaimedActivityKey(_ context.Context, _, _ int64) (bool, error) {
	f.claimedCalled++
	return f.claimed, f.claimedErr
}

func (f *fakeKeyReserver) ReserveForActivity(_ context.Context, activityID, userID int64) (*keybind.ReservationResult, error) {
	f.reserveCalled++
	f.lastReserveAct = activityID
	f.lastReserveUser = userID
	return f.reservation, f.reserveErr
}

// fakeReferralChecker is a hand-rolled ReferralBenefitChecker for gating tests.
type fakeReferralChecker struct {
	inherited bool
	err       error
	calls     int
}

func (f *fakeReferralChecker) HasInheritedReferralBenefits(_ context.Context, _ int64) (bool, error) {
	f.calls++
	return f.inherited, f.err
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
		require.Equal(t, int64(42), f.lastReserveUser)
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

	// Super-referral invitee gate: a user who already inherited invitee benefits
	// at registration must NOT get an activity key on top (would double-grant).
	t.Run("referral invitee -> gated out, no reserve", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: true, reservation: &keybind.ReservationResult{ReservationID: "x"}}
		ref := &fakeReferralChecker{inherited: true}
		s := &Service{keys: f, referral: ref}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusReferralInvitee, status)
		require.Nil(t, res)
		require.Equal(t, 1, ref.calls)
		require.Zero(t, f.claimedCalled, "must not check claim when gated as invitee")
		require.Zero(t, f.reserveCalled, "must not reserve for a referral invitee")
	})

	// Non-invitee (or plain affiliate invitee that inherited nothing) passes the
	// gate and proceeds to the normal reserve path.
	t.Run("not a referral invitee -> proceeds to reserve", func(t *testing.T) {
		want := &keybind.ReservationResult{ReservationID: "ok"}
		f := &fakeKeyReserver{enabled: true, reservation: want}
		ref := &fakeReferralChecker{inherited: false}
		s := &Service{keys: f, referral: ref}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusReserved, status)
		require.Same(t, want, res)
		require.Equal(t, 1, ref.calls)
		require.Equal(t, 1, f.reserveCalled)
	})

	// Fail closed: if the referral check errors we must NOT hand out a key,
	// since we can't rule out a double grant.
	t.Run("referral check error -> fail closed, gated as invitee", func(t *testing.T) {
		f := &fakeKeyReserver{enabled: true, reservation: &keybind.ReservationResult{ReservationID: "x"}}
		ref := &fakeReferralChecker{err: errors.New("db down")}
		s := &Service{keys: f, referral: ref}
		status, res := s.reserveActivityKey(ctx, 7, 42)
		require.Equal(t, KeyStatusReferralInvitee, status)
		require.Nil(t, res)
		require.Zero(t, f.reserveCalled, "must not reserve when referral status is unknown")
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
