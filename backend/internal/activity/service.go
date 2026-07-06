package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/mail"
	"strings"

	"github.com/Wei-Shaw/sub2api/internal/keybind"
)

var (
	ErrInvalidInput      = errors.New("invalid activity input")
	ErrEventNotAvailable = errors.New("activity event is not available")
)

// KeyReserver is the subset of the keybind service the activity feature needs
// to hand a pool key to a user who signs up. Kept as an interface so the
// service can be unit-tested without a live keybind/Redis stack, and so a nil
// dependency (feature disabled) degrades to a plain email signup.
type KeyReserver interface {
	// Enabled reports whether the underlying key-pool feature is operational.
	Enabled() bool
	// UserHasClaimedActivityKey reports whether the user already owns a key
	// tied to this activity (grant is once-per-user-per-activity).
	UserHasClaimedActivityKey(ctx context.Context, userID, activityID int64) (bool, error)
	// ReserveForActivity locks one claimable pool key for this activity and
	// returns the reservation the client uses to commit at /bind-key.
	ReserveForActivity(ctx context.Context, activityID int64) (*keybind.ReservationResult, error)
}

type Service struct {
	repo *Repository
	// keys is optional. When nil (or its Enabled() is false), signup succeeds
	// without reserving a key (KeyStatusDisabled).
	keys KeyReserver
}

func NewService(repo *Repository, keys KeyReserver) *Service {
	return &Service{repo: repo, keys: keys}
}

func (s *Service) ListActiveEvents(ctx context.Context, userID int64) ([]Event, error) {
	return s.repo.ListActiveEvents(ctx, userID)
}

func (s *Service) Signup(ctx context.Context, activityID, userID int64, receiveEmail string) (*SignupResult, error) {
	email, ok := normalizeEmail(receiveEmail)
	if !ok {
		return nil, ErrInvalidInput
	}

	signup, err := s.repo.UpsertSignup(ctx, activityID, userID, email)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEventNotAvailable
	}
	if err != nil {
		return nil, err
	}

	res := &SignupResult{Signup: signup}
	res.KeyStatus, res.Reservation = s.reserveActivityKey(ctx, activityID, userID)
	return res, nil
}

// reserveActivityKey tries to hand the signed-up user a pool key for this
// activity. It never fails the signup: any error degrades to "no key" so the
// user still gets their signup recorded. The returned status tells the client
// whether (and how) to route the user to the bind-gift page.
//
// Ordering matters: we short-circuit on an already-claimed key BEFORE calling
// ReserveForActivity, so a user re-submitting the form (idempotent signup)
// doesn't lock a second key they can't use.
func (s *Service) reserveActivityKey(ctx context.Context, activityID, userID int64) (string, *keybind.ReservationResult) {
	if s.keys == nil || !s.keys.Enabled() {
		return KeyStatusDisabled, nil
	}

	claimed, err := s.keys.UserHasClaimedActivityKey(ctx, userID, activityID)
	if err != nil {
		log.Printf("[activity] check claimed key for user %d activity %d failed: %v", userID, activityID, err)
		return KeyStatusNoKeyAvailable, nil
	}
	if claimed {
		return KeyStatusAlreadyClaimed, nil
	}

	reservation, err := s.keys.ReserveForActivity(ctx, activityID)
	if err != nil {
		if errors.Is(err, keybind.ErrNoActivityKey) {
			return KeyStatusNoKeyAvailable, nil
		}
		log.Printf("[activity] reserve key for user %d activity %d failed: %v", userID, activityID, err)
		return KeyStatusNoKeyAvailable, nil
	}
	return KeyStatusReserved, reservation
}

func (s *Service) CreateEvent(ctx context.Context, input CreateEventInput) (int64, error) {
	input.Name = normalizeText(input.Name)
	input.Description = normalizeText(input.Description)
	if input.Name == "" || input.Description == "" {
		return 0, ErrInvalidInput
	}
	if err := validateWindow(input); err != nil {
		return 0, ErrInvalidInput
	}
	return s.repo.CreateEvent(ctx, input)
}

func (s *Service) UpdateEvent(ctx context.Context, input UpdateEventInput) (*Event, error) {
	input.Name = normalizeText(input.Name)
	input.Description = normalizeText(input.Description)
	input.Status = strings.ToLower(normalizeText(input.Status))
	if input.ID <= 0 || input.Name == "" || input.Description == "" {
		return nil, ErrInvalidInput
	}
	if input.Status == "" {
		input.Status = "active"
	}
	if input.Status != "active" && input.Status != "disabled" {
		return nil, ErrInvalidInput
	}
	if err := validateUpdateWindow(input); err != nil {
		return nil, ErrInvalidInput
	}

	event, err := s.repo.UpdateEvent(ctx, input)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrEventNotAvailable
	}
	if err != nil {
		return nil, err
	}
	return event, nil
}

func (s *Service) ListSignups(ctx context.Context, activityID int64) ([]Signup, error) {
	return s.repo.ListSignups(ctx, activityID)
}

func normalizeEmail(value string) (string, bool) {
	email := strings.TrimSpace(value)
	if email == "" || len(email) > 255 {
		return "", false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", false
	}
	return email, true
}

func validateUpdateWindow(input UpdateEventInput) error {
	if input.StartsAt != nil && input.EndsAt != nil && !input.ClearEndsAt && !input.EndsAt.After(*input.StartsAt) {
		return fmt.Errorf("ends_at must be after starts_at")
	}
	return nil
}
