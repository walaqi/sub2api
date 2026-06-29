package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

var (
	ErrInvalidInput      = errors.New("invalid activity input")
	ErrEventNotAvailable = errors.New("activity event is not available")
)

type Service struct {
	repo *Repository
}

func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

func (s *Service) ListActiveEvents(ctx context.Context, userID int64) ([]Event, error) {
	return s.repo.ListActiveEvents(ctx, userID)
}

func (s *Service) Signup(ctx context.Context, activityID, userID int64, receiveEmail string) (*Signup, error) {
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
	return signup, nil
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
