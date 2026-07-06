package activity

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

type sqlClient interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type Repository struct {
	db sqlClient
}

func NewRepository(db sqlClient) *Repository {
	return &Repository{db: db}
}

func (r *Repository) ListActiveEvents(ctx context.Context, userID int64) (_ []Event, err error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT e.id, e.name, e.description, e.status, e.starts_at, e.ends_at,
       s.receive_email IS NOT NULL AS signed_up, s.receive_email
FROM activity_events e
LEFT JOIN activity_signups s ON s.activity_id = e.id AND s.user_id = $1
WHERE e.status = 'active'
  AND e.starts_at <= NOW()
  AND (e.ends_at IS NULL OR e.ends_at > NOW())
ORDER BY e.starts_at DESC, e.id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	var events []Event
	for rows.Next() {
		var item Event
		var receiveEmail sql.NullString
		if err := rows.Scan(&item.ID, &item.Name, &item.Description, &item.Status, &item.StartsAt, &item.EndsAt, &item.SignedUp, &receiveEmail); err != nil {
			return nil, err
		}
		if receiveEmail.Valid {
			v := receiveEmail.String
			item.ReceiveEmail = &v
		}
		events = append(events, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return events, nil
}

func (r *Repository) UpsertSignup(ctx context.Context, activityID, userID int64, receiveEmail string) (_ *Signup, err error) {
	rows, err := r.db.QueryContext(ctx, `
WITH active_event AS (
    SELECT id
    FROM activity_events
    WHERE id = $1
      AND status = 'active'
      AND starts_at <= NOW()
      AND (ends_at IS NULL OR ends_at > NOW())
), upserted AS (
    INSERT INTO activity_signups (activity_id, user_id, receive_email, created_at, updated_at)
    SELECT id, $2, $3, NOW(), NOW()
    FROM active_event
    ON CONFLICT (activity_id, user_id)
    DO UPDATE SET receive_email = EXCLUDED.receive_email, updated_at = NOW()
    RETURNING id, activity_id, user_id, receive_email, created_at, updated_at
)
SELECT s.id, s.activity_id, s.user_id, COALESCE(NULLIF(u.username, ''), u.email) AS username,
       s.receive_email, s.created_at, s.updated_at
FROM upserted s
JOIN users u ON u.id = s.user_id`, activityID, userID, receiveEmail)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, sql.ErrNoRows
	}

	var signup Signup
	if err := rows.Scan(&signup.ID, &signup.ActivityID, &signup.UserID, &signup.Username, &signup.ReceiveEmail, &signup.CreatedAt, &signup.UpdatedAt); err != nil {
		return nil, err
	}
	return &signup, nil
}

func (r *Repository) CreateEvent(ctx context.Context, input CreateEventInput) (_ int64, err error) {
	rows, err := r.db.QueryContext(ctx, `
INSERT INTO activity_events (name, description, status, starts_at, ends_at, created_at, updated_at)
VALUES ($1, $2, 'active', COALESCE($3, NOW()), $4, NOW(), NOW())
RETURNING id`, input.Name, input.Description, input.StartsAt, input.EndsAt)
	if err != nil {
		return 0, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return 0, err
		}
		return 0, errors.New("activity event insert returned no id")
	}

	var id int64
	if err := rows.Scan(&id); err != nil {
		return 0, err
	}
	return id, nil
}

func (r *Repository) UpdateEvent(ctx context.Context, input UpdateEventInput) (_ *Event, err error) {
	rows, err := r.db.QueryContext(ctx, `
UPDATE activity_events
SET name = $2,
    description = $3,
    status = $4,
    starts_at = COALESCE($5, starts_at),
    ends_at = CASE WHEN $6 THEN NULL ELSE COALESCE($7, ends_at) END,
    updated_at = NOW()
WHERE id = $1
RETURNING id, name, description, status, starts_at, ends_at`, input.ID, input.Name, input.Description, input.Status, input.StartsAt, input.ClearEndsAt, input.EndsAt)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, sql.ErrNoRows
	}

	var event Event
	if err := rows.Scan(&event.ID, &event.Name, &event.Description, &event.Status, &event.StartsAt, &event.EndsAt); err != nil {
		return nil, err
	}
	return &event, nil
}

func (r *Repository) ListSignups(ctx context.Context, activityID int64) (_ []Signup, err error) {
	rows, err := r.db.QueryContext(ctx, `
SELECT s.id, s.activity_id, s.user_id, COALESCE(NULLIF(u.username, ''), u.email) AS username,
       s.receive_email, s.created_at, s.updated_at
FROM activity_signups s
JOIN users u ON u.id = s.user_id
WHERE s.activity_id = $1
ORDER BY s.created_at ASC, s.id ASC`, activityID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	var signups []Signup
	for rows.Next() {
		var item Signup
		if err := rows.Scan(&item.ID, &item.ActivityID, &item.UserID, &item.Username, &item.ReceiveEmail, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		signups = append(signups, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return signups, nil
}

// HasInheritedReferralBenefits reports whether userID already received
// super-referral invitee benefits at registration. It is TRUE when EITHER:
//   - referral_reward_tracker.invitee_reward_granted = TRUE (the invitee
//     registration gift was actually granted), OR
//   - a user_recharge_discounts row with source='referral_inherit' exists for
//     the user (the inviter's recharge discount was inherited).
//
// Both signals are checked because OnInviterBound performs the two side effects
// INDEPENDENTLY and does not stop if the first fails: grantInviteeReward errors
// are only logged, then inheritDiscountFromInviter still runs (see
// referral_reward_service.go OnInviterBound). So a user can end up with an
// inherited discount while invitee_reward_granted stays FALSE. Keying the gate
// on the granted flag alone would let that user grab an activity key and stack
// the inherited (30-day, higher-value) discount on top — exactly what this gate
// must prevent. The OR closes that window.
//
// It still does NOT catch users who inherited nothing: plain affiliate invitees
// whose inviter lacked super-referral eligibility (no gift, no discount row) and
// invitees bound while the global reward switch was off. Those remain eligible
// for activity keys.
func (r *Repository) HasInheritedReferralBenefits(ctx context.Context, userID int64) (_ bool, err error) {
	if userID <= 0 {
		return false, nil
	}
	rows, err := r.db.QueryContext(ctx, `
SELECT
  EXISTS (
    SELECT 1 FROM referral_reward_tracker
    WHERE invitee_id = $1 AND invitee_reward_granted = TRUE
  )
  OR EXISTS (
    SELECT 1 FROM user_recharge_discounts
    WHERE user_id = $1 AND source = 'referral_inherit'
  )`, userID)
	if err != nil {
		return false, fmt.Errorf("query referral invitee benefits: %w", err)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return false, err
		}
		return false, nil
	}
	var has bool
	if err := rows.Scan(&has); err != nil {
		return false, err
	}
	return has, rows.Err()
}

func normalizeText(s string) string {
	return strings.TrimSpace(s)
}

func validateWindow(input CreateEventInput) error {
	if input.StartsAt != nil && input.EndsAt != nil && !input.EndsAt.After(*input.StartsAt) {
		return fmt.Errorf("ends_at must be after starts_at")
	}
	return nil
}
