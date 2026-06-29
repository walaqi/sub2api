package activity

import "time"

type Event struct {
	ID           int64      `json:"id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	Status       string     `json:"status,omitempty"`
	StartsAt     time.Time  `json:"starts_at"`
	EndsAt       *time.Time `json:"ends_at,omitempty"`
	SignedUp     bool       `json:"signed_up"`
	ReceiveEmail *string    `json:"receive_email,omitempty"`
}

type Signup struct {
	ID           int64     `json:"id"`
	ActivityID   int64     `json:"activity_id"`
	UserID       int64     `json:"user_id"`
	Username     string    `json:"username"`
	ReceiveEmail string    `json:"receive_email"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type CreateEventInput struct {
	Name        string
	Description string
	StartsAt    *time.Time
	EndsAt      *time.Time
}

type UpdateEventInput struct {
	ID          int64
	Name        string
	Description string
	Status      string
	StartsAt    *time.Time
	EndsAt      *time.Time
	ClearEndsAt bool
}
