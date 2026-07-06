package activity

import (
	"time"

	"github.com/Wei-Shaw/sub2api/internal/keybind"
)

// Key reservation outcome codes returned alongside a signup. They let the
// frontend decide whether to redirect the user to the bind-gift page.
const (
	// KeyStatusReserved: a pool key was reserved; Reservation is populated and
	// the client should redirect to /bind-key?reservation=<id> to commit.
	KeyStatusReserved = "reserved"
	// KeyStatusAlreadyClaimed: the user already claimed this activity's key
	// (signup is idempotent, key grant is once-per-user-per-activity).
	KeyStatusAlreadyClaimed = "already_claimed"
	// KeyStatusNoKeyAvailable: the activity has no free key left to reserve
	// (or none configured). Signup still succeeded.
	KeyStatusNoKeyAvailable = "no_key_available"
	// KeyStatusDisabled: the key-pool feature is not wired/enabled; signup
	// behaves as a plain email registration with no key.
	KeyStatusDisabled = "disabled"
)

// SignupResult is the service-level outcome of a signup: the persisted signup
// plus whether a pool key was reserved for the user.
type SignupResult struct {
	Signup      *Signup
	KeyStatus   string
	Reservation *keybind.ReservationResult
}

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
