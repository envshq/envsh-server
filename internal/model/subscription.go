package model

import (
	"time"

	"github.com/google/uuid"
)

// Subscription tracks billing plan for a workspace.
type Subscription struct {
	ID                   uuid.UUID `db:"id"                     json:"id"`
	WorkspaceID          uuid.UUID `db:"workspace_id"           json:"workspace_id"`
	Plan                 string    `db:"plan"                   json:"plan"` // "free" or "team"
	SeatCount            int       `db:"seat_count"             json:"seat_count"`
	StripeCustomerID     *string   `db:"stripe_customer_id"     json:"-"`
	StripeSubscriptionID *string   `db:"stripe_subscription_id" json:"-"`
	Status               string    `db:"status"                 json:"status"`
	CreatedAt            time.Time `db:"created_at"             json:"created_at"`
}
