package model

import (
	"time"

	"github.com/google/uuid"
)

// User represents a registered user account.
type User struct {
	ID        uuid.UUID  `db:"id"         json:"id"`
	Email     string     `db:"email"      json:"email"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
	DeletedAt *time.Time `db:"deleted_at" json:"-"`
}
