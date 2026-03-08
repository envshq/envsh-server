package model

import (
	"time"

	"github.com/google/uuid"
)

// SSHKey represents a registered SSH public key for a user.
type SSHKey struct {
	ID          uuid.UUID  `db:"id"          json:"id"`
	UserID      uuid.UUID  `db:"user_id"     json:"user_id"`
	PublicKey   string     `db:"public_key"  json:"public_key"`
	KeyType     string     `db:"key_type"    json:"key_type"` // "ed25519" or "rsa4096"
	Fingerprint string     `db:"fingerprint" json:"fingerprint"`
	Label       *string    `db:"label"       json:"label,omitempty"`
	CreatedAt   time.Time  `db:"created_at"  json:"created_at"`
	RevokedAt   *time.Time `db:"revoked_at"  json:"revoked_at,omitempty"`
}
