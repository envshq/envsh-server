package model

import (
	"time"

	"github.com/google/uuid"
)

// Machine represents a CI/CD or automation identity scoped to one project+environment.
type Machine struct {
	ID             uuid.UUID  `db:"id"              json:"id"`
	WorkspaceID    uuid.UUID  `db:"workspace_id"    json:"workspace_id"`
	Name           string     `db:"name"            json:"name"`
	Slug           string     `db:"slug"            json:"slug"`
	PublicKey      string     `db:"public_key"      json:"public_key"`
	KeyFingerprint string     `db:"key_fingerprint" json:"key_fingerprint"`
	ProjectID      uuid.UUID  `db:"project_id"      json:"project_id"`
	Environment    string     `db:"environment"     json:"environment"`
	Status         string     `db:"status"          json:"status"` // "active" or "revoked"
	CreatedBy      uuid.UUID  `db:"created_by"      json:"created_by"`
	CreatedAt      time.Time  `db:"created_at"      json:"created_at"`
	RevokedAt      *time.Time `db:"revoked_at"      json:"revoked_at,omitempty"`
}
