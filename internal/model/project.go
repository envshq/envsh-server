package model

import (
	"time"

	"github.com/google/uuid"
)

// Project is a collection of secrets scoped to a workspace.
type Project struct {
	ID          uuid.UUID `db:"id"           json:"id"`
	WorkspaceID uuid.UUID `db:"workspace_id" json:"workspace_id"`
	Name        string    `db:"name"         json:"name"`
	Slug        string    `db:"slug"         json:"slug"`
	CreatedBy   uuid.UUID `db:"created_by"   json:"created_by"`
	CreatedAt   time.Time `db:"created_at"   json:"created_at"`
}
