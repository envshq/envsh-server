package model

import (
	"time"

	"github.com/google/uuid"
)

// Workspace is the top-level organizational unit. One per user account.
type Workspace struct {
	ID        uuid.UUID `db:"id"         json:"id"`
	OwnerID   uuid.UUID `db:"owner_id"   json:"owner_id"`
	Name      string    `db:"name"       json:"name"`
	Slug      string    `db:"slug"       json:"slug"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// WorkspaceMembership is a workspace with the user's role, used for listing a user's workspaces.
type WorkspaceMembership struct {
	WorkspaceID uuid.UUID `json:"workspace_id"`
	OwnerID     uuid.UUID `json:"owner_id"`
	Name        string    `json:"name"`
	Slug        string    `json:"slug"`
	Role        string    `json:"role"`
	CreatedAt   time.Time `json:"created_at"`
}

// WorkspaceMember represents a user's membership in a workspace.
type WorkspaceMember struct {
	ID          uuid.UUID  `db:"id"           json:"id"`
	WorkspaceID uuid.UUID  `db:"workspace_id" json:"workspace_id"`
	UserID      uuid.UUID  `db:"user_id"      json:"user_id"`
	Role        string     `db:"role"         json:"role"` // "admin" or "member"
	InvitedBy   *uuid.UUID `db:"invited_by"   json:"invited_by,omitempty"`
	JoinedAt    time.Time  `db:"joined_at"    json:"joined_at"`
	// Joined from users table (not a DB column on workspace_members):
	Email string `db:"-" json:"email,omitempty"`
}
