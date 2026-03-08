package model

import (
	"time"

	"github.com/google/uuid"
)

// AuditLog represents an immutable audit log entry. Never update or delete.
type AuditLog struct {
	ID           uuid.UUID      `db:"id"            json:"id"`
	WorkspaceID  uuid.UUID      `db:"workspace_id"  json:"workspace_id"`
	ActorType    string         `db:"actor_type"    json:"actor_type"` // "user" or "machine"
	ActorID      uuid.UUID      `db:"actor_id"      json:"actor_id"`
	Action       string         `db:"action"        json:"action"`
	ResourceType string         `db:"resource_type" json:"resource_type"`
	ResourceID   *uuid.UUID     `db:"resource_id"   json:"resource_id,omitempty"`
	Metadata     map[string]any `db:"metadata"      json:"metadata,omitempty"`
	IPAddress    *string        `db:"ip_address"    json:"ip_address,omitempty"`
	PrevHash     string         `db:"prev_hash"     json:"prev_hash"`
	CreatedAt    time.Time      `db:"created_at"    json:"created_at"`
}
