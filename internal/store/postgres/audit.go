package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogStore implements store.AuditLogStore using PostgreSQL.
// This store is insert-only. Never update or delete.
type AuditLogStore struct {
	db *pgxpool.Pool
}

// NewAuditLogStore creates a new AuditLogStore.
func NewAuditLogStore(db *pgxpool.Pool) *AuditLogStore {
	return &AuditLogStore{db: db}
}

// genesisHash is the prev_hash for the very first audit log entry.
const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// AppendAuditLog inserts a new audit log entry, computing its prev_hash from the last entry.
// This is the only write method; no updates or deletes are ever allowed.
func (s *AuditLogStore) AppendAuditLog(ctx context.Context, entry *model.AuditLog) error {
	// Determine prev_hash from the last entry in this workspace.
	last, err := s.GetLastAuditLog(ctx, entry.WorkspaceID)
	var prevHash string
	if errors.Is(err, store.ErrNotFound) {
		// First entry for this workspace — use genesis hash.
		prevHash = genesisHash
	} else if err != nil {
		return fmt.Errorf("getting last audit log: %w", err)
	} else {
		// Chain: SHA-256(last.ID + last.PrevHash)
		h := sha256.Sum256([]byte(last.ID.String() + last.PrevHash))
		prevHash = hex.EncodeToString(h[:])
	}

	entry.ID = uuid.New()
	entry.PrevHash = prevHash

	// Serialize metadata map to JSON for the JSONB column.
	var metadataJSON []byte
	if entry.Metadata != nil {
		metadataJSON, err = json.Marshal(entry.Metadata)
		if err != nil {
			return fmt.Errorf("marshaling audit log metadata: %w", err)
		}
	}

	_, err = s.db.Exec(ctx,
		`INSERT INTO audit_log (
			id, workspace_id, actor_type, actor_id,
			action, resource_type, resource_id,
			metadata, ip_address, prev_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		entry.ID, entry.WorkspaceID, entry.ActorType, entry.ActorID,
		entry.Action, entry.ResourceType, entry.ResourceID,
		metadataJSON, entry.IPAddress, entry.PrevHash,
	)
	if err != nil {
		return fmt.Errorf("inserting audit log entry: %w", err)
	}
	return nil
}

// ListAuditLogs returns paginated audit log entries for a workspace in descending time order.
func (s *AuditLogStore) ListAuditLogs(ctx context.Context, workspaceID uuid.UUID, limit, offset int) ([]model.AuditLog, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, workspace_id, actor_type, actor_id,
			action, resource_type, resource_id,
			metadata, ip_address, prev_hash, created_at
		 FROM audit_log
		 WHERE workspace_id = $1
		 ORDER BY created_at DESC
		 LIMIT $2 OFFSET $3`,
		workspaceID, limit, offset,
	)
	if err != nil {
		return nil, fmt.Errorf("listing audit logs: %w", err)
	}
	defer rows.Close()

	var entries []model.AuditLog
	for rows.Next() {
		e, err := scanAuditLog(rows)
		if err != nil {
			return nil, fmt.Errorf("scanning audit log: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit logs: %w", err)
	}
	return entries, nil
}

// GetLastAuditLog returns the most recent audit log entry for a workspace.
// Returns store.ErrNotFound if no entries exist.
func (s *AuditLogStore) GetLastAuditLog(ctx context.Context, workspaceID uuid.UUID) (*model.AuditLog, error) {
	row := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, actor_type, actor_id,
			action, resource_type, resource_id,
			metadata, ip_address, prev_hash, created_at
		 FROM audit_log
		 WHERE workspace_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`,
		workspaceID,
	)
	e, err := scanAuditLog(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting last audit log: %w", err)
	}
	return &e, nil
}

// scannable is satisfied by both pgx.Row and pgx.Rows.
type scannable interface {
	Scan(dest ...any) error
}

// scanAuditLog scans a single audit_log row into a model.AuditLog.
// It handles the JSONB metadata column by first scanning into []byte.
func scanAuditLog(row scannable) (model.AuditLog, error) {
	var e model.AuditLog
	var metadataRaw []byte
	err := row.Scan(
		&e.ID, &e.WorkspaceID, &e.ActorType, &e.ActorID,
		&e.Action, &e.ResourceType, &e.ResourceID,
		&metadataRaw, &e.IPAddress, &e.PrevHash, &e.CreatedAt,
	)
	if err != nil {
		return model.AuditLog{}, err
	}
	if metadataRaw != nil {
		if err := json.Unmarshal(metadataRaw, &e.Metadata); err != nil {
			return model.AuditLog{}, fmt.Errorf("unmarshaling audit log metadata: %w", err)
		}
	}
	return e, nil
}
