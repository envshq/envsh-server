package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/store"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MachineStore implements store.MachineStore using PostgreSQL.
type MachineStore struct {
	db *pgxpool.Pool
}

// NewMachineStore creates a new MachineStore.
func NewMachineStore(db *pgxpool.Pool) *MachineStore {
	return &MachineStore{db: db}
}

// CreateMachine inserts a new machine identity.
// Returns store.ErrDuplicateSlug on slug/public_key/fingerprint conflict.
func (s *MachineStore) CreateMachine(ctx context.Context, m *model.Machine) (*model.Machine, error) {
	m.ID = uuid.New()
	var created model.Machine
	err := s.db.QueryRow(ctx,
		`INSERT INTO machines (
			id, workspace_id, name, slug, public_key, key_fingerprint,
			project_id, environment, status, created_by
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, workspace_id, name, slug, public_key, key_fingerprint,
			project_id, environment, status, created_by, created_at, revoked_at`,
		m.ID, m.WorkspaceID, m.Name, m.Slug, m.PublicKey, m.KeyFingerprint,
		m.ProjectID, m.Environment, m.Status, m.CreatedBy,
	).Scan(
		&created.ID, &created.WorkspaceID, &created.Name, &created.Slug,
		&created.PublicKey, &created.KeyFingerprint,
		&created.ProjectID, &created.Environment, &created.Status,
		&created.CreatedBy, &created.CreatedAt, &created.RevokedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrDuplicateSlug
		}
		return nil, fmt.Errorf("creating machine: %w", err)
	}
	return &created, nil
}

// GetMachineByID returns a machine by primary key.
// Returns store.ErrNotFound if not found.
func (s *MachineStore) GetMachineByID(ctx context.Context, id uuid.UUID) (*model.Machine, error) {
	var m model.Machine
	err := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, name, slug, public_key, key_fingerprint,
			project_id, environment, status, created_by, created_at, revoked_at
		 FROM machines WHERE id = $1`,
		id,
	).Scan(
		&m.ID, &m.WorkspaceID, &m.Name, &m.Slug,
		&m.PublicKey, &m.KeyFingerprint,
		&m.ProjectID, &m.Environment, &m.Status,
		&m.CreatedBy, &m.CreatedAt, &m.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting machine by id: %w", err)
	}
	return &m, nil
}

// GetMachineBySlug returns a machine by slug within a workspace.
// Returns store.ErrNotFound if not found.
func (s *MachineStore) GetMachineBySlug(ctx context.Context, workspaceID uuid.UUID, slug string) (*model.Machine, error) {
	var m model.Machine
	err := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, name, slug, public_key, key_fingerprint,
			project_id, environment, status, created_by, created_at, revoked_at
		 FROM machines WHERE workspace_id = $1 AND slug = $2`,
		workspaceID, slug,
	).Scan(
		&m.ID, &m.WorkspaceID, &m.Name, &m.Slug,
		&m.PublicKey, &m.KeyFingerprint,
		&m.ProjectID, &m.Environment, &m.Status,
		&m.CreatedBy, &m.CreatedAt, &m.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting machine by slug: %w", err)
	}
	return &m, nil
}

// GetMachineByFingerprint returns a machine by its key fingerprint.
// Returns store.ErrNotFound if not found.
func (s *MachineStore) GetMachineByFingerprint(ctx context.Context, fingerprint string) (*model.Machine, error) {
	var m model.Machine
	err := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, name, slug, public_key, key_fingerprint,
			project_id, environment, status, created_by, created_at, revoked_at
		 FROM machines WHERE key_fingerprint = $1`,
		fingerprint,
	).Scan(
		&m.ID, &m.WorkspaceID, &m.Name, &m.Slug,
		&m.PublicKey, &m.KeyFingerprint,
		&m.ProjectID, &m.Environment, &m.Status,
		&m.CreatedBy, &m.CreatedAt, &m.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting machine by fingerprint: %w", err)
	}
	return &m, nil
}

// ListMachines returns all machines in a workspace.
func (s *MachineStore) ListMachines(ctx context.Context, workspaceID uuid.UUID) ([]model.Machine, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, workspace_id, name, slug, public_key, key_fingerprint,
			project_id, environment, status, created_by, created_at, revoked_at
		 FROM machines WHERE workspace_id = $1
		 ORDER BY created_at ASC`,
		workspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing machines: %w", err)
	}
	defer rows.Close()

	var machines []model.Machine
	for rows.Next() {
		var m model.Machine
		if err := rows.Scan(
			&m.ID, &m.WorkspaceID, &m.Name, &m.Slug,
			&m.PublicKey, &m.KeyFingerprint,
			&m.ProjectID, &m.Environment, &m.Status,
			&m.CreatedBy, &m.CreatedAt, &m.RevokedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning machine: %w", err)
		}
		machines = append(machines, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating machines: %w", err)
	}
	return machines, nil
}

// RevokeMachine sets a machine's status to "revoked" and records the timestamp.
func (s *MachineStore) RevokeMachine(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE machines SET status = 'revoked', revoked_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("revoking machine: %w", err)
	}
	return nil
}
