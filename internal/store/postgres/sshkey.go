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

// KeyStore implements store.KeyStore using PostgreSQL.
type KeyStore struct {
	db *pgxpool.Pool
}

// NewKeyStore creates a new KeyStore.
func NewKeyStore(db *pgxpool.Pool) *KeyStore {
	return &KeyStore{db: db}
}

// RegisterKey registers a new SSH public key for a user.
// Returns store.ErrDuplicateKey if the fingerprint is already registered.
func (s *KeyStore) RegisterKey(ctx context.Context, userID uuid.UUID, publicKey, keyType, fingerprint string, label *string) (*model.SSHKey, error) {
	id := uuid.New()
	var k model.SSHKey
	err := s.db.QueryRow(ctx,
		`INSERT INTO ssh_keys (id, user_id, public_key, key_type, fingerprint, label)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, user_id, public_key, key_type, fingerprint, label, created_at, revoked_at`,
		id, userID, publicKey, keyType, fingerprint, label,
	).Scan(&k.ID, &k.UserID, &k.PublicKey, &k.KeyType, &k.Fingerprint, &k.Label, &k.CreatedAt, &k.RevokedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrDuplicateKey
		}
		return nil, fmt.Errorf("registering ssh key: %w", err)
	}
	return &k, nil
}

// GetKeyByFingerprint returns a key by its fingerprint.
// Returns store.ErrNotFound if not found.
func (s *KeyStore) GetKeyByFingerprint(ctx context.Context, fingerprint string) (*model.SSHKey, error) {
	var k model.SSHKey
	err := s.db.QueryRow(ctx,
		`SELECT id, user_id, public_key, key_type, fingerprint, label, created_at, revoked_at
		 FROM ssh_keys WHERE fingerprint = $1`,
		fingerprint,
	).Scan(&k.ID, &k.UserID, &k.PublicKey, &k.KeyType, &k.Fingerprint, &k.Label, &k.CreatedAt, &k.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting ssh key by fingerprint: %w", err)
	}
	return &k, nil
}

// ListKeys returns all SSH keys for a user (including revoked).
func (s *KeyStore) ListKeys(ctx context.Context, userID uuid.UUID) ([]model.SSHKey, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, user_id, public_key, key_type, fingerprint, label, created_at, revoked_at
		 FROM ssh_keys WHERE user_id = $1
		 ORDER BY created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing ssh keys: %w", err)
	}
	defer rows.Close()

	var keys []model.SSHKey
	for rows.Next() {
		var k model.SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.KeyType, &k.Fingerprint, &k.Label, &k.CreatedAt, &k.RevokedAt); err != nil {
			return nil, fmt.Errorf("scanning ssh key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating ssh keys: %w", err)
	}
	return keys, nil
}

// ListKeysByWorkspace returns all non-revoked SSH keys for all members of a workspace.
func (s *KeyStore) ListKeysByWorkspace(ctx context.Context, workspaceID uuid.UUID) ([]model.SSHKey, error) {
	rows, err := s.db.Query(ctx,
		`SELECT k.id, k.user_id, k.public_key, k.key_type, k.fingerprint, k.label, k.created_at, k.revoked_at
		 FROM ssh_keys k
		 JOIN workspace_members wm ON wm.user_id = k.user_id
		 WHERE wm.workspace_id = $1 AND k.revoked_at IS NULL
		 ORDER BY k.created_at ASC`,
		workspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing workspace ssh keys: %w", err)
	}
	defer rows.Close()

	var keys []model.SSHKey
	for rows.Next() {
		var k model.SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.PublicKey, &k.KeyType, &k.Fingerprint, &k.Label, &k.CreatedAt, &k.RevokedAt); err != nil {
			return nil, fmt.Errorf("scanning ssh key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating ssh keys: %w", err)
	}
	return keys, nil
}

// RevokeKey marks an SSH key as revoked by setting revoked_at to now.
func (s *KeyStore) RevokeKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx,
		`UPDATE ssh_keys SET revoked_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("revoking ssh key: %w", err)
	}
	return nil
}
