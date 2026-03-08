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

// SecretStore implements store.SecretStore using PostgreSQL.
type SecretStore struct {
	db *pgxpool.Pool
}

// NewSecretStore creates a new SecretStore.
func NewSecretStore(db *pgxpool.Pool) *SecretStore {
	return &SecretStore{db: db}
}

// PushSecret atomically inserts a new secret version after verifying the base_version.
// It uses SELECT FOR UPDATE to prevent concurrent push races.
// Returns store.ErrPushConflict if the provided base_version does not match the current max version.
func (s *SecretStore) PushSecret(ctx context.Context, secret *model.Secret, recipients []model.SecretRecipient) (*model.Secret, error) {
	return withTx(ctx, s.db, func(tx pgx.Tx) (*model.Secret, error) {
		// 1. Lock the latest secret row for this project/environment to prevent
		//    concurrent push races. FOR UPDATE cannot be used with aggregates, so
		//    we lock the row(s) first, then compute the max version separately.
		_, err := tx.Exec(ctx,
			`SELECT id FROM secrets
			 WHERE project_id = $1 AND environment = $2
			 FOR UPDATE`,
			secret.ProjectID, secret.Environment,
		)
		if err != nil {
			return nil, fmt.Errorf("locking secret version: %w", err)
		}
		var currentVersion int
		err = tx.QueryRow(ctx,
			`SELECT COALESCE(MAX(version), 0)
			 FROM secrets
			 WHERE project_id = $1 AND environment = $2`,
			secret.ProjectID, secret.Environment,
		).Scan(&currentVersion)
		if err != nil {
			return nil, fmt.Errorf("getting current version: %w", err)
		}

		// 2. Validate base_version matches current.
		if secret.BaseVersion != nil && *secret.BaseVersion != currentVersion {
			return nil, store.ErrPushConflict
		}

		// 3. Insert new secret at version = currentVersion + 1.
		newVersion := currentVersion + 1
		newID := uuid.New()
		var s2 model.Secret
		err = tx.QueryRow(ctx,
			`INSERT INTO secrets (
				id, project_id, environment, ciphertext, nonce, auth_tag,
				pushed_by, pushed_by_machine, version, base_version, push_message,
				key_count, checksum
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			RETURNING id, project_id, environment, ciphertext, nonce, auth_tag,
				pushed_by, pushed_by_machine, version, base_version, push_message,
				key_count, checksum, created_at`,
			newID, secret.ProjectID, secret.Environment,
			secret.Ciphertext, secret.Nonce, secret.AuthTag,
			secret.PushedBy, secret.PushedByMachine,
			newVersion, secret.BaseVersion, secret.PushMessage,
			secret.KeyCount, secret.Checksum,
		).Scan(
			&s2.ID, &s2.ProjectID, &s2.Environment,
			&s2.Ciphertext, &s2.Nonce, &s2.AuthTag,
			&s2.PushedBy, &s2.PushedByMachine,
			&s2.Version, &s2.BaseVersion, &s2.PushMessage,
			&s2.KeyCount, &s2.Checksum, &s2.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("inserting secret: %w", err)
		}

		// 4. Insert all recipients.
		for i := range recipients {
			r := &recipients[i]
			r.ID = uuid.New()
			r.SecretID = s2.ID
			_, err := tx.Exec(ctx,
				`INSERT INTO secret_recipients (
					id, secret_id, identity_type, user_id, machine_id,
					key_fingerprint, encrypted_aes_key,
					ephemeral_public, key_nonce, key_auth_tag
				) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
				r.ID, r.SecretID, r.IdentityType, r.UserID, r.MachineID,
				r.KeyFingerprint, r.EncryptedAESKey,
				r.EphemeralPublic, r.KeyNonce, r.KeyAuthTag,
			)
			if err != nil {
				return nil, fmt.Errorf("inserting secret recipient: %w", err)
			}
		}

		return &s2, nil
	})
}

// GetLatestSecret returns the highest-versioned secret for the given project/environment.
// Returns store.ErrNotFound if no secrets exist.
func (s *SecretStore) GetLatestSecret(ctx context.Context, projectID uuid.UUID, environment string) (*model.Secret, error) {
	var sec model.Secret
	err := s.db.QueryRow(ctx,
		`SELECT id, project_id, environment, ciphertext, nonce, auth_tag,
			pushed_by, pushed_by_machine, version, base_version, push_message,
			key_count, checksum, created_at
		 FROM secrets
		 WHERE project_id = $1 AND environment = $2
		 ORDER BY version DESC
		 LIMIT 1`,
		projectID, environment,
	).Scan(
		&sec.ID, &sec.ProjectID, &sec.Environment,
		&sec.Ciphertext, &sec.Nonce, &sec.AuthTag,
		&sec.PushedBy, &sec.PushedByMachine,
		&sec.Version, &sec.BaseVersion, &sec.PushMessage,
		&sec.KeyCount, &sec.Checksum, &sec.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting latest secret: %w", err)
	}
	return &sec, nil
}

// GetSecretByID returns a secret by primary key.
// Returns store.ErrNotFound if not found.
func (s *SecretStore) GetSecretByID(ctx context.Context, id uuid.UUID) (*model.Secret, error) {
	var sec model.Secret
	err := s.db.QueryRow(ctx,
		`SELECT id, project_id, environment, ciphertext, nonce, auth_tag,
			pushed_by, pushed_by_machine, version, base_version, push_message,
			key_count, checksum, created_at
		 FROM secrets
		 WHERE id = $1`,
		id,
	).Scan(
		&sec.ID, &sec.ProjectID, &sec.Environment,
		&sec.Ciphertext, &sec.Nonce, &sec.AuthTag,
		&sec.PushedBy, &sec.PushedByMachine,
		&sec.Version, &sec.BaseVersion, &sec.PushMessage,
		&sec.KeyCount, &sec.Checksum, &sec.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting secret by id: %w", err)
	}
	return &sec, nil
}

// ListVersions returns all versions of a project/environment secret in descending order.
func (s *SecretStore) ListVersions(ctx context.Context, projectID uuid.UUID, environment string) ([]model.Secret, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, project_id, environment, ciphertext, nonce, auth_tag,
			pushed_by, pushed_by_machine, version, base_version, push_message,
			key_count, checksum, created_at
		 FROM secrets
		 WHERE project_id = $1 AND environment = $2
		 ORDER BY version DESC`,
		projectID, environment,
	)
	if err != nil {
		return nil, fmt.Errorf("listing secret versions: %w", err)
	}
	defer rows.Close()

	var secrets []model.Secret
	for rows.Next() {
		var sec model.Secret
		if err := rows.Scan(
			&sec.ID, &sec.ProjectID, &sec.Environment,
			&sec.Ciphertext, &sec.Nonce, &sec.AuthTag,
			&sec.PushedBy, &sec.PushedByMachine,
			&sec.Version, &sec.BaseVersion, &sec.PushMessage,
			&sec.KeyCount, &sec.Checksum, &sec.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning secret version: %w", err)
		}
		secrets = append(secrets, sec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating secret versions: %w", err)
	}
	return secrets, nil
}

// GetRecipientsBySecret returns all recipients for a specific secret version.
func (s *SecretStore) GetRecipientsBySecret(ctx context.Context, secretID uuid.UUID) ([]model.SecretRecipient, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, secret_id, identity_type, user_id, machine_id,
			key_fingerprint, encrypted_aes_key,
			ephemeral_public, key_nonce, key_auth_tag
		 FROM secret_recipients
		 WHERE secret_id = $1`,
		secretID,
	)
	if err != nil {
		return nil, fmt.Errorf("getting secret recipients: %w", err)
	}
	defer rows.Close()

	var recipients []model.SecretRecipient
	for rows.Next() {
		var r model.SecretRecipient
		if err := rows.Scan(
			&r.ID, &r.SecretID, &r.IdentityType, &r.UserID, &r.MachineID,
			&r.KeyFingerprint, &r.EncryptedAESKey,
			&r.EphemeralPublic, &r.KeyNonce, &r.KeyAuthTag,
		); err != nil {
			return nil, fmt.Errorf("scanning secret recipient: %w", err)
		}
		recipients = append(recipients, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating secret recipients: %w", err)
	}
	return recipients, nil
}

// ListEnvironments returns distinct environment names for a project.
func (s *SecretStore) ListEnvironments(ctx context.Context, projectID uuid.UUID) ([]string, error) {
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT environment
		 FROM secrets
		 WHERE project_id = $1
		 ORDER BY environment ASC`,
		projectID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing environments: %w", err)
	}
	defer rows.Close()

	var envs []string
	for rows.Next() {
		var env string
		if err := rows.Scan(&env); err != nil {
			return nil, fmt.Errorf("scanning environment: %w", err)
		}
		envs = append(envs, env)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating environments: %w", err)
	}
	return envs, nil
}
