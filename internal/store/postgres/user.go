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

// UserStore implements store.UserStore using PostgreSQL.
type UserStore struct {
	db *pgxpool.Pool
}

// NewUserStore creates a new UserStore.
func NewUserStore(db *pgxpool.Pool) *UserStore {
	return &UserStore{db: db}
}

// CreateUser inserts a new user with the given email and returns the created user.
// Returns store.ErrDuplicateEmail if the email is already registered.
func (s *UserStore) CreateUser(ctx context.Context, email string) (*model.User, error) {
	id := uuid.New()
	var u model.User
	err := s.db.QueryRow(ctx,
		`INSERT INTO users (id, email)
		 VALUES ($1, $2)
		 RETURNING id, email, created_at, deleted_at`,
		id, email,
	).Scan(&u.ID, &u.Email, &u.CreatedAt, &u.DeletedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrDuplicateEmail
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return &u, nil
}

// GetUserByID returns a non-deleted user by primary key.
// Returns store.ErrNotFound if not found or soft-deleted.
func (s *UserStore) GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error) {
	var u model.User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, created_at, deleted_at
		 FROM users
		 WHERE id = $1 AND deleted_at IS NULL`,
		id,
	).Scan(&u.ID, &u.Email, &u.CreatedAt, &u.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting user by id: %w", err)
	}
	return &u, nil
}

// GetUserByEmail returns a non-deleted user by email address.
// Returns store.ErrNotFound if not found or soft-deleted.
func (s *UserStore) GetUserByEmail(ctx context.Context, email string) (*model.User, error) {
	var u model.User
	err := s.db.QueryRow(ctx,
		`SELECT id, email, created_at, deleted_at
		 FROM users
		 WHERE email = $1 AND deleted_at IS NULL`,
		email,
	).Scan(&u.ID, &u.Email, &u.CreatedAt, &u.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting user by email: %w", err)
	}
	return &u, nil
}
