package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Connect creates a new pgxpool connection pool and verifies connectivity.
func Connect(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("connecting to postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}
	return pool, nil
}

// withTx runs fn inside a transaction, committing on success or rolling back on error.
func withTx[T any](ctx context.Context, db *pgxpool.Pool, fn func(pgx.Tx) (T, error)) (T, error) {
	tx, err := db.Begin(ctx)
	if err != nil {
		var zero T
		return zero, fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	result, err := fn(tx)
	if err != nil {
		var zero T
		return zero, err
	}
	if err := tx.Commit(ctx); err != nil {
		var zero T
		return zero, fmt.Errorf("committing transaction: %w", err)
	}
	return result, nil
}

// isUniqueViolation returns true if err is a PostgreSQL unique constraint violation (code 23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
