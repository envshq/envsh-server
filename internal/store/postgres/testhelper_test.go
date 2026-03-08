package postgres_test

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setupTestDB creates a fresh PostgreSQL connection for testing.
// It prefers TEST_DATABASE_URL env var; if not set, it skips.
// The caller is responsible for cleaning up test data between tests.
func setupTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connecting to test db: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("pinging test db: %v", err)
	}

	t.Cleanup(func() { pool.Close() })

	// Truncate all tables in reverse FK order to ensure a clean state.
	_, err = pool.Exec(context.Background(), `
		TRUNCATE TABLE
			subscriptions,
			audit_log,
			secret_recipients,
			secrets,
			machines,
			projects,
			ssh_keys,
			workspace_members,
			workspaces,
			users
		RESTART IDENTITY CASCADE
	`)
	if err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	return pool
}

// uniqueEmail returns a unique email address based on the test name and a timestamp.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test+%d@example.com", time.Now().UnixNano())
}

// uniqueSlug returns a unique slug based on the test name and a timestamp.
func uniqueSlug(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("test-%d", time.Now().UnixNano())
}
