// Package integration contains end-to-end tests that spin up real Postgres and
// Redis containers via testcontainers-go, run database migrations in-process,
// and start the HTTP server using net/http/httptest.
//
// Run with: go test -v -timeout 120s -count=1 ./internal/integration/...
// Skip in CI:  go test -short ./...
package integration_test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"

	internalauth "github.com/envshq/envsh-server/internal/auth"
	"github.com/envshq/envsh-server/internal/config"
	"github.com/envshq/envsh-server/internal/server/router"
	"github.com/envshq/envsh-server/internal/store/postgres"
	redistore "github.com/envshq/envsh-server/internal/store/redis"
)

// testEnv holds all shared resources for the integration test suite.
type testEnv struct {
	server *httptest.Server
	db     *pgxpool.Pool
	redis  *redis.Client
}

var env *testEnv

// TestMain starts Postgres + Redis containers, migrates the schema, wires up
// the HTTP server, and tears everything down after all tests complete.
func TestMain(m *testing.M) {
	// flag.Parse must be called before testing.Short() in TestMain.
	flag.Parse()

	if testing.Short() {
		// When -short is passed, we skip all integration tests.
		// Individual tests also call t.Skip but this avoids container startup cost.
		os.Exit(m.Run())
	}

	ctx := context.Background()

	pgContainer, pgURL, err := startPostgres(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting postgres container: %v\n", err)
		os.Exit(1)
	}

	redisContainer, redisURL, err := startRedis(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "starting redis container: %v\n", err)
		os.Exit(1)
	}

	// Retry the connection: the container may report "ready" (port bound) before
	// the PostgreSQL server has fully initialized and accepted connections.
	var db *pgxpool.Pool
	for attempt := 1; attempt <= 20; attempt++ {
		db, err = postgres.Connect(ctx, pgURL)
		if err == nil {
			break
		}
		if attempt == 20 {
			fmt.Fprintf(os.Stderr, "connecting to postgres after %d attempts: %v\n", attempt, err)
			os.Exit(1)
		}
		time.Sleep(500 * time.Millisecond)
	}

	if err := runMigrations(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "running migrations: %v\n", err)
		os.Exit(1)
	}

	redisClient, err := redistore.Connect(ctx, redisURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connecting to redis: %v\n", err)
		os.Exit(1)
	}

	srv := buildTestServer(db, redisClient)

	env = &testEnv{
		server: srv,
		db:     db,
		redis:  redisClient,
	}

	code := m.Run()

	srv.Close()
	db.Close()
	redisClient.Close()
	_ = pgContainer.Terminate(ctx)
	_ = redisContainer.Terminate(ctx)

	os.Exit(code)
}

// startPostgres creates a PostgreSQL 16 testcontainer and returns the container
// and its connection URL.
func startPostgres(ctx context.Context) (testcontainers.Container, string, error) {
	container, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("envsh_test"),
		tcpostgres.WithUsername("test"),
		tcpostgres.WithPassword("test"),
		tcpostgres.WithSQLDriver("pgx"),
	)
	if err != nil {
		return nil, "", fmt.Errorf("creating postgres container: %w", err)
	}

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		return nil, "", fmt.Errorf("getting postgres connection string: %w", err)
	}
	return container, connStr, nil
}

// startRedis creates a Redis 7 testcontainer and returns the container and its URL.
func startRedis(ctx context.Context) (testcontainers.Container, string, error) {
	container, err := tcredis.Run(ctx, "redis:7-alpine")
	if err != nil {
		return nil, "", fmt.Errorf("creating redis container: %w", err)
	}

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("getting redis connection string: %w", err)
	}
	return container, connStr, nil
}

// runMigrations applies the schema migration SQL directly against the pool.
// We embed the migration SQL here to avoid a dependency on golang-migrate.
func runMigrations(ctx context.Context, db *pgxpool.Pool) error {
	// Retry a few times: the container may not be fully ready.
	var lastErr error
	for i := 0; i < 10; i++ {
		_, lastErr = db.Exec(ctx, migrationSQL)
		if lastErr == nil {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("applying migrations: %w", lastErr)
}

// buildTestServer wires all stores, services, and the chi router, then wraps
// it in an httptest.Server.
func buildTestServer(db *pgxpool.Pool, redisClient *redis.Client) *httptest.Server {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	stores := router.Stores{
		Users:      postgres.NewUserStore(db),
		Workspaces: postgres.NewWorkspaceStore(db),
		Projects:   postgres.NewProjectStore(db),
		Secrets:    postgres.NewSecretStore(db),
		Machines:   postgres.NewMachineStore(db),
		Keys:       postgres.NewKeyStore(db),
		Audit:      postgres.NewAuditLogStore(db),
	}

	redisAuthStore := redistore.NewAuthStore(redisClient)
	jwtSvc := internalauth.NewJWTService("test-jwt-secret-for-integration-tests", redisAuthStore)
	var emailSender internalauth.EmailSender = &internalauth.ConsoleEmailSender{}
	emailSvc := internalauth.NewEmailAuthService(redisAuthStore, emailSender)
	machineSvc := internalauth.NewMachineAuthService(redisAuthStore, jwtSvc)

	services := router.Services{
		Email:   emailSvc,
		JWT:     jwtSvc,
		Machine: machineSvc,
	}

	testCfg := &config.Config{FreeTierSeatMax: 5}
	h := router.New(stores, services, redisClient, logger, testCfg)
	return httptest.NewServer(h)
}

// truncateAll removes all rows from every table in reverse FK order so each
// test starts with a clean slate.
func truncateAll(ctx context.Context, db *pgxpool.Pool) error {
	_, err := db.Exec(ctx, `
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
	return err
}

// migrationSQL is the initial schema, duplicated here so integration tests have
// no dependency on a migration runner or on reading files from disk.
const migrationSQL = `
-- Users
CREATE TABLE IF NOT EXISTS users (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email       TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at  TIMESTAMP
);

-- Workspaces (one per user account)
CREATE TABLE IF NOT EXISTS workspaces (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id    UUID NOT NULL REFERENCES users(id),
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Workspace membership
CREATE TABLE IF NOT EXISTS workspace_members (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    role            TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    invited_by      UUID REFERENCES users(id),
    joined_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, user_id)
);

-- SSH public keys (Ed25519 and RSA-4096)
CREATE TABLE IF NOT EXISTS ssh_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    public_key  TEXT NOT NULL UNIQUE,
    key_type    TEXT NOT NULL CHECK (key_type IN ('ed25519', 'rsa4096')),
    fingerprint TEXT NOT NULL UNIQUE,
    label       TEXT,
    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at  TIMESTAMP
);

-- Projects
CREATE TABLE IF NOT EXISTS projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL,
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(workspace_id, slug)
);

-- Machine identities (must be created before secrets for FK)
CREATE TABLE IF NOT EXISTS machines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL UNIQUE,
    key_fingerprint TEXT NOT NULL UNIQUE,
    project_id      UUID NOT NULL REFERENCES projects(id),
    environment     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_by      UUID NOT NULL REFERENCES users(id),
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at      TIMESTAMP
);

-- Secrets (one per project/environment, versioned)
CREATE TABLE IF NOT EXISTS secrets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID NOT NULL REFERENCES projects(id),
    environment         TEXT NOT NULL,
    ciphertext          BYTEA NOT NULL,
    nonce               BYTEA NOT NULL,
    auth_tag            BYTEA NOT NULL,
    pushed_by           UUID REFERENCES users(id),
    pushed_by_machine   UUID REFERENCES machines(id),
    version             INT NOT NULL,
    base_version        INT,
    push_message        TEXT,
    key_count           INT NOT NULL,
    checksum            TEXT NOT NULL,
    created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(project_id, environment, version)
);

-- Per-recipient encrypted AES keys
CREATE TABLE IF NOT EXISTS secret_recipients (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    secret_id           UUID NOT NULL REFERENCES secrets(id),
    identity_type       TEXT NOT NULL CHECK (identity_type IN ('user', 'machine')),
    user_id             UUID REFERENCES users(id),
    machine_id          UUID REFERENCES machines(id),
    key_fingerprint     TEXT NOT NULL,
    encrypted_aes_key   BYTEA NOT NULL,
    ephemeral_public    BYTEA,
    key_nonce           BYTEA,
    key_auth_tag        BYTEA
);

-- Audit log (append-only)
CREATE TABLE IF NOT EXISTS audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id),
    actor_type      TEXT NOT NULL CHECK (actor_type IN ('user', 'machine')),
    actor_id        UUID NOT NULL,
    action          TEXT NOT NULL,
    resource_type   TEXT NOT NULL,
    resource_id     UUID,
    metadata        JSONB,
    ip_address      TEXT,
    prev_hash       TEXT NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Billing / subscriptions
CREATE TABLE IF NOT EXISTS subscriptions (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id            UUID NOT NULL UNIQUE REFERENCES workspaces(id),
    plan                    TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'team')),
    seat_count              INT NOT NULL DEFAULT 3,
    stripe_customer_id      TEXT,
    stripe_subscription_id  TEXT,
    status                  TEXT NOT NULL DEFAULT 'active',
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_workspace_members_workspace ON workspace_members(workspace_id);
CREATE INDEX IF NOT EXISTS idx_workspace_members_user ON workspace_members(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_workspace ON projects(workspace_id);
CREATE INDEX IF NOT EXISTS idx_secrets_project_env ON secrets(project_id, environment);
CREATE INDEX IF NOT EXISTS idx_secret_recipients_secret ON secret_recipients(secret_id);
CREATE INDEX IF NOT EXISTS idx_secret_recipients_fingerprint ON secret_recipients(key_fingerprint);
CREATE INDEX IF NOT EXISTS idx_machines_workspace ON machines(workspace_id);
CREATE INDEX IF NOT EXISTS idx_ssh_keys_user ON ssh_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_workspace ON audit_log(workspace_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
`
