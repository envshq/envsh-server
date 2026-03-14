-- T-020: Initial Schema Migration
-- Creates all V1 tables in FK-safe order

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
    -- Ed25519/X25519 hybrid encryption fields
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
    seat_count              INT NOT NULL DEFAULT 0,
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

-- Security: revoke UPDATE and DELETE on audit_log to enforce append-only
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'envsh_app') THEN
        CREATE ROLE envsh_app;
    END IF;
END
$$;
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;
