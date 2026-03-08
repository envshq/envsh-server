-- T-020: Rollback initial schema migration
-- Drop all tables in reverse FK order

DROP TABLE IF EXISTS subscriptions CASCADE;
DROP TABLE IF EXISTS audit_log CASCADE;
DROP TABLE IF EXISTS secret_recipients CASCADE;
DROP TABLE IF EXISTS secrets CASCADE;
DROP TABLE IF EXISTS machines CASCADE;
DROP TABLE IF EXISTS projects CASCADE;
DROP TABLE IF EXISTS ssh_keys CASCADE;
DROP TABLE IF EXISTS workspace_members CASCADE;
DROP TABLE IF EXISTS workspaces CASCADE;
DROP TABLE IF EXISTS users CASCADE;
