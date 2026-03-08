package store

import (
	"context"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/google/uuid"
)

// UserStore manages user accounts.
type UserStore interface {
	CreateUser(ctx context.Context, email string) (*model.User, error)
	GetUserByID(ctx context.Context, id uuid.UUID) (*model.User, error)
	GetUserByEmail(ctx context.Context, email string) (*model.User, error)
}

// WorkspaceStore manages workspaces and their members.
type WorkspaceStore interface {
	CreateWorkspace(ctx context.Context, ownerID uuid.UUID, name, slug string) (*model.Workspace, error)
	GetWorkspaceByID(ctx context.Context, id uuid.UUID) (*model.Workspace, error)
	GetWorkspaceByOwner(ctx context.Context, ownerID uuid.UUID) (*model.Workspace, error)
	GetWorkspaceByMember(ctx context.Context, userID uuid.UUID) (*model.Workspace, error)
	UpdateWorkspaceName(ctx context.Context, id uuid.UUID, name string) error
	AddMember(ctx context.Context, workspaceID, userID uuid.UUID, role string, invitedBy *uuid.UUID) (*model.WorkspaceMember, error)
	RemoveMember(ctx context.Context, workspaceID, userID uuid.UUID) error
	GetMember(ctx context.Context, workspaceID, userID uuid.UUID) (*model.WorkspaceMember, error)
	ListMembers(ctx context.Context, workspaceID uuid.UUID) ([]model.WorkspaceMember, error)
	GetMemberCount(ctx context.Context, workspaceID uuid.UUID) (int, error)
	GetSubscription(ctx context.Context, workspaceID uuid.UUID) (*model.Subscription, error)
	CreateSubscription(ctx context.Context, workspaceID uuid.UUID) (*model.Subscription, error)
}

// ProjectStore manages projects within a workspace.
type ProjectStore interface {
	CreateProject(ctx context.Context, workspaceID, createdBy uuid.UUID, name, slug string) (*model.Project, error)
	GetProjectBySlug(ctx context.Context, workspaceID uuid.UUID, slug string) (*model.Project, error)
	GetProjectByID(ctx context.Context, id uuid.UUID) (*model.Project, error)
	ListProjects(ctx context.Context, workspaceID uuid.UUID) ([]model.Project, error)
	DeleteProject(ctx context.Context, id uuid.UUID) error
}

// SecretStore manages versioned encrypted secret blobs.
type SecretStore interface {
	// PushSecret atomically checks base_version and inserts a new secret version.
	// Uses SELECT FOR UPDATE to prevent races. Returns ErrPushConflict if base_version mismatch.
	PushSecret(ctx context.Context, secret *model.Secret, recipients []model.SecretRecipient) (*model.Secret, error)
	GetLatestSecret(ctx context.Context, projectID uuid.UUID, environment string) (*model.Secret, error)
	GetSecretByID(ctx context.Context, id uuid.UUID) (*model.Secret, error)
	ListVersions(ctx context.Context, projectID uuid.UUID, environment string) ([]model.Secret, error)
	GetRecipientsBySecret(ctx context.Context, secretID uuid.UUID) ([]model.SecretRecipient, error)
	ListEnvironments(ctx context.Context, projectID uuid.UUID) ([]string, error)
}

// MachineStore manages machine identities.
type MachineStore interface {
	CreateMachine(ctx context.Context, m *model.Machine) (*model.Machine, error)
	GetMachineByID(ctx context.Context, id uuid.UUID) (*model.Machine, error)
	GetMachineBySlug(ctx context.Context, workspaceID uuid.UUID, slug string) (*model.Machine, error)
	GetMachineByFingerprint(ctx context.Context, fingerprint string) (*model.Machine, error)
	ListMachines(ctx context.Context, workspaceID uuid.UUID) ([]model.Machine, error)
	RevokeMachine(ctx context.Context, id uuid.UUID) error
}

// KeyStore manages SSH public keys registered by users.
type KeyStore interface {
	RegisterKey(ctx context.Context, userID uuid.UUID, publicKey, keyType, fingerprint string, label *string) (*model.SSHKey, error)
	GetKeyByFingerprint(ctx context.Context, fingerprint string) (*model.SSHKey, error)
	ListKeys(ctx context.Context, userID uuid.UUID) ([]model.SSHKey, error)
	RevokeKey(ctx context.Context, id uuid.UUID) error
}

// AuditLogStore is insert-only. Never update or delete.
type AuditLogStore interface {
	AppendAuditLog(ctx context.Context, entry *model.AuditLog) error
	ListAuditLogs(ctx context.Context, workspaceID uuid.UUID, limit, offset int) ([]model.AuditLog, error)
	GetLastAuditLog(ctx context.Context, workspaceID uuid.UUID) (*model.AuditLog, error)
}
