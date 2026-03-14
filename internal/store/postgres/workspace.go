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

// WorkspaceStore implements store.WorkspaceStore using PostgreSQL.
type WorkspaceStore struct {
	db *pgxpool.Pool
}

// NewWorkspaceStore creates a new WorkspaceStore.
func NewWorkspaceStore(db *pgxpool.Pool) *WorkspaceStore {
	return &WorkspaceStore{db: db}
}

// CreateWorkspace creates a new workspace for the given owner.
// Returns store.ErrDuplicateSlug if the slug is already taken.
func (s *WorkspaceStore) CreateWorkspace(ctx context.Context, ownerID uuid.UUID, name, slug string) (*model.Workspace, error) {
	id := uuid.New()
	var w model.Workspace
	err := s.db.QueryRow(ctx,
		`INSERT INTO workspaces (id, owner_id, name, slug)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, owner_id, name, slug, created_at`,
		id, ownerID, name, slug,
	).Scan(&w.ID, &w.OwnerID, &w.Name, &w.Slug, &w.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrDuplicateSlug
		}
		return nil, fmt.Errorf("creating workspace: %w", err)
	}
	return &w, nil
}

// GetWorkspaceByID returns a workspace by primary key.
func (s *WorkspaceStore) GetWorkspaceByID(ctx context.Context, id uuid.UUID) (*model.Workspace, error) {
	var w model.Workspace
	err := s.db.QueryRow(ctx,
		`SELECT id, owner_id, name, slug, created_at
		 FROM workspaces
		 WHERE id = $1`,
		id,
	).Scan(&w.ID, &w.OwnerID, &w.Name, &w.Slug, &w.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting workspace by id: %w", err)
	}
	return &w, nil
}

// GetWorkspaceByOwner returns the workspace owned by the given user.
func (s *WorkspaceStore) GetWorkspaceByOwner(ctx context.Context, ownerID uuid.UUID) (*model.Workspace, error) {
	var w model.Workspace
	err := s.db.QueryRow(ctx,
		`SELECT id, owner_id, name, slug, created_at
		 FROM workspaces
		 WHERE owner_id = $1`,
		ownerID,
	).Scan(&w.ID, &w.OwnerID, &w.Name, &w.Slug, &w.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting workspace by owner: %w", err)
	}
	return &w, nil
}

// GetWorkspaceByMember returns the workspace that the given user is a member of.
// Used when logging in an invited user who doesn't own a workspace.
func (s *WorkspaceStore) GetWorkspaceByMember(ctx context.Context, userID uuid.UUID) (*model.Workspace, error) {
	var w model.Workspace
	err := s.db.QueryRow(ctx,
		`SELECT w.id, w.owner_id, w.name, w.slug, w.created_at
		 FROM workspaces w
		 JOIN workspace_members wm ON wm.workspace_id = w.id
		 WHERE wm.user_id = $1
		 ORDER BY w.created_at ASC
		 LIMIT 1`,
		userID,
	).Scan(&w.ID, &w.OwnerID, &w.Name, &w.Slug, &w.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting workspace by member: %w", err)
	}
	return &w, nil
}

// ListWorkspacesByUser returns all workspaces the user is a member of, with their role.
func (s *WorkspaceStore) ListWorkspacesByUser(ctx context.Context, userID uuid.UUID) ([]model.WorkspaceMembership, error) {
	rows, err := s.db.Query(ctx,
		`SELECT w.id, w.owner_id, w.name, w.slug, wm.role, w.created_at
		 FROM workspaces w
		 JOIN workspace_members wm ON wm.workspace_id = w.id
		 WHERE wm.user_id = $1
		 ORDER BY w.created_at ASC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing workspaces by user: %w", err)
	}
	defer rows.Close()

	var memberships []model.WorkspaceMembership
	for rows.Next() {
		var m model.WorkspaceMembership
		if err := rows.Scan(&m.WorkspaceID, &m.OwnerID, &m.Name, &m.Slug, &m.Role, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning workspace membership: %w", err)
		}
		memberships = append(memberships, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating workspace memberships: %w", err)
	}
	return memberships, nil
}

// UpdateWorkspaceName changes the display name of a workspace.
func (s *WorkspaceStore) UpdateWorkspaceName(ctx context.Context, id uuid.UUID, name string) error {
	_, err := s.db.Exec(ctx,
		`UPDATE workspaces SET name = $1 WHERE id = $2`,
		name, id,
	)
	if err != nil {
		return fmt.Errorf("updating workspace name: %w", err)
	}
	return nil
}

// AddMember adds a user to a workspace with the given role.
// If the membership already exists it returns the existing member.
func (s *WorkspaceStore) AddMember(ctx context.Context, workspaceID, userID uuid.UUID, role string, invitedBy *uuid.UUID) (*model.WorkspaceMember, error) {
	id := uuid.New()
	var m model.WorkspaceMember
	err := s.db.QueryRow(ctx,
		`INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role
		 RETURNING id, workspace_id, user_id, role, invited_by, joined_at`,
		id, workspaceID, userID, role, invitedBy,
	).Scan(&m.ID, &m.WorkspaceID, &m.UserID, &m.Role, &m.InvitedBy, &m.JoinedAt)
	if err != nil {
		return nil, fmt.Errorf("adding workspace member: %w", err)
	}
	return &m, nil
}

// RemoveMember removes a user from a workspace.
// Returns store.ErrNotFound if the member was not found.
func (s *WorkspaceStore) RemoveMember(ctx context.Context, workspaceID, userID uuid.UUID) error {
	result, err := s.db.Exec(ctx,
		`DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2`,
		workspaceID, userID,
	)
	if err != nil {
		return fmt.Errorf("removing workspace member: %w", err)
	}
	if result.RowsAffected() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// GetMember returns a single workspace member with the user's email joined in.
// Returns store.ErrNotFound if the membership does not exist.
func (s *WorkspaceStore) GetMember(ctx context.Context, workspaceID, userID uuid.UUID) (*model.WorkspaceMember, error) {
	var m model.WorkspaceMember
	err := s.db.QueryRow(ctx,
		`SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.invited_by, wm.joined_at, u.email
		 FROM workspace_members wm
		 JOIN users u ON u.id = wm.user_id
		 WHERE wm.workspace_id = $1 AND wm.user_id = $2`,
		workspaceID, userID,
	).Scan(&m.ID, &m.WorkspaceID, &m.UserID, &m.Role, &m.InvitedBy, &m.JoinedAt, &m.Email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting workspace member: %w", err)
	}
	return &m, nil
}

// ListMembers returns all members of a workspace ordered by join date, with email joined in.
func (s *WorkspaceStore) ListMembers(ctx context.Context, workspaceID uuid.UUID) ([]model.WorkspaceMember, error) {
	rows, err := s.db.Query(ctx,
		`SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.invited_by, wm.joined_at, u.email
		 FROM workspace_members wm
		 JOIN users u ON u.id = wm.user_id
		 WHERE wm.workspace_id = $1
		 ORDER BY wm.joined_at ASC`,
		workspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing workspace members: %w", err)
	}
	defer rows.Close()

	var members []model.WorkspaceMember
	for rows.Next() {
		var m model.WorkspaceMember
		if err := rows.Scan(&m.ID, &m.WorkspaceID, &m.UserID, &m.Role, &m.InvitedBy, &m.JoinedAt, &m.Email); err != nil {
			return nil, fmt.Errorf("scanning workspace member: %w", err)
		}
		members = append(members, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating workspace members: %w", err)
	}
	return members, nil
}

// GetMemberCount returns the total number of members in a workspace.
func (s *WorkspaceStore) GetMemberCount(ctx context.Context, workspaceID uuid.UUID) (int, error) {
	var count int
	err := s.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1`,
		workspaceID,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting workspace members: %w", err)
	}
	return count, nil
}

// GetSubscription returns the subscription for a workspace.
// Returns store.ErrNotFound if no subscription exists.
func (s *WorkspaceStore) GetSubscription(ctx context.Context, workspaceID uuid.UUID) (*model.Subscription, error) {
	var sub model.Subscription
	err := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, plan, seat_count, stripe_customer_id, stripe_subscription_id, status, created_at
		 FROM subscriptions
		 WHERE workspace_id = $1`,
		workspaceID,
	).Scan(
		&sub.ID, &sub.WorkspaceID, &sub.Plan, &sub.SeatCount,
		&sub.StripeCustomerID, &sub.StripeSubscriptionID, &sub.Status, &sub.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting subscription: %w", err)
	}
	return &sub, nil
}

// CreateSubscription creates a free-tier subscription for a workspace.
func (s *WorkspaceStore) CreateSubscription(ctx context.Context, workspaceID uuid.UUID) (*model.Subscription, error) {
	id := uuid.New()
	var sub model.Subscription
	err := s.db.QueryRow(ctx,
		`INSERT INTO subscriptions (id, workspace_id, plan, seat_count)
		 VALUES ($1, $2, 'free', 5)
		 RETURNING id, workspace_id, plan, seat_count, stripe_customer_id, stripe_subscription_id, status, created_at`,
		id, workspaceID,
	).Scan(
		&sub.ID, &sub.WorkspaceID, &sub.Plan, &sub.SeatCount,
		&sub.StripeCustomerID, &sub.StripeSubscriptionID, &sub.Status, &sub.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrDuplicateSlug // workspace already has a subscription
		}
		return nil, fmt.Errorf("creating subscription: %w", err)
	}
	return &sub, nil
}
