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

// ProjectStore implements store.ProjectStore using PostgreSQL.
type ProjectStore struct {
	db *pgxpool.Pool
}

// NewProjectStore creates a new ProjectStore.
func NewProjectStore(db *pgxpool.Pool) *ProjectStore {
	return &ProjectStore{db: db}
}

// CreateProject creates a new project in a workspace.
// Returns store.ErrDuplicateSlug if the slug already exists in the workspace.
func (s *ProjectStore) CreateProject(ctx context.Context, workspaceID, createdBy uuid.UUID, name, slug string) (*model.Project, error) {
	id := uuid.New()
	var p model.Project
	err := s.db.QueryRow(ctx,
		`INSERT INTO projects (id, workspace_id, name, slug, created_by)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, workspace_id, name, slug, created_by, created_at`,
		id, workspaceID, name, slug, createdBy,
	).Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Slug, &p.CreatedBy, &p.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, store.ErrDuplicateSlug
		}
		return nil, fmt.Errorf("creating project: %w", err)
	}
	return &p, nil
}

// GetProjectBySlug returns a project by its slug within a workspace.
// Returns store.ErrNotFound if not found.
func (s *ProjectStore) GetProjectBySlug(ctx context.Context, workspaceID uuid.UUID, slug string) (*model.Project, error) {
	var p model.Project
	err := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, name, slug, created_by, created_at
		 FROM projects
		 WHERE workspace_id = $1 AND slug = $2`,
		workspaceID, slug,
	).Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Slug, &p.CreatedBy, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting project by slug: %w", err)
	}
	return &p, nil
}

// GetProjectByID returns a project by primary key.
// Returns store.ErrNotFound if not found.
func (s *ProjectStore) GetProjectByID(ctx context.Context, id uuid.UUID) (*model.Project, error) {
	var p model.Project
	err := s.db.QueryRow(ctx,
		`SELECT id, workspace_id, name, slug, created_by, created_at
		 FROM projects
		 WHERE id = $1`,
		id,
	).Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Slug, &p.CreatedBy, &p.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("getting project by id: %w", err)
	}
	return &p, nil
}

// ListProjects returns all projects in a workspace.
func (s *ProjectStore) ListProjects(ctx context.Context, workspaceID uuid.UUID) ([]model.Project, error) {
	rows, err := s.db.Query(ctx,
		`SELECT id, workspace_id, name, slug, created_by, created_at
		 FROM projects
		 WHERE workspace_id = $1
		 ORDER BY created_at ASC`,
		workspaceID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	defer rows.Close()

	var projects []model.Project
	for rows.Next() {
		var p model.Project
		if err := rows.Scan(&p.ID, &p.WorkspaceID, &p.Name, &p.Slug, &p.CreatedBy, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning project: %w", err)
		}
		projects = append(projects, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating projects: %w", err)
	}
	return projects, nil
}

// DeleteProject removes a project by primary key.
func (s *ProjectStore) DeleteProject(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting project: %w", err)
	}
	return nil
}
