package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
)

func TestProjectStore_CreateProject_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, err := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}

	slug := uniqueSlug(t)
	proj, err := ps.CreateProject(ctx, w.ID, ownerID, "My Project", slug)
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	if proj.Slug != slug {
		t.Errorf("expected slug %q, got %q", slug, proj.Slug)
	}
	if proj.WorkspaceID != w.ID {
		t.Errorf("expected workspace %v, got %v", w.ID, proj.WorkspaceID)
	}
	if proj.CreatedBy != ownerID {
		t.Errorf("expected createdBy %v, got %v", ownerID, proj.CreatedBy)
	}
}

func TestProjectStore_CreateProject_DuplicateSlug(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	slug := uniqueSlug(t)
	_, err := ps.CreateProject(ctx, w.ID, ownerID, "First", slug)
	if err != nil {
		t.Fatalf("first CreateProject: %v", err)
	}

	_, err = ps.CreateProject(ctx, w.ID, ownerID, "Second", slug)
	if err == nil {
		t.Fatal("expected ErrDuplicateSlug, got nil")
	}
	if err != store.ErrDuplicateSlug {
		t.Errorf("expected ErrDuplicateSlug, got %v", err)
	}
}

func TestProjectStore_GetProjectBySlug_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	slug := uniqueSlug(t)
	created, _ := ps.CreateProject(ctx, w.ID, ownerID, "My Project", slug)

	got, err := ps.GetProjectBySlug(ctx, w.ID, slug)
	if err != nil {
		t.Fatalf("GetProjectBySlug: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %v, got %v", created.ID, got.ID)
	}
}

func TestProjectStore_GetProjectBySlug_NotFound(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	_, err := ps.GetProjectBySlug(ctx, w.ID, "no-such-slug")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestProjectStore_GetProjectByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	_, err := ps.GetProjectByID(ctx, uuid.New())
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestProjectStore_ListProjects(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	_, _ = ps.CreateProject(ctx, w.ID, ownerID, "Alpha", uniqueSlug(t))
	_, _ = ps.CreateProject(ctx, w.ID, ownerID, "Beta", uniqueSlug(t))

	projects, err := ps.ListProjects(ctx, w.ID)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(projects) != 2 {
		t.Errorf("expected 2 projects, got %d", len(projects))
	}
}

func TestProjectStore_DeleteProject(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	proj, _ := ps.CreateProject(ctx, w.ID, ownerID, "Delete Me", uniqueSlug(t))

	if err := ps.DeleteProject(ctx, proj.ID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}

	_, err := ps.GetProjectByID(ctx, proj.ID)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound after delete, got %v", err)
	}
}
