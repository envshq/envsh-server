package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
)

// createTestMachine is a helper that creates a machine in the database.
func createTestMachine(t *testing.T, ctx context.Context, ms *postgres.MachineStore, workspaceID, projectID, createdBy uuid.UUID, slug string) *model.Machine {
	t.Helper()
	m := &model.Machine{
		WorkspaceID:    workspaceID,
		Name:           "Test Machine",
		Slug:           slug,
		PublicKey:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 " + slug,
		KeyFingerprint: "SHA256:test" + slug,
		ProjectID:      projectID,
		Environment:    "prod",
		Status:         "active",
		CreatedBy:      createdBy,
	}
	created, err := ms.CreateMachine(ctx, m)
	if err != nil {
		t.Fatalf("CreateMachine: %v", err)
	}
	return created
}

func TestMachineStore_CreateMachine_Success(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ms := postgres.NewMachineStore(db)

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	proj, _ := ps.CreateProject(ctx, w.ID, ownerID, "Test Project", uniqueSlug(t))

	slug := uniqueSlug(t)
	m := createTestMachine(t, ctx, ms, w.ID, proj.ID, ownerID, slug)

	if m.ID == uuid.Nil {
		t.Error("expected non-nil ID")
	}
	if m.Status != "active" {
		t.Errorf("expected status 'active', got %q", m.Status)
	}
	if m.Slug != slug {
		t.Errorf("expected slug %q, got %q", slug, m.Slug)
	}
}

func TestMachineStore_CreateMachine_DuplicateSlug(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ms := postgres.NewMachineStore(db)

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	proj, _ := ps.CreateProject(ctx, w.ID, ownerID, "Test Project", uniqueSlug(t))

	slug := uniqueSlug(t)
	createTestMachine(t, ctx, ms, w.ID, proj.ID, ownerID, slug)

	// Second machine with same slug should fail.
	m2 := &model.Machine{
		WorkspaceID:    w.ID,
		Name:           "Duplicate",
		Slug:           slug,
		PublicKey:      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 differentkey",
		KeyFingerprint: "SHA256:different",
		ProjectID:      proj.ID,
		Environment:    "prod",
		Status:         "active",
		CreatedBy:      ownerID,
	}
	_, err := ms.CreateMachine(ctx, m2)
	if err == nil {
		t.Fatal("expected ErrDuplicateSlug, got nil")
	}
	if err != store.ErrDuplicateSlug {
		t.Errorf("expected ErrDuplicateSlug, got %v", err)
	}
}

func TestMachineStore_GetMachineByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ms := postgres.NewMachineStore(db)
	ctx := context.Background()

	_, err := ms.GetMachineByID(ctx, uuid.New())
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMachineStore_GetMachineByFingerprint(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ms := postgres.NewMachineStore(db)

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	proj, _ := ps.CreateProject(ctx, w.ID, ownerID, "Test Project", uniqueSlug(t))

	slug := uniqueSlug(t)
	created := createTestMachine(t, ctx, ms, w.ID, proj.ID, ownerID, slug)

	got, err := ms.GetMachineByFingerprint(ctx, created.KeyFingerprint)
	if err != nil {
		t.Fatalf("GetMachineByFingerprint: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %v, got %v", created.ID, got.ID)
	}
}

func TestMachineStore_GetMachineByFingerprint_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ms := postgres.NewMachineStore(db)
	ctx := context.Background()

	_, err := ms.GetMachineByFingerprint(ctx, "SHA256:nonexistent")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMachineStore_ListMachines(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ms := postgres.NewMachineStore(db)

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	proj, _ := ps.CreateProject(ctx, w.ID, ownerID, "Test Project", uniqueSlug(t))

	createTestMachine(t, ctx, ms, w.ID, proj.ID, ownerID, uniqueSlug(t))
	createTestMachine(t, ctx, ms, w.ID, proj.ID, ownerID, uniqueSlug(t))

	machines, err := ms.ListMachines(ctx, w.ID)
	if err != nil {
		t.Fatalf("ListMachines: %v", err)
	}
	if len(machines) != 2 {
		t.Errorf("expected 2 machines, got %d", len(machines))
	}
}

func TestMachineStore_RevokeMachine(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)
	ms := postgres.NewMachineStore(db)

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	proj, _ := ps.CreateProject(ctx, w.ID, ownerID, "Test Project", uniqueSlug(t))

	m := createTestMachine(t, ctx, ms, w.ID, proj.ID, ownerID, uniqueSlug(t))

	if err := ms.RevokeMachine(ctx, m.ID); err != nil {
		t.Fatalf("RevokeMachine: %v", err)
	}

	got, err := ms.GetMachineByID(ctx, m.ID)
	if err != nil {
		t.Fatalf("GetMachineByID after revoke: %v", err)
	}
	if got.Status != "revoked" {
		t.Errorf("expected status 'revoked', got %q", got.Status)
	}
	if got.RevokedAt == nil {
		t.Error("expected non-nil RevokedAt after revoke")
	}
}
