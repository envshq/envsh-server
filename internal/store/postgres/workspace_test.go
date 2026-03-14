package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
)

// createTestUserWithStore is a test helper that creates a user and returns its ID.
func createTestUserWithStore(t *testing.T, ctx context.Context, us *postgres.UserStore) uuid.UUID {
	t.Helper()
	u, err := us.CreateUser(ctx, uniqueEmail(t))
	if err != nil {
		t.Fatalf("creating test user: %v", err)
	}
	return u.ID
}

func TestWorkspaceStore_CreateWorkspace_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	slug := uniqueSlug(t)

	w, err := ws.CreateWorkspace(ctx, ownerID, "Test Workspace", slug)
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	if w.OwnerID != ownerID {
		t.Errorf("expected owner %v, got %v", ownerID, w.OwnerID)
	}
	if w.Slug != slug {
		t.Errorf("expected slug %q, got %q", slug, w.Slug)
	}
}

func TestWorkspaceStore_CreateWorkspace_DuplicateSlug(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	slug := uniqueSlug(t)

	_, err := ws.CreateWorkspace(ctx, ownerID, "First", slug)
	if err != nil {
		t.Fatalf("first CreateWorkspace: %v", err)
	}

	ownerID2 := createTestUserWithStore(t, ctx, us)
	_, err = ws.CreateWorkspace(ctx, ownerID2, "Second", slug)
	if err == nil {
		t.Fatal("expected ErrDuplicateSlug, got nil")
	}
	if err != store.ErrDuplicateSlug {
		t.Errorf("expected ErrDuplicateSlug, got %v", err)
	}
}

func TestWorkspaceStore_GetWorkspaceByID_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))

	got, err := ws.GetWorkspaceByID(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetWorkspaceByID: %v", err)
	}
	if got.ID != w.ID {
		t.Errorf("expected ID %v, got %v", w.ID, got.ID)
	}
}

func TestWorkspaceStore_GetWorkspaceByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	_, err := ws.GetWorkspaceByID(ctx, uuid.New())
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWorkspaceStore_GetWorkspaceByOwner_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))

	got, err := ws.GetWorkspaceByOwner(ctx, ownerID)
	if err != nil {
		t.Fatalf("GetWorkspaceByOwner: %v", err)
	}
	if got.ID != w.ID {
		t.Errorf("expected ID %v, got %v", w.ID, got.ID)
	}
}

func TestWorkspaceStore_UpdateWorkspaceName(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Old Name", uniqueSlug(t))

	if err := ws.UpdateWorkspaceName(ctx, w.ID, "New Name"); err != nil {
		t.Fatalf("UpdateWorkspaceName: %v", err)
	}

	got, _ := ws.GetWorkspaceByID(ctx, w.ID)
	if got.Name != "New Name" {
		t.Errorf("expected name %q, got %q", "New Name", got.Name)
	}
}

func TestWorkspaceStore_AddMember_RemoveMember(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))
	memberID := createTestUserWithStore(t, ctx, us)

	m, err := ws.AddMember(ctx, w.ID, memberID, "member", &ownerID)
	if err != nil {
		t.Fatalf("AddMember: %v", err)
	}
	if m.Role != "member" {
		t.Errorf("expected role %q, got %q", "member", m.Role)
	}

	// List should include member.
	members, err := ws.ListMembers(ctx, w.ID)
	if err != nil {
		t.Fatalf("ListMembers: %v", err)
	}
	found := false
	for _, mbr := range members {
		if mbr.UserID == memberID {
			found = true
		}
	}
	if !found {
		t.Error("expected memberID in ListMembers result")
	}

	// Remove and verify.
	if err := ws.RemoveMember(ctx, w.ID, memberID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	members2, _ := ws.ListMembers(ctx, w.ID)
	for _, mbr := range members2 {
		if mbr.UserID == memberID {
			t.Error("expected memberID to be removed from ListMembers")
		}
	}
}

func TestWorkspaceStore_GetMember_NotFound(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))

	_, err := ws.GetMember(ctx, w.ID, uuid.New())
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestWorkspaceStore_GetMemberCount(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))

	// Initially zero members (workspace members are not auto-created here).
	count, err := ws.GetMemberCount(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetMemberCount: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 members, got %d", count)
	}

	// Add one.
	memberID := createTestUserWithStore(t, ctx, us)
	_, _ = ws.AddMember(ctx, w.ID, memberID, "member", nil)

	count2, _ := ws.GetMemberCount(ctx, w.ID)
	if count2 != 1 {
		t.Errorf("expected 1 member, got %d", count2)
	}
}

func TestWorkspaceStore_CreateSubscription_GetSubscription(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))

	sub, err := ws.CreateSubscription(ctx, w.ID)
	if err != nil {
		t.Fatalf("CreateSubscription: %v", err)
	}
	if sub.Plan != "free" {
		t.Errorf("expected plan %q, got %q", "free", sub.Plan)
	}
	if sub.SeatCount != 0 {
		t.Errorf("expected seat_count 0, got %d", sub.SeatCount)
	}

	got, err := ws.GetSubscription(ctx, w.ID)
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if got.ID != sub.ID {
		t.Errorf("expected subscription ID %v, got %v", sub.ID, got.ID)
	}
}

func TestWorkspaceStore_GetSubscription_NotFound(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test", uniqueSlug(t))

	_, err := ws.GetSubscription(ctx, w.ID)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
