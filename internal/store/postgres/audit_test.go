package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
)

func makeAuditEntry(workspaceID, actorID uuid.UUID) *model.AuditLog {
	return &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      actorID,
		Action:       "secret.pushed",
		ResourceType: "secret",
		Metadata:     map[string]any{"version": 1},
	}
}

func TestAuditLogStore_AppendAuditLog_GenesisHash(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	als := postgres.NewAuditLogStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	entry := makeAuditEntry(w.ID, ownerID)
	if err := als.AppendAuditLog(ctx, entry); err != nil {
		t.Fatalf("AppendAuditLog: %v", err)
	}

	// First entry should have the genesis prev_hash.
	const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if entry.PrevHash != genesisHash {
		t.Errorf("expected genesis hash, got %q", entry.PrevHash)
	}
	if entry.ID == uuid.Nil {
		t.Error("expected non-nil ID after append")
	}
}

func TestAuditLogStore_AppendAuditLog_ChainedHash(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	als := postgres.NewAuditLogStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	// First entry.
	e1 := makeAuditEntry(w.ID, ownerID)
	if err := als.AppendAuditLog(ctx, e1); err != nil {
		t.Fatalf("first AppendAuditLog: %v", err)
	}

	// Second entry — prev_hash must be derived from e1.
	e2 := makeAuditEntry(w.ID, ownerID)
	if err := als.AppendAuditLog(ctx, e2); err != nil {
		t.Fatalf("second AppendAuditLog: %v", err)
	}

	// The genesis hash is only for the first entry.
	const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"
	if e2.PrevHash == genesisHash {
		t.Error("expected chained hash, got genesis hash for second entry")
	}
	// PrevHash must be a 64-char hex string.
	if len(e2.PrevHash) != 64 {
		t.Errorf("expected 64-char prev_hash, got %d chars", len(e2.PrevHash))
	}
}

func TestAuditLogStore_GetLastAuditLog_NotFound(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	als := postgres.NewAuditLogStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Empty WS", uniqueSlug(t))

	_, err := als.GetLastAuditLog(ctx, w.ID)
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestAuditLogStore_ListAuditLogs(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	als := postgres.NewAuditLogStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	_ = als.AppendAuditLog(ctx, makeAuditEntry(w.ID, ownerID))
	_ = als.AppendAuditLog(ctx, makeAuditEntry(w.ID, ownerID))
	_ = als.AppendAuditLog(ctx, makeAuditEntry(w.ID, ownerID))

	entries, err := als.ListAuditLogs(ctx, w.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs: %v", err)
	}
	if len(entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(entries))
	}
}

func TestAuditLogStore_ListAuditLogs_Pagination(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	als := postgres.NewAuditLogStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	_ = als.AppendAuditLog(ctx, makeAuditEntry(w.ID, ownerID))
	_ = als.AppendAuditLog(ctx, makeAuditEntry(w.ID, ownerID))
	_ = als.AppendAuditLog(ctx, makeAuditEntry(w.ID, ownerID))

	// First page.
	page1, _ := als.ListAuditLogs(ctx, w.ID, 2, 0)
	if len(page1) != 2 {
		t.Errorf("expected 2 entries on page 1, got %d", len(page1))
	}

	// Second page.
	page2, _ := als.ListAuditLogs(ctx, w.ID, 2, 2)
	if len(page2) != 1 {
		t.Errorf("expected 1 entry on page 2, got %d", len(page2))
	}
}

func TestAuditLogStore_WithNilMetadata(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	als := postgres.NewAuditLogStore(db)
	ctx := context.Background()

	ownerID := createTestUserWithStore(t, ctx, us)
	w, _ := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))

	entry := &model.AuditLog{
		WorkspaceID:  w.ID,
		ActorType:    "user",
		ActorID:      ownerID,
		Action:       "key.revoked",
		ResourceType: "ssh_key",
		Metadata:     nil, // no metadata
	}

	if err := als.AppendAuditLog(ctx, entry); err != nil {
		t.Fatalf("AppendAuditLog with nil metadata: %v", err)
	}
}
