package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
)

func TestKeyStore_RegisterKey_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	userID := createTestUserWithStore(t, ctx, us)
	label := "my-laptop"
	fingerprint := "SHA256:testfp" + uniqueSlug(t)

	k, err := ks.RegisterKey(ctx, userID, "ssh-ed25519 AAAAC3Nz key", "ed25519", fingerprint, &label)
	if err != nil {
		t.Fatalf("RegisterKey: %v", err)
	}
	if k.UserID != userID {
		t.Errorf("expected userID %v, got %v", userID, k.UserID)
	}
	if k.Fingerprint != fingerprint {
		t.Errorf("expected fingerprint %q, got %q", fingerprint, k.Fingerprint)
	}
	if k.Label == nil || *k.Label != label {
		t.Errorf("expected label %q, got %v", label, k.Label)
	}
}

func TestKeyStore_RegisterKey_DuplicateFingerprint(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	userID := createTestUserWithStore(t, ctx, us)
	fingerprint := "SHA256:dup" + uniqueSlug(t)

	_, err := ks.RegisterKey(ctx, userID, "ssh-ed25519 AAAAC3Nz key1", "ed25519", fingerprint, nil)
	if err != nil {
		t.Fatalf("first RegisterKey: %v", err)
	}

	_, err = ks.RegisterKey(ctx, userID, "ssh-ed25519 AAAAC3Nz key2", "ed25519", fingerprint, nil)
	if err == nil {
		t.Fatal("expected ErrDuplicateKey, got nil")
	}
	if err != store.ErrDuplicateKey {
		t.Errorf("expected ErrDuplicateKey, got %v", err)
	}
}

func TestKeyStore_GetKeyByFingerprint_Success(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	userID := createTestUserWithStore(t, ctx, us)
	fingerprint := "SHA256:fp" + uniqueSlug(t)
	created, _ := ks.RegisterKey(ctx, userID, "ssh-ed25519 key", "ed25519", fingerprint, nil)

	got, err := ks.GetKeyByFingerprint(ctx, fingerprint)
	if err != nil {
		t.Fatalf("GetKeyByFingerprint: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %v, got %v", created.ID, got.ID)
	}
}

func TestKeyStore_GetKeyByFingerprint_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	_, err := ks.GetKeyByFingerprint(ctx, "SHA256:nonexistent")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestKeyStore_ListKeys(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	userID := createTestUserWithStore(t, ctx, us)
	_, _ = ks.RegisterKey(ctx, userID, "ssh-ed25519 key1", "ed25519", "SHA256:fp1"+uniqueSlug(t), nil)
	_, _ = ks.RegisterKey(ctx, userID, "ssh-ed25519 key2", "ed25519", "SHA256:fp2"+uniqueSlug(t), nil)

	keys, err := ks.ListKeys(ctx, userID)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(keys))
	}
}

func TestKeyStore_ListKeys_OtherUserNotIncluded(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	userID1 := createTestUserWithStore(t, ctx, us)
	userID2 := createTestUserWithStore(t, ctx, us)

	_, _ = ks.RegisterKey(ctx, userID1, "ssh-ed25519 key1", "ed25519", "SHA256:fp1"+uniqueSlug(t), nil)
	_, _ = ks.RegisterKey(ctx, userID2, "ssh-ed25519 key2", "ed25519", "SHA256:fp2"+uniqueSlug(t), nil)

	keys, _ := ks.ListKeys(ctx, userID1)
	if len(keys) != 1 {
		t.Errorf("expected 1 key for user1, got %d", len(keys))
	}
}

func TestKeyStore_RevokeKey(t *testing.T) {
	db := setupTestDB(t)
	us := postgres.NewUserStore(db)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	userID := createTestUserWithStore(t, ctx, us)
	fingerprint := "SHA256:rev" + uniqueSlug(t)
	k, _ := ks.RegisterKey(ctx, userID, "ssh-ed25519 key", "ed25519", fingerprint, nil)

	if err := ks.RevokeKey(ctx, k.ID); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	// Verify revoked_at is set.
	got, err := ks.GetKeyByFingerprint(ctx, fingerprint)
	if err != nil {
		t.Fatalf("GetKeyByFingerprint after revoke: %v", err)
	}
	if got.RevokedAt == nil {
		t.Error("expected non-nil RevokedAt after revoke")
	}
}

func TestKeyStore_ListKeys_EmptyForUnknownUser(t *testing.T) {
	db := setupTestDB(t)
	ks := postgres.NewKeyStore(db)
	ctx := context.Background()

	keys, err := ks.ListKeys(ctx, uuid.New())
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys for unknown user, got %d", len(keys))
	}
}
