package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// createTestProject creates a workspace + project for secret tests and returns their IDs.
func createTestProject(t *testing.T, ctx context.Context, db *pgxpool.Pool) (projectID, ownerID uuid.UUID) {
	t.Helper()
	us := postgres.NewUserStore(db)
	ws := postgres.NewWorkspaceStore(db)
	ps := postgres.NewProjectStore(db)

	ownerID = createTestUserWithStore(t, ctx, us)
	w, err := ws.CreateWorkspace(ctx, ownerID, "Test WS", uniqueSlug(t))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v", err)
	}
	proj, err := ps.CreateProject(ctx, w.ID, ownerID, "Test Project", uniqueSlug(t))
	if err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	return proj.ID, ownerID
}

func makeSecret(projectID, ownerID uuid.UUID, baseVersion *int) *model.Secret {
	return &model.Secret{
		ProjectID:   projectID,
		Environment: "prod",
		Ciphertext:  []byte("ciphertext"),
		Nonce:       []byte("123456789012"),     // 12 bytes
		AuthTag:     []byte("1234567890123456"), // 16 bytes
		PushedBy:    &ownerID,
		BaseVersion: baseVersion,
		KeyCount:    1,
		Checksum:    "abc123",
	}
}

func makeRecipient(ownerID uuid.UUID) model.SecretRecipient {
	return model.SecretRecipient{
		IdentityType:    "user",
		UserID:          &ownerID,
		KeyFingerprint:  "fp:test:abc123",
		EncryptedAESKey: []byte("encryptedkey"),
		EphemeralPublic: []byte("ephemeralpub"),
		KeyNonce:        []byte("keynonce"),
		KeyAuthTag:      []byte("keyauthtag"),
	}
}

func TestSecretStore_PushSecret_FirstVersion(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	sec := makeSecret(projectID, ownerID, nil) // nil base_version = first push
	recipients := []model.SecretRecipient{makeRecipient(ownerID)}

	result, err := ss.PushSecret(ctx, sec, recipients)
	if err != nil {
		t.Fatalf("PushSecret: %v", err)
	}
	if result.Version != 1 {
		t.Errorf("expected version 1, got %d", result.Version)
	}
	if result.ID == uuid.Nil {
		t.Error("expected non-nil ID")
	}
}

func TestSecretStore_PushSecret_IncrementVersion(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	// Push version 1
	sec1 := makeSecret(projectID, ownerID, nil)
	r1, err := ss.PushSecret(ctx, sec1, []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("first PushSecret: %v", err)
	}
	if r1.Version != 1 {
		t.Errorf("expected version 1, got %d", r1.Version)
	}

	// Push version 2 with base_version=1
	baseV := 1
	sec2 := makeSecret(projectID, ownerID, &baseV)
	r2, err := ss.PushSecret(ctx, sec2, []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("second PushSecret: %v", err)
	}
	if r2.Version != 2 {
		t.Errorf("expected version 2, got %d", r2.Version)
	}
}

func TestSecretStore_PushSecret_ConflictDetection(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	// Push version 1
	sec1 := makeSecret(projectID, ownerID, nil)
	_, err := ss.PushSecret(ctx, sec1, []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("first PushSecret: %v", err)
	}

	// Push with wrong base_version (0 instead of 1)
	wrongBase := 0
	sec2 := makeSecret(projectID, ownerID, &wrongBase)
	_, err = ss.PushSecret(ctx, sec2, []model.SecretRecipient{makeRecipient(ownerID)})
	if err == nil {
		t.Fatal("expected ErrPushConflict, got nil")
	}
	if err != store.ErrPushConflict {
		t.Errorf("expected ErrPushConflict, got %v", err)
	}
}

func TestSecretStore_GetLatestSecret_Success(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	_, err := ss.PushSecret(ctx, makeSecret(projectID, ownerID, nil), []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("first push: %v", err)
	}
	baseV := 1
	_, err = ss.PushSecret(ctx, makeSecret(projectID, ownerID, &baseV), []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("second push: %v", err)
	}

	latest, err := ss.GetLatestSecret(ctx, projectID, "prod")
	if err != nil {
		t.Fatalf("GetLatestSecret: %v", err)
	}
	if latest.Version != 2 {
		t.Errorf("expected version 2, got %d", latest.Version)
	}
}

func TestSecretStore_GetLatestSecret_NotFound(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, _ := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	_, err := ss.GetLatestSecret(ctx, projectID, "staging")
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestSecretStore_ListVersions_DescendingOrder(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	_, err := ss.PushSecret(ctx, makeSecret(projectID, ownerID, nil), []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("first push: %v", err)
	}
	baseV := 1
	_, err = ss.PushSecret(ctx, makeSecret(projectID, ownerID, &baseV), []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("second push: %v", err)
	}

	versions, err := ss.ListVersions(ctx, projectID, "prod")
	if err != nil {
		t.Fatalf("ListVersions: %v", err)
	}
	if len(versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(versions))
	}
	// Should be in descending order.
	if versions[0].Version != 2 {
		t.Errorf("expected first version to be 2, got %d", versions[0].Version)
	}
	if versions[1].Version != 1 {
		t.Errorf("expected second version to be 1, got %d", versions[1].Version)
	}
}

func TestSecretStore_GetRecipientsBySecret(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	result, err := ss.PushSecret(ctx, makeSecret(projectID, ownerID, nil), []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("PushSecret: %v", err)
	}

	recipients, err := ss.GetRecipientsBySecret(ctx, result.ID)
	if err != nil {
		t.Fatalf("GetRecipientsBySecret: %v", err)
	}
	if len(recipients) != 1 {
		t.Fatalf("expected 1 recipient, got %d", len(recipients))
	}
	if recipients[0].KeyFingerprint != "fp:test:abc123" {
		t.Errorf("expected fingerprint %q, got %q", "fp:test:abc123", recipients[0].KeyFingerprint)
	}
}

func TestSecretStore_ListEnvironments(t *testing.T) {
	db := setupTestDB(t)
	ctx := context.Background()
	projectID, ownerID := createTestProject(t, ctx, db)
	ss := postgres.NewSecretStore(db)

	// Push to two environments.
	sec1 := makeSecret(projectID, ownerID, nil)
	sec1.Environment = "staging"
	_, err := ss.PushSecret(ctx, sec1, []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("push to staging: %v", err)
	}

	sec2 := makeSecret(projectID, ownerID, nil)
	sec2.Environment = "production"
	_, err = ss.PushSecret(ctx, sec2, []model.SecretRecipient{makeRecipient(ownerID)})
	if err != nil {
		t.Fatalf("push to production: %v", err)
	}

	envs, err := ss.ListEnvironments(ctx, projectID)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	if len(envs) != 2 {
		t.Errorf("expected 2 environments, got %d", len(envs))
	}
}
