package postgres_test

import (
	"context"
	"testing"

	"github.com/envshq/envsh-server/internal/store"
	"github.com/envshq/envsh-server/internal/store/postgres"
	"github.com/google/uuid"
)

func TestUserStore_CreateUser_Success(t *testing.T) {
	db := setupTestDB(t)
	s := postgres.NewUserStore(db)
	ctx := context.Background()

	email := uniqueEmail(t)
	user, err := s.CreateUser(ctx, email)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if user.Email != email {
		t.Errorf("expected email %q, got %q", email, user.Email)
	}
	if user.ID == uuid.Nil {
		t.Error("expected non-nil ID")
	}
	if user.CreatedAt.IsZero() {
		t.Error("expected non-zero CreatedAt")
	}
}

func TestUserStore_CreateUser_DuplicateEmail(t *testing.T) {
	db := setupTestDB(t)
	s := postgres.NewUserStore(db)
	ctx := context.Background()

	email := uniqueEmail(t)
	_, err := s.CreateUser(ctx, email)
	if err != nil {
		t.Fatalf("first CreateUser: %v", err)
	}

	_, err = s.CreateUser(ctx, email)
	if err == nil {
		t.Fatal("expected ErrDuplicateEmail, got nil")
	}
	if err != store.ErrDuplicateEmail {
		t.Errorf("expected ErrDuplicateEmail, got %v", err)
	}
}

func TestUserStore_GetUserByID_Success(t *testing.T) {
	db := setupTestDB(t)
	s := postgres.NewUserStore(db)
	ctx := context.Background()

	email := uniqueEmail(t)
	created, err := s.CreateUser(ctx, email)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByID(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %v, got %v", created.ID, got.ID)
	}
	if got.Email != email {
		t.Errorf("expected email %q, got %q", email, got.Email)
	}
}

func TestUserStore_GetUserByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	s := postgres.NewUserStore(db)
	ctx := context.Background()

	_, err := s.GetUserByID(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestUserStore_GetUserByEmail_Success(t *testing.T) {
	db := setupTestDB(t)
	s := postgres.NewUserStore(db)
	ctx := context.Background()

	email := uniqueEmail(t)
	created, err := s.CreateUser(ctx, email)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	got, err := s.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("expected ID %v, got %v", created.ID, got.ID)
	}
}

func TestUserStore_GetUserByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	s := postgres.NewUserStore(db)
	ctx := context.Background()

	_, err := s.GetUserByEmail(ctx, "nobody@nowhere.com")
	if err == nil {
		t.Fatal("expected ErrNotFound, got nil")
	}
	if err != store.ErrNotFound {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}
