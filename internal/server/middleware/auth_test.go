package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/auth"
	"github.com/envshq/envsh-server/internal/server/middleware"
	"github.com/envshq/envsh-server/internal/store"
)

// mockAuthStore is a minimal in-memory AuthRedisStore for testing.
type mockAuthStore struct {
	refreshTokens  map[string]string
	revokedJTIs    map[string]bool
	revokedMembers map[string]bool
	lockouts       map[string]bool
	failureCounts  map[string]int
}

func newMockAuthStore() *mockAuthStore {
	return &mockAuthStore{
		refreshTokens:  make(map[string]string),
		revokedJTIs:    make(map[string]bool),
		revokedMembers: make(map[string]bool),
		lockouts:       make(map[string]bool),
		failureCounts:  make(map[string]int),
	}
}

func (m *mockAuthStore) StoreEmailCode(_ context.Context, _, _ string) error { return nil }
func (m *mockAuthStore) VerifyEmailCode(_ context.Context, _, _ string) (int, bool, error) {
	return 0, false, nil
}
func (m *mockAuthStore) DeleteEmailCode(_ context.Context, _ string) error { return nil }
func (m *mockAuthStore) StoreChallenge(_ context.Context, _, _ string) error { return nil }
func (m *mockAuthStore) GetAndDeleteChallenge(_ context.Context, _ string) (string, error) {
	return "", nil
}
func (m *mockAuthStore) StoreRefreshToken(_ context.Context, token, userID string) error {
	m.refreshTokens[token] = userID
	return nil
}
func (m *mockAuthStore) GetRefreshToken(_ context.Context, token string) (string, error) {
	if v, ok := m.refreshTokens[token]; ok {
		return v, nil
	}
	return "", store.ErrNotFound
}
func (m *mockAuthStore) DeleteRefreshToken(_ context.Context, token string) error {
	delete(m.refreshTokens, token)
	return nil
}
func (m *mockAuthStore) RevokeJTI(_ context.Context, jti string, _ time.Duration) error {
	m.revokedJTIs[jti] = true
	return nil
}
func (m *mockAuthStore) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	return m.revokedJTIs[jti], nil
}
func (m *mockAuthStore) IncrEmailFailureCount(_ context.Context, email string, _ time.Duration) (int, error) {
	m.failureCounts[email]++
	return m.failureCounts[email], nil
}
func (m *mockAuthStore) SetLockout(_ context.Context, email string, _ time.Duration) error {
	m.lockouts[email] = true
	return nil
}
func (m *mockAuthStore) IsLockedOut(_ context.Context, email string) (bool, error) {
	return m.lockouts[email], nil
}
func (m *mockAuthStore) RevokeMemberAccess(_ context.Context, workspaceID, userID string, _ time.Duration) error {
	m.revokedMembers[workspaceID+":"+userID] = true
	return nil
}
func (m *mockAuthStore) IsMemberRevoked(_ context.Context, workspaceID, userID string) (bool, error) {
	return m.revokedMembers[workspaceID+":"+userID], nil
}

func TestRequireHuman_MissingToken(t *testing.T) {
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", newMockAuthStore())
	mw := middleware.RequireHuman(jwtSvc)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	mw(next).ServeHTTP(rec, req)

	if called {
		t.Error("handler should not have been called")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireHuman_ValidToken(t *testing.T) {
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", newMockAuthStore())
	mw := middleware.RequireHuman(jwtSvc)

	userID := uuid.New()
	workspaceID := uuid.New()
	tokens, err := jwtSvc.IssueHumanTokens(context.Background(), userID, "test@example.com", workspaceID)
	if err != nil {
		t.Fatalf("issuing tokens: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()

	var gotClaims *auth.HumanClaims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = middleware.HumanClaimsFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotClaims == nil {
		t.Fatal("expected claims in context, got nil")
	}
	if gotClaims.WorkspaceID != workspaceID {
		t.Errorf("expected workspaceID %s, got %s", workspaceID, gotClaims.WorkspaceID)
	}
}

func TestRequireHuman_ExpiredToken(t *testing.T) {
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", newMockAuthStore())
	mw := middleware.RequireHuman(jwtSvc)

	// Build an expired token manually
	userID := uuid.New()
	workspaceID := uuid.New()
	claims := auth.HumanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			ID:        uuid.New().String(),
		},
		Email:       "test@example.com",
		WorkspaceID: workspaceID,
	}
	expiredToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("test-secret-that-is-long-enough"))
	if err != nil {
		t.Fatalf("signing expired token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+expiredToken)
	rec := httptest.NewRecorder()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	mw(next).ServeHTTP(rec, req)

	if called {
		t.Error("handler should not have been called with expired token")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestRequireHumanOrMachine_AcceptsHuman(t *testing.T) {
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", newMockAuthStore())
	mw := middleware.RequireHumanOrMachine(jwtSvc)

	userID := uuid.New()
	workspaceID := uuid.New()
	tokens, err := jwtSvc.IssueHumanTokens(context.Background(), userID, "test@example.com", workspaceID)
	if err != nil {
		t.Fatalf("issuing tokens: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()

	var gotClaims *auth.HumanClaims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = middleware.HumanClaimsFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotClaims == nil {
		t.Fatal("expected human claims in context, got nil")
	}
}

func TestRequireHumanOrMachine_AcceptsMachine(t *testing.T) {
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", newMockAuthStore())
	mw := middleware.RequireHumanOrMachine(jwtSvc)

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()
	token, err := jwtSvc.IssueMachineToken(machineID, workspaceID, projectID, "production")
	if err != nil {
		t.Fatalf("issuing machine token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	var gotClaims *auth.MachineClaims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotClaims = middleware.MachineClaimsFrom(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if gotClaims == nil {
		t.Fatal("expected machine claims in context, got nil")
	}
	if gotClaims.MachineID != machineID {
		t.Errorf("expected machineID %s, got %s", machineID, gotClaims.MachineID)
	}
}

func TestRequireHuman_RevokedJTI(t *testing.T) {
	ms := newMockAuthStore()
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", ms)
	mw := middleware.RequireHuman(jwtSvc)

	userID := uuid.New()
	workspaceID := uuid.New()
	tokens, err := jwtSvc.IssueHumanTokens(context.Background(), userID, "test@example.com", workspaceID)
	if err != nil {
		t.Fatalf("issuing tokens: %v", err)
	}

	// Parse the access token to get the JTI so we can revoke it
	claims, err := jwtSvc.VerifyHumanToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("verifying token to get JTI: %v", err)
	}

	// Revoke the JTI
	ms.revokedJTIs[claims.ID] = true

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	mw(next).ServeHTTP(rec, req)

	if called {
		t.Error("handler should not have been called with revoked JTI")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked JTI, got %d", rec.Code)
	}
}

func TestRequireMachine_RevokedJTI(t *testing.T) {
	ms := newMockAuthStore()
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", ms)
	mw := middleware.RequireMachine(jwtSvc)

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()
	token, err := jwtSvc.IssueMachineToken(machineID, workspaceID, projectID, "production")
	if err != nil {
		t.Fatalf("issuing machine token: %v", err)
	}

	// Parse the token to get the JTI
	claims, err := jwtSvc.VerifyMachineToken(token)
	if err != nil {
		t.Fatalf("verifying token to get JTI: %v", err)
	}

	// Revoke the JTI
	ms.revokedJTIs[claims.ID] = true

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	mw(next).ServeHTTP(rec, req)

	if called {
		t.Error("handler should not have been called with revoked machine JTI")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked machine JTI, got %d", rec.Code)
	}
}

func TestRequireHumanOrMachine_RevokedHumanJTI(t *testing.T) {
	ms := newMockAuthStore()
	jwtSvc := auth.NewJWTService("test-secret-that-is-long-enough", ms)
	mw := middleware.RequireHumanOrMachine(jwtSvc)

	userID := uuid.New()
	workspaceID := uuid.New()
	tokens, err := jwtSvc.IssueHumanTokens(context.Background(), userID, "test@example.com", workspaceID)
	if err != nil {
		t.Fatalf("issuing tokens: %v", err)
	}

	claims, err := jwtSvc.VerifyHumanToken(tokens.AccessToken)
	if err != nil {
		t.Fatalf("verifying token: %v", err)
	}

	// Revoke the JTI
	ms.revokedJTIs[claims.ID] = true

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	rec := httptest.NewRecorder()

	var called bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	mw(next).ServeHTTP(rec, req)

	if called {
		t.Error("handler should not have been called with revoked JTI")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked JTI, got %d", rec.Code)
	}
}
