package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// buildExpiredHumanToken creates a JWT with an expiry in the past, for testing rejection.
func buildExpiredHumanToken(secret []byte, userID uuid.UUID, email string, workspaceID uuid.UUID) (string, error) {
	past := time.Now().Add(-2 * time.Hour)
	claims := HumanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(past.Add(-time.Hour)),
			ExpiresAt: jwt.NewNumericDate(past),
			ID:        uuid.New().String(),
		},
		Email:       email,
		WorkspaceID: workspaceID,
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
}

// newJWTTestService creates a JWTService with a mock auth store.
func newJWTTestService(secret string) *JWTService {
	return NewJWTService(secret, newMockAuthStore())
}

// --- Tests ---

// TestIssueHumanTokens verifies token structure, expiry, and claims.
func TestIssueHumanTokens(t *testing.T) {
	ctx := context.Background()
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newJWTTestService(secret)

	userID := uuid.New()
	workspaceID := uuid.New()

	pair, err := svc.IssueHumanTokens(ctx, userID, "alice@example.com", workspaceID)
	if err != nil {
		t.Fatalf("IssueHumanTokens: %v", err)
	}
	if pair.AccessToken == "" {
		t.Error("expected non-empty access token")
	}
	// Refresh token: 32 bytes → 64 hex chars
	if len(pair.RefreshToken) != 64 {
		t.Errorf("expected 64-char refresh token, got %d", len(pair.RefreshToken))
	}

	// Verify access token claims
	claims, err := svc.VerifyHumanToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("VerifyHumanToken: %v", err)
	}
	if claims.Subject != userID.String() {
		t.Errorf("expected sub=%s, got %s", userID, claims.Subject)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %s", claims.Email)
	}
	if claims.WorkspaceID != workspaceID {
		t.Errorf("expected workspace_id=%s, got %s", workspaceID, claims.WorkspaceID)
	}

	// Expiry should be ~24h from now
	expiry := claims.ExpiresAt.Time
	expectedExpiry := time.Now().Add(24 * time.Hour)
	diff := expectedExpiry.Sub(expiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("expiry not within 1 minute of 24h from now: %v", expiry)
	}
}

// TestIssueMachineToken verifies machine token structure and 15-min expiry.
func TestIssueMachineToken(t *testing.T) {
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newJWTTestService(secret)

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()

	tokenStr, err := svc.IssueMachineToken(machineID, workspaceID, projectID, "production")
	if err != nil {
		t.Fatalf("IssueMachineToken: %v", err)
	}

	claims, err := svc.VerifyMachineToken(tokenStr)
	if err != nil {
		t.Fatalf("VerifyMachineToken: %v", err)
	}
	if claims.MachineID != machineID {
		t.Errorf("expected machine_id=%s, got %s", machineID, claims.MachineID)
	}
	if claims.WorkspaceID != workspaceID {
		t.Errorf("expected workspace_id=%s, got %s", workspaceID, claims.WorkspaceID)
	}
	if claims.ProjectID != projectID {
		t.Errorf("expected project_id=%s, got %s", projectID, claims.ProjectID)
	}
	if claims.Environment != "production" {
		t.Errorf("expected environment=production, got %s", claims.Environment)
	}

	// Expiry should be ~15 min from now
	expiry := claims.ExpiresAt.Time
	expected15min := time.Now().Add(15 * time.Minute)
	diff := expected15min.Sub(expiry)
	if diff < -time.Minute || diff > time.Minute {
		t.Errorf("machine token expiry not within 1 minute of 15min from now: %v", expiry)
	}
}

// TestVerifyHumanToken_Valid verifies that a valid token parses correctly.
func TestVerifyHumanToken_Valid(t *testing.T) {
	ctx := context.Background()
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newJWTTestService(secret)

	userID := uuid.New()
	workspaceID := uuid.New()
	pair, err := svc.IssueHumanTokens(ctx, userID, "test@example.com", workspaceID)
	if err != nil {
		t.Fatalf("IssueHumanTokens: %v", err)
	}

	claims, err := svc.VerifyHumanToken(pair.AccessToken)
	if err != nil {
		t.Fatalf("expected valid token, got: %v", err)
	}
	if claims.Subject != userID.String() {
		t.Errorf("wrong subject: %s", claims.Subject)
	}
}

// TestVerifyHumanToken_Expired verifies that an expired token returns ErrExpiredToken.
func TestVerifyHumanToken_Expired(t *testing.T) {
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newJWTTestService(secret)

	tokenStr, err := buildExpiredHumanToken([]byte(secret), uuid.New(), "exp@example.com", uuid.New())
	if err != nil {
		t.Fatalf("buildExpiredHumanToken: %v", err)
	}

	_, err = svc.VerifyHumanToken(tokenStr)
	if !errors.Is(err, ErrExpiredToken) {
		t.Errorf("expected ErrExpiredToken, got: %v", err)
	}
}

// TestVerifyHumanToken_Tampered verifies that a tampered token returns ErrInvalidToken.
func TestVerifyHumanToken_Tampered(t *testing.T) {
	ctx := context.Background()
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newJWTTestService(secret)

	pair, err := svc.IssueHumanTokens(ctx, uuid.New(), "tamper@example.com", uuid.New())
	if err != nil {
		t.Fatalf("IssueHumanTokens: %v", err)
	}

	// Flip last character to break signature
	tokenBytes := []byte(pair.AccessToken)
	last := len(tokenBytes) - 1
	if tokenBytes[last] == 'a' {
		tokenBytes[last] = 'b'
	} else {
		tokenBytes[last] = 'a'
	}

	_, err = svc.VerifyHumanToken(string(tokenBytes))
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for tampered token, got: %v", err)
	}
}

// TestValidateAndConsumeRefreshToken verifies single-use refresh token consumption.
func TestValidateAndConsumeRefreshToken(t *testing.T) {
	ctx := context.Background()
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newJWTTestService(secret)

	userID := uuid.New()
	workspaceID := uuid.New()
	pair, err := svc.IssueHumanTokens(ctx, userID, "refresh@example.com", workspaceID)
	if err != nil {
		t.Fatalf("IssueHumanTokens: %v", err)
	}

	// First use — should succeed
	gotUserID, gotWorkspaceID, err := svc.ValidateAndConsumeRefreshToken(ctx, pair.RefreshToken)
	if err != nil {
		t.Fatalf("ValidateAndConsumeRefreshToken: %v", err)
	}
	if gotUserID != userID {
		t.Errorf("expected userID=%s, got %s", userID, gotUserID)
	}
	if gotWorkspaceID != workspaceID {
		t.Errorf("expected workspaceID=%s, got %s", workspaceID, gotWorkspaceID)
	}

	// Second use — token should be deleted → ErrInvalidToken
	_, _, err = svc.ValidateAndConsumeRefreshToken(ctx, pair.RefreshToken)
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on second use, got: %v", err)
	}
}
