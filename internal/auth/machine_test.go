package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

// newTestMachineAuthService builds a MachineAuthService using mock stores.
func newTestMachineAuthService(secret string) *MachineAuthService {
	ms := newMockAuthStore()
	jwtSvc := NewJWTService(secret, ms)
	return NewMachineAuthService(ms, jwtSvc)
}

// --- Tests ---

// TestGenerateChallenge verifies that a 64-character hex nonce is returned.
func TestGenerateChallenge(t *testing.T) {
	ctx := context.Background()
	svc := newTestMachineAuthService("test-secret-key-at-least-32-bytes!!")
	machineID := uuid.New()

	nonceHex, err := svc.GenerateChallenge(ctx, machineID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}
	// 32 bytes → 64 hex chars
	if len(nonceHex) != 64 {
		t.Errorf("expected 64-char hex nonce, got %d chars: %q", len(nonceHex), nonceHex)
	}
	// Must be valid hex
	if _, err := hex.DecodeString(nonceHex); err != nil {
		t.Errorf("nonce is not valid hex: %v", err)
	}
}

// TestVerifyChallenge_Valid generates a real Ed25519 keypair, signs the nonce, and verifies it.
func TestVerifyChallenge_Valid(t *testing.T) {
	ctx := context.Background()
	const secret = "test-secret-key-at-least-32-bytes!!"
	svc := newTestMachineAuthService(secret)

	// Generate real Ed25519 keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating Ed25519 keypair: %v", err)
	}

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()

	// Generate challenge
	nonceHex, err := svc.GenerateChallenge(ctx, machineID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	// Sign the raw nonce bytes with the private key
	nonceBytes, _ := hex.DecodeString(nonceHex)
	sig := ed25519.Sign(privKey, nonceBytes)
	signatureHex := hex.EncodeToString(sig)
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// Verify challenge
	tokenStr, err := svc.VerifyChallenge(ctx, machineID, publicKeyB64, workspaceID, projectID, "production", signatureHex)
	if err != nil {
		t.Fatalf("VerifyChallenge: %v", err)
	}
	if tokenStr == "" {
		t.Error("expected non-empty machine JWT")
	}

	// Validate the returned token has correct machine claims
	jwtSvc := NewJWTService(secret, newMockAuthStore())
	claims, err := jwtSvc.VerifyMachineToken(tokenStr)
	if err != nil {
		t.Fatalf("VerifyMachineToken: %v", err)
	}
	if claims.MachineID != machineID {
		t.Errorf("expected machine_id=%s, got %s", machineID, claims.MachineID)
	}
	if claims.Environment != "production" {
		t.Errorf("expected environment=production, got %s", claims.Environment)
	}
	if claims.ProjectID != projectID {
		t.Errorf("expected project_id=%s, got %s", projectID, claims.ProjectID)
	}
}

// TestVerifyChallenge_InvalidSignature verifies that a wrong signature returns ErrInvalidSignature.
func TestVerifyChallenge_InvalidSignature(t *testing.T) {
	ctx := context.Background()
	svc := newTestMachineAuthService("test-secret-key-at-least-32-bytes!!")

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()

	_, err = svc.GenerateChallenge(ctx, machineID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	// Sign with a DIFFERENT private key — wrong signature
	_, wrongPrivKey, _ := ed25519.GenerateKey(rand.Reader)
	wrongSig := ed25519.Sign(wrongPrivKey, []byte("some random data"))
	signatureHex := hex.EncodeToString(wrongSig)
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	_, err = svc.VerifyChallenge(ctx, machineID, publicKeyB64, workspaceID, projectID, "staging", signatureHex)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Errorf("expected ErrInvalidSignature, got: %v", err)
	}
}

// TestVerifyChallenge_SingleUse verifies the challenge is deleted after the first verify attempt.
func TestVerifyChallenge_SingleUse(t *testing.T) {
	ctx := context.Background()
	svc := newTestMachineAuthService("test-secret-key-at-least-32-bytes!!")

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()

	nonceHex, err := svc.GenerateChallenge(ctx, machineID)
	if err != nil {
		t.Fatalf("GenerateChallenge: %v", err)
	}

	nonceBytes, _ := hex.DecodeString(nonceHex)
	sig := ed25519.Sign(privKey, nonceBytes)
	signatureHex := hex.EncodeToString(sig)
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// First verify — must succeed
	_, err = svc.VerifyChallenge(ctx, machineID, publicKeyB64, workspaceID, projectID, "dev", signatureHex)
	if err != nil {
		t.Fatalf("first VerifyChallenge: %v", err)
	}

	// Second verify — challenge must be gone
	_, err = svc.VerifyChallenge(ctx, machineID, publicKeyB64, workspaceID, projectID, "dev", signatureHex)
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Errorf("expected ErrInvalidChallenge on second verify, got: %v", err)
	}
}

// TestVerifyChallenge_NoChallenge verifies that verifying without a prior challenge returns ErrInvalidChallenge.
func TestVerifyChallenge_NoChallenge(t *testing.T) {
	ctx := context.Background()
	svc := newTestMachineAuthService("test-secret-key-at-least-32-bytes!!")

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating keypair: %v", err)
	}

	machineID := uuid.New()
	workspaceID := uuid.New()
	projectID := uuid.New()
	publicKeyB64 := base64.StdEncoding.EncodeToString(pubKey)

	// No challenge stored for this machine
	_, err = svc.VerifyChallenge(ctx, machineID, publicKeyB64, workspaceID, projectID, "prod", "deadbeef00deadbeef00")
	if !errors.Is(err, ErrInvalidChallenge) {
		t.Errorf("expected ErrInvalidChallenge with no challenge, got: %v", err)
	}
}
