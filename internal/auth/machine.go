package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/store"
)

var (
	// ErrInvalidChallenge is returned when no pending challenge exists for the machine.
	ErrInvalidChallenge = errors.New("no pending challenge for this machine")
	// ErrChallengeExpired is returned when the challenge has passed its 30s TTL.
	// In practice this is surfaced as ErrInvalidChallenge since Redis auto-deletes the key.
	ErrChallengeExpired = errors.New("challenge has expired")
	// ErrInvalidSignature is returned when Ed25519 signature verification fails.
	ErrInvalidSignature = errors.New("invalid signature")
)

// MachineAuthService handles machine challenge-response authentication.
type MachineAuthService struct {
	authStore  AuthRedisStore
	jwtService *JWTService
}

// NewMachineAuthService creates a new MachineAuthService.
func NewMachineAuthService(authStore AuthRedisStore, jwtService *JWTService) *MachineAuthService {
	return &MachineAuthService{authStore: authStore, jwtService: jwtService}
}

// GenerateChallenge creates a 32-byte nonce, stores it in Redis (30s TTL), returns hex nonce.
func (s *MachineAuthService) GenerateChallenge(ctx context.Context, machineID uuid.UUID) (string, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}
	nonceHex := hex.EncodeToString(nonce)
	if err := s.authStore.StoreChallenge(ctx, machineID.String(), nonceHex); err != nil {
		return "", fmt.Errorf("storing challenge: %w", err)
	}
	return nonceHex, nil
}

// VerifyChallenge verifies an Ed25519 signature against the stored challenge nonce.
// The challenge is single-use — deleted immediately after retrieval.
// publicKeyB64 is a base64-encoded 32-byte Ed25519 public key.
// signatureHex is the hex-encoded 64-byte Ed25519 signature over the raw nonce bytes.
// On success, issues and returns a 15-minute machine JWT.
func (s *MachineAuthService) VerifyChallenge(
	ctx context.Context,
	machineID uuid.UUID,
	publicKeyB64 string,
	workspaceID uuid.UUID,
	projectID uuid.UUID,
	environment string,
	signatureHex string,
) (string, error) {
	// 1. Get and delete challenge (single-use)
	storedNonceHex, err := s.authStore.GetAndDeleteChallenge(ctx, machineID.String())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return "", ErrInvalidChallenge
		}
		return "", fmt.Errorf("getting challenge: %w", err)
	}

	// 2. Decode public key (base64-encoded 32-byte Ed25519 public key)
	pubKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(pubKeyBytes) != ed25519.PublicKeySize {
		return "", fmt.Errorf("invalid public key format")
	}
	pubKey := ed25519.PublicKey(pubKeyBytes)

	// 3. Decode signature (hex-encoded)
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return "", ErrInvalidSignature
	}

	// 4. Decode nonce bytes from hex
	nonceBytes, err := hex.DecodeString(storedNonceHex)
	if err != nil {
		return "", fmt.Errorf("decoding stored nonce: %w", err)
	}

	// 5. Verify Ed25519 signature over the raw nonce bytes
	if !ed25519.Verify(pubKey, nonceBytes, sigBytes) {
		return "", ErrInvalidSignature
	}

	// 6. Issue 15-minute machine JWT
	token, err := s.jwtService.IssueMachineToken(machineID, workspaceID, projectID, environment)
	if err != nil {
		return "", fmt.Errorf("issuing machine token: %w", err)
	}
	return token, nil
}
