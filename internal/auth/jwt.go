package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/store"
)

var (
	// ErrExpiredToken is returned when a JWT has passed its expiry time.
	ErrExpiredToken = errors.New("token has expired")
	// ErrInvalidToken is returned when a JWT fails signature verification or has invalid claims.
	ErrInvalidToken = errors.New("invalid token")
)

// HumanClaims are the JWT claims for human users.
type HumanClaims struct {
	jwt.RegisteredClaims
	Email       string    `json:"email"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
}

// MachineClaims are the JWT claims for machine identities.
type MachineClaims struct {
	jwt.RegisteredClaims
	MachineID   uuid.UUID `json:"machine_id"`
	WorkspaceID uuid.UUID `json:"workspace_id"`
	ProjectID   uuid.UUID `json:"project_id"`
	Environment string    `json:"environment"`
}

// TokenPair holds an access token and refresh token.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
}

// JWTService issues and validates JWTs.
type JWTService struct {
	secret    []byte
	authStore AuthRedisStore
}

// NewJWTService creates a new JWTService using HS256 with the provided secret.
func NewJWTService(secret string, authStore AuthRedisStore) *JWTService {
	return &JWTService{secret: []byte(secret), authStore: authStore}
}

// IssueHumanTokens issues a 24h access token + 30d refresh token for a human user.
func (s *JWTService) IssueHumanTokens(ctx context.Context, userID uuid.UUID, email string, workspaceID uuid.UUID) (*TokenPair, error) {
	jti := uuid.New().String()
	now := time.Now()

	claims := HumanClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(24 * time.Hour)),
			ID:        jti,
		},
		Email:       email,
		WorkspaceID: workspaceID,
	}

	accessToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return nil, fmt.Errorf("signing access token: %w", err)
	}

	// Generate opaque refresh token (32 random bytes, hex-encoded)
	refreshToken, err := generateOpaqueToken()
	if err != nil {
		return nil, fmt.Errorf("generating refresh token: %w", err)
	}

	// Store refresh token hash → userID in Redis (30d TTL)
	if err := s.authStore.StoreRefreshToken(ctx, refreshToken, userID.String()); err != nil {
		return nil, fmt.Errorf("storing refresh token: %w", err)
	}

	return &TokenPair{AccessToken: accessToken, RefreshToken: refreshToken}, nil
}

// IssueMachineToken issues a 15-minute access token for a machine. Non-refreshable.
func (s *JWTService) IssueMachineToken(machineID, workspaceID, projectID uuid.UUID, environment string) (string, error) {
	jti := uuid.New().String()
	now := time.Now()

	claims := MachineClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   machineID.String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(15 * time.Minute)),
			ID:        jti,
		},
		MachineID:   machineID,
		WorkspaceID: workspaceID,
		ProjectID:   projectID,
		Environment: environment,
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(s.secret)
	if err != nil {
		return "", fmt.Errorf("signing machine token: %w", err)
	}
	return token, nil
}

// VerifyHumanToken parses and validates a human JWT. Returns claims or error.
func (s *JWTService) VerifyHumanToken(tokenStr string) (*HumanClaims, error) {
	claims := &HumanClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	// Discriminate: human tokens must have a non-empty email.
	if claims.Email == "" {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// VerifyMachineToken parses and validates a machine JWT. Returns claims or error.
func (s *JWTService) VerifyMachineToken(tokenStr string) (*MachineClaims, error) {
	claims := &MachineClaims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	// Discriminate: machine tokens must have a non-nil machine_id.
	if claims.MachineID == uuid.Nil {
		return nil, ErrInvalidToken
	}
	return claims, nil
}

// ValidateAndConsumeRefreshToken validates a refresh token and returns the userID.
// The refresh token is deleted (consumed) after this call — callers must re-issue.
func (s *JWTService) ValidateAndConsumeRefreshToken(ctx context.Context, refreshToken string) (uuid.UUID, error) {
	userIDStr, err := s.authStore.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return uuid.Nil, ErrInvalidToken
		}
		return uuid.Nil, fmt.Errorf("getting refresh token: %w", err)
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.Nil, fmt.Errorf("parsing user ID from refresh token: %w", err)
	}

	if err := s.authStore.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return uuid.Nil, fmt.Errorf("deleting refresh token: %w", err)
	}

	return userID, nil
}

// RevokeRefreshToken invalidates a refresh token (logout).
func (s *JWTService) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if err := s.authStore.DeleteRefreshToken(ctx, refreshToken); err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

// CheckJTIRevoked checks whether a JWT ID (jti claim) has been revoked.
// Returns true if revoked, false otherwise.
func (s *JWTService) CheckJTIRevoked(ctx context.Context, jti string) (bool, error) {
	revoked, err := s.authStore.IsJTIRevoked(ctx, jti)
	if err != nil {
		return false, fmt.Errorf("checking JTI revocation: %w", err)
	}
	return revoked, nil
}

// generateOpaqueToken returns 32 random bytes as a hex string.
func generateOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
