package auth

import (
	"context"
	"time"
)

// AuthRedisStore defines the Redis operations needed by auth services.
// This interface allows test mocks to replace the real Redis implementation.
type AuthRedisStore interface {
	// Email code operations
	StoreEmailCode(ctx context.Context, email, code string) error
	VerifyEmailCode(ctx context.Context, email, code string) (attempts int, valid bool, err error)
	DeleteEmailCode(ctx context.Context, email string) error

	// Machine challenge operations
	StoreChallenge(ctx context.Context, machineID, nonceHex string) error
	GetAndDeleteChallenge(ctx context.Context, machineID string) (nonceHex string, err error)

	// Refresh token operations
	StoreRefreshToken(ctx context.Context, token, userID string) error
	GetRefreshToken(ctx context.Context, token string) (userID string, err error)
	DeleteRefreshToken(ctx context.Context, token string) error

	// JWT revocation
	RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error
	IsJTIRevoked(ctx context.Context, jti string) (bool, error)

	// Member revocation (instant access removal on workspace member delete)
	RevokeMemberAccess(ctx context.Context, workspaceID, userID string, ttl time.Duration) error
	IsMemberRevoked(ctx context.Context, workspaceID, userID string) (bool, error)

	// Brute-force lockout (per email)
	// IncrEmailFailureCount increments the rolling failure counter for an email
	// and returns the new count. The counter expires after ttl if not already set.
	IncrEmailFailureCount(ctx context.Context, email string, ttl time.Duration) (int, error)
	SetLockout(ctx context.Context, email string, ttl time.Duration) error
	IsLockedOut(ctx context.Context, email string) (bool, error)
}
