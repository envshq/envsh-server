package redis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/envshq/envsh-server/internal/store"
)

const (
	emailCodeTTL    = 5 * time.Minute
	challengeTTL    = 30 * time.Second
	refreshTokenTTL = 30 * 24 * time.Hour
)

// AuthStore handles all auth-related Redis operations.
type AuthStore struct {
	client *redis.Client
}

// NewAuthStore returns a new AuthStore backed by the given Redis client.
func NewAuthStore(client *redis.Client) *AuthStore {
	return &AuthStore{client: client}
}

// --- Email code operations ---

// emailCodeKey returns the Redis key for a given email's verification code.
// Format: "email-code:{email}"
func emailCodeKey(email string) string {
	return fmt.Sprintf("email-code:%s", email)
}

// hashCode returns the SHA-256 hex hash of the code — never store plaintext.
func hashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// StoreEmailCode stores the hashed code in Redis with a 5-minute TTL.
// The value format is: "{code_hash}|{attempts}|{unix_timestamp}"
func (s *AuthStore) StoreEmailCode(ctx context.Context, email, code string) error {
	key := emailCodeKey(email)
	value := fmt.Sprintf("%s|0|%d", hashCode(code), time.Now().Unix())
	if err := s.client.Set(ctx, key, value, emailCodeTTL).Err(); err != nil {
		return fmt.Errorf("storing email code: %w", err)
	}
	return nil
}

// VerifyEmailCode checks the submitted code against the stored hash.
// It increments the attempt counter on each call.
// Returns (attempts, valid, err). attempts is the new value after incrementing.
// Returns store.ErrNotFound if the key does not exist.
func (s *AuthStore) VerifyEmailCode(ctx context.Context, email, code string) (int, bool, error) {
	key := emailCodeKey(email)
	val, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return 0, false, store.ErrNotFound
	}
	if err != nil {
		return 0, false, fmt.Errorf("getting email code: %w", err)
	}

	parts := strings.SplitN(val, "|", 3)
	if len(parts) != 3 {
		return 0, false, fmt.Errorf("malformed email code value")
	}

	storedHash := parts[0]
	attemptsStr := parts[1]
	timestamp := parts[2]

	attempts, err := strconv.Atoi(attemptsStr)
	if err != nil {
		return 0, false, fmt.Errorf("parsing attempts: %w", err)
	}

	// Increment attempts before checking validity (prevent brute force)
	newAttempts := attempts + 1
	newValue := fmt.Sprintf("%s|%d|%s", storedHash, newAttempts, timestamp)

	// Get the remaining TTL so we can preserve it
	ttl, err := s.client.TTL(ctx, key).Result()
	if err != nil || ttl <= 0 {
		ttl = emailCodeTTL
	}

	if setErr := s.client.Set(ctx, key, newValue, ttl).Err(); setErr != nil {
		return newAttempts, false, fmt.Errorf("updating attempts: %w", setErr)
	}

	// Check attempt limit
	if newAttempts > 3 {
		return newAttempts, false, nil
	}

	// Validate code
	valid := hashCode(code) == storedHash
	return newAttempts, valid, nil
}

// DeleteEmailCode removes the email code from Redis.
func (s *AuthStore) DeleteEmailCode(ctx context.Context, email string) error {
	key := emailCodeKey(email)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("deleting email code: %w", err)
	}
	return nil
}

// --- Machine challenge operations ---

// challengeKey returns the Redis key for a machine's challenge nonce.
// Format: "challenge:{machine_id}"
func challengeKey(machineID string) string {
	return fmt.Sprintf("challenge:%s", machineID)
}

// StoreChallenge stores a nonce hex string for the given machine (30s TTL).
func (s *AuthStore) StoreChallenge(ctx context.Context, machineID, nonceHex string) error {
	key := challengeKey(machineID)
	value := fmt.Sprintf("%s|%d", nonceHex, time.Now().Unix())
	if err := s.client.Set(ctx, key, value, challengeTTL).Err(); err != nil {
		return fmt.Errorf("storing challenge: %w", err)
	}
	return nil
}

// GetAndDeleteChallenge retrieves and atomically deletes the nonce for a machine.
// The challenge is single-use. Returns store.ErrNotFound if no challenge exists.
func (s *AuthStore) GetAndDeleteChallenge(ctx context.Context, machineID string) (string, error) {
	key := challengeKey(machineID)
	val, err := s.client.GetDel(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getting challenge: %w", err)
	}

	// Value format: "{nonce_hex}|{unix_timestamp}"
	parts := strings.SplitN(val, "|", 2)
	if len(parts) < 1 {
		return "", fmt.Errorf("malformed challenge value")
	}
	return parts[0], nil
}

// --- Refresh token operations ---

// refreshTokenKey returns the Redis key for a refresh token.
// Key is derived from SHA-256(token) to avoid storing the token directly.
// Format: "refresh:{sha256(token)}"
func refreshTokenKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("refresh:%s", hex.EncodeToString(sum[:]))
}

// StoreRefreshToken stores userID keyed by the token hash (30d TTL).
func (s *AuthStore) StoreRefreshToken(ctx context.Context, token, userID string) error {
	key := refreshTokenKey(token)
	if err := s.client.Set(ctx, key, userID, refreshTokenTTL).Err(); err != nil {
		return fmt.Errorf("storing refresh token: %w", err)
	}
	return nil
}

// GetRefreshToken returns the userID associated with the token.
// Returns store.ErrNotFound if the token doesn't exist or has expired.
func (s *AuthStore) GetRefreshToken(ctx context.Context, token string) (string, error) {
	key := refreshTokenKey(token)
	val, err := s.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("getting refresh token: %w", err)
	}
	return val, nil
}

// DeleteRefreshToken removes the refresh token from Redis (logout / rotation).
func (s *AuthStore) DeleteRefreshToken(ctx context.Context, token string) error {
	key := refreshTokenKey(token)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

// --- JWT revocation (for T-063 security hardening) ---

// revokedJTIKey returns the Redis key for a revoked JWT ID.
// Format: "revoked:{jti}"
func revokedJTIKey(jti string) string {
	return fmt.Sprintf("revoked:%s", jti)
}

// RevokeJTI adds a JWT ID to the revocation list with the given TTL.
func (s *AuthStore) RevokeJTI(ctx context.Context, jti string, ttl time.Duration) error {
	key := revokedJTIKey(jti)
	if err := s.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("revoking JTI: %w", err)
	}
	return nil
}

// IsJTIRevoked checks whether a JWT ID has been revoked.
func (s *AuthStore) IsJTIRevoked(ctx context.Context, jti string) (bool, error) {
	key := revokedJTIKey(jti)
	val, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("checking JTI revocation: %w", err)
	}
	return val > 0, nil
}

// --- Brute-force lockout operations ---

// emailFailureKey returns the Redis key for a rolling failure count per email.
// Format: "email-failures:{email}"
func emailFailureKey(email string) string {
	return fmt.Sprintf("email-failures:%s", email)
}

// lockoutKey returns the Redis key for an email lockout.
// Format: "email-lockout:{email}"
func lockoutKey(email string) string {
	return fmt.Sprintf("email-lockout:%s", email)
}

// IncrEmailFailureCount increments the rolling failure counter for an email and
// returns the new count. If the key does not exist, it is created with the given TTL.
// On subsequent calls within the TTL window, only INCR is called (TTL not reset).
func (s *AuthStore) IncrEmailFailureCount(ctx context.Context, email string, ttl time.Duration) (int, error) {
	key := emailFailureKey(email)

	// Use a pipeline: INCR then EXPIRE only if the key is new (SETNX-style).
	// Simpler: INCR always, then check if TTL is -1 (no expiry set) and apply it once.
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("incrementing email failure count: %w", err)
	}

	// Only set TTL on the first increment to keep the 1h rolling window.
	if count == 1 {
		if err := s.client.Expire(ctx, key, ttl).Err(); err != nil {
			return int(count), fmt.Errorf("setting failure count TTL: %w", err)
		}
	}

	return int(count), nil
}

// SetLockout sets a lockout entry for the given email with the specified TTL.
func (s *AuthStore) SetLockout(ctx context.Context, email string, ttl time.Duration) error {
	key := lockoutKey(email)
	if err := s.client.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("setting lockout: %w", err)
	}
	return nil
}

// IsLockedOut checks whether the given email is currently locked out.
func (s *AuthStore) IsLockedOut(ctx context.Context, email string) (bool, error) {
	key := lockoutKey(email)
	val, err := s.client.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("checking lockout: %w", err)
	}
	return val > 0, nil
}
