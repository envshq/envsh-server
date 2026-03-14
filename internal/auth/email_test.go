package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/envshq/envsh-server/internal/store"
)

// mockHashCode is a test-only reimplementation of the SHA-256 hash used by the Redis auth store.
// This mirrors the production hashCode function in internal/store/redis/auth.go.
func mockHashCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// mockAuthStore is a minimal in-memory implementation of AuthRedisStore for auth tests.
// It is shared across email, JWT, and machine test files in this package.
type mockAuthStore struct {
	codes           map[string]mockCodeEntry
	refreshTokens   map[string]string
	challenges      map[string]string
	revokedJTIs     map[string]bool
	revokedMembers  map[string]bool
	lockouts        map[string]bool
	failureCounts   map[string]int
}

type mockCodeEntry struct {
	codeHash string
	attempts int
}

func newMockAuthStore() *mockAuthStore {
	return &mockAuthStore{
		codes:          make(map[string]mockCodeEntry),
		refreshTokens:  make(map[string]string),
		challenges:     make(map[string]string),
		revokedJTIs:    make(map[string]bool),
		revokedMembers: make(map[string]bool),
		lockouts:       make(map[string]bool),
		failureCounts:  make(map[string]int),
	}
}

// --- email code ---

func (m *mockAuthStore) StoreEmailCode(_ context.Context, email, code string) error {
	m.codes[email] = mockCodeEntry{codeHash: mockHashCode(code), attempts: 0}
	return nil
}

func (m *mockAuthStore) VerifyEmailCode(_ context.Context, email, code string) (int, bool, error) {
	entry, ok := m.codes[email]
	if !ok {
		return 0, false, store.ErrNotFound
	}
	entry.attempts++
	m.codes[email] = entry

	if entry.attempts > 3 {
		return entry.attempts, false, nil
	}

	valid := mockHashCode(code) == entry.codeHash
	return entry.attempts, valid, nil
}

func (m *mockAuthStore) DeleteEmailCode(_ context.Context, email string) error {
	delete(m.codes, email)
	return nil
}

// --- challenge ---

func (m *mockAuthStore) StoreChallenge(_ context.Context, machineID, nonceHex string) error {
	m.challenges[machineID] = nonceHex
	return nil
}

func (m *mockAuthStore) GetAndDeleteChallenge(_ context.Context, machineID string) (string, error) {
	nonce, ok := m.challenges[machineID]
	if !ok {
		return "", store.ErrNotFound
	}
	delete(m.challenges, machineID)
	return nonce, nil
}

// --- refresh token ---

func (m *mockAuthStore) StoreRefreshToken(_ context.Context, token, userID string) error {
	m.refreshTokens[token] = userID
	return nil
}

func (m *mockAuthStore) GetRefreshToken(_ context.Context, token string) (string, error) {
	v, ok := m.refreshTokens[token]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (m *mockAuthStore) DeleteRefreshToken(_ context.Context, token string) error {
	delete(m.refreshTokens, token)
	return nil
}

// --- JTI revocation ---

func (m *mockAuthStore) RevokeJTI(_ context.Context, jti string, _ time.Duration) error {
	m.revokedJTIs[jti] = true
	return nil
}

func (m *mockAuthStore) IsJTIRevoked(_ context.Context, jti string) (bool, error) {
	return m.revokedJTIs[jti], nil
}

// --- Member revocation ---

func (m *mockAuthStore) RevokeMemberAccess(_ context.Context, workspaceID, userID string, _ time.Duration) error {
	m.revokedMembers[workspaceID+":"+userID] = true
	return nil
}

func (m *mockAuthStore) IsMemberRevoked(_ context.Context, workspaceID, userID string) (bool, error) {
	return m.revokedMembers[workspaceID+":"+userID], nil
}

// --- Brute-force lockout ---

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

// compile-time check that mockAuthStore satisfies AuthRedisStore.
var _ AuthRedisStore = (*mockAuthStore)(nil)

// mockEmailSender records calls to SendCode.
type mockEmailSender struct {
	lastEmail string
	lastCode  string
	sendErr   error
}

func (s *mockEmailSender) SendCode(_ context.Context, email, code string) error {
	s.lastEmail = email
	s.lastCode = code
	return s.sendErr
}

// --- Tests ---

// TestRequestCode_Success verifies that requesting a code stores and sends it.
func TestRequestCode_Success(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	err := svc.RequestCode(ctx, "alice@example.com")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if sender.lastEmail != "alice@example.com" {
		t.Errorf("expected email alice@example.com, got %q", sender.lastEmail)
	}
	if len(sender.lastCode) != 6 {
		t.Errorf("expected 6-digit code, got %q", sender.lastCode)
	}
	if _, ok := ms.codes["alice@example.com"]; !ok {
		t.Error("expected code to be stored in mock store")
	}
}

// TestVerifyCode_Valid verifies that a correct code passes verification.
func TestVerifyCode_Valid(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	if err := svc.RequestCode(ctx, "bob@example.com"); err != nil {
		t.Fatalf("RequestCode: %v", err)
	}
	sentCode := sender.lastCode

	if err := svc.VerifyCode(ctx, "bob@example.com", sentCode); err != nil {
		t.Errorf("expected valid code to succeed, got: %v", err)
	}
	if _, ok := ms.codes["bob@example.com"]; ok {
		t.Error("expected code to be deleted after successful verification")
	}
}

// TestVerifyCode_Invalid verifies that a wrong code returns ErrInvalidCode.
func TestVerifyCode_Invalid(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	if err := svc.RequestCode(ctx, "carol@example.com"); err != nil {
		t.Fatalf("RequestCode: %v", err)
	}

	err := svc.VerifyCode(ctx, "carol@example.com", "000000")
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode, got: %v", err)
	}
}

// TestVerifyCode_TooManyAttempts verifies that after 3 failures ErrTooManyAttempts is returned.
func TestVerifyCode_TooManyAttempts(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	if err := svc.RequestCode(ctx, "dave@example.com"); err != nil {
		t.Fatalf("RequestCode: %v", err)
	}

	// Three wrong attempts — each increments the counter
	for i := 0; i < 3; i++ {
		err := svc.VerifyCode(ctx, "dave@example.com", "000000")
		if err == nil {
			t.Fatalf("attempt %d: expected error, got nil", i+1)
		}
	}

	// Fourth attempt: attempts == 4 > 3 → ErrTooManyAttempts
	err := svc.VerifyCode(ctx, "dave@example.com", "000000")
	if !errors.Is(err, ErrTooManyAttempts) {
		t.Errorf("expected ErrTooManyAttempts on 4th attempt, got: %v", err)
	}
}

// TestVerifyCode_Expired verifies that a missing Redis key returns ErrInvalidCode.
func TestVerifyCode_Expired(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	// No code stored — simulates TTL expiry
	err := svc.VerifyCode(ctx, "expired@example.com", "123456")
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode for expired/missing code, got: %v", err)
	}
}

// TestVerifyCode_BruteForce_Lockout verifies that after 10 cumulative failures
// the email is locked out and subsequent attempts return ErrInvalidCode (not ErrTooManyAttempts).
func TestVerifyCode_BruteForce_Lockout(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	const email = "victim@example.com"

	// Simulate 10 failed attempts across multiple code requests.
	// Each code request gets 3 attempts before ErrTooManyAttempts, then a new code is needed.
	// We use missing-key failures to keep it simple (each call with no code stored counts).
	for i := 0; i < maxAttemptsBeforeLockout; i++ {
		// Verify with a non-existent code — triggers the store.ErrNotFound path
		// which increments the failure counter.
		_ = svc.VerifyCode(ctx, email, "000000")
	}

	// Email should now be locked out.
	if !ms.lockouts[email] {
		t.Errorf("expected email to be locked out after %d failures", maxAttemptsBeforeLockout)
	}

	// Further attempts should return ErrInvalidCode (same as wrong code — prevents enumeration).
	err := svc.VerifyCode(ctx, email, "000000")
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode for locked-out email, got: %v", err)
	}
}

// TestVerifyCode_LockedOut verifies that a pre-locked email returns ErrInvalidCode immediately.
func TestVerifyCode_LockedOut(t *testing.T) {
	ctx := context.Background()
	ms := newMockAuthStore()
	sender := &mockEmailSender{}
	svc := NewEmailAuthService(ms, sender)

	const email = "locked@example.com"

	// Manually set a lockout.
	ms.lockouts[email] = true

	// Even with a valid code in the store, the lockout should prevent verification.
	if err := svc.RequestCode(ctx, email); err != nil {
		t.Fatalf("RequestCode: %v", err)
	}
	sentCode := sender.lastCode

	err := svc.VerifyCode(ctx, email, sentCode)
	if !errors.Is(err, ErrInvalidCode) {
		t.Errorf("expected ErrInvalidCode for locked-out email (even with correct code), got: %v", err)
	}
}
