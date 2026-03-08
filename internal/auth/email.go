package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/envshq/envsh-server/internal/store"
)

const (
	// maxAttemptsBeforeLockout is the number of failed verifications across all code
	// requests within a 1-hour window before the email is locked out for 1 hour.
	maxAttemptsBeforeLockout = 10
	// lockoutWindow is how long the failure counter persists before resetting.
	lockoutWindow = time.Hour
	// lockoutDuration is how long the lockout lasts once triggered.
	lockoutDuration = time.Hour
)

var (
	// ErrInvalidCode is returned when the verification code is wrong or expired.
	// Also returned when the email is locked out — prevents enumeration.
	ErrInvalidCode = errors.New("invalid or expired code")
	// ErrTooManyAttempts is returned when the maximum per-code attempt count has been exceeded.
	ErrTooManyAttempts = errors.New("too many failed attempts, request a new code")
	// ErrRateLimited is returned when the caller exceeds the rate limit.
	ErrRateLimited = errors.New("rate limited: too many code requests")
)

// EmailSender sends email verification codes.
type EmailSender interface {
	SendCode(ctx context.Context, email, code string) error
}

// ConsoleEmailSender logs codes to stdout — for development only.
type ConsoleEmailSender struct{}

// SendCode prints the code to stdout rather than sending a real email.
func (s *ConsoleEmailSender) SendCode(ctx context.Context, email, code string) error {
	fmt.Printf("[EMAIL] To: %s | Code: %s\n", email, code)
	return nil
}

// EmailAuthService handles email+code authentication.
type EmailAuthService struct {
	authStore AuthRedisStore
	sender    EmailSender
}

// NewEmailAuthService creates a new EmailAuthService.
func NewEmailAuthService(authStore AuthRedisStore, sender EmailSender) *EmailAuthService {
	return &EmailAuthService{authStore: authStore, sender: sender}
}

// RequestCode generates a 6-digit code and sends it to the email.
// The code is stored hashed in Redis with a 5-minute TTL.
func (s *EmailAuthService) RequestCode(ctx context.Context, email string) error {
	code, err := generateCode()
	if err != nil {
		return fmt.Errorf("generating code: %w", err)
	}
	if err := s.authStore.StoreEmailCode(ctx, email, code); err != nil {
		return fmt.Errorf("storing code: %w", err)
	}
	return s.sender.SendCode(ctx, email, code)
}

// VerifyCode checks the submitted code against the stored hash.
// Returns ErrInvalidCode if the code is wrong, expired, or the email is locked out.
// Returns ErrTooManyAttempts if more than 3 per-code failures have occurred.
// On success, the stored code is deleted.
// After 10 cumulative failures within a 1-hour window, the email is locked out for 1 hour.
// The same error message is returned whether the email is locked out or the code is wrong,
// to prevent email enumeration.
func (s *EmailAuthService) VerifyCode(ctx context.Context, email, code string) error {
	// Check for lockout BEFORE attempting verification (prevents enumeration).
	locked, err := s.authStore.IsLockedOut(ctx, email)
	if err != nil {
		return fmt.Errorf("checking lockout: %w", err)
	}
	if locked {
		// Return the same error as an invalid code to prevent enumeration.
		return ErrInvalidCode
	}

	attempts, valid, err := s.authStore.VerifyEmailCode(ctx, email, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Missing key counts as a failure for the rolling lockout counter.
			count, _ := s.authStore.IncrEmailFailureCount(ctx, email, lockoutWindow)
			if count >= maxAttemptsBeforeLockout {
				_ = s.authStore.SetLockout(ctx, email, lockoutDuration)
			}
			return ErrInvalidCode
		}
		return fmt.Errorf("verifying code: %w", err)
	}

	if attempts > 3 {
		_ = s.authStore.DeleteEmailCode(ctx, email)
		// Count as a failure toward the lockout threshold.
		count, _ := s.authStore.IncrEmailFailureCount(ctx, email, lockoutWindow)
		if count >= maxAttemptsBeforeLockout {
			_ = s.authStore.SetLockout(ctx, email, lockoutDuration)
		}
		return ErrTooManyAttempts
	}

	if !valid {
		// Increment rolling failure counter; trigger lockout if threshold reached.
		count, _ := s.authStore.IncrEmailFailureCount(ctx, email, lockoutWindow)
		if count >= maxAttemptsBeforeLockout {
			_ = s.authStore.SetLockout(ctx, email, lockoutDuration)
			return ErrInvalidCode
		}
		return ErrInvalidCode
	}

	// Valid code — clean up
	return s.authStore.DeleteEmailCode(ctx, email)
}

// generateCode returns a cryptographically random 6-digit string (zero-padded).
func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}
