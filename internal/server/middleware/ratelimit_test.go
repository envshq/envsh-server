package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/envshq/envsh-server/internal/server/middleware"
)

// inMemoryRateLimitBackend is a thread-safe in-memory implementation of
// middleware.RateLimitBackend used in unit tests (no Redis required).
type inMemoryRateLimitBackend struct {
	mu      sync.Mutex
	windows map[string][]int64 // key -> sorted list of request timestamps (ms)
}

func newInMemoryBackend() *inMemoryRateLimitBackend {
	return &inMemoryRateLimitBackend{windows: make(map[string][]int64)}
}

// Check implements middleware.RateLimitBackend using an in-memory sliding window.
func (b *inMemoryRateLimitBackend) Check(_ context.Context, key string, limit int) (int, int64, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	const windowMs = int64(60_000)
	now := time.Now()
	nowMs := now.UnixMilli()
	windowStart := nowMs - windowMs
	resetUnixSec := now.Add(60 * time.Second).Unix()

	// Remove expired entries.
	entries := b.windows[key]
	kept := entries[:0]
	for _, ts := range entries {
		if ts > windowStart {
			kept = append(kept, ts)
		}
	}
	b.windows[key] = kept

	count := len(kept)
	if count < limit {
		b.windows[key] = append(b.windows[key], nowMs)
		count++
	} else {
		// Signal "over limit" with a sentinel value so the middleware can
		// distinguish "at limit" (last allowed request) from "exceeded".
		count = limit + 1
	}

	return count, resetUnixSec, nil
}

// okHandler is a minimal handler that always responds 200 OK.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestRateLimit_WithinLimit(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 5
	mw := middleware.RateLimitWithBackend(backend, limit)

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		rec := httptest.NewRecorder()

		mw(okHandler).ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
		limitHeader := rec.Header().Get("X-RateLimit-Limit")
		if limitHeader != strconv.Itoa(limit) {
			t.Errorf("request %d: expected X-RateLimit-Limit=%d, got %s", i+1, limit, limitHeader)
		}
	}
}

func TestRateLimit_ExceedsLimit_Returns429(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 3
	mw := middleware.RateLimitWithBackend(backend, limit)

	// Send exactly limit requests — all should pass.
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/request-code", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.2")
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	// The next request must exceed the limit → 429.
	req := httptest.NewRequest(http.MethodPost, "/auth/request-code", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.2")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 after exceeding limit, got %d", rec.Code)
	}
}

func TestRateLimit_HeadersPresent(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 10
	mw := middleware.RateLimitWithBackend(backend, limit)

	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.3")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)

	for _, hdr := range []string{"X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"} {
		if rec.Header().Get(hdr) == "" {
			t.Errorf("expected header %s to be set", hdr)
		}
	}

	limitVal, err := strconv.Atoi(rec.Header().Get("X-RateLimit-Limit"))
	if err != nil {
		t.Fatalf("X-RateLimit-Limit is not a valid integer: %s", rec.Header().Get("X-RateLimit-Limit"))
	}
	remainingVal, err := strconv.Atoi(rec.Header().Get("X-RateLimit-Remaining"))
	if err != nil {
		t.Fatalf("X-RateLimit-Remaining is not a valid integer: %s", rec.Header().Get("X-RateLimit-Remaining"))
	}
	if limitVal != limit {
		t.Errorf("expected X-RateLimit-Limit=%d, got %d", limit, limitVal)
	}
	if remainingVal != limit-1 {
		t.Errorf("expected X-RateLimit-Remaining=%d, got %d", limit-1, remainingVal)
	}
}

func TestRateLimit_RemainingDecrementsCorrectly(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 5
	mw := middleware.RateLimitWithBackend(backend, limit)

	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/workspace", nil)
		req.Header.Set("X-Forwarded-For", "10.0.0.4")
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, req)

		expectedRemaining := limit - (i + 1)
		remaining, err := strconv.Atoi(rec.Header().Get("X-RateLimit-Remaining"))
		if err != nil {
			t.Fatalf("request %d: X-RateLimit-Remaining is not a valid integer", i+1)
		}
		if remaining != expectedRemaining {
			t.Errorf("request %d: expected X-RateLimit-Remaining=%d, got %d", i+1, expectedRemaining, remaining)
		}
	}
}

func TestRateLimit_429ResponseBodyAndHeaders(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 1
	mw := middleware.RateLimitWithBackend(backend, limit)

	ip := "10.0.0.5"

	// First request passes.
	req := httptest.NewRequest(http.MethodPost, "/auth/request-code", nil)
	req.Header.Set("X-Forwarded-For", ip)
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected first request to succeed, got %d", rec.Code)
	}

	// Second request is rate limited.
	req = httptest.NewRequest(http.MethodPost, "/auth/request-code", nil)
	req.Header.Set("X-Forwarded-For", ip)
	rec = httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !containsStr(body, "RATE_LIMITED") {
		t.Errorf("expected body to contain RATE_LIMITED, got: %s", body)
	}
	if !containsStr(body, "rate limit exceeded") {
		t.Errorf("expected body to contain 'rate limit exceeded', got: %s", body)
	}

	// X-RateLimit headers must be present even on 429.
	if rec.Header().Get("X-RateLimit-Limit") == "" {
		t.Error("expected X-RateLimit-Limit header on 429 response")
	}
	if rec.Header().Get("X-RateLimit-Remaining") == "" {
		t.Error("expected X-RateLimit-Remaining header on 429 response")
	}
	if rec.Header().Get("X-RateLimit-Reset") == "" {
		t.Error("expected X-RateLimit-Reset header on 429 response")
	}
}

func TestRateLimit_DifferentIPsAreIsolated(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 2
	mw := middleware.RateLimitWithBackend(backend, limit)

	// Exhaust limit for IP A.
	for i := 0; i < limit; i++ {
		req := httptest.NewRequest(http.MethodGet, "/projects", nil)
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, req)
	}

	// IP A should now be rate limited.
	req := httptest.NewRequest(http.MethodGet, "/projects", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.1")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("IP A: expected 429 after exhausting limit, got %d", rec.Code)
	}

	// IP B should still be allowed.
	req = httptest.NewRequest(http.MethodGet, "/projects", nil)
	req.Header.Set("X-Forwarded-For", "192.168.1.2")
	rec = httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("IP B: expected 200 (isolated from IP A), got %d", rec.Code)
	}
}

func TestRateLimit_DifferentPathsAreIsolated(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 1
	mw := middleware.RateLimitWithBackend(backend, limit)

	ip := "10.0.0.10"

	// Use up limit on /auth/request-code.
	req := httptest.NewRequest(http.MethodPost, "/auth/request-code", nil)
	req.Header.Set("X-Forwarded-For", ip)
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected first /auth/request-code to pass, got %d", rec.Code)
	}

	// /auth/request-code should be rate limited.
	req = httptest.NewRequest(http.MethodPost, "/auth/request-code", nil)
	req.Header.Set("X-Forwarded-For", ip)
	rec = httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected 429 on second /auth/request-code, got %d", rec.Code)
	}

	// /auth/verify-code is a separate bucket and should still be allowed.
	req = httptest.NewRequest(http.MethodPost, "/auth/verify-code", nil)
	req.Header.Set("X-Forwarded-For", ip)
	rec = httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected /auth/verify-code to pass independently, got %d", rec.Code)
	}
}

func TestRateLimit_ResetTimestampIsInFuture(t *testing.T) {
	backend := newInMemoryBackend()
	mw := middleware.RateLimitWithBackend(backend, 10)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Header.Set("X-Forwarded-For", "10.0.0.20")
	rec := httptest.NewRecorder()
	mw(okHandler).ServeHTTP(rec, req)

	resetStr := rec.Header().Get("X-RateLimit-Reset")
	if resetStr == "" {
		t.Fatal("expected X-RateLimit-Reset header to be set")
	}
	resetUnix, err := strconv.ParseInt(resetStr, 10, 64)
	if err != nil {
		t.Fatalf("X-RateLimit-Reset is not a valid integer: %s", resetStr)
	}
	now := time.Now().Unix()
	if resetUnix <= now {
		t.Errorf("X-RateLimit-Reset should be in the future, got %d (now=%d)", resetUnix, now)
	}
}

func TestRateLimit_XForwardedForMultipleAddresses(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 1
	mw := middleware.RateLimitWithBackend(backend, limit)

	// Both requests carry the same leftmost IP — should share the same bucket.
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/keys", nil)
		// "203.0.113.1" is the originating client; "10.0.0.1" is an intermediate proxy.
		req.Header.Set("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, req)

		if i == 0 && rec.Code != http.StatusOK {
			t.Fatalf("first request: expected 200, got %d", rec.Code)
		}
		if i == 1 && rec.Code != http.StatusTooManyRequests {
			t.Errorf("second request: expected 429 (same originating IP), got %d", rec.Code)
		}
	}
}

func TestRateLimit_RemoteAddrFallback(t *testing.T) {
	backend := newInMemoryBackend()
	limit := 2
	mw := middleware.RateLimitWithBackend(backend, limit)

	// No X-Forwarded-For; RemoteAddr used as fallback.
	for i := 0; i < limit+1; i++ {
		req := httptest.NewRequest(http.MethodGet, "/audit", nil)
		// httptest sets RemoteAddr to "192.0.2.1:1234" by default.
		rec := httptest.NewRecorder()
		mw(okHandler).ServeHTTP(rec, req)

		if i < limit && rec.Code != http.StatusOK {
			t.Errorf("request %d: expected 200, got %d", i+1, rec.Code)
		}
		if i == limit && rec.Code != http.StatusTooManyRequests {
			t.Errorf("request %d: expected 429 (RemoteAddr fallback), got %d", i+1, rec.Code)
		}
	}
}

// containsStr is a simple substring check used to avoid importing strings.
func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
