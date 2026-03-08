package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/envshq/envsh-server/internal/server/response"
)

const (
	rateLimitWindowMs  = int64(60_000) // 60 seconds in milliseconds
	rateLimitWindowSec = 60
)

// RateLimitBackend is the interface used by RateLimit. It is exported so that
// tests can inject an in-memory implementation without a real Redis connection.
type RateLimitBackend interface {
	// Check records the current request and returns:
	//   count        - number of requests in the window after recording the current one
	//   resetUnixSec - Unix timestamp when the window resets
	//   err          - non-nil if the backend is unavailable
	Check(ctx context.Context, key string, limit int) (count int, resetUnixSec int64, err error)
}

// redisRateLimitBackend is the production Redis-backed implementation.
type redisRateLimitBackend struct {
	client *redis.Client
}

// Check performs a sliding window rate-limit check using a Redis Lua script.
// The script atomically removes old entries, counts existing ones, and adds the
// current request only when the limit has not been reached.
func (b *redisRateLimitBackend) Check(ctx context.Context, key string, limit int) (int, int64, error) {
	now := time.Now()
	nowMs := now.UnixMilli()
	windowStart := nowMs - rateLimitWindowMs
	resetUnixSec := now.Add(rateLimitWindowSec * time.Second).Unix()

	luaScript := redis.NewScript(`
local key          = KEYS[1]
local now_ms       = tonumber(ARGV[1])
local window_start = tonumber(ARGV[2])
local limit        = tonumber(ARGV[3])
local ttl_sec      = tonumber(ARGV[4])
local reset_sec    = tonumber(ARGV[5])

-- 1. Remove timestamps older than the sliding window.
redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)

-- 2. Count requests that remain in the window.
local count = redis.call('ZCARD', key)

-- 3. Only record the current request if we are still within the limit.
--    This avoids unbounded growth of the sorted set when hammered.
if count < limit then
	-- Use "timestamp-random" as member to avoid collisions within the same ms.
	redis.call('ZADD', key, now_ms, now_ms .. '-' .. math.random(999999))
	redis.call('EXPIRE', key, ttl_sec)
	count = count + 1
else
	-- Signal "over limit" with a sentinel value so the caller can distinguish
	-- "at limit" (last allowed request) from "over limit" (should be rejected).
	count = limit + 1
end

return {count, reset_sec}
`)

	result, err := luaScript.Run(ctx, b.client,
		[]string{key},
		nowMs,
		windowStart,
		int64(limit),
		int64(rateLimitWindowSec+10), // TTL slightly longer than the window
		resetUnixSec,
	).Slice()
	if err != nil {
		return 0, 0, fmt.Errorf("running rate limit lua: %w", err)
	}

	count := int(result[0].(int64))
	reset := result[1].(int64)
	return count, reset, nil
}

// RateLimit returns a chi-compatible middleware that enforces a per-IP sliding
// window rate limit using Redis. limit is the maximum number of requests
// allowed per 60-second window.
//
// On Redis failure the middleware fails open (requests pass through) so that a
// Redis outage does not take down the API.
func RateLimit(redisClient *redis.Client, limit int) func(http.Handler) http.Handler {
	return RateLimitWithBackend(&redisRateLimitBackend{client: redisClient}, limit)
}

// RateLimitWithBackend is the same as RateLimit but accepts any RateLimitBackend.
// Use this in tests to inject an in-memory backend.
func RateLimitWithBackend(backend RateLimitBackend, limit int) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIP(r)
			key := "rl:" + ip + ":" + r.URL.Path

			count, resetUnixSec, err := backend.Check(r.Context(), key, limit)
			if err != nil {
				// Fail open: a Redis outage should not block requests.
				next.ServeHTTP(w, r)
				return
			}

			remaining := limit - count
			if remaining < 0 {
				remaining = 0
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetUnixSec, 10))

			if count > limit {
				response.Error(w, http.StatusTooManyRequests, response.CodeRateLimited, "rate limit exceeded")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractClientIP returns the client IP from X-Forwarded-For or RemoteAddr.
// When X-Forwarded-For contains a comma-separated list, the leftmost (originating)
// address is used.
func extractClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		ip := strings.TrimSpace(parts[0])
		if ip != "" {
			return ip
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr without a port — return as-is.
		return r.RemoteAddr
	}
	return host
}
