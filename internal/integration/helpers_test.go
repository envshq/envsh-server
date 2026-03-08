package integration_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// --- HTTP helpers ---

// apiRequest performs a JSON HTTP request to the test server.
// If token is non-empty it is sent as a Bearer Authorization header.
func apiRequest(t *testing.T, method, path string, body any, token string) (int, map[string]any) {
	t.Helper()

	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, env.server.URL+path, bodyReader)
	if err != nil {
		t.Fatalf("creating request %s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("executing request %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		// Non-JSON body — return empty map but preserve status
		return resp.StatusCode, nil
	}
	return resp.StatusCode, result
}

// mustStatus fails the test if the actual status does not match expected.
func mustStatus(t *testing.T, expected, actual int, body map[string]any) {
	t.Helper()
	if expected != actual {
		b, _ := json.MarshalIndent(body, "", "  ")
		t.Fatalf("expected HTTP %d, got %d\nbody: %s", expected, actual, string(b))
	}
}

// getStr extracts a string value from a nested map using dot-separated keys.
// e.g. getStr(m, "user.id") returns m["user"]["id"].
func getStr(m map[string]any, key string) string {
	v := getVal(m, key)
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// getFloat extracts a float64 from the map.
func getFloat(m map[string]any, key string) float64 {
	v := getVal(m, key)
	if v == nil {
		return 0
	}
	f, _ := v.(float64)
	return f
}

// getVal traverses nested maps using a simple dot-separated path.
func getVal(m map[string]any, path string) any {
	// Simple single-key lookup (no dot notation needed for our tests).
	return m[path]
}

// --- Auth helpers ---

// loginUser performs the full email+code flow and returns a JWT token.
// It uses the Redis auth store directly to skip the email delivery step
// by extracting the stored code.
func loginUser(t *testing.T, email string) string {
	t.Helper()

	// Step 1: Request a code. The ConsoleEmailSender will print it but not deliver it.
	// We intercept via Redis directly.
	status, body := apiRequest(t, "POST", "/auth/email-login", map[string]any{"email": email}, "")
	mustStatus(t, http.StatusOK, status, body)

	// Step 2: Read the code from Redis (key: "email-code:{email}").
	// The stored value format is "{sha256_hash}|{attempts}|{unix_ts}".
	// We need to find the code in a different way since it's hashed.
	// Instead, we use the test helper that injects a known code.
	code := extractEmailCodeFromRedis(t, email)

	// Step 3: Verify the code and get the token.
	status, body = apiRequest(t, "POST", "/auth/email-verify", map[string]any{
		"email": email,
		"code":  code,
	}, "")
	mustStatus(t, http.StatusOK, status, body)

	token := getStr(body, "token")
	if token == "" {
		t.Fatalf("email-verify did not return a token; body: %v", body)
	}
	return token
}

// extractEmailCodeFromRedis retrieves the stored email code by brute-forcing
// 000000-999999 against the stored SHA-256 hash.
// This is only acceptable in tests — never in production code.
func extractEmailCodeFromRedis(t *testing.T, email string) string {
	t.Helper()

	key := fmt.Sprintf("email-code:%s", strings.ToLower(email))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	val, err := env.redis.Get(ctx, key).Result()
	if err != nil {
		t.Fatalf("getting email code from Redis (key %q): %v", key, err)
	}

	// Format: "{hash}|{attempts}|{ts}"
	var storedHash string
	_, err = fmt.Sscanf(val, "%64s", &storedHash) // SHA-256 hex is 64 chars
	if err != nil || len(storedHash) != 64 {
		// Try splitting manually
		parts := splitN(val, "|", 3)
		if len(parts) < 1 {
			t.Fatalf("unexpected email code format in Redis: %q", val)
		}
		storedHash = parts[0]
	}

	// Brute-force the 6-digit code space (000000–999999).
	for i := 0; i <= 999999; i++ {
		candidate := fmt.Sprintf("%06d", i)
		sum := sha256.Sum256([]byte(candidate))
		if hex.EncodeToString(sum[:]) == storedHash {
			return candidate
		}
	}
	t.Fatalf("could not find email code matching hash %s for %s", storedHash, email)
	return ""
}

// splitN splits s by sep at most n parts (avoids importing strings in test helper).
func splitN(s, sep string, n int) []string {
	var result []string
	for i := 0; i < n-1; i++ {
		idx := -1
		for j := 0; j+len(sep) <= len(s); j++ {
			if s[j:j+len(sep)] == sep {
				idx = j
				break
			}
		}
		if idx < 0 {
			break
		}
		result = append(result, s[:idx])
		s = s[idx+len(sep):]
	}
	result = append(result, s)
	return result
}

// createProject creates a project and returns its ID.
func createProject(t *testing.T, token, name, slug string) string {
	t.Helper()
	status, body := apiRequest(t, "POST", "/projects", map[string]any{
		"name": name,
		"slug": slug,
	}, token)
	mustStatus(t, http.StatusCreated, status, body)
	id := getStr(body, "id")
	if id == "" {
		t.Fatalf("create project returned no id; body: %v", body)
	}
	return id
}

// pushSecret pushes a dummy encrypted secret bundle and returns the version number.
// The server stores opaque blobs — for integration tests we send deterministic
// base64-encoded dummy bytes. Crypto correctness is tested at the unit level.
func pushSecret(t *testing.T, token, projectID, environment string, baseVersion *int, recipients []map[string]any) float64 {
	t.Helper()

	// Dummy 32-byte values, base64-encoded.
	dummyCiphertext := base64.StdEncoding.EncodeToString(make([]byte, 64))
	dummyNonce := base64.StdEncoding.EncodeToString(make([]byte, 12))
	dummyAuthTag := base64.StdEncoding.EncodeToString(make([]byte, 16))
	dummyEncKey := base64.StdEncoding.EncodeToString(make([]byte, 40))
	dummyEphPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	dummyKeyNonce := base64.StdEncoding.EncodeToString(make([]byte, 12))
	dummyKeyAuthTag := base64.StdEncoding.EncodeToString(make([]byte, 16))

	if len(recipients) == 0 {
		// Default single recipient placeholder — fingerprint only needs to be unique.
		recipients = []map[string]any{
			{
				"key_fingerprint":  "sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
				"identity_type":    "user",
				"encrypted_aes_key": dummyEncKey,
				"ephemeral_public":  dummyEphPub,
				"key_nonce":         dummyKeyNonce,
				"key_auth_tag":      dummyKeyAuthTag,
			},
		}
	} else {
		// Fill missing crypto fields for each recipient.
		for i := range recipients {
			if _, ok := recipients[i]["encrypted_aes_key"]; !ok {
				recipients[i]["encrypted_aes_key"] = dummyEncKey
			}
			if _, ok := recipients[i]["ephemeral_public"]; !ok {
				recipients[i]["ephemeral_public"] = dummyEphPub
			}
			if _, ok := recipients[i]["key_nonce"]; !ok {
				recipients[i]["key_nonce"] = dummyKeyNonce
			}
			if _, ok := recipients[i]["key_auth_tag"]; !ok {
				recipients[i]["key_auth_tag"] = dummyKeyAuthTag
			}
		}
	}

	reqBody := map[string]any{
		"project_id":  projectID,
		"environment": environment,
		"ciphertext":  dummyCiphertext,
		"nonce":       dummyNonce,
		"auth_tag":    dummyAuthTag,
		"checksum":    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"message":     "test push",
		"recipients":  recipients,
	}
	if baseVersion != nil {
		reqBody["base_version"] = *baseVersion
	}

	status, body := apiRequest(t, "POST", "/secrets/push", reqBody, token)
	mustStatus(t, http.StatusCreated, status, body)
	return getFloat(body, "version")
}

// pullSecret pulls the latest secret for a project/environment.
func pullSecret(t *testing.T, token, projectID, environment string) (int, map[string]any) {
	t.Helper()
	return apiRequest(t, "GET",
		fmt.Sprintf("/secrets/pull?project_id=%s&environment=%s", projectID, environment),
		nil, token,
	)
}

// registerKey registers an SSH public key for the authenticated user.
func registerKey(t *testing.T, token, pubKey, fingerprint, label string) string {
	t.Helper()
	status, body := apiRequest(t, "POST", "/keys", map[string]any{
		"public_key":  pubKey,
		"fingerprint": fingerprint,
		"key_type":    "ed25519",
		"label":       label,
	}, token)
	mustStatus(t, http.StatusCreated, status, body)
	return getStr(body, "id")
}

// createMachine creates a machine identity and returns its ID.
func createMachine(t *testing.T, token, name, slug, projectID, environment, pubKey, fingerprint string) string {
	t.Helper()
	status, body := apiRequest(t, "POST", "/machines", map[string]any{
		"name":            name,
		"slug":            slug,
		"project_id":      projectID,
		"environment":     environment,
		"public_key":      pubKey,
		"key_fingerprint": fingerprint,
	}, token)
	mustStatus(t, http.StatusCreated, status, body)
	return getStr(body, "id")
}

// machineLogin performs the full machine auth flow:
// 1. POST /auth/machine-challenge → nonce
// 2. Sign nonce with Ed25519 private key
// 3. POST /auth/machine-verify → JWT
func machineLogin(t *testing.T, machineID string, privKey ed25519.PrivateKey) string {
	t.Helper()

	// Step 1: Get challenge nonce.
	status, body := apiRequest(t, "POST", "/auth/machine-challenge", map[string]any{
		"machine_id": machineID,
	}, "")
	mustStatus(t, http.StatusOK, status, body)

	nonceHex := getStr(body, "nonce")
	if nonceHex == "" {
		t.Fatalf("machine-challenge returned no nonce; body: %v", body)
	}

	// Step 2: Decode nonce hex → raw bytes, sign with Ed25519.
	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil {
		t.Fatalf("decoding nonce hex: %v", err)
	}
	sigBytes := ed25519.Sign(privKey, nonceBytes)
	sigHex := hex.EncodeToString(sigBytes)

	// Step 3: Verify.
	status, body = apiRequest(t, "POST", "/auth/machine-verify", map[string]any{
		"machine_id": machineID,
		"nonce":      nonceHex,
		"signature":  sigHex,
	}, "")
	mustStatus(t, http.StatusOK, status, body)

	token := getStr(body, "token")
	if token == "" {
		t.Fatalf("machine-verify returned no token; body: %v", body)
	}
	return token
}

// generateEd25519Key generates a fresh Ed25519 key pair for testing.
func generateEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating ed25519 key: %v", err)
	}
	return pub, priv
}

// ed25519PubKeyToSSH formats an Ed25519 public key as an SSH authorized_keys line.
// This matches the format the server expects (stored as-is, no parsing).
func ed25519PubKeyToBase64(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString([]byte(pub))
}

// computeFingerprint returns a unique fingerprint string for an Ed25519 public key.
func computeFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256([]byte(pub))
	return "sha256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// uniqueEmail returns a unique email for each test invocation.
func uniqueEmail(suffix string) string {
	return fmt.Sprintf("test+%d+%s@example.com", time.Now().UnixNano(), suffix)
}

// uniqueSlug returns a unique slug.
func uniqueSlug(prefix string) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s-%x", prefix, b)
}

// resetDB truncates all tables between tests for isolation.
func resetDB(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := truncateAll(ctx, env.db); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}

	// Also flush Redis between tests so rate limits and auth codes don't bleed over.
	if err := env.redis.FlushAll(ctx).Err(); err != nil {
		t.Fatalf("flushing redis: %v", err)
	}
}

// intPtr returns a pointer to an int value — convenience for base_version.
func intPtr(v int) *int { return &v }

// assertRecipients verifies that the pull response contains the expected
// number of recipients and that our fingerprint is present.
func assertRecipientPresent(t *testing.T, body map[string]any, fingerprint string) {
	t.Helper()
	rawRecips, ok := body["recipients"]
	if !ok {
		t.Fatal("pull response has no 'recipients' field")
	}
	recips, ok := rawRecips.([]any)
	if !ok {
		t.Fatal("'recipients' is not an array")
	}
	for _, r := range recips {
		rm, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if rm["key_fingerprint"] == fingerprint {
			return
		}
	}
	t.Fatalf("fingerprint %q not found in recipients: %v", fingerprint, recips)
}

// mustGetString is a fatal-on-empty string getter for nested response fields.
func mustGetString(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	v := getStr(m, key)
	if v == "" {
		b, _ := json.MarshalIndent(m, "", "  ")
		t.Fatalf("expected non-empty value for key %q in:\n%s", key, string(b))
	}
	return v
}

// inviteMember invites a user to the workspace as a member.
// Returns the invited user's ID.
func inviteMember(t *testing.T, adminToken, email, role string) string {
	t.Helper()
	status, body := apiRequest(t, "POST", "/workspace/members/invite", map[string]any{
		"email": email,
		"role":  role,
	}, adminToken)
	mustStatus(t, http.StatusOK, status, body)
	userMap, ok := body["user"].(map[string]any)
	if !ok {
		t.Fatalf("invite response missing 'user' field; body: %v", body)
	}
	id, _ := userMap["id"].(string)
	if id == "" {
		t.Fatalf("invite response missing user id; body: %v", body)
	}
	return id
}

// dbExec executes a raw SQL statement against the test database.
// Used to set up state that would be awkward through the HTTP API.
func dbExec(t *testing.T, sql string, args ...any) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := env.db.Exec(ctx, sql, args...)
	if err != nil {
		t.Fatalf("db exec %q: %v", sql, err)
	}
}

// dbPool returns the shared test DB pool for tests that need direct DB access.
func dbPool() *pgxpool.Pool { return env.db }
