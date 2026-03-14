package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/server/response"
	"github.com/envshq/envsh-server/internal/store"
)

// KeyHandler handles SSH key endpoints.
type KeyHandler struct {
	keys     store.KeyStore
	machines store.MachineStore
	audit    store.AuditLogStore
}

// NewKeyHandler creates a new KeyHandler.
func NewKeyHandler(keys store.KeyStore, machines store.MachineStore, audit store.AuditLogStore) *KeyHandler {
	return &KeyHandler{keys: keys, machines: machines, audit: audit}
}

// List returns all SSH keys for the authenticated user.
//
// GET /keys
func (h *KeyHandler) List(w http.ResponseWriter, r *http.Request) {
	_, userID, ok := requireMember(w, r)
	if !ok {
		return
	}

	keys, err := h.keys.ListKeys(r.Context(), userID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{"keys": keys})
}

// registerKeyRequest is the request body for POST /keys.
type registerKeyRequest struct {
	PublicKey   string `json:"public_key"`
	Label       string `json:"label"`
	Fingerprint string `json:"fingerprint"`
	KeyType     string `json:"key_type"`
}

// Register registers a new SSH public key for the user.
//
// POST /keys
func (h *KeyHandler) Register(w http.ResponseWriter, r *http.Request) {
	workspaceID, userID, ok := requireMember(w, r)
	if !ok {
		return
	}

	var req registerKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.PublicKey = strings.TrimSpace(req.PublicKey)
	if req.PublicKey == "" {
		response.BadRequest(w, "public_key is required")
		return
	}

	// Determine key type from public key prefix if not provided
	keyType := req.KeyType
	if keyType == "" {
		keyType = inferKeyType(req.PublicKey)
	}
	if keyType == "" {
		response.BadRequest(w, "unsupported key type; supported: ssh-ed25519, ssh-rsa")
		return
	}

	// Fingerprint must be provided by the client (CLI computes it)
	fingerprint := req.Fingerprint
	if fingerprint == "" {
		response.BadRequest(w, "fingerprint is required")
		return
	}

	var labelPtr *string
	if label := strings.TrimSpace(req.Label); label != "" {
		labelPtr = &label
	}

	ctx := r.Context()

	key, err := h.keys.RegisterKey(ctx, userID, req.PublicKey, keyType, fingerprint, labelPtr)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateKey) {
			response.Conflict(w, "key already registered")
			return
		}
		response.InternalError(w)
		return
	}

	// Audit log
	resourceID := key.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "key.registered",
		ResourceType: "ssh_key",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusCreated, map[string]any{
		"id":          key.ID,
		"fingerprint": key.Fingerprint,
		"key_type":    key.KeyType,
		"label":       key.Label,
		"created_at":  key.CreatedAt,
	})
}

// Revoke revokes an SSH key.
//
// DELETE /keys/{keyID}
func (h *KeyHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	workspaceID, userID, ok := requireMember(w, r)
	if !ok {
		return
	}

	keyIDStr := chi.URLParam(r, "keyID")
	keyID, err := uuid.Parse(keyIDStr)
	if err != nil {
		response.BadRequest(w, "invalid keyID")
		return
	}

	ctx := r.Context()

	if err := h.keys.RevokeKey(ctx, keyID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}

	// Audit log
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "key.revoked",
		ResourceType: "ssh_key",
		ResourceID:   &keyID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ListWorkspaceKeys returns all non-revoked SSH keys for all members in the workspace,
// plus active machine keys (so pushers encrypt for machines too).
//
// GET /keys/workspace
func (h *KeyHandler) ListWorkspaceKeys(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireMember(w, r)
	if !ok {
		return
	}

	ctx := r.Context()

	keys, err := h.keys.ListKeysByWorkspace(ctx, workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	machines, err := h.machines.ListMachines(ctx, workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	// Filter to active machines only.
	type machineKeyEntry struct {
		ID             string `json:"id"`
		PublicKey      string `json:"public_key"`
		KeyFingerprint string `json:"key_fingerprint"`
	}
	var machineKeys []machineKeyEntry
	for _, m := range machines {
		if m.Status == "active" {
			machineKeys = append(machineKeys, machineKeyEntry{
				ID:             m.ID.String(),
				PublicKey:      m.PublicKey,
				KeyFingerprint: m.KeyFingerprint,
			})
		}
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"keys":         keys,
		"machine_keys": machineKeys,
	})
}

// inferKeyType infers the key type from the SSH public key string prefix.
func inferKeyType(publicKey string) string {
	switch {
	case strings.HasPrefix(publicKey, "ssh-ed25519"):
		return "ed25519"
	case strings.HasPrefix(publicKey, "ssh-rsa"):
		return "rsa4096"
	default:
		return ""
	}
}
