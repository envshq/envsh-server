package handler

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/server/middleware"
	"github.com/envshq/envsh-server/internal/server/response"
	"github.com/envshq/envsh-server/internal/store"
)

const (
	maxCiphertextBytes = 1 << 20 // 1 MB
	maxRecipients      = 500
)

// SecretHandler handles secret push/pull endpoints.
type SecretHandler struct {
	secrets    store.SecretStore
	projects   store.ProjectStore
	workspaces store.WorkspaceStore
	audit      store.AuditLogStore
}

// NewSecretHandler creates a new SecretHandler.
func NewSecretHandler(
	secrets store.SecretStore,
	projects store.ProjectStore,
	workspaces store.WorkspaceStore,
	audit store.AuditLogStore,
) *SecretHandler {
	return &SecretHandler{
		secrets:    secrets,
		projects:   projects,
		workspaces: workspaces,
		audit:      audit,
	}
}

// recipientRequest represents one recipient in a push request.
type recipientRequest struct {
	KeyFingerprint  string `json:"key_fingerprint"`
	IdentityType    string `json:"identity_type"`
	UserID          string `json:"user_id,omitempty"`
	MachineID       string `json:"machine_id,omitempty"`
	EncryptedAESKey string `json:"encrypted_aes_key"` // base64
	EphemeralPublic string `json:"ephemeral_public"`  // base64
	KeyNonce        string `json:"key_nonce"`         // base64
	KeyAuthTag      string `json:"key_auth_tag"`      // base64
}

// pushRequest is the request body for POST /secrets/push.
type pushRequest struct {
	ProjectID   string             `json:"project_id"`
	Environment string             `json:"environment"`
	Ciphertext  string             `json:"ciphertext"` // base64
	Nonce       string             `json:"nonce"`      // base64
	AuthTag     string             `json:"auth_tag"`   // base64
	Checksum    string             `json:"checksum"`   // sha256 hex
	BaseVersion *int               `json:"base_version"`
	Message     string             `json:"message"`
	Recipients  []recipientRequest `json:"recipients"`
}

// Push stores an encrypted secret bundle (human JWT only — machines cannot push).
//
// POST /secrets/push
func (h *SecretHandler) Push(w http.ResponseWriter, r *http.Request) {
	// Must be a human — machines cannot push
	humanClaims := middleware.HumanClaimsFrom(r.Context())
	if humanClaims == nil {
		response.Forbidden(w, "machines cannot push secrets")
		return
	}

	userID, err := uuid.Parse(humanClaims.Subject)
	if err != nil {
		response.Unauthorized(w, "invalid token")
		return
	}
	workspaceID := humanClaims.WorkspaceID

	var req pushRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	req.Environment = strings.TrimSpace(req.Environment)
	if req.ProjectID == "" || req.Environment == "" {
		response.BadRequest(w, "project_id and environment are required")
		return
	}
	if req.Ciphertext == "" || req.Nonce == "" || req.AuthTag == "" || req.Checksum == "" {
		response.BadRequest(w, "ciphertext, nonce, auth_tag, and checksum are required")
		return
	}
	if len(req.Recipients) == 0 {
		response.BadRequest(w, "at least one recipient is required")
		return
	}
	if len(req.Recipients) > maxRecipients {
		response.BadRequest(w, "too many recipients (max 500)")
		return
	}

	projectID, err := uuid.Parse(req.ProjectID)
	if err != nil {
		response.BadRequest(w, "invalid project_id")
		return
	}

	ctx := r.Context()

	// Verify project belongs to the user's workspace
	project, err := h.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}
	if project.WorkspaceID != workspaceID {
		response.NotFound(w)
		return
	}

	// Decode base64 binary fields
	ciphertext, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		response.BadRequest(w, "invalid base64 in ciphertext")
		return
	}
	if len(ciphertext) > maxCiphertextBytes {
		response.BadRequest(w, "ciphertext exceeds 1 MB limit")
		return
	}

	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		response.BadRequest(w, "invalid base64 in nonce")
		return
	}

	authTag, err := base64.StdEncoding.DecodeString(req.AuthTag)
	if err != nil {
		response.BadRequest(w, "invalid base64 in auth_tag")
		return
	}

	// Build recipients
	recipients := make([]model.SecretRecipient, 0, len(req.Recipients))
	for i, rr := range req.Recipients {
		if rr.KeyFingerprint == "" || rr.IdentityType == "" {
			response.BadRequest(w, "each recipient requires key_fingerprint and identity_type")
			return
		}
		if rr.IdentityType != "user" && rr.IdentityType != "machine" {
			response.BadRequest(w, "identity_type must be 'user' or 'machine'")
			return
		}

		encAES, err := base64.StdEncoding.DecodeString(rr.EncryptedAESKey)
		if err != nil {
			response.BadRequest(w, "invalid base64 in recipients["+itoa(i)+"].encrypted_aes_key")
			return
		}
		ephPub, err := base64.StdEncoding.DecodeString(rr.EphemeralPublic)
		if err != nil {
			response.BadRequest(w, "invalid base64 in recipients["+itoa(i)+"].ephemeral_public")
			return
		}
		keyNonce, err := base64.StdEncoding.DecodeString(rr.KeyNonce)
		if err != nil {
			response.BadRequest(w, "invalid base64 in recipients["+itoa(i)+"].key_nonce")
			return
		}
		keyAuthTag, err := base64.StdEncoding.DecodeString(rr.KeyAuthTag)
		if err != nil {
			response.BadRequest(w, "invalid base64 in recipients["+itoa(i)+"].key_auth_tag")
			return
		}

		rec := model.SecretRecipient{
			IdentityType:    rr.IdentityType,
			KeyFingerprint:  rr.KeyFingerprint,
			EncryptedAESKey: encAES,
			EphemeralPublic: ephPub,
			KeyNonce:        keyNonce,
			KeyAuthTag:      keyAuthTag,
		}

		if rr.UserID != "" {
			uid, err := uuid.Parse(rr.UserID)
			if err != nil {
				response.BadRequest(w, "invalid user_id in recipients["+itoa(i)+"]")
				return
			}
			rec.UserID = &uid
		}
		if rr.MachineID != "" {
			mid, err := uuid.Parse(rr.MachineID)
			if err != nil {
				response.BadRequest(w, "invalid machine_id in recipients["+itoa(i)+"]")
				return
			}
			rec.MachineID = &mid
		}

		recipients = append(recipients, rec)
	}

	var pushMsg *string
	if req.Message != "" {
		msg := req.Message
		pushMsg = &msg
	}

	secret := &model.Secret{
		ProjectID:   projectID,
		Environment: req.Environment,
		Ciphertext:  ciphertext,
		Nonce:       nonce,
		AuthTag:     authTag,
		PushedBy:    &userID,
		BaseVersion: req.BaseVersion,
		PushMessage: pushMsg,
		KeyCount:    len(recipients),
		Checksum:    req.Checksum,
	}

	pushed, err := h.secrets.PushSecret(ctx, secret, recipients)
	if err != nil {
		if errors.Is(err, store.ErrPushConflict) {
			response.Conflict(w, "version conflict: pull latest version before pushing")
			return
		}
		response.InternalError(w)
		return
	}

	// Audit log
	resourceID := pushed.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "secret.push",
		ResourceType: "secret",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusCreated, map[string]any{
		"version": pushed.Version,
		"id":      pushed.ID,
	})
}

// recipientResponse is the JSON representation of a secret recipient for pull responses.
type recipientResponse struct {
	ID              uuid.UUID  `json:"id"`
	SecretID        uuid.UUID  `json:"secret_id"`
	IdentityType    string     `json:"identity_type"`
	UserID          *uuid.UUID `json:"user_id,omitempty"`
	MachineID       *uuid.UUID `json:"machine_id,omitempty"`
	KeyFingerprint  string     `json:"key_fingerprint"`
	EncryptedAESKey string     `json:"encrypted_aes_key"` // base64
	EphemeralPublic string     `json:"ephemeral_public"`  // base64
	KeyNonce        string     `json:"key_nonce"`         // base64
	KeyAuthTag      string     `json:"key_auth_tag"`      // base64
}

// Pull returns the latest encrypted bundle for a project/environment.
//
// GET /secrets/pull?project_id=uuid&environment=env
func (h *SecretHandler) Pull(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	projectIDStr := r.URL.Query().Get("project_id")
	environment := r.URL.Query().Get("environment")
	if projectIDStr == "" || environment == "" {
		response.BadRequest(w, "project_id and environment query params are required")
		return
	}

	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		response.BadRequest(w, "invalid project_id")
		return
	}

	// Determine workspaceID from either human or machine JWT
	var workspaceID uuid.UUID
	humanClaims := middleware.HumanClaimsFrom(ctx)
	machineClaims := middleware.MachineClaimsFrom(ctx)

	if machineClaims != nil {
		// Machine: must be scoped to this exact project + environment
		if machineClaims.ProjectID != projectID {
			response.Forbidden(w, "machine is not authorized for this project")
			return
		}
		if machineClaims.Environment != environment {
			response.Forbidden(w, "machine is not authorized for this environment")
			return
		}
		workspaceID = machineClaims.WorkspaceID
	} else if humanClaims != nil {
		workspaceID = humanClaims.WorkspaceID
	} else {
		response.Unauthorized(w, "authentication required")
		return
	}

	// Verify project belongs to this workspace
	project, err := h.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}
	if project.WorkspaceID != workspaceID {
		response.NotFound(w)
		return
	}

	secret, err := h.secrets.GetLatestSecret(ctx, projectID, environment)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}

	rawRecipients, err := h.secrets.GetRecipientsBySecret(ctx, secret.ID)
	if err != nil {
		response.InternalError(w)
		return
	}

	// Encode binary fields as base64 for the response
	recipientList := make([]recipientResponse, len(rawRecipients))
	for i, rr := range rawRecipients {
		recipientList[i] = recipientResponse{
			ID:              rr.ID,
			SecretID:        rr.SecretID,
			IdentityType:    rr.IdentityType,
			UserID:          rr.UserID,
			MachineID:       rr.MachineID,
			KeyFingerprint:  rr.KeyFingerprint,
			EncryptedAESKey: base64.StdEncoding.EncodeToString(rr.EncryptedAESKey),
			EphemeralPublic: base64.StdEncoding.EncodeToString(rr.EphemeralPublic),
			KeyNonce:        base64.StdEncoding.EncodeToString(rr.KeyNonce),
			KeyAuthTag:      base64.StdEncoding.EncodeToString(rr.KeyAuthTag),
		}
	}

	// Audit log
	var actorType string
	var actorID uuid.UUID
	if machineClaims != nil {
		actorType = "machine"
		actorID = machineClaims.MachineID
	} else {
		actorType = "user"
		uid, _ := uuid.Parse(humanClaims.Subject)
		actorID = uid
	}
	resourceID := secret.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       "secret.pull",
		ResourceType: "secret",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	var pushMessage string
	if secret.PushMessage != nil {
		pushMessage = *secret.PushMessage
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"id":           secret.ID,
		"version":      secret.Version,
		"ciphertext":   base64.StdEncoding.EncodeToString(secret.Ciphertext),
		"nonce":        base64.StdEncoding.EncodeToString(secret.Nonce),
		"auth_tag":     base64.StdEncoding.EncodeToString(secret.AuthTag),
		"checksum":     secret.Checksum,
		"push_message": pushMessage,
		"recipients":   recipientList,
	})
}

// List returns all environments and their latest version numbers for a project.
//
// GET /secrets/list?project_id=uuid
func (h *SecretHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	projectIDStr := r.URL.Query().Get("project_id")
	if projectIDStr == "" {
		response.BadRequest(w, "project_id query param is required")
		return
	}

	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		response.BadRequest(w, "invalid project_id")
		return
	}

	// Determine workspace
	var workspaceID uuid.UUID
	humanClaims := middleware.HumanClaimsFrom(ctx)
	machineClaims := middleware.MachineClaimsFrom(ctx)
	if humanClaims != nil {
		workspaceID = humanClaims.WorkspaceID
	} else if machineClaims != nil {
		workspaceID = machineClaims.WorkspaceID
	} else {
		response.Unauthorized(w, "authentication required")
		return
	}

	// Verify project belongs to this workspace
	project, err := h.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}
	if project.WorkspaceID != workspaceID {
		response.NotFound(w)
		return
	}

	envs, err := h.secrets.ListEnvironments(ctx, projectID)
	if err != nil {
		response.InternalError(w)
		return
	}

	type envInfo struct {
		Name      string `json:"name"`
		Version   int    `json:"version"`
		UpdatedAt string `json:"updated_at"`
	}

	envList := make([]envInfo, 0, len(envs))
	for _, env := range envs {
		latest, err := h.secrets.GetLatestSecret(ctx, projectID, env)
		if err != nil {
			continue
		}
		envList = append(envList, envInfo{
			Name:      env,
			Version:   latest.Version,
			UpdatedAt: latest.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}

	response.JSON(w, http.StatusOK, map[string]any{"environments": envList})
}

// GetRecipients returns the recipient list for a specific secret version.
//
// GET /secrets/{secretID}/recipients
func (h *SecretHandler) GetRecipients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	secretIDStr := chi.URLParam(r, "secretID")
	secretID, err := uuid.Parse(secretIDStr)
	if err != nil {
		response.BadRequest(w, "invalid secretID")
		return
	}

	// Determine workspace
	var workspaceID uuid.UUID
	humanClaims := middleware.HumanClaimsFrom(ctx)
	machineClaims := middleware.MachineClaimsFrom(ctx)
	if humanClaims != nil {
		workspaceID = humanClaims.WorkspaceID
	} else if machineClaims != nil {
		workspaceID = machineClaims.WorkspaceID
	} else {
		response.Unauthorized(w, "authentication required")
		return
	}

	// Get secret and verify it belongs to a project in this workspace
	secret, err := h.secrets.GetSecretByID(ctx, secretID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}

	project, err := h.projects.GetProjectByID(ctx, secret.ProjectID)
	if err != nil {
		response.InternalError(w)
		return
	}
	if project.WorkspaceID != workspaceID {
		response.NotFound(w)
		return
	}

	rawRecipients, err := h.secrets.GetRecipientsBySecret(ctx, secretID)
	if err != nil {
		response.InternalError(w)
		return
	}

	type recipientSummary struct {
		ID             uuid.UUID  `json:"id"`
		IdentityType   string     `json:"identity_type"`
		KeyFingerprint string     `json:"key_fingerprint"`
		UserID         *uuid.UUID `json:"user_id,omitempty"`
		MachineID      *uuid.UUID `json:"machine_id,omitempty"`
	}

	list := make([]recipientSummary, len(rawRecipients))
	for i, rr := range rawRecipients {
		list[i] = recipientSummary{
			ID:             rr.ID,
			IdentityType:   rr.IdentityType,
			KeyFingerprint: rr.KeyFingerprint,
			UserID:         rr.UserID,
			MachineID:      rr.MachineID,
		}
	}

	response.JSON(w, http.StatusOK, map[string]any{"recipients": list})
}

// itoa converts an int to its string representation.
func itoa(n int) string {
	return strconv.Itoa(n)
}
