package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/auth"
	"github.com/envshq/envsh-server/internal/model"
	"github.com/envshq/envsh-server/internal/server/response"
	"github.com/envshq/envsh-server/internal/store"
)

// AuthHandler handles all authentication endpoints.
type AuthHandler struct {
	users      store.UserStore
	workspaces store.WorkspaceStore
	machines   store.MachineStore
	audit      store.AuditLogStore
	email      *auth.EmailAuthService
	jwt        *auth.JWTService
	machine    *auth.MachineAuthService
}

// NewAuthHandler creates a new AuthHandler.
func NewAuthHandler(
	users store.UserStore,
	workspaces store.WorkspaceStore,
	machines store.MachineStore,
	audit store.AuditLogStore,
	email *auth.EmailAuthService,
	jwt *auth.JWTService,
	machine *auth.MachineAuthService,
) *AuthHandler {
	return &AuthHandler{
		users:      users,
		workspaces: workspaces,
		machines:   machines,
		audit:      audit,
		email:      email,
		jwt:        jwt,
		machine:    machine,
	}
}

// emailLoginRequest is the request body for POST /auth/email-login.
type emailLoginRequest struct {
	Email string `json:"email"`
}

// EmailLogin sends a 6-digit code to the given email.
//
// POST /auth/email-login
func (h *AuthHandler) EmailLogin(w http.ResponseWriter, r *http.Request) {
	var req emailLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		response.BadRequest(w, "valid email is required")
		return
	}

	if err := h.email.RequestCode(r.Context(), req.Email); err != nil {
		if errors.Is(err, auth.ErrRateLimited) {
			response.Error(w, http.StatusTooManyRequests, response.CodeRateLimited, "too many code requests, please wait")
			return
		}
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{"message": "code sent"})
}

// emailVerifyRequest is the request body for POST /auth/email-verify.
type emailVerifyRequest struct {
	Email string `json:"email"`
	Code  string `json:"code"`
}

// EmailVerify verifies the code and issues tokens. Creates user + workspace if new.
//
// POST /auth/email-verify
func (h *AuthHandler) EmailVerify(w http.ResponseWriter, r *http.Request) {
	var req emailVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || req.Code == "" {
		response.BadRequest(w, "email and code are required")
		return
	}

	ctx := r.Context()

	if err := h.email.VerifyCode(ctx, req.Email, req.Code); err != nil {
		if errors.Is(err, auth.ErrInvalidCode) {
			response.Error(w, http.StatusBadRequest, response.CodeInvalidCode, "invalid or expired code")
			return
		}
		if errors.Is(err, auth.ErrTooManyAttempts) {
			response.Error(w, http.StatusBadRequest, response.CodeInvalidCode, "too many failed attempts, request a new code")
			return
		}
		response.InternalError(w)
		return
	}

	// Get or create user
	user, err := h.users.GetUserByEmail(ctx, req.Email)
	isNew := false
	if errors.Is(err, store.ErrNotFound) {
		user, err = h.users.CreateUser(ctx, req.Email)
		if err != nil {
			response.InternalError(w)
			return
		}
		isNew = true
	} else if err != nil {
		response.InternalError(w)
		return
	}

	// Get or create workspace
	var workspace *model.Workspace
	if isNew {
		slug := slugFromEmail(req.Email)
		workspace, err = h.workspaces.CreateWorkspace(ctx, user.ID, req.Email, slug)
		if err != nil {
			// slug collision — try with a suffix
			slug = slug + "-" + user.ID.String()[:8]
			workspace, err = h.workspaces.CreateWorkspace(ctx, user.ID, req.Email, slug)
			if err != nil {
				response.InternalError(w)
				return
			}
		}
		// Create free subscription
		if _, err := h.workspaces.CreateSubscription(ctx, workspace.ID); err != nil {
			response.InternalError(w)
			return
		}
		// Add owner as admin
		if _, err := h.workspaces.AddMember(ctx, workspace.ID, user.ID, "admin", nil); err != nil {
			response.InternalError(w)
			return
		}
	} else {
		workspace, err = h.workspaces.GetWorkspaceByOwner(ctx, user.ID)
		if errors.Is(err, store.ErrNotFound) {
			// User was pre-created by an invite but hasn't logged in yet —
			// provision their own workspace now (first-login bootstrap).
			slug := slugFromEmail(req.Email)
			workspace, err = h.workspaces.CreateWorkspace(ctx, user.ID, req.Email, slug)
			if err != nil {
				slug = slug + "-" + user.ID.String()[:8]
				workspace, err = h.workspaces.CreateWorkspace(ctx, user.ID, req.Email, slug)
			}
			if err == nil {
				if _, subErr := h.workspaces.CreateSubscription(ctx, workspace.ID); subErr != nil {
					response.InternalError(w)
					return
				}
				if _, subErr := h.workspaces.AddMember(ctx, workspace.ID, user.ID, "admin", nil); subErr != nil {
					response.InternalError(w)
					return
				}
			}
		}
		if err != nil {
			response.InternalError(w)
			return
		}
	}

	tokens, err := h.jwt.IssueHumanTokens(ctx, user.ID, user.Email, workspace.ID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"token":         tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
		},
		"workspace": map[string]any{
			"id":   workspace.ID,
			"name": workspace.Name,
			"slug": workspace.Slug,
		},
	})
}

// refreshRequest is the request body for POST /auth/refresh.
type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Refresh exchanges a refresh token for a new access token pair.
//
// POST /auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" {
		response.BadRequest(w, "refresh_token is required")
		return
	}

	ctx := r.Context()

	userID, workspaceID, err := h.jwt.ValidateAndConsumeRefreshToken(ctx, req.RefreshToken)
	if err != nil {
		response.Unauthorized(w, "invalid or expired refresh token")
		return
	}

	user, err := h.users.GetUserByID(ctx, userID)
	if err != nil {
		response.InternalError(w)
		return
	}

	// Verify user is still a member of the workspace. Fall back to owned workspace if removed.
	_, err = h.workspaces.GetMember(ctx, workspaceID, userID)
	if err != nil {
		workspace, err := h.workspaces.GetWorkspaceByOwner(ctx, user.ID)
		if err != nil {
			response.InternalError(w)
			return
		}
		workspaceID = workspace.ID
	}

	tokens, err := h.jwt.IssueHumanTokens(ctx, user.ID, user.Email, workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"token":         tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
	})
}

// logoutRequest is the request body for POST /auth/logout.
type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// Logout revokes the refresh token.
//
// POST /auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var req logoutRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RefreshToken == "" {
		response.BadRequest(w, "refresh_token is required")
		return
	}

	_ = h.jwt.RevokeRefreshToken(r.Context(), req.RefreshToken)
	response.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// machineChallengeRequest is the request body for POST /auth/machine-challenge.
type machineChallengeRequest struct {
	MachineID   string `json:"machine_id"`
	Fingerprint string `json:"fingerprint"`
}

// MachineChallenge generates a nonce challenge for a machine.
// Accepts either machine_id (UUID) or fingerprint to identify the machine.
//
// POST /auth/machine-challenge
func (h *AuthHandler) MachineChallenge(w http.ResponseWriter, r *http.Request) {
	var req machineChallengeRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	ctx := r.Context()

	var m *model.Machine
	var err error

	if req.Fingerprint != "" {
		m, err = h.machines.GetMachineByFingerprint(ctx, req.Fingerprint)
	} else if req.MachineID != "" {
		machineID, parseErr := uuid.Parse(req.MachineID)
		if parseErr != nil {
			response.BadRequest(w, "invalid machine_id")
			return
		}
		m, err = h.machines.GetMachineByID(ctx, machineID)
	} else {
		response.BadRequest(w, "machine_id or fingerprint is required")
		return
	}

	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}
	if m.Status != "active" {
		response.Forbidden(w, "machine is revoked")
		return
	}

	nonce, err := h.machine.GenerateChallenge(ctx, m.ID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{"nonce": nonce, "machine_id": m.ID})
}

// machineVerifyRequest is the request body for POST /auth/machine-verify.
type machineVerifyRequest struct {
	MachineID string `json:"machine_id"`
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

// MachineVerify verifies a machine's challenge response and issues a JWT.
//
// POST /auth/machine-verify
func (h *AuthHandler) MachineVerify(w http.ResponseWriter, r *http.Request) {
	var req machineVerifyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.MachineID == "" || req.Nonce == "" || req.Signature == "" {
		response.BadRequest(w, "machine_id, nonce, and signature are required")
		return
	}

	machineID, err := uuid.Parse(req.MachineID)
	if err != nil {
		response.BadRequest(w, "invalid machine_id")
		return
	}

	ctx := r.Context()

	m, err := h.machines.GetMachineByID(ctx, machineID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.Error(w, http.StatusUnauthorized, response.CodeInvalidSignature, "invalid machine credentials")
			return
		}
		response.InternalError(w)
		return
	}
	if m.Status != "active" {
		response.Error(w, http.StatusUnauthorized, response.CodeInvalidSignature, "machine is revoked")
		return
	}

	token, err := h.machine.VerifyChallenge(
		ctx,
		m.ID,
		m.PublicKey,
		m.WorkspaceID,
		m.ProjectID,
		m.Environment,
		req.Signature,
	)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidChallenge) || errors.Is(err, auth.ErrChallengeExpired) {
			response.Error(w, http.StatusUnauthorized, response.CodeInvalidSignature, "no pending challenge or challenge expired")
			return
		}
		if errors.Is(err, auth.ErrInvalidSignature) {
			response.Error(w, http.StatusUnauthorized, response.CodeInvalidSignature, "invalid signature")
			return
		}
		response.InternalError(w)
		return
	}

	// Audit log
	actorID := m.ID
	resourceID := m.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  m.WorkspaceID,
		ActorType:    "machine",
		ActorID:      actorID,
		Action:       "machine.authenticated",
		ResourceType: "machine",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusOK, map[string]any{
		"token": token,
		"machine": map[string]any{
			"id":   m.ID,
			"name": m.Name,
		},
	})
}

// slugFromEmail generates a workspace slug from an email address.
// e.g. "alice@example.com" → "alice"
func slugFromEmail(email string) string {
	parts := strings.SplitN(email, "@", 2)
	slug := strings.ToLower(parts[0])
	// Keep only alphanumeric and hyphens
	var b strings.Builder
	for _, c := range slug {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			_, _ = b.WriteRune(c)
		}
	}
	result := b.String()
	if result == "" {
		result = "workspace"
	}
	return result
}

func stringPtr(s string) *string {
	return &s
}
