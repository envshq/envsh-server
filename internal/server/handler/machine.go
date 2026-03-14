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

// MachineHandler handles machine identity endpoints.
type MachineHandler struct {
	machines   store.MachineStore
	projects   store.ProjectStore
	workspaces store.WorkspaceStore
	audit      store.AuditLogStore
}

// NewMachineHandler creates a new MachineHandler.
func NewMachineHandler(
	machines store.MachineStore,
	projects store.ProjectStore,
	workspaces store.WorkspaceStore,
	audit store.AuditLogStore,
) *MachineHandler {
	return &MachineHandler{machines: machines, projects: projects, workspaces: workspaces, audit: audit}
}

// List returns all machines in the workspace.
//
// GET /machines
func (h *MachineHandler) List(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireMember(w, r)
	if !ok {
		return
	}

	machines, err := h.machines.ListMachines(r.Context(), workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{"machines": machines})
}

// createMachineRequest is the request body for POST /machines.
type createMachineRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	ProjectID   string `json:"project_id"`
	Environment string `json:"environment"`
	PublicKey   string `json:"public_key"`
	Fingerprint string `json:"key_fingerprint"`
}

// Create creates a new machine identity (admin only).
//
// POST /machines
func (h *MachineHandler) Create(w http.ResponseWriter, r *http.Request) {
	workspaceID, userID, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	var req createMachineRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = uuid.New().String()
	req.Environment = strings.TrimSpace(req.Environment)
	if req.Name == "" || req.ProjectID == "" || req.Environment == "" || req.PublicKey == "" {
		response.BadRequest(w, "name, project_id, environment, and public_key are required")
		return
	}

	projectID, err := uuid.Parse(req.ProjectID)
	if err != nil {
		response.BadRequest(w, "invalid project_id")
		return
	}

	ctx := r.Context()

	// Verify project belongs to this workspace
	project, err := h.projects.GetProjectByID(ctx, projectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.BadRequest(w, "project not found")
			return
		}
		response.InternalError(w)
		return
	}
	if project.WorkspaceID != workspaceID {
		response.BadRequest(w, "project not found in this workspace")
		return
	}

	// Use fingerprint from request (CLI computes it) or generate from public key
	fingerprint := req.Fingerprint
	if fingerprint == "" {
		response.BadRequest(w, "key_fingerprint is required")
		return
	}

	m := &model.Machine{
		ID:             uuid.New(),
		WorkspaceID:    workspaceID,
		Name:           req.Name,
		Slug:           req.Slug,
		PublicKey:      req.PublicKey,
		KeyFingerprint: fingerprint,
		ProjectID:      projectID,
		Environment:    req.Environment,
		Status:         "active",
		CreatedBy:      userID,
	}

	created, err := h.machines.CreateMachine(ctx, m)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateSlug) {
			response.Conflict(w, "machine slug already in use")
			return
		}
		if errors.Is(err, store.ErrDuplicateKey) {
			response.Conflict(w, "machine key already registered")
			return
		}
		response.InternalError(w)
		return
	}

	// Audit log
	resourceID := created.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "machine.created",
		ResourceType: "machine",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusCreated, map[string]any{
		"id":              created.ID,
		"name":            created.Name,
		"slug":            created.Slug,
		"key_fingerprint": created.KeyFingerprint,
		"project_id":      created.ProjectID,
		"environment":     created.Environment,
		"status":          created.Status,
	})
}

// GetKey returns the public key for a machine.
//
// GET /machines/{machineID}/key
func (h *MachineHandler) GetKey(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireMember(w, r)
	if !ok {
		return
	}

	machineIDStr := chi.URLParam(r, "machineID")
	machineID, err := uuid.Parse(machineIDStr)
	if err != nil {
		response.BadRequest(w, "invalid machineID")
		return
	}

	ctx := r.Context()

	m, err := h.machines.GetMachineByID(ctx, machineID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}
	if m.WorkspaceID != workspaceID {
		response.NotFound(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"id":         m.ID,
		"name":       m.Name,
		"public_key": m.PublicKey,
	})
}

// Revoke revokes a machine identity (admin only).
//
// DELETE /machines/{machineID}
func (h *MachineHandler) Revoke(w http.ResponseWriter, r *http.Request) {
	workspaceID, userID, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	machineIDStr := chi.URLParam(r, "machineID")
	machineID, err := uuid.Parse(machineIDStr)
	if err != nil {
		response.BadRequest(w, "invalid machineID")
		return
	}

	ctx := r.Context()

	// Verify machine belongs to this workspace
	m, err := h.machines.GetMachineByID(ctx, machineID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.NotFound(w)
			return
		}
		response.InternalError(w)
		return
	}
	if m.WorkspaceID != workspaceID {
		response.NotFound(w)
		return
	}

	if err := h.machines.RevokeMachine(ctx, machineID); err != nil {
		response.InternalError(w)
		return
	}

	// Audit log
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "machine.revoked",
		ResourceType: "machine",
		ResourceID:   &machineID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
