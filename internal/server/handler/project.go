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

// ProjectHandler handles project endpoints.
type ProjectHandler struct {
	projects   store.ProjectStore
	workspaces store.WorkspaceStore
	audit      store.AuditLogStore
}

// NewProjectHandler creates a new ProjectHandler.
func NewProjectHandler(projects store.ProjectStore, workspaces store.WorkspaceStore, audit store.AuditLogStore) *ProjectHandler {
	return &ProjectHandler{projects: projects, workspaces: workspaces, audit: audit}
}

// List returns all projects in the workspace.
//
// GET /projects
func (h *ProjectHandler) List(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireMember(w, r)
	if !ok {
		return
	}

	projects, err := h.projects.ListProjects(r.Context(), workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{"projects": projects})
}

// createProjectRequest is the request body for POST /projects.
type createProjectRequest struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// Create creates a new project (admin only).
//
// POST /projects
func (h *ProjectHandler) Create(w http.ResponseWriter, r *http.Request) {
	workspaceID, userID, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	var req createProjectRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Slug = strings.TrimSpace(strings.ToLower(req.Slug))
	if req.Name == "" || req.Slug == "" {
		response.BadRequest(w, "name and slug are required")
		return
	}

	ctx := r.Context()

	project, err := h.projects.CreateProject(ctx, workspaceID, userID, req.Name, req.Slug)
	if err != nil {
		if errors.Is(err, store.ErrDuplicateSlug) {
			response.Conflict(w, "project slug already in use")
			return
		}
		response.InternalError(w)
		return
	}

	// Audit log
	resourceID := project.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "project.created",
		ResourceType: "project",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusCreated, project)
}

// Delete deletes a project (admin only).
//
// DELETE /projects/{projectID}
func (h *ProjectHandler) Delete(w http.ResponseWriter, r *http.Request) {
	workspaceID, userID, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	projectIDStr := chi.URLParam(r, "projectID")
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		response.BadRequest(w, "invalid projectID")
		return
	}

	ctx := r.Context()

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

	if err := h.projects.DeleteProject(ctx, projectID); err != nil {
		response.InternalError(w)
		return
	}

	// Audit log
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      userID,
		Action:       "project.deleted",
		ResourceType: "project",
		ResourceID:   &projectID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
