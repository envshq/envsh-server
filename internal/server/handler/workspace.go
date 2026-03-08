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

// WorkspaceHandler handles workspace and member endpoints.
type WorkspaceHandler struct {
	workspaces store.WorkspaceStore
	users      store.UserStore
	audit      store.AuditLogStore
}

// NewWorkspaceHandler creates a new WorkspaceHandler.
func NewWorkspaceHandler(workspaces store.WorkspaceStore, users store.UserStore, audit store.AuditLogStore) *WorkspaceHandler {
	return &WorkspaceHandler{workspaces: workspaces, users: users, audit: audit}
}

// Get returns workspace info for the authenticated user.
//
// GET /workspace
func (h *WorkspaceHandler) Get(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireMember(w, r)
	if !ok {
		return
	}

	ctx := r.Context()

	workspace, err := h.workspaces.GetWorkspaceByID(ctx, workspaceID)
	if err != nil {
		storeErrToHTTP(w, err)
		return
	}

	members, err := h.workspaces.ListMembers(ctx, workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	sub, err := h.workspaces.GetSubscription(ctx, workspaceID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		response.InternalError(w)
		return
	}

	type memberResp struct {
		ID    uuid.UUID `json:"id"`
		Email string    `json:"email"`
		Role  string    `json:"role"`
	}
	memberList := make([]memberResp, len(members))
	for i, m := range members {
		memberList[i] = memberResp{ID: m.UserID, Email: m.Email, Role: m.Role}
	}

	resp := map[string]any{
		"id":       workspace.ID,
		"name":     workspace.Name,
		"slug":     workspace.Slug,
		"owner_id": workspace.OwnerID,
		"members":  memberList,
	}
	if sub != nil {
		resp["subscription"] = map[string]any{
			"plan":       sub.Plan,
			"seat_count": sub.SeatCount,
		}
	}

	response.JSON(w, http.StatusOK, resp)
}

// updateWorkspaceRequest is the request body for PATCH /workspace.
type updateWorkspaceRequest struct {
	Name string `json:"name"`
}

// Update changes the workspace name (admin only).
//
// PATCH /workspace
func (h *WorkspaceHandler) Update(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	var req updateWorkspaceRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		response.BadRequest(w, "name is required")
		return
	}

	ctx := r.Context()

	if err := h.workspaces.UpdateWorkspaceName(ctx, workspaceID, req.Name); err != nil {
		response.InternalError(w)
		return
	}

	workspace, err := h.workspaces.GetWorkspaceByID(ctx, workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"id":   workspace.ID,
		"name": workspace.Name,
	})
}

// ListMembers lists all members of the workspace.
//
// GET /workspace/members
func (h *WorkspaceHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireMember(w, r)
	if !ok {
		return
	}

	members, err := h.workspaces.ListMembers(r.Context(), workspaceID)
	if err != nil {
		response.InternalError(w)
		return
	}

	type memberResp struct {
		ID       uuid.UUID `json:"id"`
		UserID   uuid.UUID `json:"user_id"`
		Email    string    `json:"email"`
		Role     string    `json:"role"`
		JoinedAt string    `json:"joined_at"`
	}
	list := make([]memberResp, len(members))
	for i, m := range members {
		list[i] = memberResp{
			ID:       m.ID,
			UserID:   m.UserID,
			Email:    m.Email,
			Role:     m.Role,
			JoinedAt: m.JoinedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
	}

	response.JSON(w, http.StatusOK, map[string]any{"members": list})
}

// inviteMemberRequest is the request body for POST /workspace/members/invite.
type inviteMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role"`
}

// InviteMember invites a user to the workspace (admin only).
//
// POST /workspace/members/invite
func (h *WorkspaceHandler) InviteMember(w http.ResponseWriter, r *http.Request) {
	workspaceID, inviterID, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	var req inviteMemberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" || !strings.Contains(req.Email, "@") {
		response.BadRequest(w, "valid email is required")
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if req.Role != "admin" && req.Role != "member" {
		response.BadRequest(w, "role must be 'admin' or 'member'")
		return
	}

	ctx := r.Context()

	// Check plan limit for free plan
	sub, err := h.workspaces.GetSubscription(ctx, workspaceID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		response.InternalError(w)
		return
	}
	if sub != nil && sub.Plan == "free" {
		count, err := h.workspaces.GetMemberCount(ctx, workspaceID)
		if err != nil {
			response.InternalError(w)
			return
		}
		if count >= 3 {
			response.Error(w, http.StatusForbidden, response.CodePlanLimit, "free plan is limited to 3 members, upgrade to add more")
			return
		}
	}

	// Get or create user
	user, err := h.users.GetUserByEmail(ctx, req.Email)
	if errors.Is(err, store.ErrNotFound) {
		user, err = h.users.CreateUser(ctx, req.Email)
		if err != nil {
			response.InternalError(w)
			return
		}
	} else if err != nil {
		response.InternalError(w)
		return
	}

	member, err := h.workspaces.AddMember(ctx, workspaceID, user.ID, req.Role, &inviterID)
	if err != nil {
		response.InternalError(w)
		return
	}

	// Audit log
	resourceID := member.ID
	_ = h.audit.AppendAuditLog(ctx, &model.AuditLog{
		WorkspaceID:  workspaceID,
		ActorType:    "user",
		ActorID:      inviterID,
		Action:       "member.invited",
		ResourceType: "workspace_member",
		ResourceID:   &resourceID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":    user.ID,
			"email": user.Email,
		},
		"role": member.Role,
	})
}

// RemoveMember removes a member from the workspace (admin only, cannot remove self).
//
// DELETE /workspace/members/{userID}
func (h *WorkspaceHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	workspaceID, adminID, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	targetIDStr := chi.URLParam(r, "userID")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		response.BadRequest(w, "invalid userID")
		return
	}

	if targetID == adminID {
		response.BadRequest(w, "cannot remove yourself from the workspace")
		return
	}

	ctx := r.Context()

	if err := h.workspaces.RemoveMember(ctx, workspaceID, targetID); err != nil {
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
		ActorID:      adminID,
		Action:       "member.removed",
		ResourceType: "workspace_member",
		ResourceID:   &targetID,
		IPAddress:    stringPtr(r.RemoteAddr),
	})

	response.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
