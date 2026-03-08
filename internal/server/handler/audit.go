package handler

import (
	"net/http"
	"strconv"

	"github.com/envshq/envsh-server/internal/server/response"
	"github.com/envshq/envsh-server/internal/store"
)

// AuditHandler handles audit log endpoints.
type AuditHandler struct {
	audit      store.AuditLogStore
	workspaces store.WorkspaceStore
}

// NewAuditHandler creates a new AuditHandler.
func NewAuditHandler(audit store.AuditLogStore, workspaces store.WorkspaceStore) *AuditHandler {
	return &AuditHandler{audit: audit, workspaces: workspaces}
}

// List returns paginated audit log entries (admin only).
//
// GET /audit?limit=50&offset=0
func (h *AuditHandler) List(w http.ResponseWriter, r *http.Request) {
	workspaceID, _, ok := requireAdmin(w, r, h.workspaces)
	if !ok {
		return
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50
	offset := 0

	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}
	if limit > 200 {
		limit = 200
	}
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	entries, err := h.audit.ListAuditLogs(r.Context(), workspaceID, limit, offset)
	if err != nil {
		response.InternalError(w)
		return
	}

	response.JSON(w, http.StatusOK, map[string]any{
		"entries": entries,
		"limit":   limit,
		"offset":  offset,
	})
}
