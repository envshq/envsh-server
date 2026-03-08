package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/envshq/envsh-server/internal/server/middleware"
	"github.com/envshq/envsh-server/internal/server/response"
	"github.com/envshq/envsh-server/internal/store"
)

// requireAdmin checks that the requesting user is an admin in their workspace.
// Returns workspaceID, userID, and true on success. Writes the error response and returns false on failure.
func requireAdmin(w http.ResponseWriter, r *http.Request, workspaces store.WorkspaceStore) (workspaceID uuid.UUID, userID uuid.UUID, ok bool) {
	claims := middleware.HumanClaimsFrom(r.Context())
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return uuid.Nil, uuid.Nil, false
	}
	uID, err := uuid.Parse(claims.Subject)
	if err != nil {
		response.Unauthorized(w, "invalid token")
		return uuid.Nil, uuid.Nil, false
	}
	member, err := workspaces.GetMember(r.Context(), claims.WorkspaceID, uID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			response.Forbidden(w, "not a member of this workspace")
		} else {
			response.InternalError(w)
		}
		return uuid.Nil, uuid.Nil, false
	}
	if member.Role != "admin" {
		response.Forbidden(w, "admin role required")
		return uuid.Nil, uuid.Nil, false
	}
	return claims.WorkspaceID, uID, true
}

// requireMember checks that the requesting user is any member of their workspace.
// Returns workspaceID, userID, and true on success. Writes the error response and returns false on failure.
func requireMember(w http.ResponseWriter, r *http.Request) (workspaceID uuid.UUID, userID uuid.UUID, ok bool) {
	claims := middleware.HumanClaimsFrom(r.Context())
	if claims == nil {
		response.Unauthorized(w, "authentication required")
		return uuid.Nil, uuid.Nil, false
	}
	uID, err := uuid.Parse(claims.Subject)
	if err != nil {
		response.Unauthorized(w, "invalid token")
		return uuid.Nil, uuid.Nil, false
	}
	return claims.WorkspaceID, uID, true
}

// decodeJSON decodes the request body into v. Returns false and writes error on failure.
func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		response.BadRequest(w, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// storeErrToHTTP maps store sentinel errors to HTTP responses.
func storeErrToHTTP(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		response.NotFound(w)
	case errors.Is(err, store.ErrDuplicateEmail):
		response.Conflict(w, "email already registered")
	case errors.Is(err, store.ErrDuplicateSlug):
		response.Conflict(w, "slug already in use")
	case errors.Is(err, store.ErrDuplicateKey):
		response.Conflict(w, "key already registered")
	case errors.Is(err, store.ErrPushConflict):
		response.Conflict(w, "version conflict: pull latest version before pushing")
	case errors.Is(err, store.ErrRevoked):
		response.Forbidden(w, "resource has been revoked")
	default:
		response.InternalError(w)
	}
}
