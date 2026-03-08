package response

import (
	"encoding/json"
	"net/http"
)

// Error codes per spec section 8.
const (
	CodeBadRequest       = "BAD_REQUEST"
	CodeUnauthorized     = "UNAUTHORIZED"
	CodeForbidden        = "FORBIDDEN"
	CodeNotFound         = "NOT_FOUND"
	CodeConflict         = "CONFLICT"
	CodeRateLimited      = "RATE_LIMITED"
	CodeInvalidCode      = "INVALID_CODE"
	CodeInvalidSignature = "INVALID_SIGNATURE"
	CodeNoRecipient      = "NO_RECIPIENT"
	CodePlanLimit        = "PLAN_LIMIT"
	CodeInternalError    = "INTERNAL_ERROR"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// JSON writes a JSON response with the given status code.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// Error writes a standard JSON error response.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, errorBody{Error: errorDetail{Code: code, Message: message}})
}

// BadRequest writes a 400 Bad Request error.
func BadRequest(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, CodeBadRequest, message)
}

// Unauthorized writes a 401 Unauthorized error.
func Unauthorized(w http.ResponseWriter, message string) {
	Error(w, http.StatusUnauthorized, CodeUnauthorized, message)
}

// Forbidden writes a 403 Forbidden error.
func Forbidden(w http.ResponseWriter, message string) {
	Error(w, http.StatusForbidden, CodeForbidden, message)
}

// NotFound writes a 404 Not Found error.
func NotFound(w http.ResponseWriter) {
	Error(w, http.StatusNotFound, CodeNotFound, "resource not found")
}

// Conflict writes a 409 Conflict error.
func Conflict(w http.ResponseWriter, message string) {
	Error(w, http.StatusConflict, CodeConflict, message)
}

// InternalError writes a 500 Internal Server Error.
func InternalError(w http.ResponseWriter) {
	Error(w, http.StatusInternalServerError, CodeInternalError, "an internal error occurred")
}
