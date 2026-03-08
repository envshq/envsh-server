package response_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/envshq/envsh-server/internal/server/response"
)

func TestJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	response.JSON(rec, http.StatusOK, map[string]any{"key": "value"})

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", ct)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response body: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("expected key=value, got %v", body["key"])
	}
}

func TestError(t *testing.T) {
	rec := httptest.NewRecorder()
	response.Error(rec, http.StatusBadRequest, response.CodeBadRequest, "test error")

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}

	var body struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decoding error body: %v", err)
	}
	if body.Error.Code != response.CodeBadRequest {
		t.Errorf("expected code=%s, got %s", response.CodeBadRequest, body.Error.Code)
	}
	if body.Error.Message != "test error" {
		t.Errorf("expected message='test error', got '%s'", body.Error.Message)
	}
}

func TestBadRequest(t *testing.T) {
	rec := httptest.NewRecorder()
	response.BadRequest(rec, "invalid input")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestUnauthorized(t *testing.T) {
	rec := httptest.NewRecorder()
	response.Unauthorized(rec, "not authenticated")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}
}

func TestForbidden(t *testing.T) {
	rec := httptest.NewRecorder()
	response.Forbidden(rec, "not authorized")
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}

func TestNotFound(t *testing.T) {
	rec := httptest.NewRecorder()
	response.NotFound(rec)
	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
}

func TestConflict(t *testing.T) {
	rec := httptest.NewRecorder()
	response.Conflict(rec, "already exists")
	if rec.Code != http.StatusConflict {
		t.Errorf("expected 409, got %d", rec.Code)
	}
}

func TestInternalError(t *testing.T) {
	rec := httptest.NewRecorder()
	response.InternalError(rec)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}
}
