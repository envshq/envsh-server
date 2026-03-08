package handler

import (
	"net/http"

	"github.com/envshq/envsh-server/internal/server/response"
)

// Health returns a simple liveness check.
func Health(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, http.StatusOK, map[string]any{"ok": true, "version": "v1"})
}

// HealthReady returns a readiness check (currently always OK).
func HealthReady(w http.ResponseWriter, r *http.Request) {
	response.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
