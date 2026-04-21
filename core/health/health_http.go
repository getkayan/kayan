package health

import (
	"encoding/json"
	"net/http"
)

// LiveHandler returns a handler for liveness checks (Kubernetes).
func (m *Manager) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

// ReadyHandler returns a handler for readiness checks (Kubernetes).
func (m *Manager) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if m.IsReady(r.Context()) {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
			return
		}

		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
	}
}

// FullHandler returns a handler for full health reports.
func (m *Manager) FullHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := m.Check(r.Context())

		statusCode := http.StatusOK
		if report.Status == StatusUnhealthy {
			statusCode = http.StatusServiceUnavailable
		}

		writeJSON(w, statusCode, report)
	}
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}
