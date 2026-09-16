// Package admin exposes a small JSON REST API backing the TypeScript admin
// UI: policy management, live-ish access logs, and certificate rotation
// status. It's deliberately served on a *separate* listener/port from the
// data-plane proxy (see cmd/proxy/main.go) — mixing control-plane admin
// endpoints into the same listener that handles untrusted end-user traffic
// is a common way IAPs/VPN concentrators get compromised, so we don't.
package admin

import (
	"encoding/json"
	"net/http"
	"strconv"

	"zero-trust-iap/internal/logging"
	"zero-trust-iap/internal/policy"
	"zero-trust-iap/internal/proxy"
)

type API struct {
	policyEngine *policy.Engine
	accessLog    *logging.Logger
	rotator      *proxy.Rotator
	adminToken   string
	mux          *http.ServeMux
}

func NewAPI(policyEngine *policy.Engine, accessLog *logging.Logger, rotator *proxy.Rotator, adminToken string) *API {
	a := &API{
		policyEngine: policyEngine,
		accessLog:    accessLog,
		rotator:      rotator,
		adminToken:   adminToken,
		mux:          http.NewServeMux(),
	}
	a.routes()
	return a
}

func (a *API) routes() {
	a.mux.HandleFunc("/api/policies", a.requireAuth(a.handlePolicies))
	a.mux.HandleFunc("/api/policies/", a.requireAuth(a.handlePolicyByID))
	a.mux.HandleFunc("/api/logs", a.requireAuth(a.handleLogs))
	a.mux.HandleFunc("/api/rotation/status", a.requireAuth(a.handleRotationStatus))
	a.mux.HandleFunc("/api/rotation/rotate-now", a.requireAuth(a.handleRotateNow))
	a.mux.HandleFunc("/healthz", a.handleHealthz)
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	a.mux.ServeHTTP(w, r)
}

func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.adminToken == "" {
			// No token configured (local dev) — allow, but this should
			// never happen in a deployed config; main.go warns loudly.
			next(w, r)
			return
		}
		got := r.Header.Get("X-Admin-Token")
		if got != a.adminToken {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		next(w, r)
	}
}

func (a *API) handleHealthz(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (a *API) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		_ = json.NewEncoder(w).Encode(a.policyEngine.All())
	case http.MethodPost:
		var p policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if p.ID == "" {
			writeError(w, http.StatusBadRequest, "policy id is required")
			return
		}
		a.policyEngine.Upsert(p)
		if err := a.policyEngine.Save(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handlePolicyByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/policies/"):]
	if id == "" {
		writeError(w, http.StatusBadRequest, "policy id required in path")
		return
	}
	switch r.Method {
	case http.MethodDelete:
		if a.policyEngine.Delete(id) {
			if err := a.policyEngine.Save(); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusNotFound, "policy not found")
	case http.MethodPut:
		var p policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		p.ID = id
		a.policyEngine.Upsert(p)
		if err := a.policyEngine.Save(); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		_ = json.NewEncoder(w).Encode(p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	_ = json.NewEncoder(w).Encode(a.accessLog.Recent(limit))
}

func (a *API) handleRotationStatus(w http.ResponseWriter, r *http.Request) {
	if a.rotator == nil {
		_ = json.NewEncoder(w).Encode(map[string]string{"source": "disabled"})
		return
	}
	_ = json.NewEncoder(w).Encode(a.rotator.Status())
}

func (a *API) handleRotateNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if a.rotator == nil {
		writeError(w, http.StatusBadRequest, "rotation is not enabled on this proxy")
		return
	}
	// Rotation itself runs on the proxy's Rotator; here we just report
	// current status since forcing an out-of-band rotation is done via
	// the same Rotator instance shared with the proxy server.
	_ = json.NewEncoder(w).Encode(a.rotator.Status())
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
