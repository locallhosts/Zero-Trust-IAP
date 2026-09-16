// Package admin exposes the JSON REST API backing the TypeScript admin UI.
package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"zero-trust-iap/internal/logging"
	"zero-trust-iap/internal/policy"
	"zero-trust-iap/internal/proxy"
	"zero-trust-iap/internal/risk"
)

type API struct {
	policyEngine *policy.Engine
	accessLog    *logging.Logger
	rotator      *proxy.Rotator
	riskEngine   *risk.Engine
	adminToken   string
	mux          *http.ServeMux
}

func NewAPI(policyEngine *policy.Engine, accessLog *logging.Logger, rotator *proxy.Rotator, adminToken string) *API {
	a := &API{policyEngine: policyEngine, accessLog: accessLog, rotator: rotator, riskEngine: risk.NewEngine(), adminToken: adminToken, mux: http.NewServeMux()}
	a.routes()
	return a
}

func (a *API) routes() {
	a.mux.HandleFunc("/api/policies", a.requireAuth(a.handlePolicies))
	a.mux.HandleFunc("/api/policies/", a.requireAuth(a.handlePolicyByID))
	a.mux.HandleFunc("/api/logs", a.requireAuth(a.handleLogs))
	a.mux.HandleFunc("/api/security/replay", a.requireAuth(a.handleSecurityReplay))
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
		if a.adminToken == "" || r.Header.Get("X-Admin-Token") == a.adminToken {
			next(w, r)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
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
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil { writeError(w, http.StatusBadRequest, err.Error()); return }
		if p.ID == "" { writeError(w, http.StatusBadRequest, "policy id is required"); return }
		a.policyEngine.Upsert(p)
		if err := a.policyEngine.Save(); err != nil { writeError(w, http.StatusInternalServerError, err.Error()); return }
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handlePolicyByID(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/policies/"):]
	if id == "" { writeError(w, http.StatusBadRequest, "policy id required in path"); return }
	switch r.Method {
	case http.MethodDelete:
		if a.policyEngine.Delete(id) {
			if err := a.policyEngine.Save(); err != nil { writeError(w, http.StatusInternalServerError, err.Error()); return }
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeError(w, http.StatusNotFound, "policy not found")
	case http.MethodPut:
		var p policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil { writeError(w, http.StatusBadRequest, err.Error()); return }
		p.ID = id
		a.policyEngine.Upsert(p)
		if err := a.policyEngine.Save(); err != nil { writeError(w, http.StatusInternalServerError, err.Error()); return }
		_ = json.NewEncoder(w).Encode(p)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (a *API) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" { if n, err := strconv.Atoi(v); err == nil { limit = n } }
	_ = json.NewEncoder(w).Encode(a.accessLog.Recent(limit))
}

type SecurityReplayRequest struct {
	Subject           string `json:"subject"`
	Authenticated     bool   `json:"authenticated"`
	PostureOK         bool   `json:"posture_ok"`
	CertificateValid  bool   `json:"certificate_valid"`
	PolicyAllowed     bool   `json:"policy_allowed"`
	AuthMethod        string `json:"auth_method"`
	SensitiveResource bool   `json:"sensitive_resource"`
	RecentDenials     int    `json:"recent_denials"`
}

func (a *API) handleSecurityReplay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	var req SecurityReplayRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil { writeError(w, http.StatusBadRequest, err.Error()); return }
	if req.AuthMethod == "" { req.AuthMethod = "mtls" }
	result := a.riskEngine.Evaluate(risk.Context{Subject: req.Subject, Authenticated: req.Authenticated, PostureOK: req.PostureOK, CertificateValid: req.CertificateValid, PolicyAllowed: req.PolicyAllowed, AuthMethod: req.AuthMethod, SensitiveResource: req.SensitiveResource, RecentDenials: req.RecentDenials})

	allowed := result.Decision == risk.Allow
	a.accessLog.Log(logging.Entry{
		Source: "SIMULATION", Subject: req.Subject, Method: "SIMULATE", Path: "security-lab", RemoteAddr: "admin", Allowed: allowed,
		Reason: "security lab decision replay", AuthMethod: req.AuthMethod, RiskScore: result.Score, RiskAction: string(result.Decision), RiskReasons: result.Reasons,
		LatencyMs: 0, StatusCode: 200,
	})
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"input": req, "result": result})
}

func (a *API) handleRotationStatus(w http.ResponseWriter, r *http.Request) {
	if a.rotator == nil { _ = json.NewEncoder(w).Encode(map[string]string{"source": "disabled"}); return }
	_ = json.NewEncoder(w).Encode(a.rotator.Status())
}

func (a *API) handleRotateNow(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { w.WriteHeader(http.StatusMethodNotAllowed); return }
	if a.rotator == nil { writeError(w, http.StatusBadRequest, "rotation is not enabled on this proxy"); return }
	if err := a.rotator.RotateNow(context.Background()); err != nil { writeError(w, http.StatusConflict, err.Error()); return }
	status := a.rotator.Status()
	a.accessLog.Log(logging.Entry{Source: "SYSTEM", Subject: "system", Method: "ROTATE", Path: "certificate", RemoteAddr: "admin", Allowed: true, Reason: "certificate rotated successfully", AuthMethod: "admin", RiskAction: "ALLOW", StatusCode: http.StatusOK})
	_ = json.NewEncoder(w).Encode(status)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

var _ = time.Second
