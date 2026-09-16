// Package proxy implements the Identity-Aware Proxy's request path: every
// inbound request is TLS-terminated, its client identity is verified,
// device posture is checked, policy is evaluated, adaptive risk is scored,
// and only an ALLOW reaches the upstream service.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"zero-trust-iap/internal/identity"
	"zero-trust-iap/internal/logging"
	"zero-trust-iap/internal/policy"
	"zero-trust-iap/internal/posture"
	"zero-trust-iap/internal/risk"
)

type Server struct {
	cfg            *Config
	spiffeVerifier *identity.Verifier
	jwtVerifier    *identity.JWTVerifier
	policyEngine   *policy.Engine
	postureClient  *posture.Client
	accessLog      *logging.Logger
	reverseProxy   *httputil.ReverseProxy
	rotator        *Rotator
	riskEngine     *risk.Engine
	quarantine     *risk.QuarantineStore
}

func NewServer(cfg *Config, policyEngine *policy.Engine, accessLog *logging.Logger, rotator *Rotator) (*Server, error) {
	backend, err := url.Parse(cfg.BackendURL)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(backend)

	s := &Server{
		cfg:          cfg,
		policyEngine: policyEngine,
		accessLog:    accessLog,
		reverseProxy: rp,
		rotator:      rotator,
		riskEngine:   risk.NewEngine(),
		quarantine:   risk.NewQuarantineStore(),
	}

	if cfg.TrustDomains != nil {
		s.spiffeVerifier = identity.NewVerifier(cfg.MaxSVIDAge, cfg.TrustDomains...)
	}
	if cfg.JWTEnabled {
		s.jwtVerifier = identity.NewHS256Verifier([]byte(cfg.JWTHMACSecret), cfg.JWTIssuer, cfg.JWTAudience)
	}
	if cfg.PostureEnabled {
		s.postureClient = posture.NewClient(cfg.PostureAgentURL)
	}

	return s, nil
}

type authResult struct {
	subject    string
	spiffeID   string
	authMethod string
}

func (s *Server) authenticate(r *http.Request) (*authResult, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && s.spiffeVerifier != nil {
		leaf := r.TLS.PeerCertificates[0]
		vid, err := s.spiffeVerifier.Verify(leaf)
		if err != nil {
			return nil, err
		}
		return &authResult{subject: vid.SPIFFEID.String(), spiffeID: vid.SPIFFEID.String(), authMethod: "mtls"}, nil
	}

	if s.jwtVerifier != nil {
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token := strings.TrimPrefix(authHeader, "Bearer ")
			claims, err := s.jwtVerifier.Verify(token)
			if err != nil {
				return nil, err
			}
			return &authResult{subject: claims.Subject, authMethod: "jwt"}, nil
		}
	}

	return nil, errNoCredentials
}

var errNoCredentials = &authError{"no valid mTLS certificate or bearer JWT presented"}

type authError struct{ msg string }

func (e *authError) Error() string { return e.msg }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()

	r.Header.Del("X-Forwarded-Identity")
	r.Header.Del("X-Forwarded-Policy")

	auth, err := s.authenticate(r)
	if err != nil {
		s.deny(w, r, "", "", "none", start, "authentication failed: "+err.Error(), "", risk.Result{Decision: risk.Deny})
		return
	}

	if quarantined, reason := s.quarantine.IsQuarantined(auth.subject); quarantined {
		s.deny(w, r, auth.subject, auth.spiffeID, auth.authMethod, start,
			"identity is quarantined: "+reason, "", risk.Result{Decision: risk.Quarantine, Score: 100, Reasons: []string{"identity is currently quarantined"}})
		return
	}

	postureFacts := policy.PostureFacts{}
	postureOK := true
	if s.postureClient != nil {
		deviceID := r.Header.Get("X-Device-Id")
		if deviceID == "" {
			deviceID = auth.subject
		}
		report, err := s.postureClient.Fetch(ctx, deviceID)
		if err != nil {
			postureOK = false
		} else if report.Stale(s.cfg.PostureMaxAge) {
			postureOK = false
		} else {
			postureFacts = policy.PostureFacts{
				DiskEncrypted: report.DiskEncrypted,
				EDRRunning:    report.EDRRunning,
				PatchLevel:    report.PatchLevel,
				ReportedAt:    report.CheckedAt,
			}
		}
	}

	decision := s.policyEngine.Evaluate(policy.Request{
		Subject:      auth.subject,
		Path:         r.URL.Path,
		Method:       r.Method,
		PostureOK:    postureOK,
		PostureFacts: postureFacts,
	})

	riskResult := s.riskEngine.Evaluate(risk.Context{
		Subject:           auth.subject,
		Authenticated:     true,
		PostureOK:         postureOK,
		CertificateValid:  auth.authMethod != "mtls" || auth.spiffeID != "",
		PolicyAllowed:     decision.Allowed,
		AuthMethod:        auth.authMethod,
		SensitiveResource: isSensitivePath(r.URL.Path),
		RecentDenials:     s.recentDenials(auth.subject),
	})

	if riskResult.Decision == risk.Quarantine {
		s.quarantine.Put(auth.subject, strings.Join(riskResult.Reasons, "; "), 15*time.Minute)
		s.deny(w, r, auth.subject, auth.spiffeID, auth.authMethod, start,
			"adaptive risk threshold exceeded; identity quarantined", decision.PolicyID, riskResult)
		return
	}
	if !decision.Allowed || riskResult.Decision == risk.Deny || riskResult.Decision == risk.StepUp {
		reason := decision.Reason
		if riskResult.Decision == risk.StepUp {
			reason = "adaptive risk requires step-up authentication: " + strings.Join(riskResult.Reasons, "; ")
		}
		s.deny(w, r, auth.subject, auth.spiffeID, auth.authMethod, start, reason, decision.PolicyID, riskResult)
		return
	}

	if s.postureClient != nil && !postureOK {
		s.deny(w, r, auth.subject, auth.spiffeID, auth.authMethod, start,
			"policy matched but device posture is missing or stale (failing closed)", decision.PolicyID, riskResult)
		return
	}

	r.Header.Set("X-Forwarded-Identity", auth.subject)
	r.Header.Set("X-Forwarded-Policy", decision.PolicyID)

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.reverseProxy.ServeHTTP(rec, r)

	s.accessLog.Log(logging.Entry{
		Timestamp:   start,
		Subject:     auth.subject,
		Method:      r.Method,
		Path:        r.URL.Path,
		RemoteAddr:  r.RemoteAddr,
		Allowed:     true,
		Reason:      decision.Reason,
		PolicyID:    decision.PolicyID,
		AuthMethod:  auth.authMethod,
		SPIFFEID:    auth.spiffeID,
		RiskScore:   riskResult.Score,
		RiskAction:  string(riskResult.Decision),
		RiskReasons: riskResult.Reasons,
		LatencyMs:   time.Since(start).Milliseconds(),
		StatusCode:  rec.status,
	})
}

func isSensitivePath(p string) bool {
	for _, prefix := range []string{"/admin", "/secrets", "/vault", "/internal"} {
		if p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func (s *Server) recentDenials(subject string) int {
	count := 0
	for _, entry := range s.accessLog.Recent(20) {
		if entry.Subject == subject && !entry.Allowed {
			count++
		}
	}
	return count
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, subject, spiffeID, authMethod string, start time.Time, reason, policyID string, riskResult risk.Result) {
	s.accessLog.Log(logging.Entry{
		Timestamp:   start,
		Subject:     subject,
		Method:      r.Method,
		Path:        r.URL.Path,
		RemoteAddr:  r.RemoteAddr,
		Allowed:     false,
		Reason:      reason,
		PolicyID:    policyID,
		AuthMethod:  authMethod,
		SPIFFEID:    spiffeID,
		RiskScore:   riskResult.Score,
		RiskAction:  string(riskResult.Decision),
		RiskReasons: riskResult.Reasons,
		LatencyMs:   time.Since(start).Milliseconds(),
		StatusCode:  http.StatusForbidden,
	})
	http.Error(w, "access denied", http.StatusForbidden)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func BuildTLSConfig(cfg *Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		return nil, err
	}

	caPool := x509.NewCertPool()
	caPEM, err := os.ReadFile(cfg.ClientCAFile)
	if err != nil {
		return nil, err
	}
	if !caPool.AppendCertsFromPEM(caPEM) {
		return nil, &authError{"failed to parse client CA bundle"}
	}

	clientAuth := tls.VerifyClientCertIfGiven
	if !cfg.JWTEnabled {
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

func (r *Rotator) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.Current(), nil
}

var _ = context.Background
var _ = log.Println
