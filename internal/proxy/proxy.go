// Package proxy implements the Identity-Aware Proxy's request path: every
// inbound request is TLS-terminated, its client identity is verified
// (mTLS/SPIFFE first, JWT as a fallback), device posture is checked, the
// policy engine renders an allow/deny decision, the decision is logged,
// and only on ALLOW is the request forwarded upstream.
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
)

// Server wires together identity verification, posture checks, policy
// evaluation, and forwarding into a single http.Handler.
type Server struct {
	cfg            *Config
	spiffeVerifier *identity.Verifier
	jwtVerifier    *identity.JWTVerifier
	policyEngine   *policy.Engine
	postureClient  *posture.Client
	accessLog      *logging.Logger
	reverseProxy   *httputil.ReverseProxy
	rotator        *Rotator
}

// NewServer builds a Server from config and its collaborators.
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

// authResult captures how a request authenticated, for logging/policy.
type authResult struct {
	subject    string
	spiffeID   string
	authMethod string
}

func (s *Server) authenticate(r *http.Request) (*authResult, error) {
	// Preferred path: mTLS client certificate carrying a SPIFFE SVID.
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 && s.spiffeVerifier != nil {
		leaf := r.TLS.PeerCertificates[0]
		vid, err := s.spiffeVerifier.Verify(leaf)
		if err != nil {
			return nil, err
		}
		return &authResult{subject: vid.SPIFFEID.String(), spiffeID: vid.SPIFFEID.String(), authMethod: "mtls"}, nil
	}

	// Fallback path: bearer JWT.
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

	// Strip any client-supplied identity headers immediately, before
	// authentication or forwarding, so a client can never spoof the
	// trusted identity headers the backend app relies on.
	r.Header.Del("X-Forwarded-Identity")
	r.Header.Del("X-Forwarded-Policy")

	auth, err := s.authenticate(r)
	if err != nil {
		s.deny(w, r, "", "", "none", start, "authentication failed: "+err.Error(), "")
		return
	}

	// Device posture: fail closed if enabled and unreachable/stale.
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

	if !decision.Allowed {
		s.denyDecision(w, r, auth, start, decision)
		return
	}
	if s.postureClient != nil && !postureOK {
		s.deny(w, r, auth.subject, auth.spiffeID, auth.authMethod, start,
			"policy matched but device posture is missing or stale (failing closed)", decision.PolicyID)
		return
	}

	// ALLOW: attach trusted identity headers for the upstream app and forward.
	r.Header.Set("X-Forwarded-Identity", auth.subject)
	r.Header.Set("X-Forwarded-Policy", decision.PolicyID)

	rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
	s.reverseProxy.ServeHTTP(rec, r)

	s.accessLog.Log(logging.Entry{
		Timestamp:  start,
		Subject:    auth.subject,
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		Allowed:    true,
		Reason:     decision.Reason,
		PolicyID:   decision.PolicyID,
		AuthMethod: auth.authMethod,
		SPIFFEID:   auth.spiffeID,
		LatencyMs:  time.Since(start).Milliseconds(),
		StatusCode: rec.status,
	})
}

func (s *Server) denyDecision(w http.ResponseWriter, r *http.Request, auth *authResult, start time.Time, d policy.Decision) {
	s.deny(w, r, auth.subject, auth.spiffeID, auth.authMethod, start, d.Reason, d.PolicyID)
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, subject, spiffeID, authMethod string, start time.Time, reason, policyID string) {
	s.accessLog.Log(logging.Entry{
		Timestamp:  start,
		Subject:    subject,
		Method:     r.Method,
		Path:       r.URL.Path,
		RemoteAddr: r.RemoteAddr,
		Allowed:    false,
		Reason:     reason,
		PolicyID:   policyID,
		AuthMethod: authMethod,
		SPIFFEID:   spiffeID,
		LatencyMs:  time.Since(start).Milliseconds(),
		StatusCode: http.StatusForbidden,
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

// BuildTLSConfig constructs the server-side tls.Config requiring (but not
// yet fully verifying, beyond chain-of-trust) client certificates. Deep
// SPIFFE ID validation happens per-request in authenticate() above, since
// it needs to be logged/decisioned like any other policy check rather than
// hard-failing the TLS handshake with no audit trail.
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
		// If JWT fallback is disabled, mTLS is mandatory.
		clientAuth = tls.RequireAndVerifyClientCert
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   clientAuth,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// GetCertificate is used with tls.Config.GetCertificate so the server can
// hot-swap its leaf certificate after Vault-driven rotation without
// restarting the listener. See rotation.go.
func (r *Rotator) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.Current(), nil
}

var _ = context.Background
var _ = log.Println
