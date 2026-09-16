// Package identity implements SPIFFE-style workload identity verification.
//
// In a full SPIRE deployment, workloads fetch X.509-SVIDs (SPIFFE Verifiable
// Identity Documents) from a local SPIRE Agent over the Workload API (a Unix
// domain socket). The SVID is a short-lived X.509 certificate whose SAN
// contains a URI of the form:
//
//	spiffe://<trust-domain>/<path>
//
// This package implements the verification side of that contract: given a
// peer certificate presented over mTLS, extract its SPIFFE ID, validate it
// against the configured trust domain(s), and check certificate freshness
// (SPIRE issues certs with TTLs typically in the minutes-to-hours range,
// which is what makes "short-lived" identity meaningful).
//
// It is intentionally decoupled from any specific SPIRE SDK/transport so the
// proxy can run standalone (certs minted by the bundled Vault PKI engine or
// scripts/generate-certs.sh) or, in production, be pointed at a real SPIRE
// Agent's Workload API by swapping the Source implementation.
package identity

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// SPIFFEID is a parsed spiffe://trust-domain/path identifier.
type SPIFFEID struct {
	TrustDomain string
	Path        string
}

func (id SPIFFEID) String() string {
	return fmt.Sprintf("spiffe://%s%s", id.TrustDomain, id.Path)
}

// ErrNoSPIFFEID is returned when a certificate has no SPIFFE URI SAN.
var ErrNoSPIFFEID = errors.New("identity: certificate contains no SPIFFE URI SAN")

// ParseSPIFFEID parses a spiffe:// URI string into its components.
func ParseSPIFFEID(raw string) (SPIFFEID, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return SPIFFEID{}, fmt.Errorf("identity: invalid SPIFFE URI %q: %w", raw, err)
	}
	if u.Scheme != "spiffe" {
		return SPIFFEID{}, fmt.Errorf("identity: URI %q is not a spiffe:// URI", raw)
	}
	if u.Host == "" {
		return SPIFFEID{}, fmt.Errorf("identity: SPIFFE URI %q missing trust domain", raw)
	}
	return SPIFFEID{TrustDomain: u.Host, Path: u.Path}, nil
}

// ExtractSPIFFEID pulls the first spiffe:// URI SAN out of a leaf certificate.
func ExtractSPIFFEID(cert *x509.Certificate) (SPIFFEID, error) {
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" {
			return SPIFFEID{TrustDomain: u.Host, Path: u.Path}, nil
		}
	}
	return SPIFFEID{}, ErrNoSPIFFEID
}

// Verifier validates the SVID (X.509 cert chain + embedded SPIFFE ID)
// presented by a client during the mTLS handshake.
type Verifier struct {
	// TrustDomains is the set of trust domains this proxy accepts. In a
	// multi-tenant / federated setup this can contain more than one.
	TrustDomains map[string]bool

	// MaxCertAge caps how old an accepted SVID's NotBefore may be. Real
	// SPIRE SVIDs are short-lived (default ~1h); this guards against a
	// stale/leaked cert being replayed long after issuance even if it's
	// still technically within NotAfter.
	MaxCertAge time.Duration
}

// NewVerifier builds a Verifier for the given trust domains.
func NewVerifier(maxCertAge time.Duration, trustDomains ...string) *Verifier {
	td := make(map[string]bool, len(trustDomains))
	for _, d := range trustDomains {
		td[strings.TrimSuffix(d, "/")] = true
	}
	return &Verifier{TrustDomains: td, MaxCertAge: maxCertAge}
}

// VerifiedIdentity is the result of a successful SVID verification.
type VerifiedIdentity struct {
	SPIFFEID  SPIFFEID
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
}

// Verify checks the leaf certificate's SPIFFE ID against policy: trust
// domain membership and SVID freshness. TLS chain-of-trust validation
// (signature, CA, expiry) is already handled by crypto/tls during the
// handshake via tls.Config.ClientCAs; this function adds the SPIFFE-specific
// checks on top of that.
func (v *Verifier) Verify(cert *x509.Certificate) (*VerifiedIdentity, error) {
	id, err := ExtractSPIFFEID(cert)
	if err != nil {
		return nil, err
	}
	if !v.TrustDomains[id.TrustDomain] {
		return nil, fmt.Errorf("identity: trust domain %q is not trusted (got SPIFFE ID %s)", id.TrustDomain, id.String())
	}
	now := time.Now()
	if v.MaxCertAge > 0 && now.Sub(cert.NotBefore) > v.MaxCertAge {
		return nil, fmt.Errorf("identity: SVID %s is older than max allowed age %s (issued %s)", id.String(), v.MaxCertAge, cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return nil, fmt.Errorf("identity: SVID %s expired at %s", id.String(), cert.NotAfter)
	}
	if now.Before(cert.NotBefore) {
		return nil, fmt.Errorf("identity: SVID %s not yet valid (NotBefore %s)", id.String(), cert.NotBefore)
	}
	return &VerifiedIdentity{
		SPIFFEID:  id,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Serial:    cert.SerialNumber.String(),
	}, nil
}
