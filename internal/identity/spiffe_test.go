package identity

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"
)

func TestParseSPIFFEID(t *testing.T) {
	id, err := ParseSPIFFEID("spiffe://iap.local/team/engineering/alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id.TrustDomain != "iap.local" {
		t.Errorf("expected trust domain iap.local, got %q", id.TrustDomain)
	}
	if id.Path != "/team/engineering/alice" {
		t.Errorf("expected path /team/engineering/alice, got %q", id.Path)
	}
	if id.String() != "spiffe://iap.local/team/engineering/alice" {
		t.Errorf("String() roundtrip failed: got %q", id.String())
	}
}

func TestParseSPIFFEID_RejectsNonSpiffeScheme(t *testing.T) {
	_, err := ParseSPIFFEID("https://iap.local/team/engineering/alice")
	if err == nil {
		t.Fatal("expected error for non-spiffe:// scheme, got nil")
	}
}

// makeCert builds a minimal self-signed cert with the given SPIFFE URI SAN
// and validity window, for exercising Verifier without needing real
// openssl-generated fixtures on disk.
func makeCert(t *testing.T, spiffeURI string, notBefore, notAfter time.Time) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	if spiffeURI != "" {
		u, err := url.Parse(spiffeURI)
		if err != nil {
			t.Fatalf("parse test URI: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestVerifier_AcceptsValidFreshSVID(t *testing.T) {
	v := NewVerifier(time.Hour, "iap.local")
	cert := makeCert(t, "spiffe://iap.local/team/engineering/alice", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	vid, err := v.Verify(cert)
	if err != nil {
		t.Fatalf("expected valid SVID to pass, got error: %v", err)
	}
	if vid.SPIFFEID.String() != "spiffe://iap.local/team/engineering/alice" {
		t.Errorf("unexpected SPIFFE ID: %s", vid.SPIFFEID.String())
	}
}

func TestVerifier_RejectsUntrustedDomain(t *testing.T) {
	v := NewVerifier(time.Hour, "iap.local")
	cert := makeCert(t, "spiffe://evil.example/team/engineering/alice", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if _, err := v.Verify(cert); err == nil {
		t.Fatal("expected error for untrusted domain, got nil")
	}
}

func TestVerifier_RejectsExpiredCert(t *testing.T) {
	v := NewVerifier(time.Hour, "iap.local")
	cert := makeCert(t, "spiffe://iap.local/x", time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	if _, err := v.Verify(cert); err == nil {
		t.Fatal("expected error for expired cert, got nil")
	}
}

func TestVerifier_RejectsStaleSVIDOlderThanMaxAge(t *testing.T) {
	v := NewVerifier(30*time.Minute, "iap.local")
	// Issued 2h ago but still technically not-expired (NotAfter far future)
	// — should still be rejected because it's older than MaxCertAge.
	cert := makeCert(t, "spiffe://iap.local/x", time.Now().Add(-2*time.Hour), time.Now().Add(24*time.Hour))
	if _, err := v.Verify(cert); err == nil {
		t.Fatal("expected error for stale SVID beyond MaxCertAge, got nil")
	}
}

func TestVerifier_RejectsCertWithNoSPIFFEID(t *testing.T) {
	v := NewVerifier(time.Hour, "iap.local")
	cert := makeCert(t, "", time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	if _, err := v.Verify(cert); err != ErrNoSPIFFEID {
		t.Fatalf("expected ErrNoSPIFFEID, got %v", err)
	}
}
