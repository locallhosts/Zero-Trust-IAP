package identity

// A minimal, dependency-free JWT verifier. Real deployments should prefer
// mTLS/SVIDs as the primary identity mechanism (see spiffe.go); JWTs are
// supported here as a fallback path for clients that can't yet do mTLS
// (e.g. a browser hitting the admin UI, or a third-party webhook), scoped
// down to read-only / low-privilege policy tiers by the policy engine.
//
// Supports HS256 (shared secret) and RS256 (RSA public key) — the two most
// common algorithms in practice. Deliberately does NOT support "none" or
// accept an algorithm the caller didn't explicitly ask for, which closes
// the classic JWT "alg confusion" vulnerability class.

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Claims struct {
	Subject   string         `json:"sub"`
	Issuer    string         `json:"iss"`
	Audience  string         `json:"aud"`
	ExpiresAt int64          `json:"exp"`
	IssuedAt  int64          `json:"iat"`
	NotBefore int64          `json:"nbf,omitempty"`
	Extra     map[string]any `json:"-"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Algorithm identifies a supported JWT signing algorithm.
type Algorithm string

const (
	HS256 Algorithm = "HS256"
	RS256 Algorithm = "RS256"
)

// JWTVerifier validates JWTs against a single configured algorithm + key.
// Construct one verifier per accepted algorithm/key if you need to accept
// more than one (e.g. during key rotation, accept old+new for a window).
type JWTVerifier struct {
	Algorithm    Algorithm
	HMACSecret   []byte
	RSAPublicKey *rsa.PublicKey
	ExpectedAud  string
	ExpectedIss  string
	ClockSkew    time.Duration
}

// NewHS256Verifier builds a verifier for HMAC-SHA256-signed tokens.
func NewHS256Verifier(secret []byte, issuer, audience string) *JWTVerifier {
	return &JWTVerifier{Algorithm: HS256, HMACSecret: secret, ExpectedIss: issuer, ExpectedAud: audience, ClockSkew: 30 * time.Second}
}

// NewRS256VerifierFromPEM builds a verifier for RSA-SHA256-signed tokens
// from a PEM-encoded RSA public key (e.g. exported from Vault's PKI engine
// or a JWKS fetched at startup).
func NewRS256VerifierFromPEM(pemBytes []byte, issuer, audience string) (*JWTVerifier, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("identity: failed to decode PEM public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("identity: parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("identity: public key is not RSA")
	}
	return &JWTVerifier{Algorithm: RS256, RSAPublicKey: rsaPub, ExpectedIss: issuer, ExpectedAud: audience, ClockSkew: 30 * time.Second}, nil
}

// Verify parses and validates a compact-serialized JWT string, returning
// its claims on success.
func (v *JWTVerifier) Verify(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("identity: malformed JWT (expected 3 segments)")
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, fmt.Errorf("identity: decode header: %w", err)
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, fmt.Errorf("identity: parse header: %w", err)
	}
	if Algorithm(h.Alg) != v.Algorithm {
		return nil, fmt.Errorf("identity: unexpected alg %q (verifier configured for %q)", h.Alg, v.Algorithm)
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("identity: decode signature: %w", err)
	}
	signingInput := headerB64 + "." + payloadB64

	switch v.Algorithm {
	case HS256:
		mac := hmac.New(sha256.New, v.HMACSecret)
		mac.Write([]byte(signingInput))
		expected := mac.Sum(nil)
		if subtle.ConstantTimeCompare(expected, sig) != 1 {
			return nil, errors.New("identity: HMAC signature verification failed")
		}
	case RS256:
		if v.RSAPublicKey == nil {
			return nil, errors.New("identity: no RSA public key configured")
		}
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(v.RSAPublicKey, crypto.SHA256, digest[:], sig); err != nil {
			return nil, fmt.Errorf("identity: RSA signature verification failed: %w", err)
		}
	default:
		return nil, fmt.Errorf("identity: unsupported algorithm %q", v.Algorithm)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("identity: decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("identity: parse claims: %w", err)
	}
	var raw map[string]any
	_ = json.Unmarshal(payloadJSON, &raw)
	claims.Extra = raw

	now := time.Now()
	if claims.ExpiresAt != 0 && now.After(time.Unix(claims.ExpiresAt, 0).Add(v.ClockSkew)) {
		return nil, fmt.Errorf("identity: token expired at %s", time.Unix(claims.ExpiresAt, 0))
	}
	if claims.NotBefore != 0 && now.Before(time.Unix(claims.NotBefore, 0).Add(-v.ClockSkew)) {
		return nil, fmt.Errorf("identity: token not valid yet (nbf %s)", time.Unix(claims.NotBefore, 0))
	}
	if v.ExpectedIss != "" && claims.Issuer != v.ExpectedIss {
		return nil, fmt.Errorf("identity: unexpected issuer %q", claims.Issuer)
	}
	if v.ExpectedAud != "" && claims.Audience != v.ExpectedAud {
		return nil, fmt.Errorf("identity: unexpected audience %q", claims.Audience)
	}

	return &claims, nil
}

// SignHS256 is a small helper used by tests/scripts to mint demo tokens
// without pulling in an external JWT library. Not intended for production
// issuance — real tokens should come from a proper IdP/OIDC provider.
func SignHS256(secret []byte, claims Claims) (string, error) {
	h := header{Alg: string(HS256), Typ: "JWT"}
	headerJSON, err := json.Marshal(h)
	if err != nil {
		return "", err
	}
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

var _ = rand.Reader // keep crypto/rand import available for future key-gen helpers
