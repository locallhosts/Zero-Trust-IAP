package identity

import (
	"testing"
	"time"
)

func TestSignAndVerifyHS256(t *testing.T) {
	secret := []byte("test-secret")
	claims := Claims{
		Subject:   "alice",
		Issuer:    "test-issuer",
		Audience:  "test-aud",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	tok, err := SignHS256(secret, claims)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	v := NewHS256Verifier(secret, "test-issuer", "test-aud")
	got, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if got.Subject != "alice" {
		t.Errorf("expected subject alice, got %q", got.Subject)
	}
}

func TestVerify_RejectsBadSignature(t *testing.T) {
	tok, _ := SignHS256([]byte("secret-a"), Claims{
		Subject: "alice", IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	v := NewHS256Verifier([]byte("secret-b"), "", "")
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected signature verification failure, got nil error")
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	secret := []byte("s")
	tok, _ := SignHS256(secret, Claims{
		Subject:   "alice",
		IssuedAt:  time.Now().Add(-2 * time.Hour).Unix(),
		ExpiresAt: time.Now().Add(-time.Hour).Unix(),
	})
	v := NewHS256Verifier(secret, "", "")
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected expiry error, got nil")
	}
}

func TestVerify_RejectsWrongAudience(t *testing.T) {
	secret := []byte("s")
	tok, _ := SignHS256(secret, Claims{
		Subject: "alice", Audience: "other-aud",
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	v := NewHS256Verifier(secret, "", "expected-aud")
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected audience mismatch error, got nil")
	}
}

func TestVerify_RejectsMalformedToken(t *testing.T) {
	v := NewHS256Verifier([]byte("s"), "", "")
	if _, err := v.Verify("not-a-jwt"); err == nil {
		t.Fatal("expected malformed token error, got nil")
	}
}

func TestVerify_RejectsAlgorithmMismatch(t *testing.T) {
	secret := []byte("s")
	tok, _ := SignHS256(secret, Claims{Subject: "alice", ExpiresAt: time.Now().Add(time.Hour).Unix()})
	v := &JWTVerifier{Algorithm: RS256} // configured for RS256, token is HS256
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected algorithm mismatch error, got nil")
	}
}
