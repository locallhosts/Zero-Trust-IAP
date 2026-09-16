package risk

import (
	"testing"
	"time"
)

func TestEvaluateEscalatesRepeatedSensitiveDenials(t *testing.T) {
	e := NewEngine()
	result := e.Evaluate(Context{
		Subject:           "spiffe://example.org/admin",
		Authenticated:     true,
		PostureOK:         true,
		CertificateValid:  true,
		PolicyAllowed:     false,
		AuthMethod:        "mtls",
		SensitiveResource: true,
		RecentDenials:     3,
	})
	if result.Decision != Quarantine {
		t.Fatalf("decision = %s, want %s (score=%d)", result.Decision, Quarantine, result.Score)
	}
	if result.Score < 70 {
		t.Fatalf("score = %d, want at least 70", result.Score)
	}
}

func TestEvaluateCleanRequestAllows(t *testing.T) {
	result := NewEngine().Evaluate(Context{
		Subject:          "spiffe://example.org/app",
		Authenticated:    true,
		PostureOK:        true,
		CertificateValid: true,
		PolicyAllowed:    true,
		AuthMethod:       "mtls",
	})
	if result.Decision != Allow {
		t.Fatalf("decision = %s, want %s", result.Decision, Allow)
	}
	if result.Score != 0 {
		t.Fatalf("score = %d, want 0", result.Score)
	}
}

func TestQuarantineStoreExpires(t *testing.T) {
	q := NewQuarantineStore()
	if !q.Put("alice", "risk threshold exceeded", 20*time.Millisecond) {
		t.Fatal("Put returned false")
	}
	if ok, _ := q.IsQuarantined("alice"); !ok {
		t.Fatal("identity should be quarantined")
	}
	time.Sleep(30 * time.Millisecond)
	if ok, _ := q.IsQuarantined("alice"); ok {
		t.Fatal("identity should have expired")
	}
}
