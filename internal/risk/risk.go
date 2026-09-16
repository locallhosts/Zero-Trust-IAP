// Package risk implements adaptive request risk scoring for the IAP.
//
// The engine turns existing zero-trust signals into an explainable decision:
// ALLOW, STEP_UP, DENY, or QUARANTINE. It intentionally has no network or
// authentication dependencies so the policy/proxy layers can feed it trusted
// facts without creating package cycles.
package risk

import (
	"fmt"
	"sync"
	"time"
)

// Decision is the adaptive authorization outcome.
type Decision string

const (
	Allow      Decision = "ALLOW"
	StepUp     Decision = "STEP_UP"
	Deny       Decision = "DENY"
	Quarantine Decision = "QUARANTINE"
)

// Context contains signals already established by the IAP request pipeline.
type Context struct {
	Subject           string
	Authenticated     bool
	PostureOK         bool
	CertificateValid  bool
	PolicyAllowed     bool
	AuthMethod        string
	SensitiveResource bool
	RecentDenials     int
}

// Result is deliberately explainable so operators can understand why a
// request was escalated rather than receiving an opaque numeric score.
type Result struct {
	Score    int      `json:"score"`
	Decision Decision `json:"decision"`
	Reasons  []string `json:"reasons"`
}

// Engine contains thresholds for adaptive decisions.
type Engine struct {
	StepUpThreshold     int
	DenyThreshold       int
	QuarantineThreshold int
}

// NewEngine returns conservative defaults suitable for the proxy path.
func NewEngine() *Engine {
	return &Engine{
		StepUpThreshold:     30,
		DenyThreshold:       50,
		QuarantineThreshold: 70,
	}
}

// Evaluate calculates a bounded risk score from request facts. Each reason
// maps to a concrete signal so the result can be audited or replayed.
func (e *Engine) Evaluate(c Context) Result {
	score := 0
	reasons := make([]string, 0, 6)

	if !c.Authenticated {
		score += 40
		reasons = append(reasons, "request is not authenticated")
	}
	if !c.CertificateValid && c.AuthMethod == "mtls" {
		score += 25
		reasons = append(reasons, "mTLS certificate is not valid")
	}
	if !c.PostureOK {
		score += 25
		reasons = append(reasons, "device posture is missing, stale, or unhealthy")
	}
	if !c.PolicyAllowed {
		score += 35
		reasons = append(reasons, "policy engine denied the request")
	}
	if c.SensitiveResource {
		score += 15
		reasons = append(reasons, "sensitive resource requested")
	}
	if c.AuthMethod == "jwt" {
		score += 5
		reasons = append(reasons, "JWT fallback authentication used")
	}
	if c.RecentDenials > 0 {
		penalty := c.RecentDenials * 10
		if penalty > 30 {
			penalty = 30
		}
		score += penalty
		reasons = append(reasons, fmt.Sprintf("%d recent access denials", c.RecentDenials))
	}

	if score > 100 {
		score = 100
	}

	decision := Allow
	switch {
	case score >= e.QuarantineThreshold:
		decision = Quarantine
	case score >= e.DenyThreshold:
		decision = Deny
	case score >= e.StepUpThreshold:
		decision = StepUp
	}

	if len(reasons) == 0 {
		reasons = append(reasons, "no elevated risk signals")
	}
	return Result{Score: score, Decision: decision, Reasons: reasons}
}

// QuarantineStore is a concurrency-safe in-memory quarantine registry. An
// expiry prevents a transient incident from becoming permanent state.
type QuarantineStore struct {
	mu      sync.RWMutex
	entries map[string]quarantineEntry
}

type quarantineEntry struct {
	Until  time.Time
	Reason string
}

func NewQuarantineStore() *QuarantineStore {
	return &QuarantineStore{entries: make(map[string]quarantineEntry)}
}

// Put quarantines an identity for duration. A non-positive duration is
// rejected so callers cannot accidentally create an already-expired entry.
func (q *QuarantineStore) Put(subject, reason string, duration time.Duration) bool {
	if subject == "" || duration <= 0 {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.entries[subject] = quarantineEntry{Until: time.Now().Add(duration), Reason: reason}
	return true
}

// IsQuarantined reports active quarantine state and automatically removes
// expired entries.
func (q *QuarantineStore) IsQuarantined(subject string) (bool, string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	entry, ok := q.entries[subject]
	if !ok {
		return false, ""
	}
	if time.Now().After(entry.Until) {
		delete(q.entries, subject)
		return false, ""
	}
	return true, entry.Reason
}

// Release removes an identity from quarantine and reports whether it existed.
func (q *QuarantineStore) Release(subject string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if _, ok := q.entries[subject]; !ok {
		return false
	}
	delete(q.entries, subject)
	return true
}
