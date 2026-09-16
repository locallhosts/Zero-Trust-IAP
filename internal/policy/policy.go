// Package policy implements the IAP's access-control decision point.
//
// A Policy binds a "who" (identity matcher) to a "what" (resource matcher)
// plus additional conditions (required device posture). The Engine
// evaluates every request against the loaded policy set and returns an
// explicit ALLOW or DENY with a reason, which is what gets written to the
// access log — "deny by default, allow explicitly, always log why" is the
// core zero-trust decision rule this package encodes.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"regexp"
	"sync"
	"time"
)

// Decision is the outcome of evaluating a request against the policy set.
type Decision struct {
	Allowed   bool   `json:"allowed"`
	Reason    string `json:"reason"`
	PolicyID  string `json:"policy_id,omitempty"`
	MatchedBy string `json:"matched_by,omitempty"`
}

// PostureRequirement expresses minimum device posture needed for a policy
// to match. Empty/zero fields mean "no requirement."
type PostureRequirement struct {
	RequireDiskEncryption bool   `json:"require_disk_encryption,omitempty"`
	RequireEDR            bool   `json:"require_edr,omitempty"`
	MinPatchLevel         string `json:"min_patch_level,omitempty"` // simple lexical/date compare, e.g. "2026-08-01"
}

// Policy is a single access-control rule.
type Policy struct {
	ID       string `json:"id"`
	Describe string `json:"describe"`
	// Subjects: SPIFFE IDs or JWT subjects allowed to match. Supports "*"
	// wildcard and simple prefix matching via trailing "*".
	Subjects []string `json:"subjects"`
	// PathPrefixes: URL path prefixes this policy governs.
	PathPrefixes []string `json:"path_prefixes"`
	// Methods: HTTP methods allowed; empty means all methods.
	Methods []string           `json:"methods,omitempty"`
	Posture PostureRequirement `json:"posture,omitempty"`
	Enabled bool               `json:"enabled"`
}

// Request is the subset of an incoming request the policy engine needs.
type Request struct {
	Subject      string // SPIFFE ID string or JWT subject
	Path         string
	Method       string
	PostureOK    bool
	PostureFacts PostureFacts
}

// PostureFacts carries the device posture signals reported by the agent.
type PostureFacts struct {
	DiskEncrypted bool      `json:"disk_encrypted"`
	EDRRunning    bool      `json:"edr_running"`
	PatchLevel    string    `json:"patch_level"`
	ReportedAt    time.Time `json:"reported_at"`
}

// Engine holds the active policy set and evaluates requests against it.
type Engine struct {
	mu       sync.RWMutex
	policies []Policy
	path     string // backing file, for persistence on Update
}

// NewEngine constructs an engine from an initial policy set.
func NewEngine(initial []Policy) *Engine {
	return &Engine{policies: initial}
}

// LoadFromFile reads a JSON policy file (see configs/policy.example.json)
// and returns an Engine backed by it. Subsequent calls to Save() persist
// back to the same path, which is what the admin UI's policy editor uses.
func LoadFromFile(p string) (*Engine, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", p, err)
	}
	var policies []Policy
	if err := json.Unmarshal(b, &policies); err != nil {
		return nil, fmt.Errorf("policy: parse %s: %w", p, err)
	}
	return &Engine{policies: policies, path: p}, nil
}

// Save persists the current policy set back to the backing file, if any.
func (e *Engine) Save() error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.path == "" {
		return fmt.Errorf("policy: engine has no backing file")
	}
	b, err := json.MarshalIndent(e.policies, "", "  ")
	if err != nil {
		return err
	}
	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, e.path)
}

// All returns a copy of the current policy set.
func (e *Engine) All() []Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Policy, len(e.policies))
	copy(out, e.policies)
	return out
}

// Replace atomically swaps in a new policy set (used by the admin API).
func (e *Engine) Replace(policies []Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.policies = policies
}

// Upsert adds or updates a single policy by ID.
func (e *Engine) Upsert(p Policy) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, existing := range e.policies {
		if existing.ID == p.ID {
			e.policies[i] = p
			return
		}
	}
	e.policies = append(e.policies, p)
}

// Delete removes a policy by ID.
func (e *Engine) Delete(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, existing := range e.policies {
		if existing.ID == id {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return true
		}
	}
	return false
}

var wildcardSuffix = regexp.MustCompile(`\*$`)

func subjectMatches(pattern, subject string) bool {
	if pattern == "*" {
		return true
	}
	if wildcardSuffix.MatchString(pattern) {
		prefix := pattern[:len(pattern)-1]
		return len(subject) >= len(prefix) && subject[:len(prefix)] == prefix
	}
	return pattern == subject
}

func methodMatches(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	for _, m := range methods {
		if m == method {
			return true
		}
	}
	return false
}

func postureMatches(req PostureRequirement, facts PostureFacts) (bool, string) {
	if req.RequireDiskEncryption && !facts.DiskEncrypted {
		return false, "disk encryption required but not detected"
	}
	if req.RequireEDR && !facts.EDRRunning {
		return false, "EDR required but not running"
	}
	if req.MinPatchLevel != "" && facts.PatchLevel < req.MinPatchLevel {
		return false, fmt.Sprintf("patch level %q older than required %q", facts.PatchLevel, req.MinPatchLevel)
	}
	return true, ""
}

// Evaluate runs "deny by default, first-matching-policy-wins" evaluation.
// Policies are checked in slice order; disabled policies are skipped.
func (e *Engine) Evaluate(r Request) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for _, p := range e.policies {
		if !p.Enabled {
			continue
		}
		subjectOK := false
		for _, s := range p.Subjects {
			if subjectMatches(s, r.Subject) {
				subjectOK = true
				break
			}
		}
		if !subjectOK {
			continue
		}
		pathOK := false
		var matchedPrefix string
		for _, prefix := range p.PathPrefixes {
			if pathHasPrefix(r.Path, prefix) {
				pathOK = true
				matchedPrefix = prefix
				break
			}
		}
		if !pathOK {
			continue
		}
		if !methodMatches(p.Methods, r.Method) {
			continue
		}
		if ok, reason := postureMatches(p.Posture, r.PostureFacts); !ok {
			return Decision{
				Allowed:  false,
				Reason:   fmt.Sprintf("policy %q matched identity/path but denied on posture: %s", p.ID, reason),
				PolicyID: p.ID,
			}
		}
		return Decision{
			Allowed:   true,
			Reason:    fmt.Sprintf("matched policy %q (subject pattern, path prefix %q)", p.ID, matchedPrefix),
			PolicyID:  p.ID,
			MatchedBy: matchedPrefix,
		}
	}
	return Decision{Allowed: false, Reason: "no policy matched subject/path/method (deny by default)"}
}

func pathHasPrefix(p, prefix string) bool {
	cp := path.Clean(p)
	cprefix := path.Clean(prefix)
	if cprefix == "/" {
		return true
	}
	return cp == cprefix || (len(cp) > len(cprefix) && cp[:len(cprefix)] == cprefix && cp[len(cprefix)] == '/')
}
