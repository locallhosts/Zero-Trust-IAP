package policy

import "testing"

func testEngine() *Engine {
	return NewEngine([]Policy{
		{
			ID:           "engineers",
			Subjects:     []string{"spiffe://iap.local/team/engineering/*"},
			PathPrefixes: []string{"/"},
			Posture:      PostureRequirement{RequireDiskEncryption: true},
			Enabled:      true,
		},
		{
			ID:           "contractors-dashboard",
			Subjects:     []string{"spiffe://iap.local/team/contractors/*"},
			PathPrefixes: []string{"/dashboard"},
			Methods:      []string{"GET"},
			Enabled:      true,
		},
		{
			ID:           "disabled-policy",
			Subjects:     []string{"*"},
			PathPrefixes: []string{"/"},
			Enabled:      false,
		},
	})
}

func TestEvaluate_AllowsMatchingEngineerWithGoodPosture(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{
		Subject: "spiffe://iap.local/team/engineering/alice",
		Path:    "/app",
		Method:  "GET",
		PostureFacts: PostureFacts{
			DiskEncrypted: true,
		},
	})
	if !d.Allowed {
		t.Fatalf("expected allow, got deny: %s", d.Reason)
	}
	if d.PolicyID != "engineers" {
		t.Fatalf("expected policy 'engineers', got %q", d.PolicyID)
	}
}

func TestEvaluate_DeniesOnBadPosture(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{
		Subject: "spiffe://iap.local/team/engineering/alice",
		Path:    "/app",
		Method:  "GET",
		PostureFacts: PostureFacts{
			DiskEncrypted: false,
		},
	})
	if d.Allowed {
		t.Fatalf("expected deny due to posture, got allow")
	}
}

func TestEvaluate_DeniesByDefaultWhenNoPolicyMatches(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{
		Subject: "spiffe://iap.local/team/unknown/eve",
		Path:    "/whatever",
		Method:  "GET",
	})
	if d.Allowed {
		t.Fatalf("expected deny by default, got allow")
	}
	if d.PolicyID != "" {
		t.Fatalf("expected no policy ID on default deny, got %q", d.PolicyID)
	}
}

func TestEvaluate_RespectsMethodRestriction(t *testing.T) {
	e := testEngine()
	d := e.Evaluate(Request{
		Subject: "spiffe://iap.local/team/contractors/bob",
		Path:    "/dashboard",
		Method:  "DELETE",
	})
	if d.Allowed {
		t.Fatalf("expected deny for DELETE method not in allowed list, got allow")
	}
}

func TestEvaluate_SkipsDisabledPolicies(t *testing.T) {
	e := testEngine()
	// The "disabled-policy" rule would match anything on "/", but it's
	// disabled, so a totally unrelated subject should still be denied.
	d := e.Evaluate(Request{
		Subject: "anyone",
		Path:    "/",
		Method:  "GET",
	})
	if d.Allowed {
		t.Fatalf("expected deny — matching policy is disabled, got allow via %q", d.PolicyID)
	}
}

func TestSubjectWildcardMatching(t *testing.T) {
	cases := []struct {
		pattern, subject string
		want             bool
	}{
		{"*", "anything", true},
		{"spiffe://iap.local/team/eng/*", "spiffe://iap.local/team/eng/alice", true},
		{"spiffe://iap.local/team/eng/*", "spiffe://iap.local/team/other/alice", false},
		{"spiffe://iap.local/team/eng/alice", "spiffe://iap.local/team/eng/alice", true},
		{"spiffe://iap.local/team/eng/alice", "spiffe://iap.local/team/eng/bob", false},
	}
	for _, c := range cases {
		got := subjectMatches(c.pattern, c.subject)
		if got != c.want {
			t.Errorf("subjectMatches(%q, %q) = %v, want %v", c.pattern, c.subject, got, c.want)
		}
	}
}

func TestUpsertAndDelete(t *testing.T) {
	e := NewEngine(nil)
	e.Upsert(Policy{ID: "a", Enabled: true, Subjects: []string{"*"}, PathPrefixes: []string{"/"}})
	if len(e.All()) != 1 {
		t.Fatalf("expected 1 policy after upsert, got %d", len(e.All()))
	}
	e.Upsert(Policy{ID: "a", Enabled: false, Subjects: []string{"*"}, PathPrefixes: []string{"/"}})
	if len(e.All()) != 1 {
		t.Fatalf("expected upsert to replace, got %d policies", len(e.All()))
	}
	if e.All()[0].Enabled {
		t.Fatalf("expected upsert to have updated Enabled to false")
	}
	if !e.Delete("a") {
		t.Fatalf("expected delete to succeed")
	}
	if len(e.All()) != 0 {
		t.Fatalf("expected 0 policies after delete, got %d", len(e.All()))
	}
	if e.Delete("nonexistent") {
		t.Fatalf("expected delete of nonexistent ID to return false")
	}
}

func TestPathHasPrefix(t *testing.T) {
	cases := []struct {
		path, prefix string
		want         bool
	}{
		{"/dashboard", "/dashboard", true},
		{"/dashboard/foo", "/dashboard", true},
		{"/dashboardxyz", "/dashboard", false},
		{"/", "/", true},
		{"/anything", "/", true},
	}
	for _, c := range cases {
		got := pathHasPrefix(c.path, c.prefix)
		if got != c.want {
			t.Errorf("pathHasPrefix(%q, %q) = %v, want %v", c.path, c.prefix, got, c.want)
		}
	}
}
