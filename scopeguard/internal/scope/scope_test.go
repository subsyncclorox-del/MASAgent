package scope

import (
	"net"
	"testing"
)

func mustParse(t *testing.T, y string) *Scope {
	t.Helper()
	s, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return s
}

const sample = `
engagement_id: ENG-001
name: Example bounty
allow_domains:
  - example.com
  - "*.staging.example.com"
  - "*.lab.test"
allow_cidrs:
  - 203.0.113.0/24
allow_ports: [80, 443]
deny_domains:
  - admin.example.com
deny_cidrs:
  - 203.0.113.5/32
`

func TestRefusesEmptyScope(t *testing.T) {
	if _, err := Parse([]byte("engagement_id: X\n")); err != ErrEmptyScope {
		t.Fatalf("expected ErrEmptyScope, got %v", err)
	}
}

func TestRefusesNoEngagement(t *testing.T) {
	if _, err := Parse([]byte("allow_domains: [example.com]\n")); err != ErrNoEngagementID {
		t.Fatalf("expected ErrNoEngagementID, got %v", err)
	}
}

func TestRejectsUnknownKey(t *testing.T) {
	if _, err := Parse([]byte("engagement_id: X\nallow_domains: [a.com]\ntest_everything: true\n")); err == nil {
		t.Fatal("expected error on unknown key, got nil")
	}
}

func TestDomainMatching(t *testing.T) {
	s := mustParse(t, sample)
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"example.com", 443, true},
		{"www.example.com", 443, true},        // subdomain of apex rule
		{"api.staging.example.com", 443, true}, // wildcard
		{"staging.example.com", 443, true},     // covered by the example.com apex rule
		{"admin.example.com", 443, false},      // deny wins
		{"evil.com", 443, false},
		{"example.com", 22, false},             // port not allowed
		{"example.com.attacker.com", 443, false}, // suffix trick must not match
	}
	for _, c := range cases {
		got := s.Check(c.host, c.port).Allowed
		if got != c.want {
			t.Errorf("Check(%q,%d)=%v want %v", c.host, c.port, got, c.want)
		}
	}
	// A pure wildcard rule ("*.lab.test") must NOT match its own apex.
	if s.Check("lab.test", 443).Allowed {
		t.Error("lab.test (apex) must not match the *.lab.test wildcard")
	}
	if !s.Check("host.lab.test", 443).Allowed {
		t.Error("host.lab.test should match *.lab.test")
	}
}

func TestCIDRMatching(t *testing.T) {
	s := mustParse(t, sample)
	if !s.Check("203.0.113.10", 80).Allowed {
		t.Error("203.0.113.10 should be in scope")
	}
	if s.Check("203.0.113.5", 80).Allowed {
		t.Error("203.0.113.5 is denied by deny_cidrs")
	}
	if s.Check("198.51.100.1", 80).Allowed {
		t.Error("198.51.100.1 is out of scope")
	}
}

func TestResolvedIPDenied(t *testing.T) {
	s := mustParse(t, sample)
	// an in-scope domain that resolves into a denied network must be blocked
	d := s.Check("www.example.com", 443, net.ParseIP("203.0.113.5"))
	if d.Allowed {
		t.Errorf("domain resolving into deny_cidrs must be blocked, got %+v", d)
	}
}

func TestDefaultsApplied(t *testing.T) {
	s := mustParse(t, "engagement_id: X\nallow_domains: [a.com]\n")
	if !s.AllowsPort(443) || !s.AllowsPort(80) {
		t.Error("default ports should include 80 and 443")
	}
	if s.Limits.RequestsPerSecondPerHost <= 0 || s.Limits.MaxConcurrentPerHost <= 0 {
		t.Error("default limits should be positive")
	}
}
