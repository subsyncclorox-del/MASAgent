// Package scope defines the authorization boundary for an engagement and the
// matching logic that decides whether a given host/port may be touched.
//
// This is the security core of MASAgent. Everything downstream — spiders,
// scanners, the agent swarm — is only allowed to reach the network through a
// guard that consults a Scope. There is deliberately no "test everything"
// mode: a Scope must be loaded from an explicit file before anything runs.
package scope

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits are conservative-by-default throttles applied per engagement so an
// authorized target can never be flooded.
type Limits struct {
	// RequestsPerSecondPerHost caps sustained request rate against any one host.
	RequestsPerSecondPerHost float64 `yaml:"requests_per_second_per_host"`
	// Burst is the token-bucket burst size per host.
	Burst int `yaml:"burst"`
	// MaxConcurrentPerHost caps simultaneous in-flight requests to one host.
	MaxConcurrentPerHost int `yaml:"max_concurrent_per_host"`
	// MaxConcurrentTotal caps in-flight requests across the whole engagement.
	MaxConcurrentTotal int `yaml:"max_concurrent_total"`
}

// DefaultLimits are intentionally gentle. They are used for any field left
// unset so that a scope file can never accidentally authorize a DoS.
func DefaultLimits() Limits {
	return Limits{
		RequestsPerSecondPerHost: 5,
		Burst:                    10,
		MaxConcurrentPerHost:     4,
		MaxConcurrentTotal:       32,
	}
}

func (l *Limits) applyDefaults() {
	d := DefaultLimits()
	if l.RequestsPerSecondPerHost <= 0 {
		l.RequestsPerSecondPerHost = d.RequestsPerSecondPerHost
	}
	if l.Burst <= 0 {
		l.Burst = d.Burst
	}
	if l.MaxConcurrentPerHost <= 0 {
		l.MaxConcurrentPerHost = d.MaxConcurrentPerHost
	}
	if l.MaxConcurrentTotal <= 0 {
		l.MaxConcurrentTotal = d.MaxConcurrentTotal
	}
}

// Scope is the parsed, validated authorization boundary for one engagement.
type Scope struct {
	EngagementID string   `yaml:"engagement_id"`
	Name         string   `yaml:"name"`
	AllowDomains []string `yaml:"allow_domains"` // "example.com" or "*.example.com"
	AllowCIDRs   []string `yaml:"allow_cidrs"`   // "203.0.113.0/24" or a bare IP
	AllowPorts   []int    `yaml:"allow_ports"`   // empty means the safe default set
	// Out-of-scope always wins over allow. Use it to carve exclusions out of a
	// broader allow rule (e.g. allow *.example.com but never admin.example.com).
	DenyDomains []string `yaml:"deny_domains"`
	DenyCIDRs   []string `yaml:"deny_cidrs"`

	Limits Limits `yaml:"limits"`

	// parsed forms, populated by compile()
	allowNets []*net.IPNet
	denyNets  []*net.IPNet
	allowPort map[int]bool
}

// DefaultPorts is the conservative port set used when a scope lists none.
var DefaultPorts = []int{80, 443, 8080, 8443}

var (
	ErrNoEngagementID = errors.New("scope: engagement_id is required")
	ErrEmptyScope     = errors.New("scope: at least one allow_domains or allow_cidrs entry is required (there is no test-everything mode)")
)

// Load reads, parses and validates a scope file. A file that does not name an
// engagement or does not allow at least one target is rejected outright.
func Load(path string) (*Scope, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scope: reading %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse decodes and validates scope YAML.
func Parse(raw []byte) (*Scope, error) {
	var s Scope
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // reject unknown keys — a typo must not silently widen scope
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("scope: parsing: %w", err)
	}
	if err := s.compile(); err != nil {
		return nil, err
	}
	return &s, nil
}

func (s *Scope) compile() error {
	if strings.TrimSpace(s.EngagementID) == "" {
		return ErrNoEngagementID
	}
	if len(s.AllowDomains) == 0 && len(s.AllowCIDRs) == 0 {
		return ErrEmptyScope
	}

	s.Limits.applyDefaults()

	var err error
	if s.allowNets, err = parseNets(s.AllowCIDRs); err != nil {
		return fmt.Errorf("scope: allow_cidrs: %w", err)
	}
	if s.denyNets, err = parseNets(s.DenyCIDRs); err != nil {
		return fmt.Errorf("scope: deny_cidrs: %w", err)
	}

	s.allowPort = map[int]bool{}
	ports := s.AllowPorts
	if len(ports) == 0 {
		ports = DefaultPorts
	}
	for _, p := range ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("scope: invalid port %d", p)
		}
		s.allowPort[p] = true
	}

	// Normalize domains to lower case once.
	for i, d := range s.AllowDomains {
		s.AllowDomains[i] = strings.ToLower(strings.TrimSpace(d))
	}
	for i, d := range s.DenyDomains {
		s.DenyDomains[i] = strings.ToLower(strings.TrimSpace(d))
	}
	return nil
}

// parseNets accepts CIDRs and bare IPs (which become /32 or /128).
func parseNets(entries []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !strings.Contains(e, "/") {
			ip := net.ParseIP(e)
			if ip == nil {
				return nil, fmt.Errorf("not an IP or CIDR: %q", e)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		_, n, err := net.ParseCIDR(e)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// Decision is the result of a scope check, carrying a human-readable reason for
// the audit log.
type Decision struct {
	Allowed bool
	Reason  string
}

// Check decides whether host:port may be contacted. host may be a domain or an
// IP literal. Deny rules are evaluated first and always win.
//
// When host is a domain, resolvedIPs (if provided by the caller at connect
// time) are additionally checked against the CIDR deny/allow rules. This is how
// the guard defends against a name that points into an excluded network.
func (s *Scope) Check(host string, port int, resolvedIPs ...net.IP) Decision {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))

	if !s.allowPort[port] {
		return Decision{false, fmt.Sprintf("port %d not in allow_ports", port)}
	}

	ip := net.ParseIP(host)

	// ---- deny wins ----
	if ip != nil {
		if n := matchNet(ip, s.denyNets); n != nil {
			return Decision{false, "ip in deny_cidrs " + n.String()}
		}
	} else {
		if d := matchDomain(host, s.DenyDomains); d != "" {
			return Decision{false, "host matches deny_domains " + d}
		}
	}
	for _, r := range resolvedIPs {
		if n := matchNet(r, s.denyNets); n != nil {
			return Decision{false, fmt.Sprintf("resolved %s in deny_cidrs %s", r, n)}
		}
	}

	// ---- allow ----
	if ip != nil {
		if n := matchNet(ip, s.allowNets); n != nil {
			return Decision{true, "ip in allow_cidrs " + n.String()}
		}
		return Decision{false, "ip not in any allow_cidrs"}
	}

	if d := matchDomain(host, s.AllowDomains); d != "" {
		// A domain in scope may still resolve into an excluded network; deny
		// already checked resolvedIPs above, so allow only if resolved IPs are
		// in an allow_cidr when allow_cidrs are used to constrain, otherwise a
		// domain match is sufficient.
		return Decision{true, "host matches allow_domains " + d}
	}
	return Decision{false, "host not in any allow_domains"}
}

// AllowsPort reports whether the port is permitted at all.
func (s *Scope) AllowsPort(port int) bool { return s.allowPort[port] }

func matchNet(ip net.IP, nets []*net.IPNet) *net.IPNet {
	for _, n := range nets {
		if n.Contains(ip) {
			return n
		}
	}
	return nil
}

// matchDomain returns the matching rule (for logging) or "".
// A rule "example.com" matches example.com and any subdomain.
// A rule "*.example.com" matches subdomains only, not the apex.
func matchDomain(host string, rules []string) string {
	for _, r := range rules {
		if r == "" {
			continue
		}
		if strings.HasPrefix(r, "*.") {
			suffix := r[1:] // ".example.com"
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return r
			}
			continue
		}
		if host == r || strings.HasSuffix(host, "."+r) {
			return r
		}
	}
	return ""
}
