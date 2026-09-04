// Package detect is the deterministic detection engine: rule-based checks that
// run BEFORE any LLM reasoning. These are high-signal, low-false-positive
// findings (missing headers, exposed files, obvious misconfigurations) derived
// from evidence the target already returns. No guessing, no exploitation.
package detect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"

	"github.com/masagent/recon/internal/client"
	"github.com/masagent/recon/internal/fingerprint"
)

// Severity levels used across MASAgent.
type Severity string

const (
	Info     Severity = "info"
	Low      Severity = "low"
	Medium   Severity = "medium"
	High     Severity = "high"
	Critical Severity = "critical"
)

// Finding is one deterministic result. Evidence is what was observed; it is not
// a proof-of-concept — the PoC validator produces those later.
type Finding struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	URL      string   `json:"url"`
	Evidence string   `json:"evidence"`
	Class    string   `json:"class"`
}

// sensitivePaths are commonly-exposed files worth a low-noise probe. Each has a
// content signature so a catch-all 200 page does not become a false positive.
var sensitivePaths = []struct {
	path, title, class string
	sev                Severity
	// strong is true when the signature is specific enough to trust even on a
	// catch-all server; weak/marker paths are suppressed when catch-all is seen.
	strong bool
}{
	{"/.git/config", "Exposed .git directory", "information-disclosure", High, true},
	{"/.env", "Exposed .env file", "information-disclosure", Critical, true},
	{"/.svn/entries", "Exposed .svn metadata", "information-disclosure", Medium, true},
	{"/server-status", "Apache server-status exposed", "information-disclosure", Medium, true},
	{"/actuator/env", "Spring actuator env exposed", "information-disclosure", High, true},
	{"/phpinfo.php", "phpinfo() exposed", "information-disclosure", Medium, true},
	{"/.well-known/security.txt", "security.txt present", "info", Info, false},
	{"/robots.txt", "robots.txt present", "info", Info, false},
}

// origin reduces any URL to scheme://host[:port], so path probes are joined onto
// the real origin rather than concatenated onto the seed's path and query.
func origin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

// Run executes the deterministic checks against a base URL and its fingerprint.
func Run(ctx context.Context, baseURL string, fp *fingerprint.Result) ([]Finding, error) {
	var findings []Finding

	// 1. Missing security headers (from the fingerprint we already have).
	if fp != nil {
		for _, h := range fp.SecurityHeadersMissing {
			sev := Low
			if h == "Content-Security-Policy" || h == "Strict-Transport-Security" {
				sev = Medium
			}
			findings = append(findings, Finding{
				ID: "hdr-" + slug(h), Title: "Missing security header: " + h,
				Severity: sev, URL: baseURL, Evidence: h + " not present in response",
				Class: "security-misconfiguration",
			})
		}
	}

	base, err := origin(baseURL)
	if err != nil {
		return findings, err
	}

	c, err := client.New(0)
	if err != nil {
		return findings, err
	}

	// 2. Detect a catch-all server: does a random path also return 200? If so we
	// only trust strong content signatures (suppresses false positives).
	catchAll := isCatchAll(ctx, c, base)

	// 3. Exposed sensitive paths.
	for _, sp := range sensitivePaths {
		if catchAll && !sp.strong {
			continue
		}
		u := base + sp.path
		resp, err := client.Get(ctx, c, u)
		if err != nil {
			continue
		}
		body := peek(resp, 1024)
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && looksReal(sp.path, body) {
			findings = append(findings, Finding{
				ID: "exp-" + slug(sp.path), Title: sp.title, Severity: sp.sev,
				URL: u, Evidence: "HTTP 200 with expected content signature", Class: sp.class,
			})
		}
	}
	return findings, nil
}

func isCatchAll(ctx context.Context, c *http.Client, base string) bool {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	u := base + "/masagent-404-probe-" + hex.EncodeToString(b)
	resp, err := client.Get(ctx, c, u)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// looksReal requires a content signature specific to each path so a generic 200
// page cannot masquerade as an exposed file.
func looksReal(path, body string) bool {
	b := strings.ToLower(body)
	html := strings.Contains(b, "<html") || strings.Contains(b, "<!doctype")
	switch {
	case strings.Contains(path, ".git/config"):
		return strings.Contains(b, "[core]") || strings.Contains(b, "repositoryformatversion")
	case strings.Contains(path, ".env"):
		return !html && strings.Contains(b, "=") &&
			(strings.Contains(b, "key") || strings.Contains(b, "secret") ||
				strings.Contains(b, "password") || strings.Contains(b, "db_") || strings.Contains(b, "token"))
	case strings.Contains(path, "phpinfo"):
		// A real phpinfo page has these table headers; the word alone in an HTML
		// shell (e.g. reflected input) is not enough.
		return strings.Contains(b, "php version") ||
			(strings.Contains(b, "phpinfo") && strings.Contains(b, "system"))
	case strings.Contains(path, "server-status"):
		return strings.Contains(b, "apache server status")
	case strings.Contains(path, "actuator"):
		return !html && strings.Contains(b, "{") && strings.Contains(b, "\"")
	case strings.Contains(path, ".svn"):
		// Real .svn/entries is not HTML and begins with a format integer.
		return !html && (strings.Contains(b, "dir") || strings.HasPrefix(strings.TrimSpace(b), "12"))
	case strings.Contains(path, "security.txt"):
		return strings.Contains(b, "contact:")
	case strings.Contains(path, "robots.txt"):
		return strings.Contains(b, "user-agent") || strings.Contains(b, "disallow")
	default:
		return false
	}
}

func peek(resp *http.Response, n int) string {
	buf := make([]byte, n)
	read, _ := resp.Body.Read(buf)
	return string(buf[:read])
}

func slug(s string) string {
	s = strings.ToLower(s)
	s = strings.NewReplacer("/", "-", ".", "", " ", "-", ":", "").Replace(s)
	return strings.Trim(s, "-")
}
