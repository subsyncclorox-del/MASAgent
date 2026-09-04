// Package fingerprint identifies server tech from response headers and body
// signatures. It only reads what the target already returns; it sends nothing
// intrusive. This feeds the attack-surface map the planner reads.
package fingerprint

import (
	"context"
	"net/http"
	"strings"

	"github.com/masagent/recon/internal/client"
)

// Tech is a single identified technology with the evidence that identified it.
type Tech struct {
	Name     string `json:"name"`
	Category string `json:"category"` // server | framework | language | waf | cdn
	Evidence string `json:"evidence"`
}

// Result is the fingerprint of one host.
type Result struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Tech    []Tech            `json:"tech"`
	// SecurityHeadersMissing lists standard hardening headers not present.
	SecurityHeadersMissing []string `json:"security_headers_missing"`
}

var headerSignatures = []struct {
	header, contains, name, category string
}{
	{"Server", "nginx", "nginx", "server"},
	{"Server", "apache", "Apache", "server"},
	{"Server", "cloudflare", "Cloudflare", "cdn"},
	{"X-Powered-By", "php", "PHP", "language"},
	{"X-Powered-By", "express", "Express", "framework"},
	{"X-Powered-By", "asp.net", "ASP.NET", "framework"},
	{"X-Aspnet-Version", "", "ASP.NET", "framework"},
	{"X-Generator", "drupal", "Drupal", "framework"},
	{"Via", "varnish", "Varnish", "cdn"},
	{"Set-Cookie", "laravel_session", "Laravel", "framework"},
	{"Set-Cookie", "csrftoken", "Django", "framework"},
}

var securityHeaders = []string{
	"Content-Security-Policy",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"Referrer-Policy",
}

// Identify fetches url through the scope guard and derives a fingerprint.
func Identify(ctx context.Context, url string) (*Result, error) {
	c, err := client.New(0)
	if err != nil {
		return nil, err
	}
	resp, err := client.Get(ctx, c, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return fromHeaders(url, resp.Header), nil
}

func fromHeaders(url string, h http.Header) *Result {
	r := &Result{URL: url, Headers: map[string]string{}}
	for k := range h {
		r.Headers[k] = h.Get(k)
	}
	for _, sig := range headerSignatures {
		v := h.Get(sig.header)
		if v == "" {
			continue
		}
		if sig.contains == "" || strings.Contains(strings.ToLower(v), sig.contains) {
			r.Tech = append(r.Tech, Tech{Name: sig.name, Category: sig.category, Evidence: sig.header + ": " + v})
		}
	}
	for _, sh := range securityHeaders {
		if h.Get(sh) == "" {
			r.SecurityHeadersMissing = append(r.SecurityHeadersMissing, sh)
		}
	}
	return r
}
