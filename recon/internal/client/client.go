// Package client builds HTTP clients that egress ONLY through the scopeguard
// forward proxy. Recon code never dials directly; if the proxy is unset it
// fails closed rather than reaching the network.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ErrNoProxy is returned when no scopeguard proxy is configured. Failing closed
// is deliberate: recon must not be able to reach the network unmediated.
var ErrNoProxy = errors.New("recon: SCOPEGUARD_PROXY is not set; refusing to make unmediated requests")

// New returns an *http.Client routed through the scopeguard proxy named by the
// SCOPEGUARD_PROXY env var (e.g. http://127.0.0.1:8899).
func New(timeout time.Duration) (*http.Client, error) {
	p := os.Getenv("SCOPEGUARD_PROXY")
	if p == "" {
		return nil, ErrNoProxy
	}
	pu, err := url.Parse(p)
	if err != nil {
		return nil, fmt.Errorf("recon: bad SCOPEGUARD_PROXY %q: %w", p, err)
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyURL(pu),
			MaxIdleConns:        16,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}, nil
}

// Get is a small helper for a scope-guarded GET.
func Get(ctx context.Context, c *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MASAgent-recon/0.1 (authorized-testing)")
	return c.Do(req)
}
