package guard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/masagent/scopeguard/internal/audit"
	"github.com/masagent/scopeguard/internal/scope"
)

// ErrOutOfScope is returned for any host/port the scope does not permit.
var ErrOutOfScope = errors.New("guard: target is out of scope")

// Guard binds a Scope, a Throttle and an audit Logger. It is the single choke
// point for network egress. Modules receive an *http.Client from Guard; they
// never construct their own transport.
type Guard struct {
	Scope    *scope.Scope
	throttle *Throttle
	audit    *audit.Logger
	resolver *net.Resolver
}

func New(s *scope.Scope, log *audit.Logger) *Guard {
	return &Guard{
		Scope:    s,
		throttle: NewThrottle(s.Limits),
		audit:    log,
		resolver: net.DefaultResolver,
	}
}

// Allow performs a scope check for actor against host:port, resolving the name
// so that a domain pointing into an excluded network is caught. The decision is
// always written to the audit log.
func (g *Guard) Allow(ctx context.Context, actor, host string, port int) (scope.Decision, error) {
	var resolved []net.IP
	if net.ParseIP(host) == nil {
		ips, err := g.resolver.LookupIP(ctx, "ip", host)
		if err == nil {
			resolved = ips
		}
		// A resolution failure is not itself out-of-scope; the dial will fail
		// safely later. We still evaluate the domain rules below.
	}
	d := g.Scope.Check(host, port, resolved...)
	target := net.JoinHostPort(host, strconv.Itoa(port))
	_ = g.audit.Decision(actor, target, d.Allowed, d.Reason)
	if !d.Allowed {
		return d, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, target, d.Reason)
	}
	return d, nil
}

// HTTPClient returns an *http.Client whose transport refuses out-of-scope
// dials, pins DNS to the checked IP, and applies rate/concurrency limits. actor
// labels the caller in the audit log.
func (g *Guard) HTTPClient(actor string) *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}

		// Resolve and check BEFORE dialing.
		var pinned net.IP
		if ip := net.ParseIP(host); ip != nil {
			pinned = ip
		} else {
			ips, err := g.resolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			// Pick the first IP that the scope allows; check all for deny.
			d := g.Scope.Check(host, port, ips...)
			if !d.Allowed {
				_ = g.audit.Decision(actor, addr, false, d.Reason)
				return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, addr, d.Reason)
			}
			for _, ip := range ips {
				if g.Scope.Check(ip.String(), port).Allowed || len(g.Scope.AllowCIDRs) == 0 {
					pinned = ip
					break
				}
			}
			if pinned == nil {
				pinned = ips[0]
			}
		}

		// Final check on the concrete IP (defends against rebinding: we dial the
		// exact IP we validated).
		d := g.Scope.Check(host, port, pinned)
		if !d.Allowed {
			_ = g.audit.Decision(actor, addr, false, d.Reason)
			return nil, fmt.Errorf("%w: %s (%s)", ErrOutOfScope, addr, d.Reason)
		}

		release, err := g.throttle.Acquire(ctx, host)
		if err != nil {
			return nil, err
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(pinned.String(), portStr))
		if err != nil {
			release()
			return nil, err
		}
		_ = g.audit.Log(audit.Event{Kind: "request", Actor: actor, Target: addr, Reason: "dial " + pinned.String()})
		return &guardedConn{Conn: conn, release: release}, nil
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:         dialContext,
			MaxIdleConns:        16,
			IdleConnTimeout:     30 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			DisableKeepAlives:   false,
		},
	}
}

// guardedConn releases its concurrency slot when closed.
type guardedConn struct {
	net.Conn
	release func()
}

func (c *guardedConn) Close() error {
	c.release()
	return c.Conn.Close()
}

// ForwardProxy is an http.Handler implementing an HTTP/HTTPS forward proxy that
// non-Go modules (Python, TypeScript) point at. It applies exactly the same
// scope, throttle and audit rules as the in-process client, so no module — in
// any language — gets unmediated egress.
type ForwardProxy struct {
	g     *Guard
	actor string
}

func (g *Guard) ForwardProxy(actor string) *ForwardProxy { return &ForwardProxy{g: g, actor: actor} }

func (p *ForwardProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}
	// Plain HTTP proxying.
	host, port := hostPort(r.URL.Host, 80)
	if _, err := p.g.Allow(r.Context(), p.actor, host, port); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	client := p.g.HTTPClient(p.actor)
	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, r.URL.String(), r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(outReq.Header, r.Header)
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// handleConnect tunnels HTTPS after a scope check on the CONNECT target. The
// tunnel is opaque, so the check happens up front on host:port and the dial is
// pinned via the guard's dialer.
func (p *ForwardProxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	host, port := hostPort(r.Host, 443)
	if _, err := p.g.Allow(r.Context(), p.actor, host, port); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	// Reuse the guard's checked dialer by dialing through the HTTP client's
	// transport DialContext.
	tr := p.g.HTTPClient(p.actor).Transport.(*http.Transport)
	upstream, err := tr.DialContext(r.Context(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		upstream.Close()
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go pipe(upstream, client)
	go pipe(client, upstream)
}

func pipe(dst, src net.Conn) { defer dst.Close(); defer src.Close(); _, _ = io.Copy(dst, src) }

func hostPort(hostport string, def int) (string, int) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, def
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return h, def
	}
	return h, port
}

func copyHeaders(dst, src http.Header) {
	hopByHop := map[string]bool{"Connection": true, "Proxy-Connection": true, "Keep-Alive": true, "Transfer-Encoding": true, "Te": true, "Trailer": true, "Upgrade": true}
	for k, vv := range src {
		if hopByHop[k] {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
