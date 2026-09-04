// Command scopeguard is the non-bypassable network gate for an engagement.
//
// It loads an explicit scope file, opens an append-only audit log, and exposes:
//
//   - a forward HTTP/HTTPS proxy (--proxy) that every non-Go module points at
//     via HTTP(S)_PROXY, so no spider, scanner or agent gets raw egress;
//   - a control API (--control) with /healthz and /check for services that want
//     an explicit allow/deny decision before acting.
//
// It refuses to start without a valid scope. There is no test-everything mode.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/masagent/scopeguard/internal/audit"
	"github.com/masagent/scopeguard/internal/guard"
	"github.com/masagent/scopeguard/internal/scope"
)

func main() {
	var (
		scopePath   = flag.String("scope", "", "path to the engagement scope file (required)")
		proxyAddr   = flag.String("proxy", "127.0.0.1:8899", "forward-proxy listen address")
		controlAddr = flag.String("control", "127.0.0.1:8898", "control API listen address")
		auditPath   = flag.String("audit", "", "audit log path (default: audit-<engagement>.jsonl)")
		verifyPath  = flag.String("verify", "", "verify the hash chain of an audit log and exit")
	)
	flag.Parse()

	if *verifyPath != "" {
		f, err := os.Open(*verifyPath)
		if err != nil {
			log.Fatalf("scopeguard: %v", err)
		}
		defer f.Close()
		n, broken, err := audit.Verify(f)
		if err != nil {
			log.Fatalf("scopeguard: verify: %v", err)
		}
		if broken != 0 {
			log.Fatalf("scopeguard: audit chain BROKEN at record %d (verified %d before it)", broken, n)
		}
		log.Printf("scopeguard: audit chain intact, %d records verified", n)
		return
	}

	if *scopePath == "" {
		log.Fatal("scopeguard: --scope is required; there is no test-everything mode")
	}
	s, err := scope.Load(*scopePath)
	if err != nil {
		log.Fatalf("scopeguard: %v", err)
	}

	ap := *auditPath
	if ap == "" {
		ap = "audit-" + s.EngagementID + ".jsonl"
	}
	logger, closer, err := audit.Open(ap, s.EngagementID)
	if err != nil {
		log.Fatalf("scopeguard: opening audit log: %v", err)
	}
	defer closer.Close()

	g := guard.New(s, logger)
	_ = logger.Log(audit.Event{Kind: "note", Reason: "scopeguard started", Detail: map[string]any{
		"engagement": s.EngagementID, "allow_domains": s.AllowDomains, "allow_cidrs": s.AllowCIDRs,
	}})

	log.Printf("scopeguard: engagement %s (%s)", s.EngagementID, s.Name)
	log.Printf("scopeguard: proxy on %s, control on %s, audit -> %s", *proxyAddr, *controlAddr, ap)

	// Forward proxy.
	proxySrv := &http.Server{Addr: *proxyAddr, Handler: g.ForwardProxy("proxy")}

	// Control API.
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "engagement": s.EngagementID})
	})
	mux.HandleFunc("/check", func(w http.ResponseWriter, r *http.Request) {
		host := r.URL.Query().Get("host")
		port, _ := strconv.Atoi(r.URL.Query().Get("port"))
		if port == 0 {
			port = 443
		}
		actor := r.URL.Query().Get("actor")
		if actor == "" {
			actor = "control"
		}
		d, err := g.Allow(r.Context(), actor, host, port)
		writeJSON(w, 200, map[string]any{"allowed": d.Allowed, "reason": d.Reason, "error": errStr(err)})
	})
	controlSrv := &http.Server{Addr: *controlAddr, Handler: mux}

	go func() {
		if err := proxySrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("proxy: %v", err)
		}
	}()
	go func() {
		if err := controlSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("control: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("scopeguard: shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxySrv.Shutdown(ctx)
	_ = controlSrv.Shutdown(ctx)
	_ = logger.Log(audit.Event{Kind: "note", Reason: "scopeguard stopped"})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
