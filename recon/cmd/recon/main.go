// Command recon spiders and fingerprints an in-scope target and emits a JSON
// attack-surface map on stdout for the Python planner to consume.
//
// It egresses ONLY through the scopeguard proxy (SCOPEGUARD_PROXY). Without it,
// every request fails closed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"time"

	"github.com/masagent/recon/internal/detect"
	"github.com/masagent/recon/internal/fingerprint"
	"github.com/masagent/recon/internal/spider"
)

// SurfaceMap is the combined recon output.
type SurfaceMap struct {
	Target      string              `json:"target"`
	GeneratedAt time.Time           `json:"generated_at"`
	Fingerprint *fingerprint.Result `json:"fingerprint"`
	Spider      *spider.Result      `json:"spider"`
	Findings    []detect.Finding    `json:"deterministic_findings"`
	Params      []string            `json:"parameters"`
}

func main() {
	var (
		target   = flag.String("target", "", "seed URL to map (must be in scope)")
		maxPages = flag.Int("max-pages", 50, "max pages to crawl")
		depth    = flag.Int("depth", 3, "max crawl depth")
		timeout  = flag.Duration("timeout", 5*time.Minute, "overall timeout")
	)
	flag.Parse()
	if *target == "" {
		log.Fatal("recon: --target is required")
	}
	if os.Getenv("SCOPEGUARD_PROXY") == "" {
		log.Fatal("recon: SCOPEGUARD_PROXY is not set; recon refuses unmediated egress")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	sm := SurfaceMap{Target: *target, GeneratedAt: time.Now().UTC()}

	if fp, err := fingerprint.Identify(ctx, *target); err != nil {
		log.Printf("recon: fingerprint: %v", err)
	} else {
		sm.Fingerprint = fp
	}

	cr, err := spider.New(*maxPages, *depth)
	if err != nil {
		log.Fatalf("recon: %v", err)
	}
	if sr, err := cr.Crawl(ctx, *target); err != nil {
		log.Printf("recon: spider: %v", err)
	} else {
		sm.Spider = sr
		for p := range sr.Params {
			sm.Params = append(sm.Params, p)
		}
	}

	if f, err := detect.Run(ctx, *target, sm.Fingerprint); err != nil {
		log.Printf("recon: detect: %v", err)
	} else {
		sm.Findings = f
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sm); err != nil {
		log.Fatal(err)
	}
}
