# Architecture

MASAgent is a set of decoupled services in the language each job suits, glued by
structured job records and (in production) a message queue. The one hard rule
that crosses every boundary: **the scope guard is the only way to the network.**

## Services

### scopeguard (Go)
The network gate and safety core. Loads the scope, serves a forward proxy and a
control API, applies rate/concurrency limits, and writes the hash-chained audit
log. Also verifies audit logs (`-verify`). See [`SAFETY.md`](SAFETY.md).

Packages:
- `internal/scope` — scope model, parsing, and host/port/IP matching.
- `internal/guard` — the guarded `http.Client`, the forward proxy, and the
  throttle (per-host token bucket + concurrency caps).
- `internal/audit` — append-only, hash-chained JSONL log + verifier.

### recon (Go)
Throughput-bound mapping. Spiders the in-scope surface, fingerprints tech from
response headers, and runs the deterministic detection engine (rule-based checks
with a catch-all-200 guard to keep false positives out). Emits a JSON
attack-surface map. Egresses only through the guard proxy.

### orchestrator (Python)
The brain. Reads the surface map, builds a prioritized plan, directs the agent
swarm and scanner integrations under a concurrency cap and a hard spend cap,
validates every candidate through the evidence gate, and renders reports.

Modules: `planner`, `coordinator`, `agents/*`, `scanners/*`, `poc/*`,
`report/*`, `modelrouter`, `scope_client`, `engagement`, `audit`, `cli`.

### api (TypeScript/Node)
The API server and job-queue front end. Registers engagements, mints
scope-bound tokens, and accepts jobs behind the authorization gate. Rejects any
job whose target the scope guard does not allow. Streams findings over SSE.

### sandbox (Docker)
A minimal, capability-dropped container that reproduces one finding recipe and
prints a JSON verdict. Its only egress is the scope guard, so even PoC traffic
stays in scope.

## Why these languages

- **Go** for the guard and recon — the fast networking/security ecosystem lives
  here, and both are throughput-bound.
- **Python** for the brain — the agent/LLM/orchestration ecosystem, and the
  natural home for `sqlmap`-style integrations.
- **TypeScript** for the API and dashboard — a typed HTTP surface and job queue.
- **Rust (optional, future)** for a faster intercepting proxy or hot-path
  response parsers if Go isn't enough.

## Data flow

1. A scope file defines the engagement. `scopeguard` loads it and opens the
   audit log.
2. `recon` maps the surface through the guard → `surface-map.json`.
3. The `planner` turns the map into `plan.json`.
4. The `coordinator` runs agents/scanners (through the guard), collecting
   candidates.
5. The `validator` reproduces each candidate (sandbox → guarded replay).
6. The `report` layer dedupes, ranks, and renders `report.{json,md}` and
   `bugbounty.md`.

Every step appends to the audit log; nothing reaches the network except through
the guard.

## Message queue

The reference API ships an in-memory `JobStore` with the exact interface a
Redis/NATS-backed queue would expose (`enqueue`, `get`, `listByEngagement`,
`update`, `addFinding`, `pending`). Swapping the store for a real broker leaves
the API and worker unchanged.
