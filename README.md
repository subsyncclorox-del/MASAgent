# MASAgent

**Autonomous AI penetration-testing platform — for AUTHORIZED security testing only.**

Point MASAgent at an in-scope target, give it whatever context you have (docs,
credentials, API specs, architecture notes), and it maps, plans, tests, chains,
validates, and reports vulnerabilities — with reproducible proof and a design
built for near-zero false positives.

> ⚠️ **Authorized use only.** MASAgent runs only against targets you are
> permitted to test: a bug-bounty program's published scope, systems you own, or
> a target under a signed engagement. See [`AUTHORIZATION.md`](AUTHORIZATION.md).
> The safety core is not a wrapper you can switch off — it is the thing every
> other component is built behind.

---

## What it does, and what it refuses to do

MASAgent is a **discover → prove → report** tool. It exists to produce evidence a
program can act on. It deliberately does **not** build intrusion capability:

| Builds | Refuses (see [non-goals](docs/SAFETY.md#non-goals)) |
|---|---|
| Non-bypassable scope enforcement | Any mode that runs without a scope |
| Recon, planning, agent swarm | Detection-evasion for unauthorized access |
| Evidence-gated findings + PoC | Persistence, C2, lateral movement |
| Vulnerability chaining for proof | Data exfiltration beyond minimal proof |

## Safety first, by construction

Nothing downstream runs until the safety core passes. See [`docs/SAFETY.md`](docs/SAFETY.md).

1. **Every run requires an explicit scope file** — allowed domains/IPs/CIDRs,
   ports, exclusions, and an engagement id. No scope, no run.
2. **A scope guard sits between every module and the network.** No spider,
   scanner, or agent gets a raw network handle; they all egress through the
   guard, which drops and logs anything out of scope. It fails **closed**.
3. **A per-engagement token is bound to a specific scope.** The API rejects any
   job whose target isn't covered by its token.
4. **Conservative per-host rate limits and concurrency caps** so it cannot DoS an
   authorized target.
5. **A tamper-evident audit log** records every host touched, tool run, agent
   action, and finding.

## Architecture (multi-language, decoupled)

```
                        ┌───────────────────────────────────────────┐
   scope.yaml  ───────► │  scopeguard (Go)  — the only egress path    │ ──► network
                        │  scope check · rate limit · audit · proxy   │     (in-scope only)
                        └───────▲───────────────▲───────────────▲─────┘
                                │ proxy+control  │               │
   ┌──────────────┐   ┌─────────┴───────┐  ┌─────┴───────┐  ┌────┴─────────────┐
   │ api (TS)     │   │ recon (Go)      │  │ orchestrator │  │ sandbox (Docker) │
   │ auth gate    │   │ spider·finger·  │  │ (Python)     │  │ PoC validation   │
   │ job queue    │   │ deterministic   │  │ planner·swarm│  │ evidence gate    │
   └──────────────┘   └─────────────────┘  └──────────────┘  └──────────────────┘
```

- **Go** — throughput-bound recon/scanning core and the scope guard.
- **Python** — the brain: planner, agent swarm, orchestration, PoC validation.
- **TypeScript/Node** — API server, job queue front end, authorization gate.
- **Docker** — per-job sandbox for reproducing findings under strict limits.

Details in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and the full pipeline in
[`docs/PIPELINE.md`](docs/PIPELINE.md).

## Quickstart

Prerequisites: Go 1.24+, Python 3.10+, (optional) Node 20+ for the API, and
Docker for sandboxed PoC validation.

```bash
# 1. Build the Go core
make build            # produces bin/scopeguard and bin/recon

# 2. Install the orchestrator
cd orchestrator && pip install -e . && cd ..

# 3. Write a scope file (authorization boundary)
cp examples/scope.example.yaml scope.yaml   # then edit it for YOUR target

# 4. Run the full pipeline (the CLI launches the guard for you)
export PATH="$PWD/bin:$PATH"
masagent run --scope scope.yaml --target https://example.com --start-guard --out ./out
```

By default this runs **site-wide**: it discovers in-scope subdomains (DNS-based, passive) under your scope's `allow_domains` and tests every one. Pass `--no-subdomains` to test only the given host.

Outputs land in `./out/`:

- `surface-map.json` — the mapped attack surface
- `plan.json` — the prioritized test plan
- `report.json` / `report.md` — findings, evidence-gated
- `bugbounty.md` — per-finding submission blocks
- `orchestrator-<engagement>.jsonl` — hash-chained audit log

Verify an audit log's integrity at any time:

```bash
bin/scopeguard -verify out/orchestrator-ENG-2026-0001.jsonl
```

## API + dashboard

```bash
cd api && npm install && npm run build
MASAGENT_TOKEN_SECRET=... MASAGENT_ADMIN_KEY=... SCOPEGUARD_CONTROL=http://127.0.0.1:8898 \
  node dist/server.js
```

- `POST /engagements` (admin) → registers an engagement, returns a scoped token
- `POST /jobs` (bearer token) → submits a job; rejected unless the target is in
  scope **and** the token covers it
- `GET /jobs/:id` · `GET /jobs` · `GET /jobs/:id/findings` (SSE stream)

Every job endpoint runs behind the authorization gate. See [`docs/PIPELINE.md`](docs/PIPELINE.md).

## Coverage

Web (SQLi, XSS, SSTI, command injection, SSRF, deserialization, path traversal,
file upload, auth/session), APIs (REST + GraphQL from ingested schemas),
IDOR/BOLA and privilege escalation across roles, AI/LLM app testing (prompt
injection), and a light SCA/SAST source-review mode. See
[`docs/PIPELINE.md`](docs/PIPELINE.md#coverage).

## Development

```bash
make test        # go test ./... in each module + pytest + tsc typecheck
make build       # build the Go binaries
```

## Status

This repository is a working, tested **foundation**: the safety core (scope
guard, authorization, audit, evidence gate) is functional and covered by tests;
recon, the planner, the agent swarm, the scanner integrations, and reporting run
end-to-end. Model-driven planning, the full external-scanner matrix, and the
benchmark harness are wired with clear integration points and grow from here.
See [`docs/BENCHMARK.md`](docs/BENCHMARK.md) for how progress is measured.

## License

[MIT](LICENSE), with the authorized-use terms in [`AUTHORIZATION.md`](AUTHORIZATION.md).
