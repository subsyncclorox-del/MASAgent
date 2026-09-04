# The pipeline

MASAgent runs eleven stages. Every stage that touches the network does so through
the scope guard.

1. **Context ingestion** — target URL plus optional docs, credentials, API specs
   (OpenAPI/GraphQL), and architecture notes from `--context`. More context =
   deeper testing.
2. **Discovery + Spider (Go/Python)** — enumerate in-scope subdomains (passive DNS brute-force under the scope's apex domains, each scope-checked), then crawl every in-scope host: routes, forms, params, endpoints, JS bundles. `--no-subdomains` limits the run to a single host.
3. **Recon (Go)** — fingerprint stack/tech/headers, probe for exposed files,
   build the live attack-surface map.
4. **Planner (Python)** — read the map and produce a prioritized test plan
   (which endpoints, which vuln classes, which tools, what order). Deterministic
   first; a model refines ordering when configured, but the plan never depends on
   it.
5. **Deterministic detection engine (Go)** — rule-based checks with no LLM
   guessing: missing headers, exposed secrets/files, obvious misconfigurations. A
   catch-all-200 guard and per-path content signatures keep false positives out.
6. **External scanner layer (Python)** — normalized wrappers for `nuclei`,
   `sqlmap`, `dalfox`. Every call is scope-checked and egresses through the guard;
   a missing binary degrades gracefully.
7. **JS + IDOR/BOLA analysis** — parse client JS for endpoints; test object- and
   function-level access control across the roles supplied in context.
8. **Coordinator + agent swarm (Python)** — a coordinator directs parallel
   agents, all through the guard, the rate limiter, and the spend cap, logging
   their reasoning. Two kinds: deterministic agents (scripted probes for a
   vuln class) and, when a model is configured, an **autonomous LLM agent**
   per host that chooses its own actions — request, observe, hypothesize,
   chain, report — via tool-calling. The guard makes off-scope requests
   impossible even under model control, and the spend cap bounds each run.
9. **Vulnerability chaining** — proven findings are composed into attack paths.
   A chain is only emitted when each constituent finding is already proven, so a
   chain never introduces an unproven claim.
10. **Mandatory PoC validation (sandboxed)** — every candidate is reproduced
    before it is reported: Docker sandbox first, guarded in-process replay as a
    fallback. No proof, no finding.
11. **Consolidate + report** — dedupe, rank by severity, attach evidence; render
    JSON, Markdown, and a bug-bounty submission format.

## Coverage

- **Web app** — SQLi, XSS, SSTI, command injection, SSRF, deserialization, path
  traversal, file upload, auth/session flaws, business-logic bugs.
- **APIs** — REST and GraphQL, driven from ingested schemas.
- **Auth flows** — login, session handling, OAuth, privilege escalation,
  IDOR/BOLA across roles.
- **AI/LLM apps** — prompt injection and tool-abuse against authorized
  LLM-backed features, using benign canaries during discovery.
- **Source review mode** — light SCA (vulnerable deps) and SAST-style checks when
  source is provided in `--context`.

## Agents

Each agent subclasses `Agent`, which enforces a scope check before any request
and an audit entry for every step. Shipped agents:

- `idor-bola` — cross-role object-access testing (reads only).
- `xss` — reflected-input detection with a benign marker.
- `prompt-injection` — canary-based instruction-override testing for LLM apps.

New agents register with `@register("<vuln-class>")` and are picked up by the
coordinator automatically.

## Enhancements (roadmap, wired with integration points)

Regression testing of confirmed findings, continuous re-testing on surface
change, CI/CD integration (open a PR with finding + evidence + suggested fix),
the [benchmark harness](BENCHMARK.md), compliance report templates
(SOC 2 / ISO 27001), per-run observability, model routing tiers with a hard
spend cap (implemented in `modelrouter`), and per-agent explainability
(implemented via the audit log).
