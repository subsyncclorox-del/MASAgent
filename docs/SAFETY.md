# Safety model

The safety core is built **first** and everything else runs behind it. This
document is the reference for how each control works and why.

## 1. No scope, no run

A run requires a scope file naming an `engagement_id` and at least one allowed
target. The Go scope parser rejects a file with no engagement or no targets
(`ErrNoEngagementID`, `ErrEmptyScope`), and it rejects **unknown keys** so a typo
like `test_everything: true` fails loudly instead of silently widening scope. The
Python `Engagement.load` enforces the same. There is no code path that runs
without a scope, and none that accepts a target from the request body instead of
the scope.

## 2. The scope guard is the only egress path

`scopeguard` (Go) is a process that:

- loads the scope and an append-only audit log;
- exposes a **forward proxy** (`--proxy`) that every non-Go module points at via
  `HTTP(S)_PROXY`, and an in-process guarded `http.Client` for Go modules;
- exposes a **control API** (`--control`) with `/check` for an explicit
  allow/deny decision.

For every connection it: checks the port, resolves the host, checks the name and
**every resolved IP** against the allow/deny rules (deny always wins), and dials
the **exact IP it validated** — defeating DNS-rebinding TOCTOU. Out-of-scope
requests are dropped and logged. If the guard is unreachable, callers treat the
result as **deny** (fail closed), so an outage can never become unmediated access.

No module constructs its own transport. The Python `ScopeClient` only ever hands
out an httpx client bound to the proxy; the Go `client` package refuses to run
without `SCOPEGUARD_PROXY`.

## 3. Tokens bound to a scope

An engagement token is `HMAC(engagement_id . scope_sha . exp)`. The API's
authorization gate verifies the signature and expiry, and rejects any job whose
declared engagement or scope hash does not match the token. A token minted for
one engagement cannot drive a job against another. The scheme is byte-compatible
between the TypeScript API and the Python orchestrator.

## 4. Rate limits and concurrency caps

The guard applies a per-host token bucket plus per-host and global concurrency
caps, with conservative defaults (`5 rps/host`, `4 concurrent/host`,
`32 total`). Limits come from the scope file and can only be set, never removed;
unset fields fall back to the safe defaults. A single violent burst is clamped
before it reaches the target.

## 5. Tamper-evident audit log

Every scope decision, request, tool run, agent action, and finding is written as
a JSON line with a SHA-256 hash chain (`prev_hash` → `hash`). Altering or
deleting a line breaks the chain; `scopeguard -verify <log>` detects it. Both the
Go guard and the Python orchestrator write chained logs.

## 6. Evidence-gated findings

A candidate becomes a reported finding **only** after it is reproduced — first in
the Docker sandbox, and if Docker is unavailable, via an in-process replay that
is still bound to the scope guard. Anything not proven is filed as
*unconfirmed* for the analyst, never as a finding. This is what drives the
near-zero false-positive rate.

## Non-goals

MASAgent will not grow features whose purpose is unauthorized access:

- no mode that runs without a scope;
- no detection-evasion / anti-forensics for evading defenders during
  unauthorized access;
- no persistence, command-and-control, or lateral-movement tooling;
- no data exfiltration beyond the minimum needed to prove a finding.

The chaining and PoC validation exist to produce evidence a program can act on —
nothing more.
