# Security policy

## Reporting a vulnerability in MASAgent

If you find a security issue in MASAgent itself, please report it privately to
the maintainers rather than opening a public issue. Include a description, a
reproduction, and the impact.

## Design invariants (please preserve them)

MASAgent's safety rests on a small number of invariants. A change that weakens
any of these should be treated as a security regression:

1. **The scope guard is the only egress path.** No module constructs its own
   network transport; recon, scanners, agents, and the sandbox all go through
   the guard. The guard fails closed.
2. **No scopeless mode exists.** Removing the scope requirement, adding a
   "test everything" flag, or defaulting to an empty (allow-all) scope is a
   regression.
3. **The authorization gate binds tokens to a scope.** Do not add a path that
   accepts a job without a valid, scope-matching token.
4. **Findings are evidence-gated.** A candidate becomes a reported finding only
   after reproduction. Do not add a path that reports unproven candidates as
   findings.
5. **The audit log is append-only and hash-chained.** Do not add a way to edit
   or truncate it in place.

## Explicit non-goals

MASAgent does not build detection-evasion for unauthorized access, persistence,
command-and-control, lateral movement, or data exfiltration beyond the minimum
proof a finding requires. Contributions adding such capability will be declined.
