# Authorized use

MASAgent is a tool for **authorized security testing only**. By running it you
assert that you have explicit permission to test each target in your scope file.

## Permitted

- **Bug-bounty / VDP programs** — targets within a program's *published* scope,
  tested in accordance with that program's rules.
- **Systems you own** — infrastructure and applications you control.
- **Signed engagements** — targets covered by a written penetration-testing
  agreement (statement of work, rules of engagement) with the asset owner.

## Not permitted

- Any target you are not authorized to test.
- Using MASAgent to gain or maintain unauthorized access.
- Removing, disabling, or working around the scope guard, the authorization
  gate, the rate limits, or the audit log.
- Using findings for any purpose other than reporting them to the party
  responsible for the asset.

## What the tool enforces

The controls below are structural, not advisory:

- **No scope, no run.** The CLI and the orchestrator refuse to start without a
  valid scope file naming an engagement and at least one allowed target.
- **The scope guard is the only egress path.** Every module reaches the network
  through it; out-of-scope requests are dropped and logged. It fails closed.
- **Tokens are bound to a scope.** A job whose target is not covered by its
  engagement token is rejected by the API.
- **Everything is logged.** A tamper-evident audit trail records every host
  touched and every action taken, so an engagement is fully accountable.

## Your responsibility

These controls reduce the chance of an accident. They do not grant authorization.
Obtaining and honoring permission for every target is your responsibility. If you
are unsure whether a target is in scope, do not add it.
