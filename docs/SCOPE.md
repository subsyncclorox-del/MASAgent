# The scope file

The scope file is the authorization boundary. See
[`../examples/scope.example.yaml`](../examples/scope.example.yaml) for a
commented template.

## Fields

| Field | Required | Meaning |
|---|---|---|
| `engagement_id` | yes | Unique id for this engagement; appears in every audit record and every token. |
| `name` | no | Human label. |
| `allow_domains` | one of allow_* | In-scope domains. `example.com` also covers subdomains; `*.x.com` covers subdomains only, not the apex. |
| `allow_cidrs` | one of allow_* | In-scope networks (CIDR) or bare IPs. |
| `allow_ports` | no | Ports MASAgent may touch. Default `[80, 443, 8080, 8443]`. |
| `deny_domains` | no | Excluded domains. **Deny always wins.** |
| `deny_cidrs` | no | Excluded networks/IPs. Deny always wins, including against a domain that *resolves* into one. |
| `limits` | no | Per-host rate/concurrency caps (see below). |

At least one of `allow_domains` / `allow_cidrs` must be present. A file with none
is rejected — there is no test-everything mode.

## Matching rules

- **Deny is checked first and always wins**, for the host name and for every IP a
  name resolves to.
- A bare domain rule matches the apex and all subdomains. A `*.` rule matches
  subdomains only.
- Suffix tricks don't match: `example.com.attacker.com` is **not** in scope for a
  rule of `example.com`.
- Ports not in `allow_ports` are refused regardless of host.
- **Unknown keys are rejected** so a typo can't silently widen scope.

## Limits

```yaml
limits:
  requests_per_second_per_host: 5   # token-bucket rate per host
  burst: 10                         # burst size per host
  max_concurrent_per_host: 4        # simultaneous requests to one host
  max_concurrent_total: 32          # simultaneous requests across the run
```

Any field left unset uses the safe default. Limits can be tightened but the guard
always applies *some* limit — there is no "unlimited" setting.
