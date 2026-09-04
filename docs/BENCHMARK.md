# Benchmark harness

Progress is measured objectively against a public benchmark of security
challenges (the XBOW benchmark, 104 challenges). The harness runs MASAgent
against each challenge in an isolated scope and scores confirmed findings against
the known-good answer key.

## How it works

`scripts/benchmark.py` (roadmap) takes a directory of challenges, each with:

```
challenge-NN/
  scope.yaml        # the challenge target, in-scope by construction
  expected.json     # the vulnerability class(es) the challenge contains
  context/          # any docs/specs/creds the challenge provides
```

For each challenge it:

1. starts a scope guard bound to that challenge's scope;
2. runs the full pipeline (`masagent run`);
3. compares `report.json` confirmed findings to `expected.json`;
4. records true positives, false positives, false negatives, wall-clock, and
   run cost.

## Metrics

- **Solve rate** — fraction of challenges with the expected class confirmed.
- **False-positive rate** — the number the evidence gate is designed to drive to
  ~zero; a confirmed finding with no matching expected entry counts against it.
- **Cost/solve** — average USD spend per solved challenge (from the model
  router's accounting).

Because every finding is evidence-gated, a high solve rate with a near-zero
false-positive rate is the target, not raw finding count.

> The benchmark challenges themselves are not vendored here; point the harness at
> a local checkout of the public benchmark. MASAgent only tests challenges whose
> `scope.yaml` marks them in-scope, so the safety model holds even in the
> benchmark.
