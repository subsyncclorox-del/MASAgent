#!/usr/bin/env bash
# Codespace bootstrap for MASAgent. Runs once at container create.
set -uo pipefail

echo "==> Building Go binaries (scopeguard, recon)"
make build

echo "==> Installing the Python orchestrator (provides the 'masagent' CLI)"
pip install -e ./orchestrator

echo "==> Installing API (TypeScript) dependencies"
( cd api && npm install --no-audit --no-fund )

echo "==> Building the PoC sandbox image (best-effort; guarded-replay is the fallback)"
docker build -t masagent/sandbox:latest ./sandbox || echo "   (skipped — Docker not ready yet; run 'docker build -t masagent/sandbox:latest ./sandbox' later)"

cat <<'EOF'

==============================================================
MASAgent is ready.

  1. cp examples/scope.example.yaml scope.yaml   # edit for YOUR target
  2. masagent run --scope scope.yaml \
       --target https://your-in-scope-host --start-guard --out ./out
  3. cat out/report.md

'masagent' and the scopeguard/recon binaries are on PATH.
Authorized targets only — see AUTHORIZATION.md.
==============================================================
EOF
