#!/usr/bin/env bash
# Codespace bootstrap for MASAgent. Runs once at container create.
set -uo pipefail

export PATH="$PWD/bin:$HOME/go/bin:$HOME/.local/bin:$PATH"
mkdir -p "$HOME/.local/bin"

echo "==> Building Go binaries (scopeguard, recon)"
make build

echo "==> Installing the Python orchestrator (provides the 'masagent' CLI)"
pip install -e ./orchestrator

echo "==> Installing API (TypeScript) dependencies"
( cd api && npm install --no-audit --no-fund )

echo "==> Installing external scanners (nuclei, dalfox, sqlmap) — best-effort"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || echo "   (nuclei install failed — install later with the same command)"
go install github.com/hahwul/dalfox/v2@latest               || echo "   (dalfox install failed)"
if [ ! -x "$HOME/.local/bin/sqlmap" ]; then
  git clone --depth 1 https://github.com/sqlmapproject/sqlmap "$HOME/sqlmap" 2>/dev/null \
    && ln -sf "$HOME/sqlmap/sqlmap.py" "$HOME/.local/bin/sqlmap" \
    || echo "   (sqlmap install failed)"
fi

echo "==> Fetching nuclei templates (best-effort)"
nuclei -update-templates >/dev/null 2>&1 || echo "   (template fetch skipped)"

echo "==> Building the PoC sandbox image (best-effort; guarded-replay is the fallback)"
docker build -t masagent/sandbox:latest ./sandbox || echo "   (skipped — Docker not ready yet)"

echo ""
echo "==> Tool check:"
for t in scopeguard recon masagent nuclei dalfox sqlmap; do
  if command -v "$t" >/dev/null 2>&1; then echo "    [ok] $t"; else echo "    [--] $t (missing)"; fi
done

cat <<'EOF'

==============================================================
MASAgent is ready.

  1. cp examples/scope.example.yaml scope.yaml   # edit for YOUR target
  2. masagent run --scope scope.yaml \
       --target https://your-in-scope-host --start-guard --out ./out
  3. cat out/report.md

For deep (autonomous) mode, also export a model key before running:
  export OPENROUTER_API_KEY=sk-...

Authorized targets only — see AUTHORIZATION.md.
==============================================================
EOF
