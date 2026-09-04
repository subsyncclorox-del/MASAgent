"""masagent CLI.

    masagent run --scope scope.yaml --target <in-scope-host> [--context ./context/]

Refuses to start without a valid scope. Requires a running scopeguard (start it
with the Go binary, or pass --start-guard to have the CLI launch it).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from . import __version__
from .audit import Audit
from .config import Config
from .coordinator import Coordinator, Finding
from .engagement import Engagement
from .modelrouter import ModelRouter
from .planner import build_plan
from .poc.sandbox import Sandbox
from .poc.validator import Validator, ProofResult
from .report.report import Report, render_bugbounty, render_json, render_markdown
from .scope_client import ScopeClient


def _die(msg: str, code: int = 2) -> "None":
    print(f"masagent: {msg}", file=sys.stderr)
    raise SystemExit(code)


def _load_engagement(scope_path: str) -> Engagement:
    if not scope_path:
        _die("--scope is required. There is no test-everything mode.")
    if not Path(scope_path).exists():
        _die(f"scope file not found: {scope_path}")
    try:
        return Engagement.load(scope_path)
    except Exception as e:  # noqa: BLE001
        _die(f"invalid scope: {e}")


def _maybe_start_guard(cfg: Config, scope_path: str) -> subprocess.Popen | None:
    binary = shutil.which("scopeguard") or str(Path(__file__).resolve().parents[3] / "scopeguard" / "scopeguard")
    if not Path(binary).exists() and not shutil.which("scopeguard"):
        _die("scopeguard binary not found; build it (go build ./scopeguard/cmd/scopeguard) "
             "or start it manually, then omit --start-guard")
    proc = subprocess.Popen([binary, "-scope", scope_path,
                             "-proxy", cfg.scopeguard_proxy.split("//")[-1],
                             "-control", cfg.scopeguard_control.split("//")[-1]])
    return proc


def _run_recon(cfg: Config, target: str, surface_map: str | None) -> dict:
    if surface_map:
        return json.loads(Path(surface_map).read_text())
    binary = shutil.which("recon") or str(Path(__file__).resolve().parents[3] / "recon" / "recon")
    if not (shutil.which("recon") or Path(binary).exists()):
        _die("recon binary not found; build it (go build ./recon/cmd/recon) "
             "or pass --surface-map <file.json>")
    env = dict(os.environ, SCOPEGUARD_PROXY=cfg.scopeguard_proxy)
    proc = subprocess.run([binary, "-target", target], capture_output=True, text=True, env=env, check=False)
    if proc.returncode != 0:
        _die(f"recon failed: {proc.stderr[-500:]}")
    return json.loads(proc.stdout)



def _deterministic_findings(surface: dict) -> list[Finding]:
    """Deterministic engine results are evidence-based observations (HTTP 200 +
    content signature, or an absent header). They enter the report as confirmed
    with proof method 'deterministic-observation'."""
    out: list[Finding] = []
    for d in surface.get("deterministic_findings", []):
        out.append(Finding(
            vuln_class=d.get("class", "security-misconfiguration"),
            endpoint=d.get("url", surface.get("target", "")),
            title=d.get("title", "deterministic finding"),
            severity=d.get("severity", "info"),
            source="deterministic",
            rationale=d.get("evidence", ""),
            proof=ProofResult(True, "deterministic-observation", d.get("evidence", "")),
        ))
    return out


def cmd_run(args) -> int:
    cfg = Config.from_env()
    eng = _load_engagement(args.scope)
    print(f"masagent: engagement {eng.engagement_id} ({eng.name or 'unnamed'})", file=sys.stderr)

    guard_proc = None
    if args.start_guard:
        guard_proc = _maybe_start_guard(cfg, args.scope)
        time.sleep(1.5)

    scope = ScopeClient(cfg.scopeguard_control, cfg.scopeguard_proxy)
    if not scope.healthy():
        _die(f"scopeguard control not reachable at {cfg.scopeguard_control}. "
             "Start scopeguard first, or pass --start-guard.")

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    audit = Audit(str(outdir / f"orchestrator-{eng.engagement_id}.jsonl"), eng.engagement_id)
    audit.log("note", reason="run started", detail={"target": args.target, "version": __version__})

    router = ModelRouter(cfg.openrouter_key, cfg.openrouter_base, cfg.spend_cap_usd,
                         cfg.self_hosted_model_base)

    # Confirm the target itself is in scope before doing anything.
    from urllib.parse import urlparse
    u = urlparse(args.target if "//" in args.target else "https://" + args.target)
    scope.require(u.hostname or args.target, u.port or 443, actor="cli")

    print("masagent: recon…", file=sys.stderr)
    surface = _run_recon(cfg, args.target, args.surface_map)
    (outdir / "surface-map.json").write_text(json.dumps(surface, indent=2))

    print("masagent: planning…", file=sys.stderr)
    plan = build_plan(surface, router)
    (outdir / "plan.json").write_text(plan.to_json())

    print(f"masagent: executing {len(plan.tasks)} tasks…", file=sys.stderr)
    sandbox = Sandbox(cfg.sandbox_image, cfg.scopeguard_proxy, eng.engagement_id)
    validator = Validator(scope, sandbox, audit)
    coord = Coordinator(scope, audit, validator, router, cfg.max_agent_concurrency)
    run = coord.run(plan)
    run.confirmed += _deterministic_findings(surface)

    rep = Report(eng.engagement_id, args.target, run.confirmed, run.unconfirmed, run.spend)
    rep.dedupe_and_rank()
    (outdir / "report.json").write_text(render_json(rep))
    (outdir / "report.md").write_text(render_markdown(rep))
    (outdir / "bugbounty.md").write_text(render_bugbounty(rep))
    audit.log("note", reason="run complete",
              detail={"confirmed": len(rep.confirmed), "unconfirmed": len(rep.unconfirmed)})

    print(f"masagent: {len(rep.confirmed)} confirmed, {len(rep.unconfirmed)} unconfirmed. "
          f"Reports in {outdir}/", file=sys.stderr)
    if guard_proc:
        guard_proc.terminate()
    return 0


def cmd_plan(args) -> int:
    surface = json.loads(Path(args.surface_map).read_text())
    print(build_plan(surface, None).to_json())
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="masagent", description="Autonomous pentest platform (authorized testing only).")
    p.add_argument("--version", action="version", version=f"masagent {__version__}")
    sub = p.add_subparsers(dest="cmd")

    r = sub.add_parser("run", help="run the full pipeline")
    r.add_argument("--scope", required=True, help="engagement scope file (YAML)")
    r.add_argument("--target", required=True, help="in-scope seed target")
    r.add_argument("--context", help="directory of docs/specs/creds for deeper testing")
    r.add_argument("--surface-map", help="use a pre-computed recon surface map instead of running recon")
    r.add_argument("--start-guard", action="store_true", help="launch scopeguard for this run")
    r.add_argument("--out", default="./masagent-out", help="output directory")
    r.set_defaults(func=cmd_run)

    pl = sub.add_parser("plan", help="print a test plan from a surface map")
    pl.add_argument("--surface-map", required=True)
    pl.set_defaults(func=cmd_plan)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
