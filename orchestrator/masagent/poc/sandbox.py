"""Per-job Docker sandbox for reproducing findings.

Each reproduction runs in an isolated, resource-capped, network-restricted
container that is torn down afterwards. The container's only route to the target
is the scope guard proxy (passed in as env), so even proof-of-concept traffic
cannot leave scope. If Docker is unavailable, the sandbox reports so and the
validator falls back to in-process guarded replay (still scope-bound).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class SandboxResult:
    ran: bool
    ok: bool
    stdout: str = ""
    stderr: str = ""
    reason: str = ""


class Sandbox:
    def __init__(self, image: str, proxy_url: str, engagement_id: str) -> None:
        self.image = image
        self.proxy_url = proxy_url
        self.engagement_id = engagement_id

    def available(self) -> bool:
        return shutil.which("docker") is not None

    def run_recipe(self, recipe: dict, timeout: int = 120) -> SandboxResult:
        """Execute a reproduction recipe inside the sandbox. The recipe is passed
        as JSON on stdin to the sandbox's /entrypoint, which replays it through
        the scope guard and prints a JSON verdict."""
        if not self.available():
            return SandboxResult(ran=False, ok=False, reason="docker unavailable")
        args = [
            "docker", "run", "--rm", "-i",
            "--network", "bridge",
            "--cpus", "1", "--memory", "512m", "--pids-limit", "128",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-e", f"SCOPEGUARD_PROXY={self.proxy_url}",
            "-e", f"ENGAGEMENT_ID={self.engagement_id}",
            self.image,
        ]
        try:
            proc = subprocess.run(
                args, input=json.dumps(recipe), capture_output=True,
                text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return SandboxResult(ran=True, ok=False, reason="sandbox timeout")
        except Exception as e:  # noqa: BLE001
            return SandboxResult(ran=False, ok=False, reason=str(e))
        # The sandbox entrypoint prints a JSON verdict containing "proven".
        # If that token is absent, the container never executed our recipe
        # (missing/broken image, pull failure) — report ran=False so the
        # validator falls back to a scope-guarded in-process replay rather than
        # mistaking an infrastructure failure for an unproven finding.
        if '"proven"' not in proc.stdout:
            reason = "sandbox image could not execute recipe"
            tail = (proc.stderr or proc.stdout).strip().splitlines()
            if tail:
                reason += ": " + tail[-1][:200]
            return SandboxResult(ran=False, ok=False, stdout=proc.stdout,
                                 stderr=proc.stderr, reason=reason)
        ok = proc.returncode == 0 and '"proven": true' in proc.stdout
        return SandboxResult(ran=True, ok=ok, stdout=proc.stdout, stderr=proc.stderr)
