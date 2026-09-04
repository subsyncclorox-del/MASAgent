"""Client to the Go scopeguard.

Two responsibilities:

1. Ask the scopeguard control API whether a host:port is in scope (allow/deny),
   which the guard also records in the audit log.
2. Provide the proxy configuration every subprocess and HTTP client must use so
   that egress physically goes through the guard.

If the scope guard is unreachable, calls fail CLOSED — we treat "unknown" as
"out of scope" so a guard outage can never become unmediated access.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass

import httpx


class ScopeError(RuntimeError):
    """Raised when a target is out of scope or the guard cannot confirm scope."""


@dataclass
class ScopeClient:
    control_url: str
    proxy_url: str

    def check(self, host: str, port: int = 443, actor: str = "orchestrator") -> tuple[bool, str]:
        """Return (allowed, reason). Fails closed on any error."""
        q = urllib.parse.urlencode({"host": host, "port": port, "actor": actor})
        try:
            r = httpx.get(f"{self.control_url}/check?{q}", timeout=10)
            r.raise_for_status()
            data = r.json()
        except Exception as e:  # noqa: BLE001 — any failure means we cannot confirm scope
            return False, f"scope guard unreachable ({e}); failing closed"
        return bool(data.get("allowed")), str(data.get("reason", ""))

    def require(self, host: str, port: int = 443, actor: str = "orchestrator") -> None:
        allowed, reason = self.check(host, port, actor)
        if not allowed:
            raise ScopeError(f"{host}:{port} is out of scope: {reason}")

    def proxy_env(self) -> dict[str, str]:
        """Environment variables that force any child process through the guard."""
        return {
            "HTTP_PROXY": self.proxy_url,
            "HTTPS_PROXY": self.proxy_url,
            "http_proxy": self.proxy_url,
            "https_proxy": self.proxy_url,
            "SCOPEGUARD_PROXY": self.proxy_url,
        }

    def httpx_client(self, actor: str = "orchestrator") -> httpx.Client:
        """An httpx client whose egress is the scope guard proxy."""
        return httpx.Client(
            proxy=self.proxy_url,
            timeout=30,
            headers={"User-Agent": f"MASAgent/{actor} (authorized-testing)"},
        )

    def healthy(self) -> bool:
        try:
            r = httpx.get(f"{self.control_url}/healthz", timeout=5)
            return r.status_code == 200
        except Exception:  # noqa: BLE001
            return False
