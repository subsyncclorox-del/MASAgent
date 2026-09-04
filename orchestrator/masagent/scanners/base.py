from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from urllib.parse import urlparse

from ..scope_client import ScopeClient


class ScannerUnavailable(RuntimeError):
    pass


@dataclass
class ScanFinding:
    tool: str
    vuln_class: str
    endpoint: str
    title: str
    severity: str
    evidence: str
    raw: dict = field(default_factory=dict)


class Scanner:
    binary: str = ""
    tool: str = ""

    def __init__(self, scope: ScopeClient) -> None:
        self.scope = scope

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def _guarded_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.update(self.scope.proxy_env())
        return env

    def _require_scope(self, target: str) -> None:
        u = urlparse(target if "//" in target else "//" + target)
        port = u.port or (443 if u.scheme == "https" else 80)
        self.scope.require(u.hostname or target, port, actor=self.tool)

    def _run(self, args: list[str], timeout: int = 600) -> subprocess.CompletedProcess:
        if not self.available():
            raise ScannerUnavailable(f"{self.binary} not installed")
        return subprocess.run(
            args, capture_output=True, text=True, timeout=timeout,
            env=self._guarded_env(), check=False,
        )

    def scan(self, target: str, params: list[str] | None = None) -> list[ScanFinding]:  # pragma: no cover
        raise NotImplementedError
