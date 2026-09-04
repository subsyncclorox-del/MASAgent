"""dalfox integration — XSS detection/verification. JSON output, egress through
the scope guard proxy."""
from __future__ import annotations

import json

from .base import Scanner, ScanFinding, ScannerUnavailable


class Dalfox(Scanner):
    binary = "dalfox"
    tool = "dalfox"

    def scan(self, target: str, params: list[str] | None = None) -> list[ScanFinding]:
        self._require_scope(target)
        args = [self.binary, "url", target, "--format", "json", "--proxy", self.scope.proxy_url, "--silence"]
        try:
            proc = self._run(args)
        except ScannerUnavailable:
            raise
        findings: list[ScanFinding] = []
        try:
            results = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            results = []
        for r in results:
            findings.append(ScanFinding(
                tool="dalfox",
                vuln_class="xss",
                endpoint=r.get("data", target),
                title=f"XSS ({r.get('type', 'verify')})",
                severity="high" if r.get("type") == "V" else "medium",
                evidence=r.get("evidence", ""),
                raw=r,
            ))
        return findings
