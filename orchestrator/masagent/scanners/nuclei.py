"""nuclei integration — templated detection of known CVEs, misconfigurations and
exposures. Runs through the scope guard proxy and parses JSONL output."""
from __future__ import annotations

import json

from .base import Scanner, ScanFinding, ScannerUnavailable

_SEV_MAP = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical", "unknown": "info"}


class Nuclei(Scanner):
    binary = "nuclei"
    tool = "nuclei"

    def scan(self, target: str, params: list[str] | None = None) -> list[ScanFinding]:
        self._require_scope(target)
        # -jsonl for machine output; -proxy forces egress through the guard even
        # if the tool ignores env proxies.
        args = [
            self.binary, "-u", target, "-jsonl", "-silent",
            "-proxy", self.scope.proxy_url, "-rate-limit", "20",
        ]
        try:
            proc = self._run(args)
        except ScannerUnavailable:
            raise
        findings: list[ScanFinding] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = r.get("info", {})
            findings.append(ScanFinding(
                tool="nuclei",
                vuln_class=(info.get("tags") or ["misc"])[0],
                endpoint=r.get("matched-at") or r.get("host") or target,
                title=info.get("name", r.get("template-id", "nuclei match")),
                severity=_SEV_MAP.get(info.get("severity", "info"), "info"),
                evidence=r.get("template-id", ""),
                raw=r,
            ))
        return findings
