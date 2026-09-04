"""sqlmap integration — SQL injection detection.

Runs with conservative, non-destructive flags: detection and enumeration of the
current DB banner only (enough to prove the injection), never dumping full
tables. Batch/non-interactive; egress pinned to the scope guard proxy.
"""
from __future__ import annotations

import re

from .base import Scanner, ScanFinding, ScannerUnavailable


class SQLMap(Scanner):
    binary = "sqlmap"
    tool = "sqlmap"

    def scan(self, target: str, params: list[str] | None = None) -> list[ScanFinding]:
        self._require_scope(target)
        args = [
            self.binary, "-u", target, "--batch", "--smart",
            "--level", "1", "--risk", "1",         # conservative
            "--proxy", self.scope.proxy_url,
            "--banner",                             # minimal proof, no data dump
        ]
        if params:
            args += ["-p", ",".join(params)]
        try:
            proc = self._run(args, timeout=900)
        except ScannerUnavailable:
            raise
        out = proc.stdout + "\n" + proc.stderr
        findings: list[ScanFinding] = []
        if re.search(r"is vulnerable|parameter .* is vulnerable|sqlmap identified", out, re.I):
            param_match = re.search(r"parameter '([^']+)'", out)
            findings.append(ScanFinding(
                tool="sqlmap",
                vuln_class="sqli",
                endpoint=target,
                title=f"SQL injection in parameter {param_match.group(1) if param_match else '(see log)'}",
                severity="critical",
                evidence="sqlmap confirmed injection (banner retrieved)",
                raw={"stdout_tail": out[-2000:]},
            ))
        return findings
