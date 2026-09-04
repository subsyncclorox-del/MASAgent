"""Reflection agent — reflected-input candidate detection (XSS / injection sink).

Sends a benign, uniquely-identifiable marker (no active payload) into each
parameter and checks whether it is reflected unencoded. A raw reflection is a
candidate; the PoC validator later confirms exploitability in the sandbox with a
contained proof. This keeps false positives out and avoids firing live payloads
during discovery.
"""
from __future__ import annotations

import secrets
from urllib.parse import urlencode, urlparse, parse_qs

from .base import Agent, Candidate, register


@register("xss")
class ReflectionAgent(Agent):
    def investigate(self) -> list[Candidate]:
        candidates: list[Candidate] = []
        marker = "masa" + secrets.token_hex(4)
        params = self.ctx.params or ["q"]
        self.reason(f"Probing {len(params)} parameter(s) for unencoded reflection with marker {marker}.")

        u = urlparse(self.ctx.target)
        base_q = parse_qs(u.query)
        for p in params:
            q = {**{k: v[0] for k, v in base_q.items()}, p: marker}
            test_url = u._replace(query=urlencode(q)).geturl()
            try:
                resp = self.request("GET", test_url)
            except Exception as e:  # noqa: BLE001
                self.reason(f"Request for {p} failed: {e}")
                continue
            body = resp.text or ""
            if marker in body:
                encoded = f"&lt;{marker}" in body or f"%3C{marker}" in body
                candidates.append(Candidate(
                    vuln_class="xss",
                    endpoint=test_url,
                    title=f"Reflected input in parameter '{p}'",
                    severity="medium",
                    rationale=(
                        f"Marker reflected {'(HTML-encoded)' if encoded else 'UNENCODED'} in the "
                        "response. Unencoded reflection is an XSS candidate; the PoC validator "
                        "confirms script execution in a sandboxed browser."
                    ),
                    reproduction={
                        "kind": "reflected-xss",
                        "param": p,
                        "url": test_url,
                        "marker": marker,
                        "encoded_on_discovery": encoded,
                        "expect": "sandboxed browser executes a contained proof payload",
                    },
                    confidence=0.7 if not encoded else 0.2,
                ))
        return candidates
