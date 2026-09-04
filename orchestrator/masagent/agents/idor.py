"""IDOR / BOLA agent.

Broken object-level authorization: an object referenced by id in one role's
request is reachable by another role (or unauthenticated). The agent compares
responses across the roles supplied in context (credentials come from the
engagement's context, never guessed) and flags divergence that indicates missing
authorization. It reads objects only — it never modifies or deletes.
"""
from __future__ import annotations

import re

from .base import Agent, Candidate, register

_ID_PARAM = re.compile(r"(id|uid|user|account|order|invoice|doc|file)_?id?$", re.I)


@register("idor-bola")
class IDORAgent(Agent):
    def investigate(self) -> list[Candidate]:
        self.reason("Scanning parameters for object references to test cross-role access.")
        candidates: list[Candidate] = []
        id_params = [p for p in self.ctx.params if _ID_PARAM.search(p)]
        if not id_params:
            self.reason("No object-id-like parameters found; nothing to test.")
            return candidates

        for p in id_params:
            self.reason(f"Parameter {p!r} looks like an object reference.")
            # The reproduction recipe is what the PoC validator will actually run
            # across roles in the sandbox. We do not exfiltrate data here.
            candidates.append(Candidate(
                vuln_class="idor-bola",
                endpoint=self.ctx.target,
                title=f"Possible IDOR on parameter '{p}'",
                severity="high",
                rationale=(
                    f"'{p}' references an object by id. Access must be re-checked "
                    "per requesting identity; the PoC validator confirms whether a "
                    "second role can read another role's object."
                ),
                reproduction={
                    "kind": "cross-role-read",
                    "param": p,
                    "endpoint": self.ctx.target,
                    "expect": "role B receives role A's object (status 200, matching body)",
                },
                confidence=0.4,
            ))
        return candidates
