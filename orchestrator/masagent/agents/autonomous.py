"""Autonomous LLM-driven agent — the closest thing here to how XBOW works.

Instead of running scripted probes, this hands the model a set of tools and lets
it decide its own moves: make a request, read the response, form a hypothesis,
test it, chain findings, and report only what it can back with evidence. It runs
a ReAct-style tool-calling loop.

Two invariants hold no matter what the model decides:

  * Every HTTP action goes through the scope guard. The model literally cannot
    reach an out-of-scope host — the tool refuses and tells it so. Autonomy does
    not widen scope.
  * Every reported candidate still passes through the evidence gate (the PoC
    validator) before it becomes a finding. The model's say-so is a candidate,
    not a proof.

It also respects the run's spend cap (via ModelRouter) and logs every step to
the audit log, so the whole autonomous session is reproducible and defensible.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable
from urllib.parse import urlparse

from ..audit import Audit
from ..modelrouter import ModelRouter, SpendCapExceeded
from ..scope_client import ScopeClient
from .base import Candidate

# Tool schema advertised to the model.
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": (
                "Make an HTTP request to an IN-SCOPE target through the scope guard. "
                "Out-of-scope hosts are refused. Returns status, response headers and a "
                "truncated body. Use this to probe endpoints, submit inputs, and observe behavior."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]},
                    "url": {"type": "string", "description": "Absolute URL of an in-scope target."},
                    "headers": {"type": "object", "description": "Optional request headers.", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string", "description": "Optional request body (raw string or JSON)."},
                },
                "required": ["method", "url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_finding",
            "description": (
                "Report a candidate vulnerability you have gathered evidence for. Include a "
                "reproduction recipe so it can be independently re-verified. Only report what "
                "your requests actually demonstrated."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_class": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "rationale": {"type": "string", "description": "Why this is a vulnerability, citing what you observed."},
                    "reproduction": {"type": "object", "description": "Replayable recipe: kind, url/endpoint, params, marker/canary, expected observation."},
                },
                "required": ["vuln_class", "title", "severity", "rationale"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "Conclude testing this target. Call when you have exhausted useful avenues.",
            "parameters": {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]},
        },
    },
]

SYSTEM = (
    "You are an autonomous penetration-testing agent operating under EXPLICIT AUTHORIZATION "
    "for the target in scope. You may only interact with in-scope hosts; the http_request "
    "tool enforces this and will refuse anything out of scope. Work methodically: map the "
    "endpoint, form hypotheses about likely vulnerability classes (injection, XSS, SSRF, "
    "auth/session, IDOR/BOLA, access control, business logic), test them with real requests, "
    "and observe the responses. Chain findings where one enables another. Do NOT attempt "
    "destructive actions, data exfiltration beyond a minimal proof, or denial of service. "
    "Report a finding ONLY when your own requests demonstrated it, and always include a "
    "reproduction recipe. When done, call finish. Think step by step before each tool call."
)

HttpFn = Callable[[str, str, dict, str], dict]


@dataclass
class Mission:
    target: str
    params: list[str]
    surface: dict
    context: dict  # filename -> contents (docs, specs, test credentials)


class AutonomousAgent:
    def __init__(
        self,
        agent_id: str,
        scope: ScopeClient,
        audit: Audit,
        router: ModelRouter,
        http_fn: HttpFn | None = None,
        max_iterations: int = 24,
        max_body_chars: int = 2000,
        tier: str = "smart",
    ) -> None:
        self.id = agent_id
        self.scope = scope
        self.audit = audit
        self.router = router
        self.max_iterations = max_iterations
        self.max_body_chars = max_body_chars
        self.tier = tier
        self.http_fn = http_fn or self._guarded_http

    # --- the guarded HTTP tool (default implementation) ---
    def _guarded_http(self, method: str, url: str, headers: dict, body: str) -> dict:
        u = urlparse(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        allowed, reason = self.scope.check(u.hostname or "", port, actor=self.id)
        if not allowed:
            return {"error": f"out of scope: {reason}"}
        try:
            with self.scope.httpx_client(actor=self.id) as c:
                resp = c.request(method, url, headers=headers or None,
                                 content=body.encode() if body else None)
            hdrs = {k: v for k, v in resp.headers.items()
                    if k.lower() in ("content-type", "server", "location", "set-cookie", "www-authenticate")}
            return {"status": resp.status_code, "headers": hdrs,
                    "body": (resp.text or "")[: self.max_body_chars]}
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}

    def _mission_prompt(self, m: Mission) -> str:
        ctx = ""
        if m.context:
            ctx = "\n\nProvided context (use it — e.g. credentials enable authenticated and multi-role tests):\n"
            for name, content in m.context.items():
                ctx += f"\n--- {name} ---\n{str(content)[:4000]}\n"
        return (
            f"Target in scope: {m.target}\n"
            f"Known parameters: {m.params}\n"
            f"Attack-surface map (truncated):\n{json.dumps(m.surface)[:6000]}\n"
            f"{ctx}\n"
            "Test this target for vulnerabilities. Use http_request to probe, report_finding "
            "for anything you prove, and finish when done."
        )

    def run(self, mission: Mission) -> list[Candidate]:
        candidates: list[Candidate] = []
        messages: list[dict] = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": self._mission_prompt(mission)},
        ]
        self.audit.agent(self.id, "autonomous session start", target=mission.target)

        for step in range(self.max_iterations):
            try:
                msg = self.router.act(self.tier, messages, TOOLS)
            except SpendCapExceeded as e:
                self.audit.agent(self.id, "spend cap reached", reasoning=str(e))
                break
            except Exception as e:  # noqa: BLE001
                self.audit.agent(self.id, "model error", reasoning=str(e))
                break

            messages.append(_dump(msg))
            if getattr(msg, "content", None):
                self.audit.agent(self.id, "reasoning", reasoning=str(msg.content)[:1000])

            tool_calls = getattr(msg, "tool_calls", None) or []
            if not tool_calls:
                # No action taken; nudge once then stop.
                messages.append({"role": "user", "content": "Call a tool (http_request/report_finding) or finish."})
                continue

            finished = False
            for tc in tool_calls:
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = self._dispatch(name, args, candidates)
                messages.append({"role": "tool", "tool_call_id": tc.id, "content": json.dumps(result)[:4000]})
                if name == "finish":
                    finished = True
            if finished:
                break

        self.audit.agent(self.id, "autonomous session end",
                         candidates=len(candidates), steps=step + 1)
        return candidates

    def _dispatch(self, name: str, args: dict, candidates: list[Candidate]) -> dict:
        if name == "http_request":
            res = self.http_fn(args.get("method", "GET"), args.get("url", ""),
                               args.get("headers") or {}, args.get("body") or "")
            self.audit.agent(self.id, f"http_request {args.get('method')} {args.get('url')}",
                             status=res.get("status"), error=res.get("error"))
            return res
        if name == "report_finding":
            cand = Candidate(
                vuln_class=args.get("vuln_class", "business-logic"),
                endpoint=args.get("reproduction", {}).get("url")
                or args.get("reproduction", {}).get("endpoint") or "",
                title=args.get("title", "autonomous finding"),
                severity=args.get("severity", "medium"),
                rationale=args.get("rationale", ""),
                reproduction=args.get("reproduction") or {},
                confidence=0.6,
            )
            candidates.append(cand)
            self.audit.agent(self.id, "report_finding", title=cand.title, severity=cand.severity)
            return {"recorded": True, "note": "candidate queued for independent evidence-gate validation"}
        if name == "finish":
            self.audit.agent(self.id, "finish", reasoning=args.get("summary", ""))
            return {"ok": True}
        return {"error": f"unknown tool {name}"}


def _dump(msg) -> dict:
    """Normalize an SDK assistant message to a JSON-appendable dict."""
    if hasattr(msg, "model_dump"):
        return msg.model_dump()
    return {"role": "assistant", "content": getattr(msg, "content", None),
            "tool_calls": getattr(msg, "tool_calls", None)}
