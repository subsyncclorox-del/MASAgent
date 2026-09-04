from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from ..audit import Audit
from ..modelrouter import ModelRouter
from ..scope_client import ScopeClient


@dataclass
class Candidate:
    """A candidate finding. `reproduction` is a structured, replayable recipe the
    PoC validator will run in the sandbox. No proof here yet — just the claim and
    how to test it."""
    vuln_class: str
    endpoint: str
    title: str
    severity: str            # info|low|medium|high|critical
    rationale: str
    reproduction: dict = field(default_factory=dict)  # {method,url,headers,body,expect}
    confidence: float = 0.5


@dataclass
class AgentContext:
    scope: ScopeClient
    audit: Audit
    router: ModelRouter | None
    target: str
    params: list[str] = field(default_factory=list)


class Agent:
    """Base agent. Subclasses implement `investigate` and return candidates.

    The base class enforces the invariants: a scope check before any request and
    an audit entry for every step. Subclasses should call `self.request(...)`
    rather than doing their own HTTP.
    """
    vuln_class: str = "generic"

    def __init__(self, agent_id: str, ctx: AgentContext) -> None:
        self.id = agent_id
        self.ctx = ctx

    def request(self, method: str, url: str, **kw):
        from urllib.parse import urlparse
        u = urlparse(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        self.ctx.scope.require(u.hostname or "", port, actor=self.id)  # fails closed
        with self.ctx.scope.httpx_client(actor=self.id) as c:
            resp = c.request(method, url, **kw)
        self.ctx.audit.agent(self.id, f"{method} {url} -> {resp.status_code}")
        return resp

    def reason(self, note: str) -> None:
        self.ctx.audit.agent(self.id, "reasoning", reasoning=note)

    def investigate(self) -> list[Candidate]:  # pragma: no cover - overridden
        raise NotImplementedError


# --- Registry ---------------------------------------------------------------

registry: dict[str, Callable[[str, AgentContext], Agent]] = {}


def register(vuln_class: str):
    def deco(cls):
        cls.vuln_class = vuln_class
        registry[vuln_class] = cls
        return cls
    return deco


def get_agent(vuln_class: str, agent_id: str, ctx: AgentContext) -> Agent | None:
    cls = registry.get(vuln_class)
    return cls(agent_id, ctx) if cls else None
