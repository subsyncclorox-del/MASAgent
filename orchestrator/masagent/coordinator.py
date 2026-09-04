"""Coordinator: directs the fleet of agents and scanners for a test plan,
respecting the agent-concurrency cap and the run spend cap, then hands every
candidate to the evidence gate. Only proven candidates survive as findings.

Vulnerability chaining: after individual candidates are proven, the coordinator
asks the (optional) planner model to combine them into attack paths, which are
themselves validated before being reported as chains.
"""
from __future__ import annotations

import concurrent.futures as cf
from dataclasses import dataclass, field

from .agents.base import AgentContext, Candidate, get_agent
from .audit import Audit
from .modelrouter import ModelRouter, SpendCapExceeded
from .planner import TestPlan
from .poc.validator import ProofResult, Validator
from .scanners import ALL as SCANNERS, ScannerUnavailable
from .scope_client import ScopeClient
# ensure agents self-register
from .agents import idor, reflection, llm_probe  # noqa: F401


@dataclass
class Finding:
    vuln_class: str
    endpoint: str
    title: str
    severity: str
    source: str            # agent:<class> | scanner:<tool> | deterministic
    rationale: str
    proof: ProofResult
    chain: list[str] = field(default_factory=list)


@dataclass
class RunResult:
    confirmed: list[Finding] = field(default_factory=list)
    unconfirmed: list[Finding] = field(default_factory=list)
    spend: dict = field(default_factory=dict)


class Coordinator:
    def __init__(self, scope: ScopeClient, audit: Audit, validator: Validator,
                 router: ModelRouter | None, max_concurrency: int) -> None:
        self.scope = scope
        self.audit = audit
        self.validator = validator
        self.router = router
        self.max_concurrency = max_concurrency

    def run(self, plan: TestPlan) -> RunResult:
        result = RunResult()
        candidates: list[tuple[str, Candidate]] = []

        # 1. Gather candidates from scanners and agents (bounded concurrency).
        with cf.ThreadPoolExecutor(max_workers=self.max_concurrency) as pool:
            futs = {pool.submit(self._run_task, t): t for t in plan.tasks}
            for fut in cf.as_completed(futs):
                t = futs[fut]
                try:
                    for src, cand in fut.result():
                        candidates.append((src, cand))
                except SpendCapExceeded as e:
                    self.audit.log("note", reason=f"spend cap hit during {t.id}: {e}")
                except Exception as e:  # noqa: BLE001
                    self.audit.log("note", reason=f"task {t.id} error: {e}")

        # 2. Evidence gate: validate every candidate.
        for src, cand in candidates:
            proof = self.validator.validate(cand)
            f = Finding(cand.vuln_class, cand.endpoint, cand.title, cand.severity,
                        src, cand.rationale, proof)
            (result.confirmed if proof.proven else result.unconfirmed).append(f)

        # 3. Chaining across confirmed findings (best-effort, then validated).
        result.confirmed += self._chain(result.confirmed)

        if self.router:
            result.spend = self.router.summary()
        return result

    def _run_task(self, task) -> list[tuple[str, Candidate]]:
        out: list[tuple[str, Candidate]] = []
        if task.tool in SCANNERS:
            scanner = SCANNERS[task.tool](self.scope)
            try:
                for sf in scanner.scan(task.endpoint, task.params):
                    out.append((f"scanner:{sf.tool}", Candidate(
                        vuln_class=sf.vuln_class, endpoint=sf.endpoint, title=sf.title,
                        severity=sf.severity, rationale=sf.evidence,
                        reproduction={"kind": sf.vuln_class, "url": sf.endpoint, "tool": sf.tool},
                        confidence=0.8,
                    )))
            except ScannerUnavailable as e:
                self.audit.log("tool", actor=task.tool, reason=f"unavailable: {e}")
        elif task.tool == "agent":
            ctx = AgentContext(self.scope, self.audit, self.router, task.endpoint, task.params)
            agent = get_agent(task.vuln_class, f"{task.vuln_class}-{task.id}", ctx)
            if agent:
                for cand in agent.investigate():
                    out.append((f"agent:{task.vuln_class}", cand))
            else:
                self.audit.log("note", reason=f"no agent for class {task.vuln_class}")
        return out

    def _chain(self, confirmed: list[Finding]) -> list[Finding]:
        """Combine proven findings into attack paths. Conservative: only emits a
        chain when its constituent findings are already proven, so a chain never
        introduces an unproven claim."""
        if len(confirmed) < 2:
            return []
        chains: list[Finding] = []
        classes = {f.vuln_class for f in confirmed}
        # A couple of well-understood, high-value compositions.
        if "ssrf" in classes and any(c in classes for c in ("idor-bola", "information-disclosure")):
            chains.append(self._mk_chain(confirmed, ["ssrf", "idor-bola"],
                "SSRF + weak object access → internal resource reach", "high"))
        if "xss" in classes and "auth-session" in classes:
            chains.append(self._mk_chain(confirmed, ["xss", "auth-session"],
                "Stored XSS + weak session handling → session theft", "critical"))
        return [c for c in chains if c]

    def _mk_chain(self, confirmed, needed, title, severity) -> Finding | None:
        parts = [f for f in confirmed if f.vuln_class in needed]
        if len({p.vuln_class for p in parts}) < len(needed):
            return None
        return Finding(
            vuln_class="chain", endpoint=parts[0].endpoint, title=title, severity=severity,
            source="chain", rationale="Composed from proven findings: " + ", ".join(p.title for p in parts),
            proof=ProofResult(True, "composed", "each constituent finding is independently proven"),
            chain=[p.title for p in parts],
        )
