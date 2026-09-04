"""Planner: turn the recon attack-surface map into a prioritized test plan.

Deterministic first — the plan is derived from concrete surface (forms, params,
endpoints, tech). When a model is available, it refines ordering and adds
hypotheses, but the pipeline never depends on the LLM to produce a usable plan.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict

from .modelrouter import ModelRouter

# Vulnerability classes MASAgent tests for. Kept explicit so coverage is auditable.
VULN_CLASSES = [
    "sqli", "xss", "ssti", "command-injection", "ssrf", "path-traversal",
    "file-upload", "deserialization", "auth-session", "idor-bola",
    "privilege-escalation", "graphql-abuse", "business-logic", "prompt-injection",
    "information-disclosure", "security-misconfiguration",
]


@dataclass
class TestTask:
    id: str
    endpoint: str
    vuln_class: str
    tool: str            # deterministic | nuclei | sqlmap | dalfox | agent
    priority: int        # 1 (highest) .. 5
    rationale: str = ""
    params: list[str] = field(default_factory=list)


@dataclass
class TestPlan:
    target: str
    tasks: list[TestTask] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({"target": self.target, "tasks": [asdict(t) for t in self.tasks]}, indent=2)


def _seed_tasks(surface: dict) -> list[TestTask]:
    tasks: list[TestTask] = []
    n = 0

    def add(endpoint, vuln, tool, prio, why, params=None):
        nonlocal n
        n += 1
        tasks.append(TestTask(f"T{n:03d}", endpoint, vuln, tool, prio, why, params or []))

    target = surface.get("target", "")
    spider = surface.get("spider") or {}
    params = surface.get("parameters") or []

    # Forms -> injection + xss (highest priority: user-controlled sinks).
    for page in (spider.get("pages") or []):
        for form in (page.get("forms") or []):
            action = form.get("action") or page.get("url")
            inputs = form.get("inputs") or []
            add(action, "sqli", "sqlmap", 1, f"form with inputs {inputs}", inputs)
            add(action, "xss", "dalfox", 1, f"reflected/stored candidate on {inputs}", inputs)

    # Query parameters -> idor/bola + injection + reflected-xss.
    if params:
        add(target, "idor-bola", "agent", 1, f"object-id-like params: {params}", params)
        add(target, "sqli", "sqlmap", 2, f"query params: {params}", params)
        # Built-in agent covers XSS even when dalfox is unavailable.
        add(target, "xss", "agent", 1, f"reflected-xss probe on query params: {params}", params)

    # Tech-specific nuclei templates.
    fp = surface.get("fingerprint") or {}
    for t in (fp.get("tech") or []):
        add(target, "business-logic", "nuclei", 3, f"tech {t.get('name')} -> known-CVE templates")
        break

    # Always run the baseline nuclei misconfig/exposure set.
    add(target, "ssrf", "nuclei", 2, "baseline SSRF/exposure templates")
    add(target, "path-traversal", "nuclei", 2, "baseline traversal templates")

    # If deterministic findings already exist, queue agent verification.
    for f in (surface.get("deterministic_findings") or []):
        add(f.get("url", target), f.get("class", "business-logic"), "agent", 2,
            f"verify deterministic finding: {f.get('title')}")

    return tasks


def build_plan(surface: dict, router: ModelRouter | None = None) -> TestPlan:
    plan = TestPlan(target=surface.get("target", ""), tasks=_seed_tasks(surface))

    if router and router.enabled:
        try:
            hint = router.complete(
                tier="smart",
                system=(
                    "You are a penetration-test planner for AUTHORIZED testing. "
                    "Given an attack-surface map and a seed task list, return a JSON "
                    "array of extra {endpoint,vuln_class,priority,rationale} tasks that "
                    "target likely-high-impact issues the seed list missed. Only "
                    "in-scope endpoints. No exploitation instructions — just what to test."
                ),
                prompt=json.dumps({"surface": surface, "seed_tasks": [t.id for t in plan.tasks]})[:12000],
                max_tokens=800,
            )
            extra = json.loads(hint)
            base = len(plan.tasks)
            for i, e in enumerate(extra, 1):
                if e.get("vuln_class") in VULN_CLASSES:
                    plan.tasks.append(TestTask(
                        id=f"T{base + i:03d}",
                        endpoint=e.get("endpoint", plan.target),
                        vuln_class=e["vuln_class"],
                        tool="agent",
                        priority=int(e.get("priority", 3)),
                        rationale="(llm) " + str(e.get("rationale", "")),
                    ))
        except Exception:  # noqa: BLE001 — LLM refinement is best-effort only
            pass

    plan.tasks.sort(key=lambda t: t.priority)
    return plan
