"""Consolidate, dedupe, rank and render findings.

Outputs: JSON (machine), Markdown (human), and a bug-bounty submission format.
Only PROVEN findings appear in the report body; unconfirmed candidates go in an
appendix clearly marked as needing manual confirmation.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Report:
    engagement_id: str
    target: str
    confirmed: list = field(default_factory=list)   # list[Finding]
    unconfirmed: list = field(default_factory=list)
    spend: dict = field(default_factory=dict)

    def dedupe_and_rank(self) -> None:
        self.confirmed = _dedupe(self.confirmed)
        self.unconfirmed = _dedupe(self.unconfirmed)
        self.confirmed.sort(key=lambda f: (_SEV_RANK.get(f.severity, 5), f.vuln_class))


def _dedupe(findings: list) -> list:
    seen: dict[tuple, object] = {}
    for f in findings:
        key = (f.vuln_class, f.endpoint, f.title)
        if key not in seen:
            seen[key] = f
    return list(seen.values())


def _finding_dict(f) -> dict:
    return {
        "vuln_class": f.vuln_class, "endpoint": f.endpoint, "title": f.title,
        "severity": f.severity, "source": f.source, "rationale": f.rationale,
        "chain": getattr(f, "chain", []),
        "proof": {"proven": f.proof.proven, "method": f.proof.method, "evidence": f.proof.evidence},
    }


def render_json(rep: Report) -> str:
    return json.dumps({
        "engagement_id": rep.engagement_id,
        "target": rep.target,
        "summary": {
            "confirmed": len(rep.confirmed),
            "unconfirmed": len(rep.unconfirmed),
            "by_severity": _by_severity(rep.confirmed),
        },
        "spend": rep.spend,
        "findings": [_finding_dict(f) for f in rep.confirmed],
        "unconfirmed": [_finding_dict(f) for f in rep.unconfirmed],
    }, indent=2)


def _by_severity(findings) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        out[f.severity] = out.get(f.severity, 0) + 1
    return out


def render_markdown(rep: Report) -> str:
    lines = [
        f"# MASAgent report — {rep.target}",
        "",
        f"**Engagement:** `{rep.engagement_id}`  ",
        f"**Confirmed findings:** {len(rep.confirmed)} · **Unconfirmed:** {len(rep.unconfirmed)}",
        "",
        "> Every finding below was reproduced with a proof (evidence-gated). "
        "Unconfirmed candidates are listed separately and require manual review.",
        "",
        "## Confirmed findings",
        "",
    ]
    if not rep.confirmed:
        lines.append("_No findings could be proven._")
    for i, f in enumerate(rep.confirmed, 1):
        lines += [
            f"### {i}. {f.title} — `{f.severity.upper()}`",
            "",
            f"- **Class:** {f.vuln_class}",
            f"- **Endpoint:** {f.endpoint}",
            f"- **Source:** {f.source}",
            f"- **Proof ({f.proof.method}):** {f.proof.evidence}",
        ]
        if getattr(f, "chain", []):
            lines.append(f"- **Attack chain:** {' → '.join(f.chain)}")
        lines += ["", f"{f.rationale}", ""]
    if rep.unconfirmed:
        lines += ["## Unconfirmed candidates (manual review needed)", ""]
        for f in rep.unconfirmed:
            lines.append(f"- {f.title} ({f.severity}) @ {f.endpoint} — {f.proof.evidence}")
    if rep.spend:
        lines += ["", "## Run cost", "", f"```json\n{json.dumps(rep.spend, indent=2)}\n```"]
    return "\n".join(lines) + "\n"


def render_bugbounty(rep: Report) -> str:
    """One markdown block per confirmed finding, in a typical bounty format."""
    blocks = []
    for f in rep.confirmed:
        blocks.append("\n".join([
            f"## {f.title}",
            "",
            f"**Severity:** {f.severity}",
            f"**Asset:** {f.endpoint}",
            "",
            "### Summary",
            f.rationale,
            "",
            "### Steps to reproduce",
            f"Reproduced via {f.proof.method}. Evidence:",
            "",
            "```",
            f.proof.evidence,
            "```",
            "",
            "### Impact",
            f"Class: {f.vuln_class}. See severity rating.",
            "",
            "---",
        ]))
    return "\n".join(blocks) if blocks else "_No confirmed findings to submit._\n"
