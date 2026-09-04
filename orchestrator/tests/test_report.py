from masagent.coordinator import Finding
from masagent.poc.validator import ProofResult
from masagent.report.report import Report, render_json, render_markdown, render_bugbounty
import json


def mkf(cls, sev, title="t"):
    return Finding(cls, "https://example.com", title, sev, "agent:x", "why",
                   ProofResult(True, "sandbox", "evidence"))


def test_dedupe_and_rank():
    rep = Report("E", "https://example.com",
                 confirmed=[mkf("xss", "medium"), mkf("xss", "medium"), mkf("sqli", "critical")])
    rep.dedupe_and_rank()
    assert len(rep.confirmed) == 2                    # deduped identical xss
    assert rep.confirmed[0].severity == "critical"    # ranked first


def test_renderers():
    rep = Report("E", "https://example.com", confirmed=[mkf("sqli", "critical")])
    rep.dedupe_and_rank()
    assert "CRITICAL" in render_markdown(rep)
    assert json.loads(render_json(rep))["summary"]["confirmed"] == 1
    assert "Steps to reproduce" in render_bugbounty(rep)
