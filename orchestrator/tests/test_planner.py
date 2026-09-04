import json
from masagent.planner import build_plan, VULN_CLASSES

SURFACE = {
    "target": "https://example.com/search?q=1",
    "parameters": ["q", "user_id"],
    "fingerprint": {"tech": [{"name": "nginx"}], "security_headers_missing": ["Content-Security-Policy"]},
    "spider": {"pages": [{"url": "https://example.com/login",
                          "forms": [{"action": "https://example.com/login", "method": "POST",
                                     "inputs": ["username", "password"]}]}]},
    "deterministic_findings": [{"url": "https://example.com/.env", "title": "Exposed .env", "class": "information-disclosure"}],
}


def test_plan_has_tasks_and_is_sorted():
    plan = build_plan(SURFACE, None)
    assert plan.tasks
    prios = [t.priority for t in plan.tasks]
    assert prios == sorted(prios)


def test_plan_covers_expected_classes():
    plan = build_plan(SURFACE, None)
    classes = {t.vuln_class for t in plan.tasks}
    assert "sqli" in classes
    assert "idor-bola" in classes
    assert classes <= set(VULN_CLASSES)


def test_plan_json_serializable():
    json.loads(build_plan(SURFACE, None).to_json())
