import json
import types

from masagent.agents.autonomous import AutonomousAgent, Mission
from masagent.audit import Audit


def _tc(tid, name, args):
    return types.SimpleNamespace(id=tid, function=types.SimpleNamespace(name=name, arguments=json.dumps(args)))


class _Msg:
    def __init__(self, content=None, tool_calls=None):
        self.content = content
        self.tool_calls = tool_calls or []

    def model_dump(self):
        return {"role": "assistant", "content": self.content, "tool_calls": []}


class FakeRouter:
    """Replays a scripted sequence of assistant turns."""
    enabled = True

    def __init__(self, script):
        self.script = script
        self.i = 0

    def act(self, tier, messages, tools, max_tokens=1024):
        msg = self.script[self.i]
        self.i += 1
        return msg


class FakeScope:
    def check(self, host, port=443, actor="x"):
        return (host == "in.example.com", "ok" if host == "in.example.com" else "out of scope")


def test_autonomous_loop_drives_tools_and_reports(tmp_path):
    calls = []

    def fake_http(method, url, headers, body):
        calls.append((method, url))
        return {"status": 200, "headers": {}, "body": "results for MARKER123"}

    script = [
        _Msg(content="I'll probe the search param.",
             tool_calls=[_tc("1", "http_request", {"method": "GET", "url": "https://in.example.com/?q=MARKER123"})]),
        _Msg(content="Reflected unencoded — reporting.",
             tool_calls=[_tc("2", "report_finding", {
                 "vuln_class": "xss", "title": "Reflected XSS in q", "severity": "medium",
                 "rationale": "MARKER123 reflected unencoded",
                 "reproduction": {"kind": "reflected-xss", "url": "https://in.example.com/?q=MARKER123", "marker": "MARKER123"}})]),
        _Msg(content="Done.", tool_calls=[_tc("3", "finish", {"summary": "one finding"})]),
    ]

    audit = Audit(str(tmp_path / "a.jsonl"), "T")
    agent = AutonomousAgent("auto-1", FakeScope(), audit, FakeRouter(script), http_fn=fake_http)
    cands = agent.run(Mission(target="https://in.example.com", params=["q"], surface={}, context={}))

    assert calls == [("GET", "https://in.example.com/?q=MARKER123")]
    assert len(cands) == 1
    assert cands[0].vuln_class == "xss"
    assert cands[0].reproduction["marker"] == "MARKER123"


def test_autonomous_stops_at_iteration_cap(tmp_path):
    # Model never calls a tool -> loop must terminate at the cap, not hang.
    forever = [_Msg(content="thinking...") for _ in range(100)]
    audit = Audit(str(tmp_path / "a.jsonl"), "T")
    agent = AutonomousAgent("auto-2", FakeScope(), audit, FakeRouter(forever),
                            http_fn=lambda *a: {"status": 200}, max_iterations=5)
    cands = agent.run(Mission(target="https://in.example.com", params=[], surface={}, context={}))
    assert cands == []


def test_guarded_http_refuses_out_of_scope(tmp_path):
    audit = Audit(str(tmp_path / "a.jsonl"), "T")
    agent = AutonomousAgent("auto-3", FakeScope(), audit, FakeRouter([]))
    # out-of-scope host -> tool returns an error, never touches network
    res = agent._guarded_http("GET", "https://evil.example.org/", {}, "")
    assert "error" in res and "out of scope" in res["error"]
