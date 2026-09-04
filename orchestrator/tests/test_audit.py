import json
from masagent.audit import Audit


def test_chain_written(tmp_path):
    p = tmp_path / "a.jsonl"
    a = Audit(str(p), "E")
    a.log("note", reason="one")
    a.agent("agent-1", "did a thing", reasoning="because")
    lines = p.read_text().strip().splitlines()
    assert len(lines) == 2
    e0, e1 = json.loads(lines[0]), json.loads(lines[1])
    assert e1["prev_hash"] == e0["hash"]
    assert e0["prev_hash"] == "genesis"
