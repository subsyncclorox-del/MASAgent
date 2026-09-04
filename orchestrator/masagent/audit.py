"""Orchestrator-side audit log.

A hash-chained JSONL log mirroring the Go audit format, so agent reasoning,
scanner runs, PoC attempts and findings are all attributable and tamper-evident.
Written to orchestrator-<engagement>.jsonl alongside the guard's own log.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path


class Audit:
    def __init__(self, path: str, engagement_id: str) -> None:
        self._path = Path(path)
        self._eid = engagement_id
        self._prev = "genesis"
        self._lock = threading.Lock()

    def _hash(self, event: dict) -> str:
        e = dict(event)
        e["hash"] = ""
        return hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def log(self, kind: str, **fields) -> None:
        with self._lock:
            event = {
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "engagement_id": self._eid,
                "kind": kind,
                **fields,
                "prev_hash": self._prev,
                "hash": "",
            }
            event["hash"] = self._hash(event)
            self._prev = event["hash"]
            with self._path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")

    def agent(self, agent_id: str, action: str, reasoning: str = "", **detail) -> None:
        self.log("agent", actor=agent_id, reason=action, detail={"reasoning": reasoning, **detail})

    def finding(self, finding_id: str, title: str, severity: str, **detail) -> None:
        self.log("finding", target=finding_id, reason=title, detail={"severity": severity, **detail})
