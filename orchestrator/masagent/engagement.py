"""Engagement + per-engagement authorization token.

An engagement token is bound to a specific scope: it carries the engagement id
and a hash of the scope file. The API authorization gate (TypeScript) and any
job submission must present a token whose scope hash matches the loaded scope,
so a token minted for one engagement cannot drive a job against another target.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml


def scope_digest(scope_path: str | os.PathLike) -> str:
    """Stable sha256 over the canonicalized scope document."""
    doc = yaml.safe_load(Path(scope_path).read_text())
    canonical = json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class Engagement:
    engagement_id: str
    scope_path: str
    scope_sha: str = ""
    name: str = ""
    started_at: float = field(default_factory=time.time)

    @staticmethod
    def load(scope_path: str) -> "Engagement":
        doc = yaml.safe_load(Path(scope_path).read_text())
        eid = doc.get("engagement_id")
        if not eid:
            raise ValueError("scope file has no engagement_id; refusing to start")
        if not doc.get("allow_domains") and not doc.get("allow_cidrs"):
            raise ValueError("scope allows no targets; there is no test-everything mode")
        return Engagement(
            engagement_id=eid,
            scope_path=scope_path,
            scope_sha=scope_digest(scope_path),
            name=doc.get("name", ""),
        )


def mint_token(secret: str, engagement_id: str, scope_sha: str, ttl_seconds: int = 86400) -> str:
    """HMAC-signed engagement token: <eid>.<scope_sha>.<exp>.<sig>."""
    exp = int(time.time()) + ttl_seconds
    payload = f"{engagement_id}.{scope_sha}.{exp}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def verify_token(secret: str, token: str, engagement_id: str, scope_sha: str) -> tuple[bool, str]:
    """Reject any token whose engagement/scope does not match, is expired, or is
    forged. This is the check that stops a job running against an out-of-token
    target."""
    try:
        eid, sha, exp_s, sig = token.split(".")
    except ValueError:
        return False, "malformed token"
    payload = f"{eid}.{sha}.{exp_s}"
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        return False, "bad signature"
    if int(exp_s) < int(time.time()):
        return False, "token expired"
    if eid != engagement_id:
        return False, "token engagement mismatch"
    if sha != scope_sha:
        return False, "token scope mismatch (scope file changed since token was minted)"
    return True, "ok"
