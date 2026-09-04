import time
from pathlib import Path

import pytest

from masagent.engagement import Engagement, mint_token, verify_token, scope_digest

GOOD = """
engagement_id: ENG-42
name: Test
allow_domains: [example.com]
allow_ports: [443]
"""


def write(tmp_path, text) -> str:
    p = tmp_path / "scope.yaml"
    p.write_text(text)
    return str(p)


def test_load_good(tmp_path):
    e = Engagement.load(write(tmp_path, GOOD))
    assert e.engagement_id == "ENG-42"
    assert len(e.scope_sha) == 64


def test_refuses_no_engagement_id(tmp_path):
    with pytest.raises(ValueError):
        Engagement.load(write(tmp_path, "allow_domains: [a.com]\n"))


def test_refuses_no_targets(tmp_path):
    with pytest.raises(ValueError):
        Engagement.load(write(tmp_path, "engagement_id: X\n"))


def test_token_roundtrip(tmp_path):
    e = Engagement.load(write(tmp_path, GOOD))
    tok = mint_token("secret", e.engagement_id, e.scope_sha)
    ok, reason = verify_token("secret", tok, e.engagement_id, e.scope_sha)
    assert ok, reason


def test_token_rejects_scope_mismatch(tmp_path):
    e = Engagement.load(write(tmp_path, GOOD))
    tok = mint_token("secret", e.engagement_id, e.scope_sha)
    ok, reason = verify_token("secret", tok, e.engagement_id, "0" * 64)
    assert not ok and "scope" in reason


def test_token_rejects_forgery(tmp_path):
    e = Engagement.load(write(tmp_path, GOOD))
    tok = mint_token("secret", e.engagement_id, e.scope_sha)
    ok, _ = verify_token("wrong-secret", tok, e.engagement_id, e.scope_sha)
    assert not ok


def test_token_expiry(tmp_path):
    e = Engagement.load(write(tmp_path, GOOD))
    tok = mint_token("secret", e.engagement_id, e.scope_sha, ttl_seconds=-1)
    ok, reason = verify_token("secret", tok, e.engagement_id, e.scope_sha)
    assert not ok and "expired" in reason
