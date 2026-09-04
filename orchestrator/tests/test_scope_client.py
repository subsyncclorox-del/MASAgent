from masagent.scope_client import ScopeClient, ScopeError
import pytest


def test_fails_closed_when_guard_down():
    # Point at a port nothing is listening on: must fail CLOSED (deny).
    sc = ScopeClient("http://127.0.0.1:9", "http://127.0.0.1:9")
    allowed, reason = sc.check("example.com", 443)
    assert allowed is False
    assert "failing closed" in reason or "unreachable" in reason


def test_require_raises_when_out_of_scope():
    sc = ScopeClient("http://127.0.0.1:9", "http://127.0.0.1:9")
    with pytest.raises(ScopeError):
        sc.require("example.com", 443)
