import masagent.discovery as disc


class FakeScope:
    """Allows anything under example.com except admin.example.com."""
    def check(self, host, port=443, actor="x"):
        if host == "admin.example.com":
            return (False, "deny_domains")
        return (host.endswith("example.com"), "ok")


def test_enumerate_filters_by_resolution_and_scope(monkeypatch):
    # Only these names "resolve".
    resolving = {"example.com", "www.example.com", "api.example.com",
                 "admin.example.com", "dashboard.example.com"}
    monkeypatch.setattr(disc, "_resolves", lambda h: h in resolving)

    hosts = disc.enumerate_subdomains(["example.com"], FakeScope())

    # resolves + in scope
    assert "www.example.com" in hosts
    assert "api.example.com" in hosts
    assert "dashboard.example.com" in hosts
    assert "example.com" in hosts
    # resolves but denied -> excluded
    assert "admin.example.com" not in hosts
    # never-resolving candidate -> excluded
    assert "grafana.example.com" not in hosts


def test_wildcard_apex_normalized(monkeypatch):
    monkeypatch.setattr(disc, "_resolves", lambda h: h == "api.example.com")
    hosts = disc.enumerate_subdomains(["*.example.com"], FakeScope())
    assert hosts == ["api.example.com"]
