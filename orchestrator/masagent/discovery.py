"""Subdomain discovery for site-wide / estate-wide testing.

Passive by construction: it performs DNS lookups only, for candidate names
*under an in-scope apex domain*. It never contacts a third-party OSINT service,
and every discovered host is scope-checked before it enters the pipeline, so an
enumerated name that a deny rule excludes is dropped.

This is what turns a single-target run into a site-wide one: point at
example.com and it also finds api.example.com, dashboard.example.com, etc.,
then the orchestrator runs the full pipeline against each.
"""
from __future__ import annotations

import concurrent.futures as cf
import socket

from .scope_client import ScopeClient

# Common subdomain labels for DNS brute-force. Compact but high-yield.
COMMON_LABELS = [
    "www", "api", "app", "apps", "dashboard", "demo", "staging", "stage", "dev",
    "test", "qa", "uat", "beta", "alpha", "sandbox", "preview", "prod",
    "admin", "portal", "console", "manage", "my", "account", "accounts",
    "auth", "login", "secure", "sso", "id",
    "cdn", "assets", "static", "img", "images", "media", "files", "download",
    "mail", "smtp", "webmail", "email", "mx", "imap", "pop",
    "blog", "shop", "store", "help", "support", "docs", "status", "kb",
    "graphql", "ws", "socket", "rt", "stream", "chat", "widget",
    "edge", "functions", "fn", "api-v1", "api-v2", "v1", "v2",
    "git", "gitlab", "ci", "jenkins", "build", "registry",
    "grafana", "kibana", "monitor", "metrics", "logs", "prometheus",
    "db", "database", "redis", "cache", "internal", "intranet", "vpn",
    "ns1", "ns2", "new", "old", "legacy", "origin", "gateway", "proxy",
]


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except OSError:
        return False


def enumerate_subdomains(
    apexes: list[str],
    scope: ScopeClient,
    extra_labels: list[str] | None = None,
    max_workers: int = 50,
) -> list[str]:
    """Return sorted, de-duplicated, in-scope hosts discovered under `apexes`.

    A wildcard apex ("*.x.com") is normalized to its base ("x.com").
    """
    labels = list(dict.fromkeys(COMMON_LABELS + (extra_labels or [])))
    candidates: list[str] = []
    for apex in apexes:
        base = apex[2:] if apex.startswith("*.") else apex
        candidates.append(base)                       # the apex itself
        candidates += [f"{label}.{base}" for label in labels]
    candidates = list(dict.fromkeys(candidates))

    resolved: list[str] = []
    with cf.ThreadPoolExecutor(max_workers=max_workers) as pool:
        for host, ok in zip(candidates, pool.map(_resolves, candidates)):
            if ok:
                resolved.append(host)

    # Keep only what the scope guard confirms is in scope (deny rules can carve
    # out an individual host even under an allowed apex).
    in_scope: list[str] = []
    for host in resolved:
        allowed, _ = scope.check(host, 443, actor="discovery")
        if allowed:
            in_scope.append(host)
    return sorted(set(in_scope))
