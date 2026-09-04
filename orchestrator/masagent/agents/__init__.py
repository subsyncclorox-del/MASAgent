"""Agent swarm.

Each agent owns one endpoint or vuln class, reasons about it, tests it through
the scope guard, interprets results, and iterates. Agents produce *candidate*
findings only; nothing is reported until the PoC validator reproduces it in the
sandbox (evidence-gated).

Every agent action goes through ScopeClient (network) and logs its reasoning to
the audit log (explainability). Agents have no raw network handle.
"""
from .base import Agent, Candidate, AgentContext, registry, get_agent

__all__ = ["Agent", "Candidate", "AgentContext", "registry", "get_agent"]
