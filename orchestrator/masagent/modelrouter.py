"""Model routing with fast / smart / long tiers, a hard per-run spend cap, and
an optional self-hosted endpoint for air-gapped runs.

The router is the ONLY place that talks to an LLM. It tracks spend and refuses
further calls once the cap is hit, so a runaway agent cannot burn budget. When
no key is configured, it operates in deterministic-only mode: callers must be
able to proceed without an LLM (the pipeline still runs its rule-based engine).
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Rough per-1K-token prices (USD) for cost accounting only. Update as needed;
# actual billing is authoritative. Kept intentionally conservative (high) so the
# cap trips early rather than late.
TIER_MODELS = {
    "fast":  ("openai/gpt-4o-mini", 0.0002, 0.0008),
    "smart": ("anthropic/claude-sonnet-4", 0.003, 0.015),
    "long":  ("google/gemini-1.5-pro", 0.0035, 0.0105),
}


class SpendCapExceeded(RuntimeError):
    pass


@dataclass
class ModelRouter:
    api_key: str | None
    base_url: str
    spend_cap_usd: float
    self_hosted_base: str | None = None
    spent_usd: float = 0.0
    calls: int = 0
    _log: list[dict] = field(default_factory=list)

    @property
    def enabled(self) -> bool:
        return bool(self.api_key) or bool(self.self_hosted_base)

    def _account(self, tier: str, in_tok: int, out_tok: int) -> None:
        _, pin, pout = TIER_MODELS.get(tier, TIER_MODELS["fast"])
        cost = (in_tok / 1000) * pin + (out_tok / 1000) * pout
        if self.spent_usd + cost > self.spend_cap_usd:
            raise SpendCapExceeded(
                f"run spend cap ${self.spend_cap_usd:.2f} would be exceeded "
                f"(spent ${self.spent_usd:.4f}, this call ~${cost:.4f})"
            )
        self.spent_usd += cost
        self.calls += 1
        self._log.append({"tier": tier, "in": in_tok, "out": out_tok, "cost": round(cost, 6)})

    def complete(self, tier: str, system: str, prompt: str, max_tokens: int = 1024) -> str:
        """Return a completion, accounting for spend. Raises SpendCapExceeded at
        the cap. In deterministic-only mode (no key), raises RuntimeError so the
        caller uses its non-LLM path."""
        if not self.enabled:
            raise RuntimeError("no model configured; use deterministic path")
        # Estimate tokens before the call for the pre-cap check.
        est_in = (len(system) + len(prompt)) // 4
        self._account(tier, est_in, max_tokens)
        base = self.self_hosted_base or self.base_url
        model, *_ = TIER_MODELS.get(tier, TIER_MODELS["fast"])
        try:
            from openai import OpenAI  # optional dependency
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("openai client not installed; pip install masagent[llm]") from e
        client = OpenAI(api_key=self.api_key or "sk-local", base_url=base)
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system}, {"role": "user", "content": prompt}],
            max_tokens=max_tokens,
        )
        return resp.choices[0].message.content or ""

    def act(self, tier: str, messages: list[dict], tools: list[dict], max_tokens: int = 1024):
        """One tool-calling step. Returns the assistant message (SDK object with
        .content and .tool_calls); the caller appends msg.model_dump() to the
        running message list and executes any tool calls. Accounts spend and
        raises SpendCapExceeded at the cap, so an autonomous loop cannot run
        away. Raises RuntimeError in deterministic-only mode (no model)."""
        if not self.enabled:
            raise RuntimeError("no model configured; autonomous mode needs a model key")
        est_in = sum(len(str(m.get("content") or "")) for m in messages) // 4
        self._account(tier, est_in, max_tokens)
        base = self.self_hosted_base or self.base_url
        model, *_ = TIER_MODELS.get(tier, TIER_MODELS["fast"])
        try:
            from openai import OpenAI
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("openai client not installed; pip install masagent[llm]") from e
        client = OpenAI(api_key=self.api_key or "sk-local", base_url=base)
        resp = client.chat.completions.create(
            model=model, messages=messages, tools=tools,
            tool_choice="auto", max_tokens=max_tokens,
        )
        return resp.choices[0].message

    def summary(self) -> dict:
        return {"calls": self.calls, "spent_usd": round(self.spent_usd, 4), "cap_usd": self.spend_cap_usd}
