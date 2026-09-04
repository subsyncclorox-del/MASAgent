"""Runtime configuration, sourced from environment with safe defaults.

Nothing here loosens the safety core: the scope guard and its proxy are always
required for any network action.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    scopeguard_proxy: str        # http://127.0.0.1:8899 — HTTP(S) egress proxy
    scopeguard_control: str      # http://127.0.0.1:8898 — allow/deny control API
    # Model routing (optional; pipeline degrades to deterministic-only if unset).
    openrouter_key: str | None
    openrouter_base: str
    self_hosted_model_base: str | None
    # Hard spend cap in USD per run. The coordinator halts agents at this cap.
    spend_cap_usd: float
    max_agent_concurrency: int
    # Docker image used for sandboxed PoC validation.
    sandbox_image: str

    @staticmethod
    def from_env() -> "Config":
        return Config(
            scopeguard_proxy=os.getenv("SCOPEGUARD_PROXY", "http://127.0.0.1:8899"),
            scopeguard_control=os.getenv("SCOPEGUARD_CONTROL", "http://127.0.0.1:8898"),
            openrouter_key=os.getenv("OPENROUTER_API_KEY"),
            openrouter_base=os.getenv("OPENROUTER_BASE", "https://openrouter.ai/api/v1"),
            self_hosted_model_base=os.getenv("SELF_HOSTED_MODEL_BASE"),
            spend_cap_usd=float(os.getenv("MASAGENT_SPEND_CAP_USD", "5.0")),
            max_agent_concurrency=int(os.getenv("MASAGENT_MAX_AGENTS", "6")),
            sandbox_image=os.getenv("MASAGENT_SANDBOX_IMAGE", "masagent/sandbox:latest"),
        )
