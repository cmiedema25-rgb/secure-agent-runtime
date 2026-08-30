"""Composition root used by the CLI and HTTP API."""

from __future__ import annotations

import os
from pathlib import Path

from .audit import HashChainAuditLog
from .config import PolicyConfig
from .policy import PolicyEngine
from .providers.base import AgentProvider
from .providers.mock import DeterministicProvider
from .providers.openai_compatible import OpenAICompatibleProvider
from .runtime import SecureAgentRuntime
from .tools import default_registry

DEFAULT_AUDIT_KEY = "development-only-audit-key-change-me"


def build_runtime(
    *,
    policy_path: str | Path = "config/policy.toml",
    audit_path: str | Path = "var/audit.jsonl",
    provider_name: str = "offline",
) -> SecureAgentRuntime:
    config = PolicyConfig.load(policy_path)
    signing_key = os.environ.get("AUDIT_SIGNING_KEY", DEFAULT_AUDIT_KEY)
    provider: AgentProvider
    if provider_name == "offline":
        provider = DeterministicProvider()
    elif provider_name == "openai-compatible":
        provider = OpenAICompatibleProvider(
            api_key=os.environ.get("MODEL_API_KEY", ""),
            model=os.environ.get("MODEL_NAME", "gpt-4.1-mini"),
            base_url=os.environ.get("MODEL_BASE_URL", "https://api.openai.com/v1"),
            allowed_hosts=config.allowed_egress_hosts,
        )
    else:
        raise ValueError(f"unknown provider: {provider_name}")
    return SecureAgentRuntime(
        provider=provider,
        policy=PolicyEngine(config),
        tools=default_registry(),
        audit=HashChainAuditLog(audit_path, signing_key),
    )
