"""Agent config (brain) loading.

An *agent config* is a YAML file describing the agent's brain — the
system prompt and the model the agent runs on. Identity (keypair,
agent_id) is a separate concern handled by :class:`Identity`.

The two are deliberately decoupled:

- Identity is durable and rarely changes (rotation is a real event).
- Brain config is iteration-friendly — operators tune prompts and swap
  models often. Coupling them would force identity churn for every
  prompt tweak.

Schema (v0.1):

.. code-block:: yaml

    sys_prompt: |
      You are "Danny Hype." Keep it short.
    model:
      type: anthropic
      name: claude-haiku-4-5-20251001
      api_key_env: ANTHROPIC_API_KEY
      # additional fields (temperature, max_tokens, etc.) pass through
      # untouched to whatever LLM client consumes the dict.

Forward-compat: any unknown top-level fields are preserved on
``AgentConfig.raw`` so consumers can read future extensions without
the SDK gating them.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class AgentConfig:
    """Parsed agent config: sys_prompt + model block."""

    sys_prompt: str
    model: dict[str, Any]
    raw: dict[str, Any]
    """Full parsed YAML — preserves forward-compat fields the SDK
    doesn't yet know about."""

    @classmethod
    def from_yaml_file(cls, path: str | Path) -> "AgentConfig":
        """Load an agent config from a YAML file.

        Raises:
            FileNotFoundError: file doesn't exist.
            ValueError: YAML is missing required fields or malformed.
        """
        path = Path(path)
        if not path.is_file():
            raise FileNotFoundError(f"Agent config YAML not found: {path}")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            raise ValueError(
                f"Agent config at {path} must be a YAML mapping at top level"
            )
        return cls._from_dict(data, source=str(path))

    @classmethod
    def _from_dict(cls, data: dict[str, Any], *, source: str) -> "AgentConfig":
        sys_prompt = data.get("sys_prompt")
        if not isinstance(sys_prompt, str) or not sys_prompt.strip():
            raise ValueError(
                f"Agent config at {source} is missing a non-empty 'sys_prompt'"
            )
        model = data.get("model")
        if not isinstance(model, dict) or not model:
            raise ValueError(
                f"Agent config at {source} is missing a non-empty 'model' block"
            )
        return cls(sys_prompt=sys_prompt, model=dict(model), raw=dict(data))


__all__ = ["AgentConfig"]
