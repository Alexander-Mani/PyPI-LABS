"""prompt_manager.py — singleton registry for named prompt strategies."""
from __future__ import annotations

from pathlib import Path

import yaml

_PROMPTS_YAML = Path(__file__).resolve().parent / "configs" / "prompts.yaml"


class PromptManager:
    """
    Loads configs/prompts.yaml once and exposes strategy lookup.

    Usage:
        pm = PromptManager.instance()
        system, user_tpl = pm.get_llm_strategy("few_shot")
        system, init_msg = pm.get_agentic_strategy("role_based")
    """

    _inst: PromptManager | None = None

    def __init__(self, path: Path = _PROMPTS_YAML):
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        self._strategies: dict = data.get("strategies", {})
        self._agentic: dict    = data.get("agentic_strategies", {})

    @classmethod
    def instance(cls) -> PromptManager:
        if cls._inst is None:
            cls._inst = cls()
        return cls._inst

    def llm_strategy_names(self) -> list[str]:
        return list(self._strategies.keys())

    def agentic_strategy_names(self) -> list[str]:
        return list(self._agentic.keys())

    def get_llm_strategy(self, name: str) -> tuple[str, str]:
        """Returns (system_prompt, user_template)."""
        s = self._strategies[name]
        return s["system_prompt"], s["user_template"]

    def get_agentic_strategy(self, name: str) -> tuple[str, str]:
        """Returns (system_prompt, initial_user_message)."""
        s = self._agentic[name]
        return s["system_prompt"], s["initial_user_message"]
