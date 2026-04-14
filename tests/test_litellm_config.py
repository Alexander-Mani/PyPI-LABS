"""Regression tests for LiteLLM proxy configuration drift."""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ANALYZER_CONFIGS = _REPO_ROOT / "src" / "analyzer" / "configs"
_LITELLM_CONFIG = _REPO_ROOT / "configs" / "litellm_config.yaml"


def _analyzer_model_names() -> dict[str, str]:
    models: dict[str, str] = {}
    pattern = re.compile(r"""^model_name:\s*["']?([^"'\n#]+)""", re.MULTILINE)
    for path in sorted(_ANALYZER_CONFIGS.glob("*.yaml")):
        if path.name == "prompts.yaml":
            continue
        match = pattern.search(path.read_text(encoding="utf-8"))
        assert match is not None, f"{path} is missing model_name"
        models[path.name] = match.group(1).strip()
    return models


def _litellm_model_names() -> set[str]:
    pattern = re.compile(r"""^\s*-\s*model_name:\s*["']?([^"'\n#]+)""", re.MULTILINE)
    return {
        match.group(1).strip()
        for match in pattern.finditer(_LITELLM_CONFIG.read_text(encoding="utf-8"))
    }


def test_litellm_config_covers_analyzer_model_names():
    """Every analyzer model name must be routable through the proxy."""
    litellm_names = _litellm_model_names()
    missing = {
        f"{config_name}: {model_name}"
        for config_name, model_name in _analyzer_model_names().items()
        if model_name not in litellm_names
    }

    assert not missing


def test_litellm_drop_params_uses_litellm_settings():
    text = _LITELLM_CONFIG.read_text(encoding="utf-8")

    assert "litellm_settings:" in text
    assert not re.search(r"^general_settings:\s*\n\s+drop_params:", text, re.MULTILINE)
