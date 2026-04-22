"""Regression tests for LiteLLM proxy configuration drift."""

from __future__ import annotations

import re
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ANALYZER_CONFIGS = _REPO_ROOT / "src" / "analyzer" / "configs"
_LITELLM_CONFIG = _REPO_ROOT / "configs" / "litellm_config.yaml"
_PROFILE_CONFIG = _REPO_ROOT / "configs" / "evaluation_profiles.yaml"


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


def _analyzer_model_names_by_stem() -> dict[str, str]:
    return {
        Path(config_name).stem: model_name
        for config_name, model_name in _analyzer_model_names().items()
    }


def _litellm_model_names() -> set[str]:
    pattern = re.compile(r"""^\s*-\s*model_name:\s*["']?([^"'\n#]+)""", re.MULTILINE)
    return {
        match.group(1).strip()
        for match in pattern.finditer(_LITELLM_CONFIG.read_text(encoding="utf-8"))
    }


def _profile_config_stems() -> dict[str, set[str]]:
    profiles: dict[str, set[str]] = {}
    current_profile: str | None = None
    in_configs = False

    for line in _PROFILE_CONFIG.read_text(encoding="utf-8").splitlines():
        profile_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if profile_match:
            current_profile = profile_match.group(1)
            profiles[current_profile] = set()
            in_configs = False
            continue
        if current_profile and re.match(r"^    configs:\s*$", line):
            in_configs = True
            continue
        config_match = re.match(r"^      - ([A-Za-z0-9_-]+)\s*$", line)
        if current_profile and in_configs and config_match:
            profiles[current_profile].add(config_match.group(1))

    return profiles


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


def test_litellm_router_settings_define_same_provider_fallbacks():
    text = _LITELLM_CONFIG.read_text(encoding="utf-8")

    assert "router_settings:" in text
    assert '"gemini-2.5-flash-lite": ["gemini-3.1-flash-lite-preview", "gemini-2.0-flash-lite"]' in text
    assert '"gemini-2.5-flash": ["gemini-3-flash-preview", "gemini-2.0-flash"]' in text
    assert '"gemini-2.5-pro": ["gemini-3.1-pro-preview"]' in text
    assert '"together_ai/Qwen/Qwen3.5-397B-A17B": ["together_ai/moonshotai/Kimi-K2.5", "together_ai/zai-org/GLM-5.1"]' in text


def test_evaluation_profiles_reference_existing_analyzer_configs():
    analyzer_stems = set(_analyzer_model_names_by_stem())
    missing = {
        f"{profile}: {stem}"
        for profile, stems in _profile_config_stems().items()
        for stem in stems
        if stem not in analyzer_stems
    }

    assert not missing


def test_evaluation_profiles_models_are_litellm_routable():
    analyzer_models = _analyzer_model_names_by_stem()
    litellm_names = _litellm_model_names()
    missing = {
        f"{profile}: {stem}: {analyzer_models[stem]}"
        for profile, stems in _profile_config_stems().items()
        for stem in stems
        if analyzer_models[stem] not in litellm_names
    }

    assert not missing


def test_budget_no_gemini_profile_excludes_gemini_flash_lite():
    profiles = _profile_config_stems()

    assert "gemini_flash_lite" in profiles["budget"]
    assert "gemini_flash_lite" not in profiles["budget_no_gemini"]


def test_test_profiles_have_expected_gemini_split():
    profiles = _profile_config_stems()

    assert "gemini_flash_lite" in profiles["test"]
    assert "gemini_flash_lite" not in profiles["test_no_gemini"]


def test_medium_profile_uses_medium_analyzer_configs():
    profiles = _profile_config_stems()

    assert {"claude_sonnet", "gpt_mini", "gemini_flash", "together_medium", "claude_sonnet_agentic"} <= profiles["medium"]


def test_frontier_profile_uses_frontier_analyzer_configs():
    profiles = _profile_config_stems()

    assert {"claude_opus", "gpt", "gemini", "together_frontier", "claude_agentic"} <= profiles["frontier"]


def test_all_models_profile_includes_budget_medium_and_frontier_profiles():
    profiles = _profile_config_stems()

    expected = profiles["budget"] | profiles["medium"] | profiles["frontier"]
    assert expected <= profiles["all_models"]


def test_agentic_configs_use_plan_then_execute_flow():
    for stem in ("claude_haiku_agentic", "claude_sonnet_agentic", "claude_agentic"):
        text = (_ANALYZER_CONFIGS / f"{stem}.yaml").read_text(encoding="utf-8")
        assert 'agentic_flow: "plan_then_execute"' in text
        assert re.search(r"^max_turns:\s*8\s*$", text, re.MULTILINE)
