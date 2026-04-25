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


def _profile_shadow_stems() -> dict[str, set[str]]:
    profiles: dict[str, set[str]] = {}
    current_profile: str | None = None
    in_shadow = False

    for line in _PROFILE_CONFIG.read_text(encoding="utf-8").splitlines():
        profile_match = re.match(r"^  ([A-Za-z0-9_-]+):\s*$", line)
        if profile_match:
            current_profile = profile_match.group(1)
            profiles[current_profile] = set()
            in_shadow = False
            continue
        if current_profile and re.match(r"^    shadow_detector_stems:\s*$", line):
            in_shadow = True
            continue
        shadow_match = re.match(r"^      - ([A-Za-z0-9_-]+)\s*$", line)
        if current_profile and in_shadow and shadow_match:
            profiles[current_profile].add(shadow_match.group(1))
            continue
        if in_shadow and line.startswith("    ") and line.strip() and not line.startswith("      "):
            in_shadow = False

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
    assert "gemini-2.0-flash" not in text
    assert "gemini-2.0-flash-lite" not in text
    assert '"together_ai/moonshotai/Kimi-K2.5": ["together_ai/zai-org/GLM-5.1"]' not in text


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
    shadow_profiles = _profile_shadow_stems()

    assert "gemini_flash_lite" in profiles["test"]
    assert "gemini_flash_lite" not in profiles["test_no_gemini"]
    assert profiles["gemini_only"] == {"gemini_resilient_flash", "gemini_resilient_pro"}
    assert profiles["gemini_only_test"] == {"gemini_resilient_flash", "gemini_resilient_pro"}
    assert shadow_profiles["frontier"] == {"together_frontier_qwen"}
    assert shadow_profiles["all_models"] == {"together_frontier_qwen"}
    assert profiles["frontier_together_bakeoff"] == {
        "together_frontier_kimi_bench",
        "together_frontier_glm51_bench",
        "together_frontier_qwen397b_bench",
        "together_frontier_minimax25_bench",
    }


def test_medium_profile_uses_medium_analyzer_configs():
    profiles = _profile_config_stems()

    assert {"claude_sonnet", "gpt_mini", "gemini_flash", "together_medium", "claude_sonnet_agentic"} <= profiles["medium"]


def test_frontier_profile_uses_frontier_analyzer_configs():
    profiles = _profile_config_stems()

    assert {"claude_opus", "gpt", "gemini", "together_frontier", "together_frontier_qwen", "claude_agentic"} <= profiles["frontier"]


def test_frontier_together_configs_use_kimi_and_qwen_frontier_models():
    kimi_text = (_ANALYZER_CONFIGS / "together_frontier.yaml").read_text(encoding="utf-8")
    qwen_text = (_ANALYZER_CONFIGS / "together_frontier_qwen.yaml").read_text(encoding="utf-8")

    assert 'model_name: "together_ai/moonshotai/Kimi-K2.5"' in kimi_text
    assert 'model_name: "together_ai/Qwen/Qwen3.5-397B-A17B"' in qwen_text
    for text in (kimi_text, qwen_text):
        assert 'max_tokens: 8192' in text
        assert 'type: "json_schema"' in text
        assert 'name: "supply_chain_verdict"' in text
        assert "fallback_models" not in text


def test_frontier_bakeoff_configs_use_json_schema_and_1024_tokens():
    stems = (
        "together_frontier_kimi_bench",
        "together_frontier_glm51_bench",
        "together_frontier_qwen397b_bench",
        "together_frontier_minimax25_bench",
    )

    for stem in stems:
        text = (_ANALYZER_CONFIGS / f"{stem}.yaml").read_text(encoding="utf-8")
        assert 'max_tokens: 1024' in text
        assert 'type: "json_schema"' in text
        assert 'name: "supply_chain_verdict"' in text
        assert "fallback_models" not in text


def test_frontier_bakeoff_models_are_routable_through_litellm():
    litellm_names = _litellm_model_names()

    assert "together_ai/Qwen/Qwen3.5-397B-A17B" in litellm_names
    assert "together_ai/moonshotai/Kimi-K2.5" in litellm_names
    assert "together_ai/zai-org/GLM-5.1" in litellm_names
    assert "together_ai/MiniMaxAI/MiniMax-M2.5" in litellm_names


def test_gemini_resilient_configs_use_schema_and_reasoning_controls():
    flash_text = (_ANALYZER_CONFIGS / "gemini_resilient_flash.yaml").read_text(encoding="utf-8")
    pro_text = (_ANALYZER_CONFIGS / "gemini_resilient_pro.yaml").read_text(encoding="utf-8")

    for text in (flash_text, pro_text):
        assert 'max_tokens: 1024' in text
        assert 'type: "json_schema"' in text
        assert 'name: "supply_chain_verdict"' in text
        assert "fallback_models" not in text

    assert 'reasoning_effort: "none"' in flash_text
    assert 'reasoning_effort: "minimal"' in pro_text


def test_canonical_gemini_medium_and_frontier_configs_use_promoted_hardening():
    flash_text = (_ANALYZER_CONFIGS / "gemini_flash.yaml").read_text(encoding="utf-8")
    pro_text = (_ANALYZER_CONFIGS / "gemini.yaml").read_text(encoding="utf-8")

    for text in (flash_text, pro_text):
        assert 'max_tokens: 1024' in text
        assert 'type: "json_schema"' in text
        assert 'name: "supply_chain_verdict"' in text

    assert 'reasoning_effort: "none"' in flash_text
    assert 'reasoning_effort: "minimal"' in pro_text


def test_all_models_profile_includes_budget_medium_and_frontier_profiles():
    profiles = _profile_config_stems()

    expected = profiles["budget"] | profiles["medium"] | profiles["frontier"]
    assert expected <= profiles["all_models"]


def test_agentic_configs_use_plan_then_execute_flow():
    for stem in ("claude_haiku_agentic", "claude_sonnet_agentic", "claude_agentic"):
        text = (_ANALYZER_CONFIGS / f"{stem}.yaml").read_text(encoding="utf-8")
        assert 'agentic_flow: "plan_then_execute"' in text
        assert re.search(r"^max_turns:\s*8\s*$", text, re.MULTILINE)
