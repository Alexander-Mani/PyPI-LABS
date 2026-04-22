"""Regression tests for detector adapter error semantics."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import AgenticAdapter, LLMAdapter, LLMRawAdapter, ProxyCallResult  # noqa: E402
from entry_extractor import PackageInfo  # noqa: E402


class _FakeUsage:
    prompt_tokens = 11
    completion_tokens = 7


class _FakeMessage:
    content = '{"verdict":"benign","confidence":0.9}'
    tool_calls = None


class _FakeChoice:
    message = _FakeMessage()
    finish_reason = "stop"


class _FakeParsedResponse:
    usage = _FakeUsage()
    choices = [_FakeChoice()]
    model = "gpt-5.4-nano"


class _FakeLegacyAPIResponse:
    headers = {"x-litellm-response-cost": "0.0012"}

    def parse(self):
        return _FakeParsedResponse()


class _FakeCompletions:
    def __init__(self):
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeLegacyAPIResponse()


class _FakeOpenAIClient:
    completions = _FakeCompletions()

    def __init__(self, base_url, api_key):
        self.base_url = base_url
        self.api_key = api_key
        chat = type("Chat", (), {"completions": self.completions})()
        self.with_raw_response = type("Raw", (), {"chat": chat})()


def _install_fake_openai(monkeypatch):
    fake_module = type("OpenAIModule", (), {"OpenAI": _FakeOpenAIClient})()
    monkeypatch.setitem(sys.modules, "openai", fake_module)
    _FakeOpenAIClient.completions.calls.clear()
    return _FakeOpenAIClient.completions


def test_agentic_adapter_llm_failure_returns_error_not_benign(monkeypatch):
    adapter = AgenticAdapter.__new__(AgenticAdapter)
    adapter._model_name = "claude-haiku-4-5"
    adapter._system_prompt = ""
    adapter._initial_template = "Investigate {package_name} {version}"
    adapter._max_turns = 5
    adapter._temperature = 0.0
    adapter._proxy_url = "http://127.0.0.1:4000"
    adapter._detector_name = "claude_haiku_agentic"
    adapter._current_pkg = None

    def fail_agentic_loop(pkg, system_prompt, initial_template, **kwargs):
        raise RuntimeError("proxy failed")

    monkeypatch.setattr(adapter, "_agentic_loop", fail_agentic_loop)
    pkg = PackageInfo(name="demo", version="1.0.0", files={}, files_raw={})

    result = adapter.run(pkg)

    assert result.detector == "claude_haiku_agentic"
    assert result.experiment_mode == "error"
    assert result.verdict is False
    assert result.input_tokens == 0
    assert result.output_tokens == 0
    assert result.details["model"] == "claude-haiku-4-5"
    assert "proxy failed" in result.details["error"]
    assert adapter._current_pkg is None


def test_llm_adapter_proxy_raw_response_is_not_context_manager(monkeypatch):
    completions = _install_fake_openai(monkeypatch)
    adapter = LLMAdapter.__new__(LLMAdapter)
    adapter._model_name = "gpt-5.4-nano"
    adapter._temperature = 0.0
    adapter._detector_name = "gpt_nano"
    adapter._proxy_url = "http://127.0.0.1:4000"

    text, input_tokens, output_tokens, cost = adapter._call_via_proxy(
        "system prompt",
        "user prompt",
    )

    assert text == '{"verdict":"benign","confidence":0.9}'
    assert input_tokens == 11
    assert output_tokens == 7
    assert cost == 0.0012
    assert completions.calls[0]["model"] == "gpt-5.4-nano"


def _make_llm_adapter() -> LLMAdapter:
    adapter = LLMAdapter.__new__(LLMAdapter)
    adapter._model_name = "gpt-5.4-nano"
    adapter._temperature = 0.0
    adapter._system_prompt = "system"
    adapter._user_template = "{file_listing}"
    adapter._detector_name = "gpt_nano"
    adapter._proxy_url = "http://127.0.0.1:4000"
    adapter._response_format = None
    adapter._extra_body = None
    adapter._retry_attempts = 0
    adapter._retry_delay_seconds = 0.0
    adapter._retry_unparseable = False
    adapter._retry_transport_categories = set()
    adapter._retry_protocol_errors = set()
    adapter._fallback_models = []
    return adapter


def _pkg() -> PackageInfo:
    return PackageInfo(
        name="demo",
        version="1.0.0",
        files={"setup.py": "print('x')\n"},
        files_raw={"setup.py": "print('x')\n"},
        heuristic_flags=["shell_execution"],
    )


def test_llm_protocol_failure_empty_response_is_final_error_without_protocol_retry(monkeypatch):
    adapter = _make_llm_adapter()
    monkeypatch.setattr(adapter, "_call_api", lambda *args, **kwargs: ("", 101, 3, 0.0042))

    result = adapter.run(_pkg(), prompt_strategy="few_shot")

    assert result.experiment_mode == "error"
    assert result.verdict is False
    assert result.input_tokens == 101
    assert result.output_tokens == 3
    assert result.api_cost_usd == 0.0042
    assert result.details["error"] == "empty_model_response"
    assert result.details["retryable"] is False
    assert result.details["protocol_failure"] is True
    assert result.details["intended_mode"] == "hybrid"


def test_llm_protocol_failure_non_json_response_is_unparseable_error(monkeypatch):
    adapter = _make_llm_adapter()
    monkeypatch.setattr(adapter, "_call_api", lambda *args, **kwargs: ("I think this is safe.", 11, 9, 0.001))

    result = adapter.run(_pkg(), prompt_strategy="zero_shot")

    assert result.experiment_mode == "error"
    assert result.details["error"] == "unparseable_model_response"
    assert result.details["retryable"] is False
    assert result.details["raw"] == "I think this is safe."


def test_llm_protocol_failure_missing_verdict_is_error(monkeypatch):
    adapter = _make_llm_adapter()
    monkeypatch.setattr(adapter, "_call_api", lambda *args, **kwargs: ('{"confidence": 0.2}', 11, 9, 0.001))

    result = adapter.run(_pkg(), prompt_strategy="zero_shot")

    assert result.experiment_mode == "error"
    assert result.details["error"] == "unparseable_model_response"
    assert result.details["parse_error"] == "missing_or_invalid_verdict"


def test_llm_valid_json_response_remains_success(monkeypatch):
    adapter = _make_llm_adapter()
    monkeypatch.setattr(adapter, "_call_api", lambda *args, **kwargs: ('{"verdict": "malicious", "confidence": 0.8}', 11, 9, 0.001))

    result = adapter.run(_pkg(), prompt_strategy="zero_shot")

    assert result.experiment_mode == "hybrid"
    assert result.verdict is True
    assert result.confidence == 0.8


def test_llm_raw_protocol_failure_preserves_cost_and_mode(monkeypatch):
    adapter = LLMRawAdapter.__new__(LLMRawAdapter)
    adapter._model_name = "gpt-5.4-nano"
    adapter._temperature = 0.0
    adapter._system_prompt = "system"
    adapter._user_template = "{file_listing}"
    adapter._detector_name = "gpt_nano"
    adapter._proxy_url = "http://127.0.0.1:4000"
    adapter._response_format = None
    adapter._extra_body = None
    adapter._retry_attempts = 0
    adapter._retry_delay_seconds = 0.0
    adapter._retry_unparseable = False
    adapter._retry_transport_categories = set()
    adapter._retry_protocol_errors = set()
    adapter._fallback_models = []
    monkeypatch.setattr(adapter, "_call_api", lambda *args, **kwargs: ("", 21, 4, 0.002))

    result = adapter.run(_pkg(), prompt_strategy="role_based")

    assert result.experiment_mode == "error"
    assert result.input_tokens == 21
    assert result.output_tokens == 4
    assert result.api_cost_usd == 0.002
    assert result.details["error"] == "empty_model_response"
    assert result.details["intended_mode"] == "llm_raw"


def test_llm_proxy_response_format_is_forwarded(monkeypatch):
    completions = _install_fake_openai(monkeypatch)
    adapter = _make_llm_adapter()
    adapter._model_name = "together_ai/Qwen/Qwen3.5-9B"
    adapter._response_format = {"type": "json_object"}

    call = adapter._call_via_proxy("system prompt", "user prompt")

    assert call.requested_model == "together_ai/Qwen/Qwen3.5-9B"
    assert completions.calls[0]["response_format"] == {"type": "json_object"}
    assert "reasoning" not in completions.calls[0]


def test_llm_protocol_failure_can_fallback_to_secondary_model(monkeypatch):
    adapter = _make_llm_adapter()
    adapter._model_name = "gemini-2.5-flash"
    adapter._retry_attempts = 0
    adapter._retry_delay_seconds = 0.0
    adapter._retry_protocol_errors = {"empty_model_response"}
    adapter._fallback_models = ["gemini-3-flash-preview"]
    calls = []

    def fake_call_api(*args, **kwargs):
        calls.append(kwargs["model_name"])
        if kwargs["model_name"] == "gemini-2.5-flash":
            return ("", 10, 2, 0.001)
        return ProxyCallResult(
            text='{"verdict":"benign","confidence":0.7}',
            input_tokens=12,
            output_tokens=4,
            cost_usd=0.002,
            requested_model=kwargs["requested_model"],
            actual_model=kwargs["model_name"],
            pricing_model=kwargs["model_name"],
        )

    monkeypatch.setattr(adapter, "_call_api", fake_call_api)

    result = adapter.run(_pkg(), prompt_strategy="zero_shot")

    assert calls == ["gemini-2.5-flash", "gemini-3-flash-preview"]
    assert result.experiment_mode == "hybrid"
    assert result.details["requested_model"] == "gemini-2.5-flash"
    assert result.details["actual_model"] == "gemini-3-flash-preview"
    assert result.details["fallback_used"] is True
    assert result.details["pricing_breakdown"] == [
        {"model": "gemini-2.5-flash", "input_tokens": 10, "output_tokens": 2},
        {"model": "gemini-3-flash-preview", "input_tokens": 12, "output_tokens": 4},
    ]


def test_llm_transport_rate_limit_retries_when_category_is_enabled(monkeypatch):
    adapter = _make_llm_adapter()
    adapter._model_name = "gemini-2.5-flash"
    adapter._retry_attempts = 14
    adapter._retry_delay_seconds = 30.0
    adapter._retry_transport_categories = {"rate_limit", "provider_overload"}
    calls = {"count": 0}

    def fake_call_api(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] < 3:
            raise RuntimeError("Error code: 429 - quota exceeded")
        return ProxyCallResult(
            text='{"verdict":"benign","confidence":0.7}',
            input_tokens=12,
            output_tokens=4,
            cost_usd=0.002,
            requested_model=kwargs["requested_model"],
            actual_model=kwargs["model_name"],
            pricing_model=kwargs["model_name"],
        )

    monkeypatch.setattr(adapter, "_call_api", fake_call_api)
    monkeypatch.setattr(adapter, "_retry_sleep", lambda: None)

    result = adapter.run(_pkg(), prompt_strategy="zero_shot")

    assert calls["count"] == 3
    assert result.experiment_mode == "hybrid"
    assert result.details["requested_model"] == "gemini-2.5-flash"
    assert result.details["actual_model"] == "gemini-2.5-flash"
    assert result.details["attempt_count"] == 3


def test_agentic_proxy_raw_response_is_not_context_manager(monkeypatch):
    completions = _install_fake_openai(monkeypatch)
    adapter = AgenticAdapter.__new__(AgenticAdapter)
    adapter._model_name = "claude-haiku-4-5"
    adapter._system_prompt = ""
    adapter._max_turns = 5
    adapter._temperature = 0.0
    adapter._proxy_url = "http://127.0.0.1:4000"
    adapter._detector_name = "claude_haiku_agentic"

    response = adapter._make_api_call(
        [{"role": "user", "content": "inspect package"}],
        system_prompt="system prompt",
    )

    assert response["content"] == [
        {"type": "text", "text": '{"verdict":"benign","confidence":0.9}'}
    ]
    assert response["stop_reason"] == "end_turn"
    assert response["input_tokens"] == 11
    assert response["output_tokens"] == 7
    assert response["cost_usd"] == 0.0012
    assert completions.calls[0]["model"] == "claude-haiku-4-5"


def test_agentic_protocol_failure_preserves_cost_and_mode(monkeypatch):
    adapter = AgenticAdapter.__new__(AgenticAdapter)
    adapter._model_name = "claude-haiku-4-5"
    adapter._system_prompt = ""
    adapter._initial_template = "Investigate {package_name} {version}"
    adapter._max_turns = 5
    adapter._temperature = 0.0
    adapter._proxy_url = "http://127.0.0.1:4000"
    adapter._agentic_flow = "plan_then_execute"
    adapter._detector_name = "claude_haiku_agentic"
    adapter._current_pkg = None
    adapter._last_plan = {"next_steps": ["read setup.py"]}

    def non_json_agentic_loop(pkg, system_prompt, initial_template, **kwargs):
        return "No malware found.", 301, 12, 0.09

    monkeypatch.setattr(adapter, "_agentic_loop", non_json_agentic_loop)

    result = adapter.run(_pkg(), prompt_strategy="role_based")

    assert result.experiment_mode == "error"
    assert result.input_tokens == 301
    assert result.output_tokens == 12
    assert result.api_cost_usd == 0.09
    assert result.details["error"] == "unparseable_model_response"
    assert result.details["retryable"] is False
    assert result.details["intended_mode"] == "agentic"
    assert result.details["agentic_flow"] == "plan_then_execute"
    assert adapter._current_pkg is None


def _make_agentic_adapter_for_plan_tests() -> AgenticAdapter:
    adapter = AgenticAdapter.__new__(AgenticAdapter)
    adapter._model_name = "claude-haiku-4-5"
    adapter._system_prompt = "system"
    adapter._initial_template = "Investigate {package_name} {version}"
    adapter._max_turns = 5
    adapter._temperature = 0.0
    adapter._proxy_url = "http://127.0.0.1:4000"
    adapter._agentic_flow = "plan_then_execute"
    adapter._detector_name = "claude_haiku_agentic"
    adapter._current_pkg = None
    adapter._last_plan = None
    return adapter


def test_agentic_plan_then_execute_runs_plan_before_verdict(monkeypatch):
    adapter = _make_agentic_adapter_for_plan_tests()
    calls = []

    def fake_make_api_call(messages, system_prompt=None, **kwargs):
        calls.append({"messages": messages, **kwargs})
        if kwargs.get("phase") == "plan":
            assert kwargs.get("tools_enabled") is False
            return {
                "content": [{"type": "text", "text": '{"suspicious_paths":["setup.py"],"search_terms":["exec"],"risk_hypotheses":["install hook"],"next_steps":["read setup.py"]}'}],
                "stop_reason": "end_turn",
                "input_tokens": 5,
                "output_tokens": 3,
                "cost_usd": 0.01,
            }
        assert kwargs.get("phase") == "turn"
        assert kwargs.get("tools_enabled", True) is True
        return {
            "content": [{"type": "text", "text": '{"verdict":"malicious","confidence":0.8,"reasoning":"setup hook executes encoded code"}'}],
            "stop_reason": "end_turn",
            "input_tokens": 7,
            "output_tokens": 4,
            "cost_usd": 0.02,
        }

    monkeypatch.setattr(adapter, "_make_api_call", fake_make_api_call)
    pkg = PackageInfo(
        name="demo",
        version="1.0.0",
        files={"setup.py": "exec('x')\n"},
        files_raw={"setup.py": "exec('x')\n"},
    )

    result = adapter.run(pkg, prompt_strategy="role_based")

    assert result.experiment_mode == "agentic"
    assert result.verdict is True
    assert result.input_tokens == 12
    assert result.output_tokens == 7
    assert result.api_cost_usd == 0.03
    assert result.details["agentic_flow"] == "plan_then_execute"
    assert result.details["plan"]["suspicious_paths"] == ["setup.py"]
    assert [call["phase"] for call in calls] == ["plan", "turn"]
    assert "Do not give a verdict yet" in calls[0]["messages"][0]["content"]


def test_agentic_plan_phase_verdict_is_error_not_benign(monkeypatch):
    adapter = _make_agentic_adapter_for_plan_tests()

    def fake_make_api_call(messages, system_prompt=None, **kwargs):
        return {
            "content": [{"type": "text", "text": '{"verdict":"benign","confidence":0.1}'}],
            "stop_reason": "end_turn",
            "input_tokens": 5,
            "output_tokens": 3,
            "cost_usd": 0.01,
        }

    monkeypatch.setattr(adapter, "_make_api_call", fake_make_api_call)
    pkg = PackageInfo(name="demo", version="1.0.0", files={"setup.py": ""}, files_raw={})

    result = adapter.run(pkg)

    assert result.experiment_mode == "error"
    assert result.verdict is False
    assert "verdict before investigation" in result.details["error"]


def test_agentic_read_only_helper_tools_search_and_file_info():
    adapter = _make_agentic_adapter_for_plan_tests()
    adapter._current_pkg = PackageInfo(
        name="demo",
        version="1.0.0",
        files={
            "setup.py": "import os\nos.system('curl http://example.invalid')\n",
            "pkg/__init__.py": "print('safe')\n",
        },
        files_raw={"setup.py": "import os\n"},
    )

    search = adapter._handle_tool("search_files", {"pattern": "os\\.system", "path_glob": "*.py"})
    info = adapter._handle_tool("file_info", {"path": "setup.py"})
    missing = adapter._handle_tool("file_info", {"path": "missing.py"})

    assert search["matches"][0]["path"] == "setup.py"
    assert info["exists"] is True
    assert info["in_raw_entrypoints"] is True
    assert missing == {"path": "missing.py", "exists": False}
