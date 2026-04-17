"""Regression tests for detector adapter error semantics."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import AgenticAdapter, LLMAdapter  # noqa: E402
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
