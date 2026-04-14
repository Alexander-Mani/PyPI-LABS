"""Regression tests for detector adapter error semantics."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import AgenticAdapter  # noqa: E402
from entry_extractor import PackageInfo  # noqa: E402


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

    def fail_agentic_loop(pkg, system_prompt, initial_template):
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
