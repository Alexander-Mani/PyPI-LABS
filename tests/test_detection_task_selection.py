"""Tests for analyzer detector task-selection gates."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from detection_controller import EvalController  # noqa: E402
from prompt_manager import PromptManager  # noqa: E402


class _FakePromptManager:
    def llm_strategy_names(self):
        return ["zero_shot", "few_shot", "role_based"]

    def agentic_strategy_names(self):
        return ["zero_shot", "role_based"]

    def get_llm_strategy(self, name):
        return f"{name}-system", f"{name}-template"

    def get_agentic_strategy(self, name):
        return f"{name}-system", f"{name}-initial"


def _controller():
    controller = EvalController.__new__(EvalController)
    controller._static = [object(), object()]
    controller._llm = [object()]
    controller._llm_raw = [object()]
    controller._agentic = [object()]
    return controller


def test_task_selection_gates_static_agentic_and_llm_lanes(monkeypatch):
    fake_pm = _FakePromptManager()
    monkeypatch.setattr(PromptManager, "instance", classmethod(lambda cls: fake_pm))
    controller = _controller()
    llm_count = len(fake_pm.llm_strategy_names())
    agentic_count = len(fake_pm.agentic_strategy_names())

    assert len(controller._build_tasks(sast_only=True)) == 2
    assert len(controller._build_tasks(skip_static=True, skip_agentic=True)) == llm_count * 2
    assert len(controller._build_tasks(only_agentic=True)) == agentic_count
    assert len(controller._build_tasks(skip_agentic=True)) == 2 + (llm_count * 2)
    alias_probe_tasks = controller._build_tasks(hybrid_zero_shot_only=True)
    assert len(alias_probe_tasks) == 1
    assert alias_probe_tasks[0][0] is controller._llm[0]
    assert alias_probe_tasks[0][1] == "zero_shot"


def test_task_selection_rejects_impossible_agentic_combination():
    controller = _controller()

    try:
        controller._build_tasks(only_agentic=True, skip_agentic=True)
    except ValueError as exc:
        message = str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("task selection should reject only_agentic + skip_agentic")

    assert "only_agentic" in message


def test_runtime_max_tokens_override_updates_non_agentic_llm_lanes():
    class _FakeAdapter:
        def __init__(self, value):
            self._max_tokens = value

    controller = EvalController.__new__(EvalController)
    controller._llm = [_FakeAdapter(256)]
    controller._llm_raw = [_FakeAdapter(384)]
    controller._agentic = [_FakeAdapter(512)]

    controller._apply_runtime_overrides(max_tokens_override=4096)

    assert controller._llm[0]._max_tokens == 4096
    assert controller._llm_raw[0]._max_tokens == 4096
    assert controller._agentic[0]._max_tokens == 4096
