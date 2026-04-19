"""Tests for analyzer progress and cost bookkeeping helpers."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import EvalDetectionResult  # noqa: E402
from detection_controller import EvalController  # noqa: E402
from entry_extractor import PackageInfo  # noqa: E402
from progress_ui import CostLedger, provider_for_model, should_use_progress  # noqa: E402


def test_provider_for_model_known_prefixes():
    assert provider_for_model("claude-haiku-4-5") == "anthropic"
    assert provider_for_model("anthropic/claude-haiku-4-5") == "anthropic"
    assert provider_for_model("gpt-5.4-nano") == "openai"
    assert provider_for_model("openai/gpt-5.4-nano") == "openai"
    assert provider_for_model("gemini-2.5-flash-lite") == "google"
    assert provider_for_model("together_ai/Qwen/Qwen3.5-9B") == "together"


def test_cost_ledger_accumulates_provider_totals_and_unknown_once():
    ledger = CostLedger()

    provider, first_unknown = ledger.add("claude-haiku-4-5", 0.01)
    assert provider == "anthropic"
    assert first_unknown is False

    provider, first_unknown = ledger.add("unknown-model", 0.02)
    assert provider == "other"
    assert first_unknown is True

    provider, first_unknown = ledger.add("unknown-model", 0.03)
    assert provider == "other"
    assert first_unknown is False

    assert round(ledger.totals["anthropic"], 6) == 0.01
    assert round(ledger.totals["other"], 6) == 0.05
    assert round(ledger.total, 6) == 0.06


def test_dry_run_resolution_disables_progress_even_when_forced():
    assert should_use_progress("always", dry_run_resolution=True) is False


class _FakeDB:
    def __init__(self):
        self.rows = []

    def insert_eval_result(self, **kwargs):
        self.rows.append(kwargs)


class _FakeAdapter:
    _tool = "fake_static"
    _experiment_mode = "static"

    def run(self, pkg, strategy, system_prompt, template_override):
        return EvalDetectionResult(
            detector=self._tool,
            experiment_mode="static",
            verdict=False,
            confidence=None,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.0,
        )


def test_controller_emits_task_and_result_events():
    db = _FakeDB()
    controller = EvalController.__new__(EvalController)
    controller._db = db
    controller._static = [_FakeAdapter()]
    controller._llm = []
    controller._llm_raw = []
    controller._agentic = []

    task_events = []
    result_events = []
    pkg = PackageInfo(name="demo", version="1.0.0", files={}, files_raw={})

    results = controller.run(
        run_id="run-1",
        pkg=pkg,
        ground_truth=False,
        sast_only=True,
        artifact_filename="demo-1.0.0.tar.gz",
        on_tasks_prepared=task_events.append,
        on_result=lambda result, strategy, mode: result_events.append(
            (result.detector, strategy, mode)
        ),
        quiet_console=True,
    )

    assert len(results) == 1
    assert task_events == [[{
        "detector": "fake_static",
        "mode": "static",
        "strategy": "zero_shot",
    }]]
    assert result_events == [("fake_static", "zero_shot", "static")]
    assert len(db.rows) == 1


def test_progress_visible_rows_prioritize_errors_and_running():
    from progress_ui import AnalyzerProgress, MAX_VISIBLE_DETECTOR_ROWS, _DetectorRow

    rows = [
        _DetectorRow(detector=f"done-{i}", mode="hybrid", strategy="zero_shot", state="done", elapsed_s=1.0)
        for i in range(MAX_VISIBLE_DETECTOR_ROWS + 5)
    ]
    rows.append(_DetectorRow(detector="broken", mode="static", strategy="zero_shot", state="error", error="missing"))
    rows.append(_DetectorRow(detector="slow", mode="llm_raw", strategy="few_shot", state="queued/running"))

    visible, hidden = AnalyzerProgress._visible_detector_rows(rows)
    visible_names = {row.detector for row in visible}

    assert len(visible) == MAX_VISIBLE_DETECTOR_ROWS
    assert hidden == len(rows) - MAX_VISIBLE_DETECTOR_ROWS
    assert "broken" in visible_names
    assert "slow" in visible_names


def test_progress_refresh_is_throttled(monkeypatch):
    from progress_ui import AnalyzerProgress, MIN_REFRESH_INTERVAL_S

    progress = AnalyzerProgress(enabled=False, total_samples=1, run_id="run", run_label="profile:test")
    calls = []

    class LiveStub:
        def refresh(self):
            calls.append("refresh")

    progress._live = LiveStub()
    times = iter([10.0, 10.1, 10.1 + MIN_REFRESH_INTERVAL_S + 0.01])
    monkeypatch.setattr("progress_ui.time.monotonic", lambda: next(times))

    progress.refresh()
    progress.refresh()
    progress.refresh()

    assert calls == ["refresh", "refresh"]
