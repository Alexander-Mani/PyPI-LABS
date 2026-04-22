"""Regression tests for financial validation model-profile failure handling."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import EvalDetectionResult  # noqa: E402
from entry_extractor import PackageInfo  # noqa: E402
from evaluate import EvaluationRunner  # noqa: E402


class _FakeDB:
    def create_eval_run(self, run_id, tier="unknown"):
        return None


class _FakeExtractor:
    def extract(self, archive_path):
        return PackageInfo(name="colorama", version="0.4.6", files={}, files_raw={})


class _FakeFilter:
    def scan(self, pkg):
        return pkg


def _runner_with_controller(controller):
    runner = EvaluationRunner.__new__(EvaluationRunner)
    runner._tier = "budget"
    runner._run_label = "profile:budget"
    runner._db = _FakeDB()
    runner._extractor = _FakeExtractor()
    runner._filter = _FakeFilter()
    runner._controller = controller
    runner._resolve_simulator_samples = lambda download=False: [
        SimpleNamespace(
            archive_path=Path("/tmp/colorama-0.4.6.whl"),
            package_name="colorama",
            version="0.4.6",
            ground_truth=False,
            artifact_filename="colorama-0.4.6.whl",
            artifact_url="http://127.0.0.1:8080/packages/colorama/colorama-0.4.6.whl",
            source_index_url="http://127.0.0.1:8080/simple/colorama/",
            sample_role="benign",
            attack_vector=None,
            resolver_policy="{}",
        )
    ]
    runner._download_sample = lambda sample: sample.archive_path
    return runner


def test_financial_validation_passes_when_selected_detector_succeeds():
    class Controller:
        def expected_non_static_detectors(self, **kwargs):
            return {"gpt_nano"}

        def run(self, **kwargs):
            return [
                EvalDetectionResult(
                    detector="bandit",
                    experiment_mode="static",
                    verdict=False,
                    confidence=None,
                    heuristic_flags=[],
                    exec_time_ms=1,
                    api_cost_usd=0.0,
                ),
                EvalDetectionResult(
                    detector="gpt_nano",
                    experiment_mode="hybrid",
                    verdict=False,
                    confidence=0.9,
                    heuristic_flags=[],
                    exec_time_ms=1,
                    api_cost_usd=0.000027,
                    input_tokens=100,
                    output_tokens=20,
                    details={"model": "gpt-5.4-nano"},
                ),
            ]

    _runner_with_controller(Controller())._validate_financial_airgap()


def test_financial_validation_warns_not_halts_on_cost_divergence_under_cap():
    class Controller:
        def expected_non_static_detectors(self, **kwargs):
            return {"gpt_nano"}

        def run(self, **kwargs):
            return [
                EvalDetectionResult(
                    detector="gpt_nano",
                    experiment_mode="hybrid",
                    verdict=False,
                    confidence=0.9,
                    heuristic_flags=[],
                    exec_time_ms=1,
                    api_cost_usd=0.0001,
                    input_tokens=100,
                    output_tokens=20,
                    details={"model": "gpt-5.4-nano"},
                ),
            ]

    _runner_with_controller(Controller())._validate_financial_airgap()


def test_financial_validation_halts_when_selected_detector_all_errors():
    class Controller:
        def expected_non_static_detectors(self, **kwargs):
            return {"gemini_flash_lite"}

        def run(self, **kwargs):
            return [
                EvalDetectionResult(
                    detector="gemini_flash_lite",
                    experiment_mode="error",
                    verdict=False,
                    confidence=None,
                    heuristic_flags=[],
                    exec_time_ms=1,
                    api_cost_usd=0.0,
                    details={
                        "model": "gemini-2.5-flash-lite",
                        "error": "503 high demand",
                    },
                )
            ]

    try:
        _runner_with_controller(Controller())._validate_financial_airgap()
    except SystemExit as exc:
        message = str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("financial validation should halt")

    assert "gemini_flash_lite" in message
    assert "gemini-2.5-flash-lite" in message
    assert "503 high demand" in message
    assert "--profile budget_no_gemini" in message


def test_financial_validation_uses_actual_cost_when_fallback_price_is_unknown():
    class Controller:
        def expected_non_static_detectors(self, **kwargs):
            return {"gemini_flash"}

        def run(self, **kwargs):
            return [
                EvalDetectionResult(
                    detector="gemini_flash",
                    experiment_mode="hybrid",
                    verdict=False,
                    confidence=0.9,
                    heuristic_flags=[],
                    exec_time_ms=1,
                    api_cost_usd=0.004,
                    input_tokens=220,
                    output_tokens=50,
                    details={
                        "model": "gemini-3.1-pro-preview",
                        "pricing_breakdown": [
                            {"model": "gemini-2.5-flash", "input_tokens": 100, "output_tokens": 20},
                            {"model": "gemini-3.1-pro-preview", "input_tokens": 120, "output_tokens": 30},
                        ],
                    },
                ),
            ]

    _runner_with_controller(Controller())._validate_financial_airgap()
