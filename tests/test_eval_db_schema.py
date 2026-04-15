"""
Regression tests for version/artifact-aware evaluation result storage.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from src.data.db_manager import DBManager  # noqa: E402


def test_eval_results_do_not_collide_across_versions_or_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(DBManager, "DB_PATH", tmp_path / "eval_results.db")
    db = DBManager()
    db.create_eval_run("run-1", "budget")

    common = {
        "run_id": "run-1",
        "package_name": "num2words",
        "experiment_mode": "static",
        "prompt_strategy": "zero_shot",
        "detector": "bandit",
        "verdict": True,
        "ground_truth": True,
        "heuristic_flags": [],
        "input_tokens": 0,
        "output_tokens": 0,
        "exec_time_ms": 1,
        "api_cost_usd": 0.0,
    }
    db.insert_eval_result(version="0.5.15", artifact_filename="num2words-0.5.15.whl", **common)
    db.insert_eval_result(version="0.5.16", artifact_filename="num2words-0.5.16.whl", **common)
    db.insert_eval_result(version="0.5.16", artifact_filename="num2words-0.5.16.tar.gz", **common)

    rows = db.get_eval_results_for_run("run-1")
    assert [(r["version"], r["artifact_filename"]) for r in rows] == [
        ("0.5.15", "num2words-0.5.15.whl"),
        ("0.5.16", "num2words-0.5.16.whl"),
        ("0.5.16", "num2words-0.5.16.tar.gz"),
    ]


def test_eval_results_reject_conflicting_ground_truth(monkeypatch, tmp_path):
    monkeypatch.setattr(DBManager, "DB_PATH", tmp_path / "eval_results.db")
    db = DBManager()
    db.create_eval_run("run-1", "budget")

    common = {
        "run_id": "run-1",
        "package_name": "num2words",
        "version": "0.5.16",
        "experiment_mode": "static",
        "prompt_strategy": "zero_shot",
        "detector": "bandit",
        "verdict": True,
        "heuristic_flags": [],
        "input_tokens": 0,
        "output_tokens": 0,
        "exec_time_ms": 1,
        "api_cost_usd": 0.0,
    }
    db.insert_eval_result(
        artifact_filename="num2words-0.5.16.whl",
        ground_truth=True,
        **common,
    )

    try:
        db.insert_eval_result(
            artifact_filename="num2words-0.5.16.tar.gz",
            ground_truth=False,
            **common,
        )
    except ValueError as exc:
        assert "conflicting ground_truth" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("conflicting ground truth should halt")
