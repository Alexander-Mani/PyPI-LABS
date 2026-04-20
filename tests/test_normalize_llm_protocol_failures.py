"""Tests for historical LLM protocol-failure DB normalization."""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts.normalize_llm_protocol_failures import normalize_llm_protocol_failures  # noqa: E402
from src.data.db_manager import DBManager  # noqa: E402


def _open_rows(db_path: Path) -> list[sqlite3.Row]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute("SELECT * FROM eval_result ORDER BY id").fetchall()
    finally:
        conn.close()


def _insert_row(db: DBManager, *, mode: str, detector: str, strategy: str, details: dict, artifact: str = "demo.whl") -> None:
    db.insert_eval_result(
        run_id="run-1",
        package_name="demo",
        version="1.0.0",
        experiment_mode=mode,
        prompt_strategy=strategy,
        detector=detector,
        artifact_filename=artifact,
        verdict=False,
        ground_truth=True,
        heuristic_flags=[],
        input_tokens=10,
        output_tokens=5,
        exec_time_ms=100,
        api_cost_usd=0.123,
        details=details,
    )


def test_normalizer_dry_run_does_not_mutate(monkeypatch, tmp_path):
    db_path = tmp_path / "eval_results.db"
    monkeypatch.setattr(DBManager, "DB_PATH", db_path)
    db = DBManager()
    db.create_eval_run("run-1", "budget")
    _insert_row(db, mode="hybrid", detector="gpt_nano", strategy="zero_shot", details={"raw": "", "model": "gpt-5.4-nano"})
    db.close()

    report = normalize_llm_protocol_failures(db_path)

    assert report.applied is False
    assert report.would_update == 1
    rows = _open_rows(db_path)
    assert rows[0]["experiment_mode"] == "hybrid"


def test_normalizer_converts_raw_llm_rows_to_errors(monkeypatch, tmp_path):
    db_path = tmp_path / "eval_results.db"
    monkeypatch.setattr(DBManager, "DB_PATH", db_path)
    db = DBManager()
    db.create_eval_run("run-1", "budget")
    _insert_row(db, mode="hybrid", detector="gpt_nano", strategy="zero_shot", details={"raw": "", "model": "gpt-5.4-nano"})
    _insert_row(
        db,
        mode="llm_raw",
        detector="claude_haiku",
        strategy="few_shot",
        details={"raw": "Plain English answer", "model": "claude-haiku-4-5"},
        artifact="demo.tar.gz",
    )
    _insert_row(
        db,
        mode="static",
        detector="fake_static",
        strategy="zero_shot",
        details={"raw": "static metadata should not be touched"},
        artifact="static.whl",
    )
    db.close()

    report = normalize_llm_protocol_failures(db_path, apply=True, backup=False)

    assert report.would_update == 2
    rows = _open_rows(db_path)
    by_artifact = {row["artifact_filename"]: row for row in rows}

    empty = by_artifact["demo.whl"]
    assert empty["experiment_mode"] == "error"
    assert empty["input_tokens"] == 10
    assert empty["api_cost_usd"] == 0.123
    empty_details = json.loads(empty["details"])
    assert empty_details["error"] == "empty_model_response"
    assert empty_details["retryable"] is True
    assert empty_details["intended_mode"] == "hybrid"
    assert empty_details["original_experiment_mode"] == "hybrid"

    unparseable = by_artifact["demo.tar.gz"]
    assert unparseable["experiment_mode"] == "error"
    unparseable_details = json.loads(unparseable["details"])
    assert unparseable_details["error"] == "unparseable_model_response"
    assert unparseable_details["retryable"] is False
    assert unparseable_details["intended_mode"] == "llm_raw"

    static_row = by_artifact["static.whl"]
    assert static_row["experiment_mode"] == "static"


def test_normalizer_reports_collision_without_mutating(monkeypatch, tmp_path):
    db_path = tmp_path / "eval_results.db"
    monkeypatch.setattr(DBManager, "DB_PATH", db_path)
    db = DBManager()
    db.create_eval_run("run-1", "budget")
    _insert_row(db, mode="hybrid", detector="gpt_nano", strategy="zero_shot", details={"raw": "", "model": "gpt-5.4-nano"})
    _insert_row(
        db,
        mode="error",
        detector="gpt_nano",
        strategy="zero_shot",
        details={"error": "existing error", "intended_mode": "hybrid"},
    )
    db.close()

    report = normalize_llm_protocol_failures(db_path, apply=True, backup=False)

    assert len(report.collisions) == 1
    rows = _open_rows(db_path)
    assert [row["experiment_mode"] for row in rows] == ["hybrid", "error"]
