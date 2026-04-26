from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import error_correct_production_data  # noqa: E402
from src.data.db_manager import DBManager  # noqa: E402



def _init_db(db_path: Path):
    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
    finally:
        DBManager.DB_PATH = original
    return db



def test_load_repair_candidates_targets_all_error_rows_and_filters(tmp_path):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("budget-good", "profile:budget:llm-no-agentic")
        db.create_eval_run("debug-run", "profile:custom-debug")
        db.create_eval_run("budget-controls", "profile:budget:llm-no-agentic", sample_set="controls")
        db.create_eval_run("agentic-run", "profile:frontier:agentic-only")
        db.create_eval_run("validation-run", "profile:budget-validation")
        db.create_eval_run("repair-run", "profile:custom-debug:repair")

        for package in ("a", "b"):
            db.insert_eval_result(
                run_id="budget-good",
                package_name=package,
                version="1.0.0",
                experiment_mode="error",
                intended_mode="hybrid",
                prompt_strategy="zero_shot",
                detector="together_budget",
                artifact_filename=f"{package}.whl",
                artifact_url=f"http://example/{package}.whl",
                verdict=False,
                ground_truth=True,
                heuristic_flags=[],
                exec_time_ms=10,
                api_cost_usd=0.1,
                details={"error": "empty_model_response", "protocol_category": "empty_finish_reason_length"},
            )
        db.insert_eval_result(
            run_id="debug-run",
            package_name="dbg",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="llm_raw",
            prompt_strategy="few_shot",
            detector="gpt_nano",
            artifact_filename="dbg.whl",
            artifact_url="http://example/dbg.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "unparseable_model_response"},
        )
        db.insert_eval_result(
            run_id="agentic-run",
            package_name="agent",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="agentic",
            prompt_strategy="zero_shot",
            detector="claude_agentic",
            artifact_filename="agent.whl",
            artifact_url="http://example/agent.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "Error code: 429"},
        )
        db.insert_eval_result(
            run_id="budget-good",
            package_name="ok",
            version="1.0.0",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="ok.whl",
            artifact_url="http://example/ok.whl",
            verdict=True,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"model": "gpt-5.4-nano"},
        )
        db.insert_eval_result(
            run_id="budget-controls",
            package_name="ctrl",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="together_budget",
            artifact_filename="ctrl.whl",
            artifact_url="http://example/ctrl.whl",
            verdict=False,
            ground_truth=False,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
        db.insert_eval_result(
            run_id="validation-run",
            package_name="val",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="val.whl",
            artifact_url="http://example/val.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
        db.insert_eval_result(
            run_id="repair-run",
            package_name="fixme",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="fixme.whl",
            artifact_url="http://example/fixme.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
    finally:
        db.close()

    candidates = error_correct_production_data.load_repair_candidates(db_path)
    with_agentic = error_correct_production_data.load_repair_candidates(db_path, include_agentic=True)
    dataset_only = error_correct_production_data.load_repair_candidates(db_path, sample_set="dataset")
    no_agentic = error_correct_production_data.load_repair_candidates(db_path, include_agentic=False)
    detector_filtered = error_correct_production_data.load_repair_candidates(db_path, detectors=["gpt_nano"])
    with_validation = error_correct_production_data.load_repair_candidates(db_path, include_validation=True)
    with_repairs = error_correct_production_data.load_repair_candidates(db_path, include_repair_runs=True)

    assert {(candidate.run_id, candidate.package_name) for candidate in candidates} == {
        ("budget-good", "a"),
        ("budget-good", "b"),
        ("debug-run", "dbg"),
        ("budget-controls", "ctrl"),
    }
    assert {(candidate.run_id, candidate.package_name) for candidate in with_agentic} == {
        ("budget-good", "a"),
        ("budget-good", "b"),
        ("debug-run", "dbg"),
        ("agentic-run", "agent"),
        ("budget-controls", "ctrl"),
    }
    assert {(candidate.run_id, candidate.package_name) for candidate in dataset_only} == {
        ("budget-good", "a"),
        ("budget-good", "b"),
        ("debug-run", "dbg"),
    }
    assert {(candidate.run_id, candidate.package_name) for candidate in no_agentic} == {
        ("budget-good", "a"),
        ("budget-good", "b"),
        ("debug-run", "dbg"),
        ("budget-controls", "ctrl"),
    }
    assert {(candidate.run_id, candidate.package_name) for candidate in detector_filtered} == {
        ("debug-run", "dbg"),
    }
    assert ("validation-run", "val") in {(candidate.run_id, candidate.package_name) for candidate in with_validation}
    assert ("repair-run", "fixme") in {(candidate.run_id, candidate.package_name) for candidate in with_repairs}


def test_partition_repair_candidates_reports_skips(tmp_path):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("mixed-errors", "profile:custom-debug")
        db.insert_eval_result(
            run_id="mixed-errors",
            package_name="missing-url",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="missing-url.whl",
            artifact_url="",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
        db.insert_eval_result(
            run_id="mixed-errors",
            package_name="bad-mode",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="unknown_mode",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="bad-mode.whl",
            artifact_url="http://example/bad-mode.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
        db.insert_eval_result(
            run_id="mixed-errors",
            package_name="good",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="good.whl",
            artifact_url="http://example/good.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
            )
    finally:
        db.close()

    candidates = error_correct_production_data.load_repair_candidates(db_path)
    rerunnable, skipped = error_correct_production_data.partition_repair_candidates(candidates)

    assert [(candidate.run_id, candidate.package_name) for candidate in rerunnable] == [("mixed-errors", "good")]
    assert {(item.candidate.package_name, item.reason) for item in skipped} == {
        ("missing-url", "missing_artifact_url"),
        ("bad-mode", "unsupported_intended_mode"),
    }



def test_apply_repairs_replaces_error_row_in_place_and_preserves_alias_details(tmp_path, monkeypatch):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("alias-run", "profile:all_models:identity-alias-probe")
        db.insert_eval_result(
            run_id="alias-run",
            package_name="colourama",
            version="0.1.6",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="together_frontier_qwen",
            artifact_filename="colourama-0.1.6.tar.gz",
            artifact_url="http://example/colourama-0.1.6.tar.gz",
            source_index_url="http://example/simple/colourama/",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            resolver_policy="policy",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={
                "error": "empty_model_response",
                "alias_probe": True,
                "alias_name": "X001",
                "alias_version": "V001",
            },
        )
    finally:
        db.close()

    candidates = error_correct_production_data.load_repair_candidates(db_path)
    policy = error_correct_production_data.RepairPolicy(
        max_tokens=16384,
        llm_retry_attempts=5,
        llm_retry_delay_seconds=45.0,
        agentic_retry_attempts=5,
        agentic_retry_delay_seconds=60.0,
    )

    fake_result = SimpleNamespace(
        experiment_mode="hybrid",
        verdict=True,
        heuristic_flags=["shell_execution"],
        input_tokens=12,
        output_tokens=7,
        exec_time_ms=55,
        api_cost_usd=0.0025,
        details={"model": "together_ai/Qwen/Qwen3.5-397B-A17B"},
    )

    def fake_repair_single_candidate(candidate, **kwargs):
        return fake_result, dict(fake_result.details), 2, {
            "identity_mask": "alias",
            "alias_probe": True,
            "alias_name": "X001",
            "alias_version": "V001",
        }

    monkeypatch.setattr(error_correct_production_data, "_repair_single_candidate", fake_repair_single_candidate)

    outcomes = error_correct_production_data.apply_repairs(db_path, candidates, policy=policy, dry_run=False)

    assert len(outcomes) == 1
    assert outcomes[0].success is True
    repair_run_id = outcomes[0].repair_run_id
    assert repair_run_id.startswith("alias-run--repair-")

    with __import__("sqlite3").connect(db_path) as conn:
        conn.row_factory = __import__("sqlite3").Row
        rows = conn.execute(
            "SELECT run_id, experiment_mode, verdict, details FROM eval_result ORDER BY run_id"
        ).fetchall()
        repair_run = conn.execute(
            "SELECT run_id, sample_set FROM eval_run WHERE run_id = ?",
            (repair_run_id,),
        ).fetchone()
    assert len(rows) == 2
    raw_row = next(row for row in rows if row["run_id"] == "alias-run")
    repair_row = next(row for row in rows if row["run_id"] == repair_run_id)
    assert repair_run["sample_set"] == "dataset"

    assert raw_row["experiment_mode"] == "error"
    assert int(raw_row["verdict"]) == 0

    assert repair_row["experiment_mode"] == "hybrid"
    assert int(repair_row["verdict"]) == 1
    details = json.loads(repair_row["details"])
    assert details["alias_probe"] is True
    assert details["alias_name"] == "X001"
    assert details["repair_script"] == "error_correct_production_data"
    assert details["repaired_from_error"] is True
    assert details["repair_attempts"] == 2
    assert details["repair_source_run_id"] == "alias-run"
    assert details["repair_source_tier"] == "profile:all_models:identity-alias-probe"
    assert details["repair_source_row_id"] == candidates[0].row_id
    assert details["original_error_details"]["error"] == "empty_model_response"


def test_main_halts_without_backup_when_no_rerunnable_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("broken-run", "profile:custom-debug")
        db.insert_eval_result(
            run_id="broken-run",
            package_name="missing-url",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="gpt_nano",
            artifact_filename="missing-url.whl",
            artifact_url="",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
    finally:
        db.close()

    backup_calls: list[Path] = []

    def fake_backup(path: Path) -> Path:
        backup_calls.append(path)
        return path.with_suffix(".bak")

    monkeypatch.setattr(error_correct_production_data, "_backup_db", fake_backup)

    rc = error_correct_production_data.main(["--db", str(db_path), "--apply"])

    assert rc == 1
    assert backup_calls == []


def test_load_repair_logging_config_defaults_to_file_only():
    cfg = error_correct_production_data._load_repair_logging_config(engine_console_logs=False)

    assert cfg["logging"]["level"] == "INFO"
    assert cfg["logging"]["console_output"] is False
    assert cfg["logging"]["per_run"] is True
    assert cfg["logging"]["file"].endswith("logs/repair/error_correct_production_data.log")


def test_parse_args_defaults_exclude_agentic():
    args = error_correct_production_data.parse_args(["--db", "/tmp/example.db"])

    assert args.include_agentic == "off"
