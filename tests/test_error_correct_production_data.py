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



def test_load_repair_candidates_targets_only_selected_error_rows(tmp_path):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("budget-good", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-old", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-controls", "profile:budget:llm-no-agentic", sample_set="controls")
        db.create_eval_run("budget-validation", "profile:budget-validation")

        for package in ("a", "b"):
            db.insert_eval_result(
                run_id="budget-old",
                package_name=package,
                version="1.0.0",
                experiment_mode="hybrid",
                intended_mode="hybrid",
                prompt_strategy="zero_shot",
                detector="gpt_nano",
                artifact_filename=f"{package}.whl",
                artifact_url=f"http://example/{package}.whl",
                verdict=True,
                ground_truth=True,
                heuristic_flags=[],
                exec_time_ms=10,
                api_cost_usd=0.1,
                details={"model": "gpt-5.4-nano"},
            )
        for package in ("a", "b", "c"):
            db.insert_eval_result(
                run_id="budget-good",
                package_name=package,
                version="1.0.0",
                experiment_mode="error" if package == "c" else "hybrid",
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
                details={"error": "empty_model_response", "protocol_category": "empty_finish_reason_length"} if package == "c" else {"model": "qwen"},
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
            run_id="budget-validation",
            package_name="z",
            version="1.0.0",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            detector="together_budget",
            artifact_filename="z.whl",
            artifact_url="http://example/z.whl",
            verdict=False,
            ground_truth=True,
            heuristic_flags=[],
            exec_time_ms=10,
            api_cost_usd=0.1,
            details={"error": "empty_model_response"},
        )
    finally:
        db.close()

    inventory = error_correct_production_data.load_run_inventory(db_path)
    selected = error_correct_production_data.select_primary_runs(inventory)
    candidates = error_correct_production_data.load_repair_candidates(db_path, selected)

    assert len(candidates) == 1
    assert candidates[0].run_id == "budget-good"
    assert candidates[0].package_name == "c"



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

    inventory = error_correct_production_data.load_run_inventory(db_path)
    selected = error_correct_production_data.select_primary_runs(inventory)
    candidates = error_correct_production_data.load_repair_candidates(db_path, selected)

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

    outcomes = error_correct_production_data.apply_repairs(db_path, candidates, dry_run=False)

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
