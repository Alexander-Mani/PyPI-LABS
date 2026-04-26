from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import summarize_thesis_eval_db  # noqa: E402
from src.data.db_manager import DBManager  # noqa: E402



def _init_db(db_path: Path):
    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
    finally:
        DBManager.DB_PATH = original
    return db



def _insert_result(
    db,
    *,
    run_id: str,
    package: str,
    version: str,
    detector: str,
    experiment_mode: str,
    intended_mode: str,
    prompt_strategy: str,
    sample_role: str,
    attack_vector: str,
    ground_truth: bool,
    verdict: bool,
    artifact: str,
    details: dict | None = None,
):
    return db.insert_eval_result(
        run_id=run_id,
        package_name=package,
        version=version,
        experiment_mode=experiment_mode,
        intended_mode=intended_mode,
        prompt_strategy=prompt_strategy,
        detector=detector,
        artifact_filename=artifact,
        artifact_url=f"http://example/{artifact}",
        sample_role=sample_role,
        attack_vector=attack_vector,
        resolver_policy="policy",
        verdict=verdict,
        ground_truth=ground_truth,
        heuristic_flags=[],
        exec_time_ms=10,
        api_cost_usd=0.1,
        details=details or {"model": detector},
    )



def test_summarizer_uses_latest_complete_runs_and_builds_alias_sensitivity(tmp_path):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("budget-old", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-new", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-controls", "profile:budget:llm-no-agentic", sample_set="controls")
        db.create_eval_run("frontier-run", "profile:frontier:llm-no-agentic")
        db.create_eval_run("static-run", "sast-only")
        db.create_eval_run("agentic-run", "profile:frontier:agentic-only")
        db.create_eval_run("alias-run", "profile:all_models:identity-alias-probe")
        db.create_eval_run("budget-validation", "profile:budget-validation")
        db.create_eval_run("frontier-run--repair-20260426-010000", "profile:frontier:llm-no-agentic:repair")
        db.create_eval_run("frontier-run--repair-20260426-020000", "profile:frontier:llm-no-agentic:repair")

        _insert_result(
            db,
            run_id="budget-old",
            package="malpkg",
            version="1.0.0",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            ground_truth=True,
            verdict=True,
            artifact="malpkg-old.whl",
        )
        _insert_result(
            db,
            run_id="budget-controls",
            package="ctrlpkg",
            version="1.0.0",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="control",
            attack_vector="None",
            ground_truth=False,
            verdict=False,
            artifact="ctrlpkg.whl",
        )
        _insert_result(
            db,
            run_id="budget-new",
            package="malpkg",
            version="1.0.0",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            ground_truth=True,
            verdict=True,
            artifact="malpkg.whl",
        )
        _insert_result(
            db,
            run_id="budget-new",
            package="benpkg",
            version="2.0.0",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="benign",
            attack_vector="Typosquatting",
            ground_truth=False,
            verdict=False,
            artifact="benpkg.whl",
        )
        frontier_error_row_id = _insert_result(
            db,
            run_id="frontier-run",
            package="frontmal",
            version="3.0.0",
            detector="claude_opus",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Account Takeover",
            ground_truth=True,
            verdict=False,
            artifact="frontmal.whl",
            details={"error": "empty_model_response", "protocol_category": "empty_finish_reason_length"},
        )
        _insert_result(
            db,
            run_id="static-run",
            package="malpkg",
            version="1.0.0",
            detector="bandit",
            experiment_mode="static",
            intended_mode="static",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            ground_truth=True,
            verdict=True,
            artifact="malpkg.whl",
        )
        _insert_result(
            db,
            run_id="agentic-run",
            package="agentmal",
            version="4.0.0",
            detector="claude_agentic",
            experiment_mode="error",
            intended_mode="agentic",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Multi-stage Execution",
            ground_truth=True,
            verdict=False,
            artifact="agentmal.whl",
            details={
                "error": "Error code: 429 - {'error': {'message': \"No deployments available for selected model, Try again in 22 seconds.\"}}"
            },
        )
        _insert_result(
            db,
            run_id="alias-run",
            package="malpkg",
            version="1.0.0",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            ground_truth=True,
            verdict=False,
            artifact="malpkg.whl",
            details={"identity_mask": "alias", "alias_probe": True},
        )
        _insert_result(
            db,
            run_id="budget-validation",
            package="ignored",
            version="9.9.9",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            ground_truth=True,
            verdict=True,
            artifact="ignored.whl",
        )
        _insert_result(
            db,
            run_id="frontier-run--repair-20260426-010000",
            package="frontmal",
            version="3.0.0",
            detector="claude_opus",
            experiment_mode="error",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Account Takeover",
            ground_truth=True,
            verdict=False,
            artifact="frontmal.whl",
            details={
                "error": "empty_model_response",
                "protocol_category": "empty_finish_reason_length",
                "repair_script": "error_correct_production_data",
                "repair_source_run_id": "frontier-run",
                "repair_source_tier": "profile:frontier:llm-no-agentic",
                "repair_source_row_id": frontier_error_row_id,
            },
        )
        _insert_result(
            db,
            run_id="frontier-run--repair-20260426-020000",
            package="frontmal",
            version="3.0.0",
            detector="claude_opus",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Account Takeover",
            ground_truth=True,
            verdict=True,
            artifact="frontmal.whl",
            details={
                "repair_script": "error_correct_production_data",
                "repair_source_run_id": "frontier-run",
                "repair_source_tier": "profile:frontier:llm-no-agentic",
                "repair_source_row_id": frontier_error_row_id,
            },
        )
    finally:
        db.close()

    inventory = summarize_thesis_eval_db.load_run_inventory(db_path)
    selected = summarize_thesis_eval_db.select_primary_runs(inventory, include_agentic=True)
    raw_rows = summarize_thesis_eval_db.load_result_rows(db_path, selected)
    repair_inventory = summarize_thesis_eval_db.load_repair_run_inventory(db_path, selected)
    selected_repairs = summarize_thesis_eval_db.select_latest_repair_runs(repair_inventory)
    repair_rows = summarize_thesis_eval_db.load_repair_result_rows(db_path, selected_repairs)
    cleaned_rows = summarize_thesis_eval_db.build_cleaned_rows(raw_rows, repair_rows)
    raw_pv_rows = summarize_thesis_eval_db.aggregate_package_version_rows(raw_rows)
    cleaned_pv_rows = summarize_thesis_eval_db.aggregate_package_version_rows(cleaned_rows)
    raw_primary = summarize_thesis_eval_db.build_primary_detector_metrics(raw_pv_rows)
    cleaned_primary = summarize_thesis_eval_db.build_primary_detector_metrics(cleaned_pv_rows)
    raw_errors = summarize_thesis_eval_db.build_error_inventory(raw_rows)
    cleaned_errors = summarize_thesis_eval_db.build_error_inventory(cleaned_rows)
    raw_alias = summarize_thesis_eval_db.build_alias_sensitivity(raw_pv_rows)
    cleaned_alias = summarize_thesis_eval_db.build_alias_sensitivity(cleaned_pv_rows)
    inventory_rows = summarize_thesis_eval_db.build_run_inventory_rows(
        inventory,
        selected,
        repair_inventory,
        selected_repairs,
    )
    repair_comparison = summarize_thesis_eval_db.build_repair_comparison(raw_rows, repair_rows)

    assert selected["profile:budget:llm-no-agentic"].run_id == "budget-new"
    assert selected["profile:all_models:identity-alias-probe"].run_id == "alias-run"
    assert selected_repairs["frontier-run"].run_id == "frontier-run--repair-20260426-020000"
    assert all(row["run_id"] != "budget-validation" for row in inventory_rows if row["selected"])

    raw_budget_metric = next(
        row for row in raw_primary
        if row["family"] == "profile:budget:llm-no-agentic" and row["detector"] == "gpt_nano"
    )
    assert raw_budget_metric["tp"] == 1
    assert raw_budget_metric["tn"] == 1
    assert raw_budget_metric["fp"] == 0
    assert raw_budget_metric["fn"] == 0

    raw_frontier_metric = next(
        row for row in raw_primary
        if row["family"] == "profile:frontier:llm-no-agentic" and row["detector"] == "claude_opus"
    )
    assert raw_frontier_metric["covered_package_versions"] == 0
    assert raw_frontier_metric["error_only_package_versions"] == 1

    cleaned_frontier_metric = next(
        row for row in cleaned_primary
        if row["family"] == "profile:frontier:llm-no-agentic" and row["detector"] == "claude_opus"
    )
    assert cleaned_frontier_metric["covered_package_versions"] == 1
    assert cleaned_frontier_metric["error_only_package_versions"] == 0
    assert cleaned_frontier_metric["tp"] == 1

    assert raw_errors == [
        {
            "family": "profile:frontier:agentic-only",
            "detector": "claude_agentic",
            "prompt_strategy": "zero_shot",
            "error_category": "deployment_unavailable_429",
            "rows": 1,
        },
        {
            "family": "profile:frontier:llm-no-agentic",
            "detector": "claude_opus",
            "prompt_strategy": "zero_shot",
            "error_category": "empty_finish_reason_length",
            "rows": 1,
        }
    ]
    assert cleaned_errors == [
        {
            "family": "profile:frontier:agentic-only",
            "detector": "claude_agentic",
            "prompt_strategy": "zero_shot",
            "error_category": "deployment_unavailable_429",
            "rows": 1,
        }
    ]

    raw_alias_row = next(row for row in raw_alias if row["detector"] == "gpt_nano" and row["package_name"] == "malpkg")
    assert raw_alias_row["canonical_family"] == "profile:budget:llm-no-agentic"
    assert raw_alias_row["canonical_any_malicious"] is True
    assert raw_alias_row["alias_any_malicious"] is False
    assert raw_alias_row["lost_detection"] is True

    cleaned_alias_row = next(
        row for row in cleaned_alias if row["detector"] == "gpt_nano" and row["package_name"] == "malpkg"
    )
    assert cleaned_alias_row["lost_detection"] is True

    selected_repair_inventory_row = next(
        row for row in inventory_rows if row["run_id"] == "frontier-run--repair-20260426-020000"
    )
    assert selected_repair_inventory_row["selection_reason"] == "selected_latest_repair"

    comparison_row = next(row for row in repair_comparison if row["correction_run_id"] == "frontier-run--repair-20260426-020000")
    assert comparison_row["source_row_id"] == frontier_error_row_id
    assert comparison_row["corrected_success"] is True

    control_inventory_row = next(row for row in inventory_rows if row["run_id"] == "budget-controls")
    assert control_inventory_row["sample_set"] == "controls"
    assert control_inventory_row["selected"] is False



def test_summarizer_main_writes_artifacts(tmp_path):
    db_path = tmp_path / "eval_results.db"
    out_dir = tmp_path / "out"
    db = _init_db(db_path)
    try:
        db.create_eval_run("budget-new", "profile:budget:llm-no-agentic")
        _insert_result(
            db,
            run_id="budget-new",
            package="malpkg",
            version="1.0.0",
            detector="gpt_nano",
            experiment_mode="hybrid",
            intended_mode="hybrid",
            prompt_strategy="zero_shot",
            sample_role="malware",
            attack_vector="Dependency Confusion",
            ground_truth=True,
            verdict=True,
            artifact="malpkg.whl",
        )
    finally:
        db.close()

    rc = summarize_thesis_eval_db.main(["--db", str(db_path), "--out-dir", str(out_dir)])

    assert rc == 0
    assert (out_dir / "run_inventory.csv").exists()
    assert (out_dir / "raw_primary_detector_metrics.md").exists()
    assert (out_dir / "cleaned_primary_detector_metrics.md").exists()
    assert (out_dir / "repair_inventory.md").exists()
    assert (out_dir / "summary.md").exists()
