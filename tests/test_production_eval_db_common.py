from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts.production_eval_db_common import load_run_inventory, select_primary_runs  # noqa: E402
from src.data.db_manager import DBManager  # noqa: E402



def _init_db(db_path: Path):
    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
    finally:
        DBManager.DB_PATH = original
    return db



def _add_row(db, *, run_id: str, package: str, version: str, detector: str, mode: str, strategy: str = "zero_shot", artifact: str = "a.whl"):
    db.insert_eval_result(
        run_id=run_id,
        package_name=package,
        version=version,
        experiment_mode=mode,
        intended_mode=mode,
        prompt_strategy=strategy,
        detector=detector,
        artifact_filename=artifact,
        verdict=(mode != "error"),
        ground_truth=True,
        heuristic_flags=[],
        exec_time_ms=10,
        api_cost_usd=0.1,
        details={"model": detector},
    )



def test_select_primary_runs_prefers_more_complete_then_newer(tmp_path):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("budget-old", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-new", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-controls", "profile:budget:llm-no-agentic", sample_set="controls")
        db.create_eval_run("budget-validation", "profile:budget-validation")
        db.create_eval_run("alias-run", "profile:all_models:identity-alias-probe")

        for package in ("a", "b"):
            _add_row(db, run_id="budget-old", package=package, version="1.0.0", detector="gpt_nano", mode="hybrid")
        for package in ("a", "b", "c"):
            _add_row(db, run_id="budget-new", package=package, version="1.0.0", detector="gpt_nano", mode="hybrid")
        for package in ("ctrl-a", "ctrl-b", "ctrl-c", "ctrl-d"):
            _add_row(db, run_id="budget-controls", package=package, version="1.0.0", detector="gpt_nano", mode="hybrid")
        _add_row(db, run_id="budget-validation", package="z", version="1.0.0", detector="gpt_nano", mode="hybrid")
        _add_row(db, run_id="alias-run", package="a", version="1.0.0", detector="gpt_nano", mode="hybrid")
    finally:
        db.close()

    inventory = load_run_inventory(db_path)
    selected = select_primary_runs(inventory)

    assert selected["profile:budget:llm-no-agentic"].run_id == "budget-new"
    assert selected["profile:budget:llm-no-agentic"].sample_set == "dataset"
    assert "profile:budget-validation" not in selected
    assert selected["profile:all_models:identity-alias-probe"].run_id == "alias-run"


def test_select_primary_runs_can_target_controls_sample_set(tmp_path):
    db_path = tmp_path / "eval_results.db"
    db = _init_db(db_path)
    try:
        db.create_eval_run("budget-dataset", "profile:budget:llm-no-agentic")
        db.create_eval_run("budget-controls", "profile:budget:llm-no-agentic", sample_set="controls")
        for package in ("a", "b"):
            _add_row(db, run_id="budget-dataset", package=package, version="1.0.0", detector="gpt_nano", mode="hybrid")
        for package in ("ctrl-a", "ctrl-b", "ctrl-c"):
            _add_row(db, run_id="budget-controls", package=package, version="1.0.0", detector="gpt_nano", mode="hybrid")
    finally:
        db.close()

    inventory = load_run_inventory(db_path)
    selected = select_primary_runs(inventory, sample_set="controls")

    assert selected["profile:budget:llm-no-agentic"].run_id == "budget-controls"
    assert selected["profile:budget:llm-no-agentic"].sample_set == "controls"
