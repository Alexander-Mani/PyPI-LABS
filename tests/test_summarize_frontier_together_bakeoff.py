from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

import summarize_frontier_together_bakeoff  # noqa: E402


def test_bakeoff_summary_ranks_candidates_by_success_then_protocol_failures(tmp_path):
    db_path = tmp_path / "eval_results.db"
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE eval_result (
                detector TEXT,
                run_id TEXT,
                experiment_mode TEXT,
                prompt_strategy TEXT,
                exec_time_ms INTEGER,
                api_cost_usd REAL,
                details TEXT
            )
            """
        )
        rows = [
            (
                "together_frontier_glm51_bench",
                "run-1",
                "hybrid",
                "zero_shot",
                2200,
                0.003,
                json.dumps({"actual_model": "together_ai/zai-org/GLM-5.1"}),
            ),
            (
                "together_frontier_glm51_bench",
                "run-1",
                "llm_raw",
                "few_shot",
                2600,
                0.0032,
                json.dumps({"actual_model": "together_ai/zai-org/GLM-5.1"}),
            ),
            (
                "together_frontier_kimi_bench",
                "run-1",
                "error",
                "zero_shot",
                5100,
                0.002,
                json.dumps({
                    "actual_model": "together_ai/moonshotai/Kimi-K2.5",
                    "protocol_failure": True,
                    "protocol_category": "empty_finish_reason_length",
                }),
            ),
            (
                "together_frontier_kimi_bench",
                "run-1",
                "hybrid",
                "few_shot",
                3200,
                0.0022,
                json.dumps({"actual_model": "together_ai/moonshotai/Kimi-K2.5"}),
            ),
            (
                "together_frontier_qwen397b_bench",
                "run-1",
                "error",
                "role_based",
                4100,
                0.004,
                json.dumps({
                    "actual_model": "together_ai/Qwen/Qwen3.5-397B-A17B",
                    "protocol_failure": True,
                    "protocol_category": "no_json_object",
                }),
            ),
            (
                "together_frontier_qwen397b_bench",
                "run-1",
                "error",
                "few_shot",
                4300,
                0.0041,
                json.dumps({
                    "actual_model": "together_ai/Qwen/Qwen3.5-397B-A17B",
                    "error": "connection reset",
                }),
            ),
        ]
        conn.executemany("INSERT INTO eval_result VALUES (?, ?, ?, ?, ?, ?, ?)", rows)

    summaries = summarize_frontier_together_bakeoff.summarize_rows(
        summarize_frontier_together_bakeoff.load_run_rows(db_path, "run-1")
    )
    output = summarize_frontier_together_bakeoff.format_summary("run-1", summaries)

    assert summaries[0].detector == "together_frontier_glm51_bench"
    assert summaries[0].successful_calls == 2
    assert summaries[1].detector == "together_frontier_kimi_bench"
    assert summaries[1].empty_finish_reason_length_count == 1
    assert summaries[2].transport_failures == 1
    assert "Together frontier bake-off summary for run-1" in output
    assert "empty_finish_reason_length=1" in output
    assert "together_ai/Qwen/Qwen3.5-397B-A17B" in output
