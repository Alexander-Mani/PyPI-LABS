from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

import summarize_protocol_failures  # noqa: E402


def test_protocol_failure_summary_groups_by_detector_mode_strategy_and_model(tmp_path):
    log_path = tmp_path / "run-1.jsonl"
    records = [
        {
            "run_id": "run-1",
            "event": "llm.protocol_error",
            "detector": "claude_opus",
            "mode": "hybrid",
            "strategy": "few_shot",
            "payload": {
                "actual_model": "claude-opus-4-6",
                "protocol_category": "empty_blank_content",
            },
        },
        {
            "run_id": "run-1",
            "event": "llm.protocol_error",
            "detector": "claude_opus",
            "mode": "hybrid",
            "strategy": "few_shot",
            "payload": {
                "actual_model": "claude-opus-4-6",
                "protocol_category": "empty_blank_content",
            },
        },
        {
            "run_id": "run-1",
            "event": "llm.protocol_error",
            "detector": "together_frontier",
            "mode": "llm_raw",
            "strategy": "role_based",
            "payload": {
                "model": "together_ai/moonshotai/Kimi-K2.5",
                "protocol_category": "empty_nontext_content",
            },
        },
    ]
    with log_path.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")

    run_id, counts = summarize_protocol_failures.load_protocol_failure_counts(log_path)
    output = summarize_protocol_failures.format_summary(run_id, counts)

    assert run_id == "run-1"
    assert counts[("claude_opus", "hybrid", "few_shot", "claude-opus-4-6", "empty_blank_content")] == 2
    assert counts[("together_frontier", "llm_raw", "role_based", "together_ai/moonshotai/Kimi-K2.5", "empty_nontext_content")] == 1
    assert "Protocol failures for run-1" in output
    assert "claude_opus" in output
    assert "empty_nontext_content" in output
