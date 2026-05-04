from data_processing.scripts.build_frozen_cut import _best_row as build_best_row, _top_errors
from data_processing.scripts.plot_frozen_cut import _best_row as plot_best_row


def test_best_row_prefers_raw_then_zero_shot_on_ties() -> None:
    rows = [
        {
            "family": "profile:medium:llm-no-agentic",
            "detector": "alpha",
            "intended_mode": "hybrid",
            "prompt_strategy": "few_shot",
            "f1": "0.9412",
            "recall": "0.8889",
            "precision": "1.0",
            "error_only_package_versions": "0",
        },
        {
            "family": "profile:medium:llm-no-agentic",
            "detector": "beta",
            "intended_mode": "llm_raw",
            "prompt_strategy": "role_based",
            "f1": "0.9412",
            "recall": "0.8889",
            "precision": "1.0",
            "error_only_package_versions": "0",
        },
        {
            "family": "profile:medium:llm-no-agentic",
            "detector": "gamma",
            "intended_mode": "llm_raw",
            "prompt_strategy": "zero_shot",
            "f1": "0.9412",
            "recall": "0.8889",
            "precision": "1.0",
            "error_only_package_versions": "0",
        },
    ]

    build_choice = build_best_row(rows, "profile:medium:llm-no-agentic")
    plot_choice = plot_best_row(rows, "profile:medium:llm-no-agentic")

    assert build_choice["detector"] == "gamma"
    assert plot_choice["detector"] == "gamma"


def test_top_errors_aggregates_same_detector_and_category() -> None:
    rows = [
        {
            "family": "profile:frontier:agentic-only",
            "detector": "claude_agentic",
            "prompt_strategy": "zero_shot",
            "error_category": "deployment_unavailable_429",
            "rows": "19",
        },
        {
            "family": "profile:frontier:agentic-only",
            "detector": "claude_agentic",
            "prompt_strategy": "role_based",
            "error_category": "deployment_unavailable_429",
            "rows": "18",
        },
        {
            "family": "profile:budget:llm-no-agentic",
            "detector": "together_budget",
            "prompt_strategy": "few_shot",
            "error_category": "empty_finish_reason_length",
            "rows": "3",
        },
    ]

    top = _top_errors(rows, limit=2)

    assert top[0]["detector"] == "claude_agentic"
    assert top[0]["error_category"] == "deployment_unavailable_429"
    assert top[0]["rows"] == 37
    assert top[1]["detector"] == "together_budget"
    assert top[1]["rows"] == 3
