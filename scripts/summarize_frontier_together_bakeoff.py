#!/usr/bin/env python3
"""Summarize a Together frontier bake-off run from eval_results.db."""

from __future__ import annotations

import argparse
import json
import sqlite3
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DB_PATH = _REPO_ROOT / "src" / "data" / "eval_results.db"


@dataclass
class CandidateSummary:
    detector: str
    model: str
    total_calls: int = 0
    successful_calls: int = 0
    protocol_failures: int = 0
    transport_failures: int = 0
    total_cost_usd: float = 0.0
    latencies_ms: list[int] | None = None
    protocol_categories: Counter[str] | None = None

    def __post_init__(self) -> None:
        if self.latencies_ms is None:
            self.latencies_ms = []
        if self.protocol_categories is None:
            self.protocol_categories = Counter()

    @property
    def success_rate(self) -> float:
        return self.successful_calls / self.total_calls if self.total_calls else 0.0

    @property
    def protocol_failure_rate(self) -> float:
        return self.protocol_failures / self.total_calls if self.total_calls else 0.0

    @property
    def mean_cost_usd(self) -> float:
        return self.total_cost_usd / self.total_calls if self.total_calls else 0.0

    @property
    def median_latency_ms(self) -> float:
        if not self.latencies_ms:
            return 0.0
        return float(statistics.median(self.latencies_ms))

    @property
    def empty_finish_reason_length_count(self) -> int:
        return int(self.protocol_categories.get("empty_finish_reason_length", 0))


def load_run_rows(db_path: Path, run_id: str) -> list[dict[str, Any]]:
    query = """
        SELECT detector, experiment_mode, prompt_strategy, exec_time_ms, api_cost_usd, details
        FROM eval_result
        WHERE run_id = ?
        ORDER BY detector, prompt_strategy
    """
    rows: list[dict[str, Any]] = []
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        for row in conn.execute(query, (run_id,)):
            details_raw = row["details"] or "{}"
            try:
                details = json.loads(details_raw) if isinstance(details_raw, str) else {}
            except json.JSONDecodeError:
                details = {}
            rows.append({
                "detector": row["detector"],
                "experiment_mode": row["experiment_mode"],
                "prompt_strategy": row["prompt_strategy"],
                "exec_time_ms": int(row["exec_time_ms"] or 0),
                "api_cost_usd": float(row["api_cost_usd"] or 0.0),
                "details": details,
            })
    return rows


def summarize_rows(rows: list[dict[str, Any]]) -> list[CandidateSummary]:
    summaries: dict[tuple[str, str], CandidateSummary] = {}
    for row in rows:
        details = row.get("details") or {}
        detector = str(row.get("detector") or "unknown-detector")
        model = str(
            details.get("actual_model")
            or details.get("model")
            or detector
        )
        key = (detector, model)
        summary = summaries.setdefault(key, CandidateSummary(detector=detector, model=model))
        summary.total_calls += 1
        summary.total_cost_usd += float(row.get("api_cost_usd") or 0.0)
        summary.latencies_ms.append(int(row.get("exec_time_ms") or 0))
        if row.get("experiment_mode") != "error":
            summary.successful_calls += 1
            continue
        if bool(details.get("protocol_failure")):
            summary.protocol_failures += 1
            summary.protocol_categories[str(
                details.get("protocol_category")
                or details.get("parse_error")
                or details.get("error")
                or "unknown"
            )] += 1
        else:
            summary.transport_failures += 1

    return sorted(
        summaries.values(),
        key=lambda entry: (
            -entry.success_rate,
            entry.protocol_failure_rate,
            entry.empty_finish_reason_length_count,
            entry.median_latency_ms,
            entry.mean_cost_usd,
            entry.detector,
        ),
    )


def format_summary(run_id: str, summaries: list[CandidateSummary]) -> str:
    if not summaries:
        return f"Together frontier bake-off summary for {run_id}\nNo matching eval_result rows found."

    headers = (
        "Rank",
        "Detector",
        "Model",
        "Calls",
        "OK",
        "Success%",
        "Protocol",
        "Transport",
        "LenCut",
        "Median s",
        "Total $",
        "Mean $",
    )
    rows: list[tuple[str, ...]] = []
    for index, entry in enumerate(summaries, start=1):
        rows.append((
            str(index),
            entry.detector,
            entry.model,
            str(entry.total_calls),
            str(entry.successful_calls),
            f"{entry.success_rate * 100:.1f}",
            str(entry.protocol_failures),
            str(entry.transport_failures),
            str(entry.empty_finish_reason_length_count),
            f"{entry.median_latency_ms / 1000:.2f}",
            f"{entry.total_cost_usd:.4f}",
            f"{entry.mean_cost_usd:.4f}",
        ))

    widths = [
        max(len(headers[idx]), *(len(row[idx]) for row in rows))
        for idx in range(len(headers))
    ]
    lines = [f"Together frontier bake-off summary for {run_id}"]
    lines.append("  ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers))))
    lines.append("  ".join("-" * widths[idx] for idx in range(len(headers))))
    for row in rows:
        lines.append("  ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))))
        entry = summaries[int(row[0]) - 1]
        if entry.protocol_categories:
            parts = ", ".join(
                f"{category}={count}"
                for category, count in sorted(entry.protocol_categories.items())
            )
            lines.append(f"      protocol: {parts}")
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="Run identifier to summarize.")
    parser.add_argument(
        "--db-path",
        default=str(_DEFAULT_DB_PATH),
        help="Path to eval_results.db. Default: src/data/eval_results.db",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    rows = load_run_rows(Path(args.db_path), args.run_id)
    print(format_summary(args.run_id, summarize_rows(rows)))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
