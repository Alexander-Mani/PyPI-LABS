#!/usr/bin/env python3
"""Summarize protocol failure events from a raw experiment log."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def _default_log_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "logs" / "experiments"


def load_protocol_failure_counts(log_path: Path) -> tuple[str | None, Counter[tuple[str, str, str, str, str]]]:
    counts: Counter[tuple[str, str, str, str, str]] = Counter()
    run_id: str | None = None
    with Path(log_path).open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            run_id = run_id or record.get("run_id")
            event = str(record.get("event") or "")
            if event != "llm.protocol_error":
                continue
            payload = record.get("payload") or {}
            model = str(
                payload.get("actual_model")
                or payload.get("model")
                or ""
            ).strip() or "unknown-model"
            category = str(payload.get("protocol_category") or "unknown").strip() or "unknown"
            key = (
                str(record.get("detector") or "unknown-detector"),
                str(record.get("mode") or "unknown-mode"),
                str(record.get("strategy") or "unknown-strategy"),
                model,
                category,
            )
            counts[key] += 1
    return run_id, counts


def format_summary(run_id: str | None, counts: Counter[tuple[str, str, str, str, str]]) -> str:
    title = f"Protocol failures for {run_id or 'unknown-run'}"
    if not counts:
        return f"{title}\nNo protocol failure events found."

    rows = sorted(counts.items(), key=lambda item: (-item[1], *item[0]))
    headers = ("Detector", "Mode", "Strategy", "Model", "Protocol Category", "Count")
    body = [
        (detector, mode, strategy, model, category, str(count))
        for (detector, mode, strategy, model, category), count in rows
    ]
    widths = [
        max(len(headers[idx]), *(len(row[idx]) for row in body))
        for idx in range(len(headers))
    ]

    lines = [title]
    lines.append("  ".join(headers[idx].ljust(widths[idx]) for idx in range(len(headers))))
    lines.append("  ".join("-" * widths[idx] for idx in range(len(headers))))
    for row in body:
        lines.append("  ".join(row[idx].ljust(widths[idx]) for idx in range(len(headers))))
    return "\n".join(lines)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="Run identifier whose raw experiment log should be summarized.")
    parser.add_argument(
        "--log-dir",
        default=str(_default_log_dir()),
        help="Directory containing raw experiment JSONL logs. Default: logs/experiments",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    log_path = Path(args.log_dir) / f"{args.run_id}.jsonl"
    if not log_path.exists():
        raise SystemExit(f"Log file not found: {log_path}")
    run_id, counts = load_protocol_failure_counts(log_path)
    print(format_summary(run_id, counts))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
