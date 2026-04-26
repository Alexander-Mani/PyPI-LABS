#!/usr/bin/env python3
"""Recompute v2 summaries for model-memory probe JSONL artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.model_memory_probe import _write_summary_artifacts, summarize_probe_file


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path, help="Path to a model-memory probe JSONL log")
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Print the recomputed summary JSON to stdout after writing artifacts.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    summary = summarize_probe_file(args.jsonl)
    summary_json_path, summary_md_path = _write_summary_artifacts(args.jsonl, summary)
    print(f"Wrote {summary_json_path}")
    print(f"Wrote {summary_md_path}")
    print(
        "Summary: "
        f"calls={summary['total_calls']} parsed={summary['parsed_results']} "
        f"schema_invalid={summary['schema_invalid_results']} transport_failures={summary['transport_failures']} "
        f"exact_true={summary['recognized_exact_version_true']} total_cost=${summary['total_cost_usd']:.6f}"
    )
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
