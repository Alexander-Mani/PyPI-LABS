#!/usr/bin/env python3
"""Manual JSONL sidecar probe for Gemini time-of-day stability."""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_LOG_DIR = _REPO_ROOT / "logs" / "gemini_stability_probe"

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
from litellm_smoke import (  # noqa: E402
    SmokeOutcome,
    _is_gemini_model,
    _load_all_litellm_models,
    _smoke_once,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _default_output_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return _DEFAULT_LOG_DIR / f"gemini-stability-probe-{stamp}.jsonl"


def _write_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def _canonical_gemini_models() -> list[str]:
    models = [model for model in _load_all_litellm_models() if _is_gemini_model(model)]
    if not models:
        raise SystemExit("HALT: no Gemini models found in configs/litellm_config.yaml")
    return models


def select_models(args: argparse.Namespace) -> tuple[list[str], str]:
    if args.models is not None:
        models = list(dict.fromkeys(args.models))
        source = "explicit --models"
    else:
        models = _canonical_gemini_models()
        source = "configs/litellm_config.yaml (Gemini only)"
    invalid = [model for model in models if not _is_gemini_model(model)]
    if invalid:
        raise SystemExit(
            "HALT: gemini stability probe only accepts Gemini model names. "
            f"Invalid: {', '.join(invalid)}"
        )
    return models, source


def _result_record(
    *,
    run_id: str,
    iteration: int,
    model: str,
    outcome: SmokeOutcome,
) -> dict[str, Any]:
    return {
        "event": "probe.result" if outcome.ok else "probe.error",
        "ts": _utc_now(),
        "run_id": run_id,
        "iteration": iteration,
        "model": model,
        "ok": outcome.ok,
        "category": outcome.category,
        "retryable": outcome.retryable,
        "status": outcome.status,
        "status_code": outcome.status_code,
        "diagnosis": outcome.diagnosis,
        "detail": outcome.detail,
        "elapsed_s": round(outcome.elapsed_s, 3),
        "message": outcome.message,
    }


def _summarize_records(records: list[dict[str, Any]]) -> dict[str, Any]:
    probe_records = [record for record in records if record.get("event") in {"probe.result", "probe.error"}]
    by_model: dict[str, dict[str, Any]] = {}
    for record in probe_records:
        model = str(record["model"])
        entry = by_model.setdefault(
            model,
            {"attempts": 0, "ok": 0, "failures": 0, "categories": Counter(), "elapsed_s": []},
        )
        entry["attempts"] += 1
        if record.get("ok"):
            entry["ok"] += 1
        else:
            entry["failures"] += 1
        entry["categories"][str(record.get("category") or "unknown")] += 1
        elapsed = record.get("elapsed_s")
        if isinstance(elapsed, (int, float)):
            entry["elapsed_s"].append(float(elapsed))

    summary_by_model: dict[str, dict[str, Any]] = {}
    for model, entry in by_model.items():
        elapsed_values = entry.pop("elapsed_s")
        summary_by_model[model] = {
            "attempts": entry["attempts"],
            "ok": entry["ok"],
            "failures": entry["failures"],
            "success_rate": round(entry["ok"] / entry["attempts"], 4) if entry["attempts"] else 0.0,
            "median_elapsed_s": round(statistics.median(elapsed_values), 3) if elapsed_values else None,
            "categories": dict(sorted(entry["categories"].items())),
        }

    return {
        "attempts": len(probe_records),
        "ok": sum(1 for record in probe_records if record.get("ok")),
        "failures": sum(1 for record in probe_records if not record.get("ok")),
        "by_model": summary_by_model,
    }


def _print_run_summary(summary: dict[str, Any]) -> None:
    print(
        f"Summary: attempts={summary['attempts']} ok={summary['ok']} "
        f"failures={summary['failures']}"
    )
    for model, entry in sorted(summary["by_model"].items()):
        categories = ", ".join(f"{key}={value}" for key, value in entry["categories"].items()) or "none"
        ok_pct = entry["success_rate"] * 100
        median = entry["median_elapsed_s"]
        median_text = f"{median:.2f}s" if isinstance(median, float) else "n/a"
        print(
            f"  {model}: attempts={entry['attempts']} ok={entry['ok']} "
            f"success={ok_pct:.1f}% median={median_text} categories={categories}"
        )


def run_probe(args: argparse.Namespace) -> int:
    models, model_source = select_models(args)
    out_path = args.out or _default_output_path()
    run_id = args.run_id or f"gemini-stability-{uuid.uuid4()}"

    if args.dry_run:
        print(f"Gemini stability probe dry-run: {len(models)} model(s)")
        print(f"base_url={args.base_url.rstrip('/')} model_source={model_source}")
        print(f"out={out_path}")
        print(f"interval_seconds={args.interval_seconds:g}")
        print(f"iterations={args.iterations}")
        print(f"until_interrupt={str(args.until_interrupt).lower()}")
        for model in models:
            print(f"MODEL {model}")
        return 0

    records: list[dict[str, Any]] = []
    start_record = {
        "event": "run.start",
        "ts": _utc_now(),
        "run_id": run_id,
        "base_url": args.base_url.rstrip("/"),
        "model_source": model_source,
        "models": models,
        "interval_seconds": args.interval_seconds,
        "iterations": args.iterations,
        "until_interrupt": args.until_interrupt,
        "timeout": args.timeout,
        "max_tokens": args.max_tokens,
    }
    _write_jsonl(out_path, start_record)
    interrupted = False
    iteration = 0

    try:
        while True:
            if not args.until_interrupt and iteration >= args.iterations:
                break
            iteration += 1
            for model in models:
                outcome = _smoke_once(args.base_url, model, args.timeout, args.max_tokens)
                record = _result_record(
                    run_id=run_id,
                    iteration=iteration,
                    model=model,
                    outcome=outcome,
                )
                records.append(record)
                _write_jsonl(out_path, record)
                print(f"{record['ts']} {record['message']}")
            if not args.until_interrupt and iteration >= args.iterations:
                break
            time.sleep(args.interval_seconds)
    except KeyboardInterrupt:
        interrupted = True
        print("Interrupted by operator; writing summary.")

    summary = _summarize_records(records)
    summary_record = {
        "event": "run.summary",
        "ts": _utc_now(),
        "run_id": run_id,
        "interrupted": interrupted,
        "iterations_completed": iteration,
        **summary,
    }
    _write_jsonl(out_path, summary_record)
    _print_run_summary(summary)
    print(f"JSONL log: {out_path}")
    return 0


def _parse_ts_hour(ts: str) -> str:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    dt = dt.astimezone(timezone.utc)
    return f"{dt.hour:02d}"


def summarize_log(path: Path) -> int:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    probe_rows = [row for row in rows if row.get("event") in {"probe.result", "probe.error"}]
    if not probe_rows:
        print(f"No probe rows found in {path}")
        return 0

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    run_ids: set[str] = set()
    for row in probe_rows:
        run_ids.add(str(row.get("run_id") or "unknown"))
        grouped[(str(row["model"]), _parse_ts_hour(str(row["ts"])))].append(row)

    print(f"Gemini stability summary: {path}")
    print(f"run_ids={', '.join(sorted(run_ids))}")
    print(
        "Model                            UTC  Attempts  OK  OK%   "
        "Median  rate_limit overload timeout auth other"
    )
    for (model, hour) in sorted(grouped):
        bucket = grouped[(model, hour)]
        attempts = len(bucket)
        ok_count = sum(1 for row in bucket if row.get("ok"))
        ok_pct = 100.0 * ok_count / attempts if attempts else 0.0
        elapsed = [float(row["elapsed_s"]) for row in bucket if isinstance(row.get("elapsed_s"), (int, float))]
        median = statistics.median(elapsed) if elapsed else None
        categories = Counter(str(row.get("category") or "unknown") for row in bucket if not row.get("ok"))
        other = sum(
            count for key, count in categories.items()
            if key not in {"rate_limit", "provider_overload", "client_timeout", "auth_error"}
        )
        median_text = f"{median:.2f}s" if isinstance(median, float) else "n/a"
        print(
            f"{model:<32} {hour}   {attempts:>8}  {ok_count:>2}  {ok_pct:>4.1f}  "
            f"{median_text:>6}  {categories.get('rate_limit', 0):>10} "
            f"{categories.get('provider_overload', 0):>8} "
            f"{categories.get('client_timeout', 0):>7} "
            f"{categories.get('auth_error', 0):>4} {other:>5}"
        )
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:4000")
    parser.add_argument("--models", nargs="+", default=None, help="Explicit Gemini model names to probe")
    parser.add_argument("--out", type=Path, default=None, help="JSONL output path")
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--max-tokens", type=int, default=8)
    parser.add_argument("--interval-seconds", type=float, default=300.0)
    parser.add_argument("--iterations", type=int, default=1, help="Number of probe cycles to run")
    parser.add_argument(
        "--until-interrupt",
        action="store_true",
        help="Keep probing until Ctrl-C instead of stopping after --iterations",
    )
    parser.add_argument(
        "--summarize",
        type=Path,
        default=None,
        help="Read an existing JSONL probe log and print a UTC-hour summary",
    )
    args = parser.parse_args(argv)
    if args.iterations < 1:
        raise SystemExit("HALT: --iterations must be >= 1")
    if args.interval_seconds < 0:
        raise SystemExit("HALT: --interval-seconds must be >= 0")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.summarize is not None:
        return summarize_log(args.summarize)
    return run_probe(args)


if __name__ == "__main__":
    raise SystemExit(main())
