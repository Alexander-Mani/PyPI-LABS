#!/usr/bin/env python3
"""Build the reproducible frozen 2026-04-26 reporting package."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import summarize_thesis_eval_db  # noqa: E402
try:  # pragma: no cover - import style depends on execution mode
    from data_processing.scripts.plot_frozen_cut import generate_all_figures  # noqa: E402
except ImportError:  # pragma: no cover
    from plot_frozen_cut import generate_all_figures  # noqa: E402

DATASET_PROBE_JSON_DEFAULT = _REPO_ROOT / "model_memory_probe" / "model-memory-probe-20260426-022803.summary.json"
DATASET_PROBE_MD_DEFAULT = _REPO_ROOT / "model_memory_probe" / "model-memory-probe-20260426-022803.summary.md"
CONTROLS_PROBE_JSON_DEFAULT = _REPO_ROOT / "model_memory_probe" / "model-memory-probe-20260426-125455.summary.json"
CONTROLS_PROBE_MD_DEFAULT = _REPO_ROOT / "model_memory_probe" / "model-memory-probe-20260426-125455.summary.md"
FAMILY_LABELS = {
    "sast-only": "Static",
    "profile:budget:llm-no-agentic": "Budget",
    "profile:medium:llm-no-agentic": "Medium",
    "profile:frontier:llm-no-agentic": "Frontier",
}
PRIMARY_LLM_FAMILIES = (
    "profile:budget:llm-no-agentic",
    "profile:medium:llm-no-agentic",
    "profile:frontier:llm-no-agentic",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=_REPO_ROOT / "eval_results.db", help="Source eval_results.db")
    parser.add_argument("--dataset-probe-json", type=Path, default=DATASET_PROBE_JSON_DEFAULT)
    parser.add_argument("--dataset-probe-md", type=Path, default=DATASET_PROBE_MD_DEFAULT)
    parser.add_argument("--controls-probe-json", type=Path, default=CONTROLS_PROBE_JSON_DEFAULT)
    parser.add_argument("--controls-probe-md", type=Path, default=CONTROLS_PROBE_MD_DEFAULT)
    parser.add_argument(
        "--out-root",
        type=Path,
        default=_REPO_ROOT / "data_processing" / "frozen_cut_20260426",
        help="Output root for the frozen cut package.",
    )
    return parser.parse_args(argv)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(_REPO_ROOT))
    except ValueError:
        return str(resolved)


def _float(value: str | float | int | None) -> float:
    if value in (None, ""):
        return 0.0
    return float(value)


def _int(value: str | int | None) -> int:
    if value in (None, ""):
        return 0
    return int(value)


def _bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() == "true"


def _run_eval_summary(db_path: Path, sample_set: str, out_dir: Path) -> None:
    rc = summarize_thesis_eval_db.main([
        "--db",
        str(db_path),
        "--sample-set",
        sample_set,
        "--out-dir",
        str(out_dir),
    ])
    if rc != 0:
        raise SystemExit(rc)


def _copy_probe_pair(json_src: Path, md_src: Path, target_dir: Path) -> list[dict[str, Any]]:
    target_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for src in (json_src, md_src):
        dest = target_dir / src.name
        shutil.copy2(src, dest)
        copied.append(
            {
                "source": _display_path(src),
                "dest": _display_path(dest),
                "size_bytes": src.stat().st_size,
                "sha256": _sha256(src),
            }
        )
    return copied


def _write_memory_probe_tables(summary_path: Path, out_csv: Path) -> None:
    summary = _read_json(summary_path)
    rows = []
    for label, metrics in sorted(summary["by_model"].items()):
        rows.append(
            {
                "label": label,
                "model_name": metrics.get("model_name"),
                "calls": metrics.get("calls"),
                "parsed": metrics.get("parsed"),
                "package_true": metrics.get("package_true"),
                "exact_true": metrics.get("exact_true"),
                "package_only_true": metrics.get("package_only_true"),
                "recognized_false": metrics.get("recognized_false"),
                "recognized_unknown": metrics.get("recognized_unknown"),
                "schema_invalid": metrics.get("schema_invalid"),
                "length_empty": metrics.get("length_empty"),
                "blank_content": metrics.get("blank_content"),
                "transport_failures": metrics.get("transport_failures"),
                "benign_package_false_positives": metrics.get("benign_package_false_positives"),
                "benign_exact_false_positives": metrics.get("benign_exact_false_positives"),
                "suspicious_exact_claims": metrics.get("suspicious_exact_claims"),
                "total_cost_usd": metrics.get("total_cost_usd"),
                "mean_cost_usd": metrics.get("mean_cost_usd"),
                "mean_latency_s": metrics.get("mean_latency_s"),
            }
        )
    _write_csv(out_csv, rows)


def _write_attack_vector_table(summary_path: Path, out_csv: Path) -> None:
    summary = _read_json(summary_path)
    rows = []
    for label, metrics in sorted(summary["by_attack_vector"].items()):
        rows.append(
            {
                "label": label,
                "calls": metrics.get("calls"),
                "parsed": metrics.get("parsed"),
                "package_true": metrics.get("package_true"),
                "exact_true": metrics.get("exact_true"),
                "package_only_true": metrics.get("package_only_true"),
                "recognized_false": metrics.get("recognized_false"),
                "recognized_unknown": metrics.get("recognized_unknown"),
                "schema_invalid": metrics.get("schema_invalid"),
                "length_empty": metrics.get("length_empty"),
                "transport_failures": metrics.get("transport_failures"),
                "benign_package_false_positives": metrics.get("benign_package_false_positives"),
                "benign_exact_false_positives": metrics.get("benign_exact_false_positives"),
                "suspicious_exact_claims": metrics.get("suspicious_exact_claims"),
                "total_cost_usd": metrics.get("total_cost_usd"),
            }
        )
    _write_csv(out_csv, rows)


def _best_row(rows: list[dict[str, str]], family: str) -> dict[str, str]:
    candidates = [row for row in rows if row["family"] == family]
    mode_rank = {"llm_raw": 2, "hybrid": 1, "agentic": 0}
    strategy_rank = {"zero_shot": 2, "role_based": 1, "few_shot": 0}
    return max(
        candidates,
        key=lambda row: (
            _float(row["f1"]),
            _float(row["recall"]),
            _float(row["precision"]),
            mode_rank.get(row["intended_mode"], -1),
            strategy_rank.get(row["prompt_strategy"], -1),
            -_int(row["error_only_package_versions"]),
        ),
    )


def _mean_f1_by_mode(rows: list[dict[str, str]]) -> dict[str, dict[str, float]]:
    grouped: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        family = row["family"]
        intended_mode = row["intended_mode"]
        if family not in PRIMARY_LLM_FAMILIES or intended_mode not in {"hybrid", "llm_raw"}:
            continue
        grouped[family][intended_mode].append(_float(row["f1"]))
    return {
        family: {
            mode: sum(values) / len(values)
            for mode, values in modes.items()
        }
        for family, modes in grouped.items()
    }


def _controls_fp_totals(rows: list[dict[str, str]]) -> list[tuple[str, int]]:
    totals = Counter()
    for row in rows:
        totals[row["detector"]] += _int(row["fp"])
    return totals.most_common()


def _top_errors(rows: list[dict[str, str]], limit: int = 5) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], int] = defaultdict(int)
    for row in rows:
        key = (row["family"], row["detector"], row["error_category"])
        grouped[key] += _int(row["rows"])
    ordered = sorted(grouped.items(), key=lambda item: item[1], reverse=True)
    return [
        {
            "family": family,
            "detector": detector,
            "error_category": error_category,
            "rows": rows_count,
        }
        for (family, detector, error_category), rows_count in ordered[:limit]
    ]


def _alias_summary(rows: list[dict[str, str]]) -> dict[str, Any]:
    by_vector = Counter()
    by_package = Counter()
    total_losses = 0
    for row in rows:
        if not _bool(row["lost_detection"]):
            continue
        total_losses += 1
        by_vector[row["attack_vector"] or "unknown"] += 1
        key = f"{row['package_name']}=={row['version']}"
        by_package[key] += 1
    return {
        "total_losses": total_losses,
        "by_attack_vector": by_vector,
        "by_package": by_package,
    }


def _best_cost_rows(primary_rows: list[dict[str, str]], cost_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    cost_index = {(row["family"], row["detector"]): row for row in cost_rows}
    mode_rank = {"llm_raw": 2, "hybrid": 1, "agentic": 0}
    strategy_rank = {"zero_shot": 2, "role_based": 1, "few_shot": 0}
    results = []
    for family in PRIMARY_LLM_FAMILIES:
        family_rows = [row for row in primary_rows if row["family"] == family]
        max_f1 = max(_float(row["f1"]) for row in family_rows)
        top_rows = [row for row in family_rows if _float(row["f1"]) == max_f1]
        row = min(
            top_rows,
            key=lambda candidate: (
                _float(cost_index.get((family, candidate["detector"]), {}).get("total_cost_usd", 1e9)),
                -_float(candidate["recall"]),
                -_float(candidate["precision"]),
                -mode_rank.get(candidate["intended_mode"], -1),
                -strategy_rank.get(candidate["prompt_strategy"], -1),
            ),
        )
        cost_row = cost_index.get((row["family"], row["detector"]))
        results.append(
            {
                "tier": FAMILY_LABELS[row["family"]],
                "detector": row["detector"],
                "mode": row["intended_mode"],
                "strategy": row["prompt_strategy"],
                "f1": _float(row["f1"]),
                "recall": _float(row["recall"]),
                "precision": _float(row["precision"]),
                "total_cost_usd": _float(cost_row["total_cost_usd"]) if cost_row else 0.0,
                "mean_cost_usd": _float(cost_row["mean_cost_usd"]) if cost_row else 0.0,
            }
        )
    return results


def _write_results_digest(out_root: Path) -> None:
    dataset_eval = out_root / "outputs" / "eval" / "dataset"
    controls_eval = out_root / "outputs" / "eval" / "controls"
    dataset_primary = _read_csv(dataset_eval / "raw_primary_detector_metrics.csv")
    controls_primary = _read_csv(controls_eval / "raw_primary_detector_metrics.csv")
    dataset_errors = _read_csv(dataset_eval / "raw_error_inventory.csv")
    dataset_alias = _read_csv(dataset_eval / "raw_alias_sensitivity.csv")
    controls_alias = _read_csv(controls_eval / "raw_alias_sensitivity.csv")
    dataset_cost = _read_csv(dataset_eval / "cost_summary.csv")
    dataset_probe = _read_json(next((out_root / "outputs" / "memory_probe" / "dataset").glob("*.summary.json")))
    controls_probe = _read_json(next((out_root / "outputs" / "memory_probe" / "controls").glob("*.summary.json")))

    mean_f1 = _mean_f1_by_mode(dataset_primary)
    best_static = _best_row(dataset_primary, "sast-only")
    best_budget = _best_row(dataset_primary, "profile:budget:llm-no-agentic")
    best_frontier = _best_row(dataset_primary, "profile:frontier:llm-no-agentic")
    controls_fp = _controls_fp_totals(controls_primary)
    top_errors = _top_errors(dataset_errors)
    dataset_alias_summary = _alias_summary(dataset_alias)
    controls_alias_summary = _alias_summary(controls_alias)
    best_cost_rows = _best_cost_rows(dataset_primary, dataset_cost)
    medium_top_rows = [
        row
        for row in dataset_primary
        if row["family"] == "profile:medium:llm-no-agentic" and _float(row["f1"]) == max(
            _float(candidate["f1"])
            for candidate in dataset_primary
            if candidate["family"] == "profile:medium:llm-no-agentic"
        )
    ]
    medium_top_detectors = sorted({row["detector"] for row in medium_top_rows if row["intended_mode"] == "llm_raw"})
    medium_top_f1 = max(_float(row["f1"]) for row in medium_top_rows)

    lines = [
        "# Results Digest",
        "",
        "This digest is generated from the packaged evaluation summaries and selected memory-probe summaries.",
        "",
        "## Evidence Base",
        "",
        "- Dataset eval summaries: `outputs/eval/dataset/`",
        "- Controls eval summaries: `outputs/eval/controls/`",
        "- Dataset memory probe: `outputs/memory_probe/dataset/`",
        "- Controls memory probe: `outputs/memory_probe/controls/`",
        "",
        "## Headline Dataset Rows",
        "",
        f"- Static best: `{best_static['detector']} {best_static['prompt_strategy']}` with `F1={_float(best_static['f1']):.4f}`.",
        f"- Budget best: `{best_budget['detector']} {best_budget['intended_mode']} {best_budget['prompt_strategy']}` with `F1={_float(best_budget['f1']):.4f}`, `recall={_float(best_budget['recall']):.4f}`, `precision={_float(best_budget['precision']):.4f}`.",
        f"- Medium top rows form a tie cluster at `F1={medium_top_f1:.4f}` across `{', '.join(medium_top_detectors)}` in raw mode.",
        f"- Frontier best: `{best_frontier['detector']} {best_frontier['intended_mode']} {best_frontier['prompt_strategy']}` with `F1={_float(best_frontier['f1']):.4f}` and `error_only_package_versions={_int(best_frontier['error_only_package_versions'])}`.",
        "",
        "## Raw vs Hybrid Means",
        "",
    ]
    for family in PRIMARY_LLM_FAMILIES:
        family_label = FAMILY_LABELS[family]
        hybrid = mean_f1[family]["hybrid"]
        raw = mean_f1[family]["llm_raw"]
        lines.append(f"- {family_label}: raw `F1={raw:.4f}` vs hybrid `F1={hybrid:.4f}`.")
    lines.extend([
        "",
        "## Controls False-Positive Pressure",
        "",
    ])
    for detector, count in controls_fp[:5]:
        lines.append(f"- `{detector}` summed FP across mode rows: `{count}`.")
    lines.extend([
        "",
        "## Reliability",
        "",
    ])
    for row in top_errors:
        lines.append(
            f"- `{row['detector']}` `{row['error_category']}` in `{row['family']}`: `{row['rows']}` rows."
        )
    lines.extend([
        "",
        "## Alias Sensitivity",
        "",
        f"- Dataset lost detections under alias masking: `{dataset_alias_summary['total_losses']}`.",
    ])
    for label, count in dataset_alias_summary["by_attack_vector"].most_common():
        lines.append(f"- Dataset alias losses in `{label}`: `{count}`.")
    if dataset_alias_summary["by_package"]:
        package, count = dataset_alias_summary["by_package"].most_common(1)[0]
        lines.append(f"- Most affected package: `{package}` with `{count}` lost detections.")
    lines.append(f"- Controls lost detections under alias masking: `{controls_alias_summary['total_losses']}`.")
    lines.extend([
        "",
        "## Memory Probe",
        "",
        f"- Dataset probe: `{dataset_probe['total_calls']}` calls, `{dataset_probe['recognized_exact_version_true']}` exact-version recognitions, `{dataset_probe['package_only_true']}` package-only associations, `{dataset_probe['recognized_false']}` recognized false, `{dataset_probe['recognized_unknown']}` unknown.",
        f"- Controls probe: `{controls_probe['total_calls']}` calls, `{controls_probe['recognized_exact_version_true']}` exact-version recognitions, `{controls_probe['package_only_true']}` package-only associations, `{controls_probe['recognized_false']}` recognized false, `{controls_probe['recognized_unknown']}` unknown.",
        "",
        "## Cost / Performance Anchors",
        "",
    ])
    for row in best_cost_rows:
        lines.append(
            f"- {row['tier']}: `{row['detector']}` {row['mode']} {row['strategy']} -> `F1={row['f1']:.4f}`, detector run cost `${row['total_cost_usd']:.6f}`, mean row cost `${row['mean_cost_usd']:.6f}`."
        )
    (out_root / "results_digest.md").write_text("\n".join(lines) + "\n")


def _write_manifest(
    out_root: Path,
    db_path: Path,
    copied_probe_entries: list[dict[str, Any]],
) -> None:
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "db": {
            "source": _display_path(db_path),
            "size_bytes": db_path.stat().st_size,
            "sha256": _sha256(db_path),
        },
        "probe_summary_files": copied_probe_entries,
        "out_root": _display_path(out_root),
    }
    (out_root / "source_manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    db_path = args.db.resolve()
    out_root = args.out_root.resolve()
    outputs_eval = out_root / "outputs" / "eval"
    outputs_memory = out_root / "outputs" / "memory_probe"
    outputs_derived = out_root / "outputs" / "derived"
    outputs_eval.mkdir(parents=True, exist_ok=True)
    outputs_memory.mkdir(parents=True, exist_ok=True)
    outputs_derived.mkdir(parents=True, exist_ok=True)

    _run_eval_summary(db_path, "dataset", outputs_eval / "dataset")
    _run_eval_summary(db_path, "controls", outputs_eval / "controls")

    copied_probe_entries: list[dict[str, Any]] = []
    copied_probe_entries.extend(
        _copy_probe_pair(args.dataset_probe_json.resolve(), args.dataset_probe_md.resolve(), outputs_memory / "dataset")
    )
    copied_probe_entries.extend(
        _copy_probe_pair(args.controls_probe_json.resolve(), args.controls_probe_md.resolve(), outputs_memory / "controls")
    )

    dataset_probe_json = next((outputs_memory / "dataset").glob("*.summary.json"))
    controls_probe_json = next((outputs_memory / "controls").glob("*.summary.json"))
    _write_memory_probe_tables(dataset_probe_json, outputs_derived / "memory_probe_dataset_by_model.csv")
    _write_memory_probe_tables(controls_probe_json, outputs_derived / "memory_probe_controls_by_model.csv")
    _write_attack_vector_table(dataset_probe_json, outputs_derived / "memory_probe_dataset_by_attack_vector.csv")
    _write_attack_vector_table(controls_probe_json, outputs_derived / "memory_probe_controls_by_attack_vector.csv")

    _write_results_digest(out_root)
    _write_manifest(out_root, db_path, copied_probe_entries)
    generated_figures = generate_all_figures(out_root)

    print(f"Built frozen cut under {out_root}")
    print(f"Dataset eval outputs: {outputs_eval / 'dataset'}")
    print(f"Controls eval outputs: {outputs_eval / 'controls'}")
    print(f"Derived probe tables: {outputs_derived}")
    print(f"Generated figures: {len(generated_figures)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
