#!/usr/bin/env python3
"""Generate matplotlib figures for the frozen 2026-04-26 results cut."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

_MPLCONFIGDIR = Path("/tmp/pypi-scada-mplconfig")
_MPLCONFIGDIR.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_MPLCONFIGDIR))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.style.use("seaborn-v0_8-whitegrid")

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
    parser.add_argument(
        "--out-root",
        type=Path,
        default=Path("data_processing/frozen_cut_20260426"),
        help="Frozen cut output root.",
    )
    return parser.parse_args(argv)


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as handle:
        return list(csv.DictReader(handle))


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def _bool(value: str | bool | None) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() == "true"


def _float(value: str | float | int | None) -> float:
    if value in (None, ""):
        return 0.0
    return float(value)


def _int(value: str | int | None) -> int:
    if value in (None, ""):
        return 0
    return int(value)


def _save(fig: plt.Figure, target_base: Path) -> None:
    target_base.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(target_base.with_suffix(".png"), dpi=200, bbox_inches="tight")
    fig.savefig(target_base.with_suffix(".pdf"), bbox_inches="tight")
    plt.close(fig)


def _best_row(rows: list[dict[str, str]], family: str) -> dict[str, str]:
    candidates = [row for row in rows if row["family"] == family]
    if not candidates:
        raise ValueError(f"No rows found for family {family}")
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


def _plot_raw_vs_hybrid(primary_rows: list[dict[str, str]], out_dir: Path) -> None:
    means: dict[str, dict[str, list[float]]] = defaultdict(lambda: defaultdict(list))
    for row in primary_rows:
        family = row["family"]
        intended_mode = row["intended_mode"]
        if family not in PRIMARY_LLM_FAMILIES or intended_mode not in {"hybrid", "llm_raw"}:
            continue
        means[family][intended_mode].append(_float(row["f1"]))

    families = list(PRIMARY_LLM_FAMILIES)
    labels = [FAMILY_LABELS[family] for family in families]
    hybrid = [sum(means[family]["hybrid"]) / len(means[family]["hybrid"]) for family in families]
    raw = [sum(means[family]["llm_raw"]) / len(means[family]["llm_raw"]) for family in families]

    fig, ax = plt.subplots(figsize=(8, 4.8))
    x = range(len(families))
    width = 0.35
    ax.bar([i - width / 2 for i in x], hybrid, width=width, label="Hybrid", color="#8093f1")
    ax.bar([i + width / 2 for i in x], raw, width=width, label="Raw", color="#f18f6b")
    ax.set_xticks(list(x), labels)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("Mean F1")
    ax.set_title("Raw vs Hybrid Mean F1 by LLM Tier")
    ax.legend()
    _save(fig, out_dir / "raw_vs_hybrid_means")


def _plot_best_rows(primary_rows: list[dict[str, str]], out_dir: Path) -> None:
    families = ["sast-only", *PRIMARY_LLM_FAMILIES]
    best = [_best_row(primary_rows, family) for family in families]
    labels = [FAMILY_LABELS[row["family"]] for row in best]
    f1_values = [_float(row["f1"]) for row in best]
    recall_values = [_float(row["recall"] or 0.0) for row in best]

    fig, ax = plt.subplots(figsize=(9, 5.2))
    y = range(len(best))
    ax.barh(list(y), f1_values, color="#5c946e", label="F1")
    ax.scatter(recall_values, list(y), color="#ef476f", marker="D", label="Recall", zorder=3)
    ax.set_yticks(list(y), labels)
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("Score")
    ax.set_title("Best Detector Row by Tier")
    for idx, row in enumerate(best):
        text = f"{row['detector']} {row['intended_mode']} {row['prompt_strategy']}"
        ax.text(min(f1_values[idx] + 0.02, 1.01), idx, text, va="center", fontsize=8)
    ax.legend(loc="lower right")
    _save(fig, out_dir / "best_rows_by_tier")


def _plot_controls_fp(primary_rows: list[dict[str, str]], out_dir: Path) -> None:
    detector_fp = Counter()
    for row in primary_rows:
        detector_fp[row["detector"]] += _int(row["fp"])
    ordered = detector_fp.most_common()
    labels = [name for name, count in ordered]
    values = [count for _, count in ordered]

    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.bar(labels, values, color="#e07a5f")
    ax.set_ylabel("Summed False Positives Across Mode Rows")
    ax.set_title("Controls False-Positive Pressure by Detector")
    ax.tick_params(axis="x", rotation=45)
    _save(fig, out_dir / "controls_false_positive_totals")


def _plot_dataset_errors(error_rows: list[dict[str, str]], out_dir: Path) -> None:
    top_categories = [
        category
        for category, _ in Counter({}).most_common(0)
    ]
    detector_totals = Counter()
    category_totals = Counter()
    by_detector_category: dict[str, Counter[str]] = defaultdict(Counter)
    for row in error_rows:
        detector = row["detector"]
        category = row["error_category"]
        count = _int(row["rows"])
        detector_totals[detector] += count
        category_totals[category] += count
        by_detector_category[detector][category] += count
    detectors = [detector for detector, _ in detector_totals.most_common()]
    top_categories = [category for category, _ in category_totals.most_common(4)]
    colors = ["#d62828", "#f77f00", "#fcbf49", "#6a4c93", "#4d908e"]

    fig, ax = plt.subplots(figsize=(10, 5.2))
    bottom = [0] * len(detectors)
    for idx, category in enumerate(top_categories):
        values = [by_detector_category[detector].get(category, 0) for detector in detectors]
        ax.bar(detectors, values, bottom=bottom, label=category, color=colors[idx % len(colors)])
        bottom = [bottom[i] + values[i] for i in range(len(values))]
    other_values = []
    for detector in detectors:
        other = sum(
            count for category, count in by_detector_category[detector].items() if category not in top_categories
        )
        other_values.append(other)
    if any(other_values):
        ax.bar(detectors, other_values, bottom=bottom, label="other", color=colors[-1])
    ax.set_ylabel("Error Rows")
    ax.set_title("Dataset Error Burden by Detector")
    ax.tick_params(axis="x", rotation=45)
    ax.legend(loc="upper right")
    _save(fig, out_dir / "dataset_error_burden")


def _plot_alias_losses(alias_rows: list[dict[str, str]], out_dir: Path) -> None:
    losses = Counter()
    for row in alias_rows:
        if _bool(row["lost_detection"]):
            losses[row["attack_vector"] or "unknown"] += 1
    labels = list(losses.keys())
    values = [losses[label] for label in labels]

    fig, ax = plt.subplots(figsize=(8, 4.8))
    ax.bar(labels, values, color="#6d597a")
    ax.set_ylabel("Lost Detections")
    ax.set_title("Dataset Alias-Masking Losses by Attack Vector")
    ax.tick_params(axis="x", rotation=30)
    _save(fig, out_dir / "alias_losses_by_attack_vector")


def _plot_memory_probe(memory_probe_root: Path, out_dir: Path) -> None:
    dataset_summary = _read_json(next((memory_probe_root / "dataset").glob("*.summary.json")))
    controls_summary = _read_json(next((memory_probe_root / "controls").glob("*.summary.json")))
    labels = ["Exact-Version", "Package-Only", "Recognized False", "Unknown"]
    dataset_values = [
        int(dataset_summary["recognized_exact_version_true"]),
        int(dataset_summary["package_only_true"]),
        int(dataset_summary["recognized_false"]),
        int(dataset_summary["recognized_unknown"]),
    ]
    controls_values = [
        int(controls_summary["recognized_exact_version_true"]),
        int(controls_summary["package_only_true"]),
        int(controls_summary["recognized_false"]),
        int(controls_summary["recognized_unknown"]),
    ]
    x = range(len(labels))
    width = 0.35
    fig, ax = plt.subplots(figsize=(8.4, 4.8))
    ax.bar([i - width / 2 for i in x], dataset_values, width=width, label="Dataset Probe", color="#2a9d8f")
    ax.bar([i + width / 2 for i in x], controls_values, width=width, label="Controls Probe", color="#e76f51")
    ax.set_xticks(list(x), labels)
    ax.set_ylabel("Count")
    ax.set_title("Memory Probe: Exact Recall vs Association")
    ax.legend()
    _save(fig, out_dir / "memory_probe_exact_vs_association")


def _plot_cost_tradeoff(primary_rows: list[dict[str, str]], cost_rows: list[dict[str, str]], out_dir: Path) -> None:
    best_by_detector: dict[tuple[str, str], dict[str, str]] = {}
    for row in primary_rows:
        family = row["family"]
        if family not in PRIMARY_LLM_FAMILIES:
            continue
        key = (family, row["detector"])
        current = best_by_detector.get(key)
        if current is None or (
            _float(row["f1"]),
            _float(row["recall"]),
            _float(row["precision"]),
        ) > (
            _float(current["f1"]),
            _float(current["recall"]),
            _float(current["precision"]),
        ):
            best_by_detector[key] = row

    cost_index = {(row["family"], row["detector"]): row for row in cost_rows}
    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    colors = {
        "profile:budget:llm-no-agentic": "#457b9d",
        "profile:medium:llm-no-agentic": "#2a9d8f",
        "profile:frontier:llm-no-agentic": "#e76f51",
    }
    for (family, detector), metric_row in sorted(best_by_detector.items()):
        cost_row = cost_index.get((family, detector))
        if cost_row is None:
            continue
        x = _float(cost_row["total_cost_usd"])
        y = _float(metric_row["f1"])
        ax.scatter(x, y, color=colors[family], s=60)
        ax.text(x, min(y + 0.015, 1.02), detector, fontsize=8)
    ax.set_xlabel("Total Detector Run Cost (USD)")
    ax.set_ylabel("Best F1")
    ax.set_ylim(0, 1.05)
    ax.set_title("Cost / Performance Tradeoff by Detector")
    legend_handles = [
        plt.Line2D([0], [0], marker="o", linestyle="", color=color, label=FAMILY_LABELS[family])
        for family, color in colors.items()
    ]
    ax.legend(handles=legend_handles, loc="lower right")
    _save(fig, out_dir / "cost_performance_tradeoff")


def generate_all_figures(out_root: Path) -> list[Path]:
    eval_dataset = out_root / "outputs" / "eval" / "dataset"
    eval_controls = out_root / "outputs" / "eval" / "controls"
    memory_probe_root = out_root / "outputs" / "memory_probe"
    figures_dir = out_root / "figures"

    dataset_primary = _read_csv(eval_dataset / "raw_primary_detector_metrics.csv")
    controls_primary = _read_csv(eval_controls / "raw_primary_detector_metrics.csv")
    dataset_errors = _read_csv(eval_dataset / "raw_error_inventory.csv")
    dataset_alias = _read_csv(eval_dataset / "raw_alias_sensitivity.csv")
    dataset_cost = _read_csv(eval_dataset / "cost_summary.csv")

    _plot_raw_vs_hybrid(dataset_primary, figures_dir)
    _plot_best_rows(dataset_primary, figures_dir)
    _plot_controls_fp(controls_primary, figures_dir)
    _plot_dataset_errors(dataset_errors, figures_dir)
    _plot_alias_losses(dataset_alias, figures_dir)
    _plot_memory_probe(memory_probe_root, figures_dir)
    _plot_cost_tradeoff(dataset_primary, dataset_cost, figures_dir)

    return sorted(figures_dir.glob("*"))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    generated = generate_all_figures(args.out_root.resolve())
    print(f"Generated {len(generated)} figure files under {args.out_root / 'figures'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
