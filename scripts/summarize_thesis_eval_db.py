#!/usr/bin/env python3
"""Summarize the production evaluation DB into raw and cleaned thesis artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts.production_eval_db_common import (  # noqa: E402
    PRIMARY_FAMILIES,
    RunRecord,
    family_for_tier,
    load_run_inventory,
    select_primary_runs,
)

PRIMARY_ANALYSIS_FAMILIES = (
    "sast-only",
    "profile:budget:llm-no-agentic",
    "profile:medium:llm-no-agentic",
    "profile:frontier:llm-no-agentic",
    "profile:frontier:agentic-only",
)
ALIAS_FAMILY = "profile:all_models:identity-alias-probe"


@dataclass(frozen=True)
class ResultRow:
    row_id: int
    run_id: str
    tier: str
    family: str
    analysis_run_id: str
    source_run_id: str
    row_origin: str
    package_name: str
    version: str
    artifact_filename: str
    detector: str
    experiment_mode: str
    intended_mode: str
    prompt_strategy: str
    sample_role: str | None
    attack_vector: str | None
    verdict: bool
    ground_truth: bool | None
    api_cost_usd: float
    exec_time_ms: int
    details: dict[str, Any]
    repair_source_row_id: int | None
    repair_source_run_id: str | None


@dataclass(frozen=True)
class PackageVersionRow:
    family: str
    analysis_run_id: str
    detector: str
    intended_mode: str
    prompt_strategy: str
    package_name: str
    version: str
    sample_role: str | None
    attack_vector: str | None
    ground_truth: bool | None
    valid_rows: int
    error_rows: int
    malicious_rows: int
    any_malicious: bool


@dataclass(frozen=True)
class RepairRunRecord:
    run_id: str
    tier: str
    created_at: str
    source_run_id: str
    source_tier: str
    source_family: str
    row_count: int
    total_cost_usd: float


@dataclass(frozen=True)
class _RunContext:
    actual_run_id: str
    tier: str
    family: str
    analysis_run_id: str
    source_run_id: str
    row_origin: str


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _load_details(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _coerce_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def load_result_rows(db_path: Path, selected: dict[str, RunRecord]) -> list[ResultRow]:
    contexts = {
        run.run_id: _RunContext(
            actual_run_id=run.run_id,
            tier=run.tier,
            family=family,
            analysis_run_id=run.run_id,
            source_run_id=run.run_id,
            row_origin="raw",
        )
        for family, run in selected.items()
    }
    return _load_rows_for_contexts(db_path, contexts)


def load_repair_run_inventory(
    db_path: Path,
    selected: dict[str, RunRecord],
) -> list[RepairRunRecord]:
    source_run_ids = tuple(run.run_id for run in selected.values())
    if not source_run_ids:
        return []
    placeholders = ", ".join("?" for _ in source_run_ids)
    query = f"""
        SELECT
            eru.run_id,
            eru.tier,
            eru.created_at,
            json_extract(er.details, '$.repair_source_run_id') AS source_run_id,
            json_extract(er.details, '$.repair_source_tier') AS source_tier,
            COUNT(er.id) AS row_count,
            COALESCE(SUM(er.api_cost_usd), 0.0) AS total_cost_usd
        FROM eval_run AS eru
        JOIN eval_result AS er
          ON er.run_id = eru.run_id
        WHERE json_extract(er.details, '$.repair_source_run_id') IN ({placeholders})
        GROUP BY eru.run_id, eru.tier, eru.created_at, source_run_id, source_tier
        ORDER BY eru.created_at DESC, eru.run_id DESC
    """
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, source_run_ids).fetchall()
    inventory: list[RepairRunRecord] = []
    for row in rows:
        source_tier = str(row["source_tier"] or "")
        source_family = family_for_tier(source_tier)
        if source_family is None:
            continue
        inventory.append(
            RepairRunRecord(
                run_id=str(row["run_id"]),
                tier=str(row["tier"]),
                created_at=str(row["created_at"]),
                source_run_id=str(row["source_run_id"]),
                source_tier=source_tier,
                source_family=source_family,
                row_count=int(row["row_count"] or 0),
                total_cost_usd=float(row["total_cost_usd"] or 0.0),
            )
        )
    return inventory


def select_latest_repair_runs(repair_inventory: list[RepairRunRecord]) -> dict[str, RepairRunRecord]:
    grouped: dict[str, list[RepairRunRecord]] = {}
    for run in repair_inventory:
        grouped.setdefault(run.source_run_id, []).append(run)
    return {
        source_run_id: max(runs, key=lambda run: (run.created_at, run.run_id))
        for source_run_id, runs in grouped.items()
    }


def load_repair_result_rows(
    db_path: Path,
    selected_repairs: dict[str, RepairRunRecord],
) -> list[ResultRow]:
    contexts = {
        repair.run_id: _RunContext(
            actual_run_id=repair.run_id,
            tier=repair.tier,
            family=repair.source_family,
            analysis_run_id=repair.source_run_id,
            source_run_id=repair.source_run_id,
            row_origin="repair",
        )
        for repair in selected_repairs.values()
    }
    return _load_rows_for_contexts(db_path, contexts)


def _load_rows_for_contexts(
    db_path: Path,
    contexts: dict[str, _RunContext],
) -> list[ResultRow]:
    run_ids = tuple(contexts)
    if not run_ids:
        return []
    placeholders = ", ".join("?" for _ in run_ids)
    query = f"""
        SELECT
            er.id,
            er.run_id,
            eru.tier,
            er.package_name,
            er.version,
            er.artifact_filename,
            er.detector,
            er.experiment_mode,
            er.intended_mode,
            er.prompt_strategy,
            er.sample_role,
            er.attack_vector,
            er.verdict,
            er.ground_truth,
            er.api_cost_usd,
            er.exec_time_ms,
            er.details
        FROM eval_result AS er
        JOIN eval_run AS eru
          ON eru.run_id = er.run_id
        WHERE er.run_id IN ({placeholders})
        ORDER BY er.run_id, er.detector, er.package_name, er.version, er.prompt_strategy, er.artifact_filename, er.id
    """
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        raw_rows = conn.execute(query, run_ids).fetchall()
    rows: list[ResultRow] = []
    for db_row in raw_rows:
        context = contexts.get(str(db_row["run_id"]))
        if context is None:
            continue
        details = _load_details(db_row["details"])
        rows.append(
            ResultRow(
                row_id=int(db_row["id"]),
                run_id=str(db_row["run_id"]),
                tier=str(db_row["tier"]),
                family=context.family,
                analysis_run_id=context.analysis_run_id,
                source_run_id=context.source_run_id,
                row_origin=context.row_origin,
                package_name=str(db_row["package_name"]),
                version=str(db_row["version"]),
                artifact_filename=str(db_row["artifact_filename"] or ""),
                detector=str(db_row["detector"]),
                experiment_mode=str(db_row["experiment_mode"]),
                intended_mode=str(db_row["intended_mode"] or db_row["experiment_mode"]),
                prompt_strategy=str(db_row["prompt_strategy"]),
                sample_role=str(db_row["sample_role"] or "") or None,
                attack_vector=str(db_row["attack_vector"] or "") or None,
                verdict=bool(int(db_row["verdict"])),
                ground_truth=(None if db_row["ground_truth"] is None else bool(int(db_row["ground_truth"]))),
                api_cost_usd=float(db_row["api_cost_usd"] or 0.0),
                exec_time_ms=int(db_row["exec_time_ms"] or 0),
                details=details,
                repair_source_row_id=_coerce_int(details.get("repair_source_row_id")),
                repair_source_run_id=str(details.get("repair_source_run_id") or "") or None,
            )
        )
    return rows


def build_cleaned_rows(raw_rows: list[ResultRow], repair_rows: list[ResultRow]) -> list[ResultRow]:
    repairs_by_source_row_id = {
        repair_row.repair_source_row_id: repair_row
        for repair_row in repair_rows
        if repair_row.repair_source_row_id is not None
    }
    cleaned: list[ResultRow] = []
    for raw_row in raw_rows:
        if raw_row.experiment_mode == "error" and raw_row.row_id in repairs_by_source_row_id:
            cleaned.append(repairs_by_source_row_id[raw_row.row_id])
        else:
            cleaned.append(raw_row)
    return cleaned


def aggregate_package_version_rows(rows: list[ResultRow]) -> list[PackageVersionRow]:
    buckets: dict[tuple[str, str, str, str, str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (
            row.family,
            row.analysis_run_id,
            row.detector,
            row.intended_mode,
            row.prompt_strategy,
            row.package_name,
            row.version,
        )
        bucket = buckets.setdefault(
            key,
            {
                "sample_role": row.sample_role,
                "attack_vector": row.attack_vector,
                "ground_truth": row.ground_truth,
                "valid_rows": 0,
                "error_rows": 0,
                "malicious_rows": 0,
            },
        )
        if row.experiment_mode == "error":
            bucket["error_rows"] += 1
        else:
            bucket["valid_rows"] += 1
            if row.verdict:
                bucket["malicious_rows"] += 1
    aggregated: list[PackageVersionRow] = []
    for key, bucket in sorted(buckets.items()):
        family, analysis_run_id, detector, intended_mode, prompt_strategy, package_name, version = key
        aggregated.append(
            PackageVersionRow(
                family=family,
                analysis_run_id=analysis_run_id,
                detector=detector,
                intended_mode=intended_mode,
                prompt_strategy=prompt_strategy,
                package_name=package_name,
                version=version,
                sample_role=bucket["sample_role"],
                attack_vector=bucket["attack_vector"],
                ground_truth=bucket["ground_truth"],
                valid_rows=int(bucket["valid_rows"]),
                error_rows=int(bucket["error_rows"]),
                malicious_rows=int(bucket["malicious_rows"]),
                any_malicious=bool(bucket["malicious_rows"]),
            )
        )
    return aggregated


def build_primary_detector_metrics(pv_rows: list[PackageVersionRow]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for row in pv_rows:
        if row.family not in PRIMARY_ANALYSIS_FAMILIES:
            continue
        key = (row.family, row.detector, row.intended_mode, row.prompt_strategy)
        bucket = buckets.setdefault(
            key,
            {
                "family": row.family,
                "detector": row.detector,
                "intended_mode": row.intended_mode,
                "prompt_strategy": row.prompt_strategy,
                "tp": 0,
                "tn": 0,
                "fp": 0,
                "fn": 0,
                "covered_package_versions": 0,
                "error_only_package_versions": 0,
                "total_package_versions": 0,
            },
        )
        bucket["total_package_versions"] += 1
        if row.valid_rows == 0:
            bucket["error_only_package_versions"] += 1
            continue
        bucket["covered_package_versions"] += 1
        if row.ground_truth is True and row.any_malicious:
            bucket["tp"] += 1
        elif row.ground_truth is True and not row.any_malicious:
            bucket["fn"] += 1
        elif row.ground_truth is False and row.any_malicious:
            bucket["fp"] += 1
        elif row.ground_truth is False and not row.any_malicious:
            bucket["tn"] += 1
    metrics: list[dict[str, Any]] = []
    for key in sorted(buckets):
        bucket = buckets[key]
        tp = bucket["tp"]
        fp = bucket["fp"]
        fn = bucket["fn"]
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        metrics.append(
            {
                **bucket,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
            }
        )
    return metrics


def build_run_inventory_rows(
    inventory: list[RunRecord],
    selected_raw: dict[str, RunRecord],
    repair_inventory: list[RepairRunRecord],
    selected_repairs: dict[str, RepairRunRecord],
) -> list[dict[str, Any]]:
    selected_raw_run_ids = {run.run_id for run in selected_raw.values()}
    selected_repair_run_ids = {run.run_id for run in selected_repairs.values()}
    repair_by_run_id = {run.run_id: run for run in repair_inventory}
    latest_repair_sources = {run.source_run_id for run in selected_repairs.values()}
    rows: list[dict[str, Any]] = []
    for run in inventory:
        repair = repair_by_run_id.get(run.run_id)
        if run.run_id in selected_raw_run_ids:
            origin = "raw"
            selection_reason = "selected_latest_complete"
            family = run.family or "excluded"
        elif repair is not None and run.run_id in selected_repair_run_ids:
            origin = "repair"
            selection_reason = "selected_latest_repair"
            family = repair.source_family
        elif repair is not None and repair.source_run_id in latest_repair_sources:
            origin = "repair"
            selection_reason = "superseded_by_newer_repair_run"
            family = repair.source_family
        elif repair is not None:
            origin = "repair"
            selection_reason = "repair_run_for_non_selected_source"
            family = repair.source_family
        else:
            origin = "raw"
            selection_reason = (
                "excluded_non_primary_family"
                if run.family is None
                else "superseded_by_more_complete_or_newer_run"
            )
            family = run.family or "excluded"
        rows.append(
            {
                "run_id": run.run_id,
                "tier": run.tier,
                "sample_set": run.sample_set,
                "family": family,
                "origin": origin,
                "created_at": run.created_at,
                "row_count": run.row_count,
                "pkg_versions": run.pkg_versions,
                "repair_source_run_id": repair.source_run_id if repair else "",
                "selected": run.run_id in selected_raw_run_ids or run.run_id in selected_repair_run_ids,
                "selection_reason": selection_reason,
            }
        )
    return rows


def build_cost_summary(rows: list[ResultRow]) -> list[dict[str, Any]]:
    buckets: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row.family, row.run_id, row.detector)
        bucket = buckets.setdefault(
            key,
            {
                "family": row.family,
                "run_id": row.run_id,
                "detector": row.detector,
                "rows": 0,
                "total_cost_usd": 0.0,
                "total_exec_time_ms": 0,
            },
        )
        bucket["rows"] += 1
        bucket["total_cost_usd"] += row.api_cost_usd
        bucket["total_exec_time_ms"] += row.exec_time_ms
    summary: list[dict[str, Any]] = []
    for key in sorted(buckets):
        bucket = buckets[key]
        row_count = bucket["rows"] or 1
        summary.append(
            {
                **bucket,
                "total_cost_usd": round(bucket["total_cost_usd"], 6),
                "mean_cost_usd": round(bucket["total_cost_usd"] / row_count, 6),
                "mean_exec_time_ms": round(bucket["total_exec_time_ms"] / row_count, 1),
            }
        )
    return summary


def _summarize_error_category(row: ResultRow) -> str:
    protocol_category = str(row.details.get("protocol_category") or "").strip()
    if protocol_category:
        return protocol_category
    error_text = str(row.details.get("error") or "").strip()
    lowered = error_text.lower()
    if "no deployments available for selected model" in lowered:
        return "deployment_unavailable_429"
    if "rate limit" in lowered or "error code: 429" in lowered:
        return "rate_limit_429"
    if "timeout" in lowered:
        return "timeout"
    if "connection" in lowered:
        return "connection_error"
    if not error_text:
        return "unknown"
    return error_text


def build_error_inventory(rows: list[ResultRow]) -> list[dict[str, Any]]:
    buckets: Counter[tuple[str, str, str, str]] = Counter()
    for row in rows:
        if row.experiment_mode != "error":
            continue
        category = _summarize_error_category(row)
        buckets[(row.family, row.detector, row.prompt_strategy, category)] += 1
    return [
        {
            "family": family,
            "detector": detector,
            "prompt_strategy": prompt_strategy,
            "error_category": category,
            "rows": count,
        }
        for (family, detector, prompt_strategy, category), count in sorted(buckets.items())
    ]


def build_alias_sensitivity(pv_rows: list[PackageVersionRow]) -> list[dict[str, Any]]:
    canonical_lookup: dict[tuple[str, str, str], PackageVersionRow] = {}
    alias_lookup: dict[tuple[str, str, str], PackageVersionRow] = {}
    detector_family: dict[str, str] = {}
    for row in pv_rows:
        if (
            row.family in {
                "profile:budget:llm-no-agentic",
                "profile:medium:llm-no-agentic",
                "profile:frontier:llm-no-agentic",
            }
            and row.intended_mode == "hybrid"
            and row.prompt_strategy == "zero_shot"
        ):
            detector_family.setdefault(row.detector, row.family)
            canonical_lookup[(row.detector, row.package_name, row.version)] = row
        elif row.family == ALIAS_FAMILY and row.intended_mode == "hybrid" and row.prompt_strategy == "zero_shot":
            alias_lookup[(row.detector, row.package_name, row.version)] = row
    rows: list[dict[str, Any]] = []
    for key, alias_row in sorted(alias_lookup.items()):
        detector, package_name, version = key
        canonical_row = canonical_lookup.get(key)
        rows.append(
            {
                "detector": detector,
                "canonical_family": detector_family.get(detector, "missing"),
                "package_name": package_name,
                "version": version,
                "ground_truth": alias_row.ground_truth,
                "sample_role": alias_row.sample_role,
                "attack_vector": alias_row.attack_vector,
                "canonical_any_malicious": canonical_row.any_malicious if canonical_row else None,
                "canonical_valid_rows": canonical_row.valid_rows if canonical_row else 0,
                "canonical_error_rows": canonical_row.error_rows if canonical_row else 0,
                "alias_any_malicious": alias_row.any_malicious,
                "alias_valid_rows": alias_row.valid_rows,
                "alias_error_rows": alias_row.error_rows,
                "lost_detection": bool(canonical_row and canonical_row.any_malicious and not alias_row.any_malicious),
            }
        )
    return rows


def build_repair_inventory_rows(
    repair_inventory: list[RepairRunRecord],
    selected_repairs: dict[str, RepairRunRecord],
) -> list[dict[str, Any]]:
    selected_repair_run_ids = {run.run_id for run in selected_repairs.values()}
    rows = []
    for run in sorted(repair_inventory, key=lambda item: (item.created_at, item.run_id), reverse=True):
        rows.append(
            {
                "repair_run_id": run.run_id,
                "repair_tier": run.tier,
                "source_run_id": run.source_run_id,
                "source_tier": run.source_tier,
                "source_family": run.source_family,
                "created_at": run.created_at,
                "row_count": run.row_count,
                "total_cost_usd": round(run.total_cost_usd, 6),
                "selected_latest_repair": run.run_id in selected_repair_run_ids,
            }
        )
    return rows


def build_repair_comparison(raw_rows: list[ResultRow], repair_rows: list[ResultRow]) -> list[dict[str, Any]]:
    raw_by_id = {row.row_id: row for row in raw_rows}
    comparison: list[dict[str, Any]] = []
    for repair_row in sorted(
        repair_rows,
        key=lambda row: (
            row.source_run_id,
            row.detector,
            row.package_name,
            row.version,
            row.prompt_strategy,
            row.artifact_filename,
            row.row_id,
        ),
    ):
        source_row = raw_by_id.get(repair_row.repair_source_row_id or -1)
        comparison.append(
            {
                "source_run_id": repair_row.repair_source_run_id or (source_row.source_run_id if source_row else ""),
                "correction_run_id": repair_row.run_id,
                "source_row_id": repair_row.repair_source_row_id or "",
                "detector": repair_row.detector,
                "intended_mode": repair_row.intended_mode,
                "prompt_strategy": repair_row.prompt_strategy,
                "package_name": repair_row.package_name,
                "version": repair_row.version,
                "artifact_filename": repair_row.artifact_filename,
                "source_error_category": _summarize_error_category(source_row) if source_row else "missing_source_row",
                "corrected_final_mode": repair_row.experiment_mode,
                "corrected_success": repair_row.experiment_mode != "error",
                "corrected_error_category": _summarize_error_category(repair_row) if repair_row.experiment_mode == "error" else "",
                "repair_attempts": repair_row.details.get("repair_attempts", ""),
            }
        )
    return comparison


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _write_md_table(path: Path, title: str, rows: list[dict[str, Any]]) -> None:
    lines = [f"# {title}", ""]
    if not rows:
        lines.append("No rows")
    else:
        headers = list(rows[0].keys())
        lines.append("| " + " | ".join(headers) + " |")
        lines.append("| " + " | ".join("---" for _ in headers) + " |")
        for row in rows:
            lines.append("| " + " | ".join(str(row.get(header, "")) for header in headers) + " |")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_summary_md(
    path: Path,
    *,
    sample_set: str,
    selected_raw: dict[str, RunRecord],
    selected_repairs: dict[str, RepairRunRecord],
    raw_primary_metrics: list[dict[str, Any]],
    cleaned_primary_metrics: list[dict[str, Any]],
    raw_error_inventory: list[dict[str, Any]],
    cleaned_error_inventory: list[dict[str, Any]],
    raw_alias_sensitivity: list[dict[str, Any]],
    cleaned_alias_sensitivity: list[dict[str, Any]],
    repair_comparison: list[dict[str, Any]],
) -> None:
    lines = ["# Thesis Eval DB Summary", "", f"- Sample set: `{sample_set}`", "", "## Selected Raw Runs", ""]
    for family in PRIMARY_FAMILIES:
        run = selected_raw.get(family)
        if run is None:
            continue
        lines.append(
            f"- `{family}` -> `{run.run_id}` "
            f"(sample_set={run.sample_set}, {run.pkg_versions} package/version units, {run.row_count} rows)"
        )
    lines.extend(["", "## Selected Latest Correction Runs", ""])
    if not selected_repairs:
        lines.append("- None")
    else:
        for source_run_id, repair in sorted(selected_repairs.items()):
            lines.append(
                f"- `{repair.run_id}` <= `{source_run_id}` ({repair.row_count} repaired rows, cost=${repair.total_cost_usd:.6f})"
            )
    lines.extend(["", "## Raw Primary Detector Metrics", ""])
    for row in raw_primary_metrics:
        lines.append(
            f"- `{row['family']}` `{row['detector']}:{row['intended_mode']}:{row['prompt_strategy']}` "
            f"TP={row['tp']} TN={row['tn']} FP={row['fp']} FN={row['fn']} "
            f"precision={row['precision']:.4f} recall={row['recall']:.4f} f1={row['f1']:.4f} "
            f"covered={row['covered_package_versions']} error_only={row['error_only_package_versions']}"
        )
    lines.extend(["", "## Cleaned Primary Detector Metrics", ""])
    for row in cleaned_primary_metrics:
        lines.append(
            f"- `{row['family']}` `{row['detector']}:{row['intended_mode']}:{row['prompt_strategy']}` "
            f"TP={row['tp']} TN={row['tn']} FP={row['fp']} FN={row['fn']} "
            f"precision={row['precision']:.4f} recall={row['recall']:.4f} f1={row['f1']:.4f} "
            f"covered={row['covered_package_versions']} error_only={row['error_only_package_versions']}"
        )
    lines.extend(["", "## Raw Remaining Error Inventory", ""])
    if not raw_error_inventory:
        lines.append("- None")
    else:
        for row in raw_error_inventory:
            lines.append(
                f"- `{row['family']}` `{row['detector']}:{row['prompt_strategy']}` `{row['error_category']}` -> {row['rows']}"
            )
    lines.extend(["", "## Cleaned Remaining Error Inventory", ""])
    if not cleaned_error_inventory:
        lines.append("- None")
    else:
        for row in cleaned_error_inventory:
            lines.append(
                f"- `{row['family']}` `{row['detector']}:{row['prompt_strategy']}` `{row['error_category']}` -> {row['rows']}"
            )
    raw_lost = sum(1 for row in raw_alias_sensitivity if row["lost_detection"])
    cleaned_lost = sum(1 for row in cleaned_alias_sensitivity if row["lost_detection"])
    fixed = sum(1 for row in repair_comparison if row["corrected_success"])
    still_error = len(repair_comparison) - fixed
    lines.extend(
        [
            "",
            "## Alias Sensitivity",
            "",
            f"- Raw alias comparison rows: {len(raw_alias_sensitivity)}",
            f"- Raw lost detections under alias masking: {raw_lost}",
            f"- Cleaned alias comparison rows: {len(cleaned_alias_sensitivity)}",
            f"- Cleaned lost detections under alias masking: {cleaned_lost}",
            "",
            "## Repair Comparison",
            "",
            f"- Total corrected source error rows compared: {len(repair_comparison)}",
            f"- Corrected to non-error: {fixed}",
            f"- Still error after correction: {still_error}",
        ]
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_artifacts(
    out_dir: Path,
    *,
    sample_set: str,
    run_inventory_rows: list[dict[str, Any]],
    repair_inventory_rows: list[dict[str, Any]],
    repair_comparison_rows: list[dict[str, Any]],
    raw_primary_metrics: list[dict[str, Any]],
    cleaned_primary_metrics: list[dict[str, Any]],
    raw_package_version_metrics: list[dict[str, Any]],
    cleaned_package_version_metrics: list[dict[str, Any]],
    raw_cost_summary: list[dict[str, Any]],
    repair_cost_summary: list[dict[str, Any]],
    raw_error_inventory: list[dict[str, Any]],
    cleaned_error_inventory: list[dict[str, Any]],
    raw_alias_sensitivity: list[dict[str, Any]],
    cleaned_alias_sensitivity: list[dict[str, Any]],
    selected_raw: dict[str, RunRecord],
    selected_repairs: dict[str, RepairRunRecord],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    artifacts = {
        "run_inventory": run_inventory_rows,
        "repair_inventory": repair_inventory_rows,
        "repair_comparison": repair_comparison_rows,
        "raw_primary_detector_metrics": raw_primary_metrics,
        "cleaned_primary_detector_metrics": cleaned_primary_metrics,
        "raw_package_version_metrics": raw_package_version_metrics,
        "cleaned_package_version_metrics": cleaned_package_version_metrics,
        "cost_summary": raw_cost_summary,
        "repair_cost_summary": repair_cost_summary,
        "raw_error_inventory": raw_error_inventory,
        "cleaned_error_inventory": cleaned_error_inventory,
        "raw_alias_sensitivity": raw_alias_sensitivity,
        "cleaned_alias_sensitivity": cleaned_alias_sensitivity,
    }
    for stem, rows in artifacts.items():
        _write_csv(out_dir / f"{stem}.csv", rows)
        _write_md_table(out_dir / f"{stem}.md", stem.replace("_", " ").title(), rows)
    _write_summary_md(
        out_dir / "summary.md",
        sample_set=sample_set,
        selected_raw=selected_raw,
        selected_repairs=selected_repairs,
        raw_primary_metrics=raw_primary_metrics,
        cleaned_primary_metrics=cleaned_primary_metrics,
        raw_error_inventory=raw_error_inventory,
        cleaned_error_inventory=cleaned_error_inventory,
        raw_alias_sensitivity=raw_alias_sensitivity,
        cleaned_alias_sensitivity=cleaned_alias_sensitivity,
        repair_comparison=repair_comparison_rows,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="Path to the production eval_results.db")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for CSV/Markdown artifacts. Default: analysis/eval_db/<timestamp>",
    )
    parser.add_argument(
        "--after-repair",
        action="store_true",
        help="Label the output set as post-repair in console output only.",
    )
    parser.add_argument(
        "--sample-set",
        choices=("dataset", "controls", "both"),
        default="dataset",
        help="Selected production run sample set to summarize (default: dataset).",
    )
    return parser.parse_args(argv)


def _package_metrics_rows(pv_rows: list[PackageVersionRow]) -> list[dict[str, Any]]:
    return [
        {
            "family": row.family,
            "analysis_run_id": row.analysis_run_id,
            "detector": row.detector,
            "intended_mode": row.intended_mode,
            "prompt_strategy": row.prompt_strategy,
            "package_name": row.package_name,
            "version": row.version,
            "sample_role": row.sample_role,
            "attack_vector": row.attack_vector,
            "ground_truth": row.ground_truth,
            "valid_rows": row.valid_rows,
            "error_rows": row.error_rows,
            "malicious_rows": row.malicious_rows,
            "any_malicious": row.any_malicious,
        }
        for row in pv_rows
    ]


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    db_path = args.db.resolve()
    inventory = load_run_inventory(db_path)
    selected_raw = select_primary_runs(inventory, include_agentic=True, sample_set=args.sample_set)
    raw_rows = load_result_rows(db_path, selected_raw)

    repair_inventory = load_repair_run_inventory(db_path, selected_raw)
    selected_repairs = select_latest_repair_runs(repair_inventory)
    repair_rows = load_repair_result_rows(db_path, selected_repairs)

    cleaned_rows = build_cleaned_rows(raw_rows, repair_rows)

    raw_pv_rows = aggregate_package_version_rows(raw_rows)
    cleaned_pv_rows = aggregate_package_version_rows(cleaned_rows)

    raw_primary_metrics = build_primary_detector_metrics(raw_pv_rows)
    cleaned_primary_metrics = build_primary_detector_metrics(cleaned_pv_rows)

    raw_error_inventory = build_error_inventory(raw_rows)
    cleaned_error_inventory = build_error_inventory(cleaned_rows)

    raw_alias_sensitivity = build_alias_sensitivity(raw_pv_rows)
    cleaned_alias_sensitivity = build_alias_sensitivity(cleaned_pv_rows)

    run_inventory_rows = build_run_inventory_rows(inventory, selected_raw, repair_inventory, selected_repairs)
    repair_inventory_rows = build_repair_inventory_rows(repair_inventory, selected_repairs)
    repair_comparison_rows = build_repair_comparison(raw_rows, repair_rows)

    out_dir = args.out_dir or (_REPO_ROOT / "analysis" / "eval_db" / _utc_stamp())
    write_artifacts(
        out_dir,
        sample_set=args.sample_set,
        run_inventory_rows=run_inventory_rows,
        repair_inventory_rows=repair_inventory_rows,
        repair_comparison_rows=repair_comparison_rows,
        raw_primary_metrics=raw_primary_metrics,
        cleaned_primary_metrics=cleaned_primary_metrics,
        raw_package_version_metrics=_package_metrics_rows(raw_pv_rows),
        cleaned_package_version_metrics=_package_metrics_rows(cleaned_pv_rows),
        raw_cost_summary=build_cost_summary(raw_rows),
        repair_cost_summary=build_cost_summary(repair_rows),
        raw_error_inventory=raw_error_inventory,
        cleaned_error_inventory=cleaned_error_inventory,
        raw_alias_sensitivity=raw_alias_sensitivity,
        cleaned_alias_sensitivity=cleaned_alias_sensitivity,
        selected_raw=selected_raw,
        selected_repairs=selected_repairs,
    )

    label = "post-repair" if args.after_repair else "current"
    print(f"DB: {db_path}")
    print(f"Output: {out_dir}")
    print(f"Mode: {label}")
    print(f"Sample set: {args.sample_set}")
    print(f"Selected raw families: {', '.join(sorted(selected_raw))}")
    print(f"Selected latest correction runs: {len(selected_repairs)}")
    print(f"Raw primary metric rows: {len(raw_primary_metrics)}")
    print(f"Cleaned primary metric rows: {len(cleaned_primary_metrics)}")
    print(f"Repair comparison rows: {len(repair_comparison_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
