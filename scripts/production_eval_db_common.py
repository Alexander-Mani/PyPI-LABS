#!/usr/bin/env python3
"""Shared helpers for production eval DB repair and summarization."""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path


PRIMARY_FAMILIES = (
    "sast-only",
    "profile:budget:llm-no-agentic",
    "profile:medium:llm-no-agentic",
    "profile:frontier:llm-no-agentic",
    "profile:frontier:agentic-only",
    "profile:all_models:identity-alias-probe",
)


@dataclass(frozen=True)
class RunRecord:
    run_id: str
    tier: str
    sample_set: str
    created_at: str
    row_count: int
    pkg_versions: int
    family: str | None



def family_for_tier(tier: str) -> str | None:
    tier = str(tier or "")
    if tier == "sast-only":
        return "sast-only"
    if tier == "profile:budget:llm-no-agentic":
        return tier
    if tier == "profile:medium:llm-no-agentic":
        return tier
    if tier == "profile:frontier:llm-no-agentic":
        return tier
    if tier == "profile:frontier:agentic-only":
        return tier
    if tier == "profile:all_models:identity-alias-probe":
        return tier
    return None



def load_run_inventory(db_path: Path) -> list[RunRecord]:
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(eval_run)").fetchall()
        }
        sample_set_expr = "r.sample_set" if "sample_set" in columns else "'dataset'"
        query = f"""
            SELECT
                r.run_id,
                r.tier,
                {sample_set_expr} AS sample_set,
                r.created_at,
                COUNT(e.id) AS row_count,
                COUNT(DISTINCT e.package_name || '==' || e.version) AS pkg_versions
            FROM eval_run AS r
            LEFT JOIN eval_result AS e
              ON e.run_id = r.run_id
            GROUP BY r.run_id, r.tier, sample_set, r.created_at
            ORDER BY r.created_at DESC, r.run_id DESC
        """
        rows = conn.execute(query).fetchall()
    return [
        RunRecord(
            run_id=str(row["run_id"]),
            tier=str(row["tier"]),
            sample_set=str(row["sample_set"] or "dataset"),
            created_at=str(row["created_at"]),
            row_count=int(row["row_count"] or 0),
            pkg_versions=int(row["pkg_versions"] or 0),
            family=family_for_tier(str(row["tier"])),
        )
        for row in rows
    ]



def select_primary_runs(
    inventory: list[RunRecord],
    *,
    include_agentic: bool = True,
    sample_set: str = "dataset",
) -> dict[str, RunRecord]:
    allowed = set(PRIMARY_FAMILIES)
    if not include_agentic:
        allowed.discard("profile:frontier:agentic-only")

    by_family: dict[str, list[RunRecord]] = {}
    for run in inventory:
        if run.family is None or run.family not in allowed:
            continue
        if run.sample_set != sample_set:
            continue
        by_family.setdefault(run.family, []).append(run)

    selected: dict[str, RunRecord] = {}
    for family, runs in by_family.items():
        selected[family] = max(
            runs,
            key=lambda run: (run.pkg_versions, run.created_at, run.row_count, run.run_id),
        )
    return selected
