#!/usr/bin/env python3
"""Normalize historical non-JSON LLM outputs into explicit error rows."""

from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
DEFAULT_DB_PATH = _REPO_ROOT / "src" / "data" / "eval_results.db"
LLM_MODES = {"hybrid", "llm_raw", "agentic"}


@dataclass
class Candidate:
    id: int
    run_id: str
    package_name: str
    version: str
    artifact_filename: str
    experiment_mode: str
    prompt_strategy: str
    detector: str
    raw: str
    details: dict

    @property
    def error(self) -> str:
        return "empty_model_response" if not self.raw.strip() else "unparseable_model_response"

    @property
    def retryable(self) -> bool:
        return self.error == "empty_model_response"


@dataclass
class NormalizationReport:
    db_path: Path
    applied: bool
    backup_path: Path | None = None
    candidates: list[Candidate] = field(default_factory=list)
    collisions: list[tuple[Candidate, int]] = field(default_factory=list)

    @property
    def would_update(self) -> int:
        return len(self.candidates)

    @property
    def empty_count(self) -> int:
        return sum(1 for candidate in self.candidates if candidate.error == "empty_model_response")

    @property
    def unparseable_count(self) -> int:
        return sum(1 for candidate in self.candidates if candidate.error == "unparseable_model_response")

    @property
    def by_key(self) -> Counter:
        counts: Counter = Counter()
        for candidate in self.candidates:
            key = (candidate.detector, candidate.experiment_mode, candidate.prompt_strategy, candidate.error)
            counts[key] += 1
        return counts


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _load_details(raw_details: str | None) -> dict | None:
    if not raw_details:
        return None
    try:
        details = json.loads(raw_details)
    except json.JSONDecodeError:
        return None
    return details if isinstance(details, dict) else None


def _iter_candidates(conn: sqlite3.Connection, run_id: str | None = None) -> list[Candidate]:
    conn.row_factory = sqlite3.Row
    where = "experiment_mode != 'error'"
    params: list[str] = []
    if run_id:
        where += " AND run_id = ?"
        params.append(run_id)
    rows = conn.execute(f"SELECT * FROM eval_result WHERE {where} ORDER BY id", params).fetchall()

    candidates: list[Candidate] = []
    for row in rows:
        if row["experiment_mode"] not in LLM_MODES:
            continue
        details = _load_details(row["details"])
        if details is None or "raw" not in details:
            continue
        raw_value = details.get("raw")
        raw_text = "" if raw_value is None else str(raw_value)
        candidates.append(
            Candidate(
                id=int(row["id"]),
                run_id=row["run_id"],
                package_name=row["package_name"],
                version=row["version"],
                artifact_filename=row["artifact_filename"],
                experiment_mode=row["experiment_mode"],
                prompt_strategy=row["prompt_strategy"],
                detector=row["detector"],
                raw=raw_text,
                details=details,
            )
        )
    return candidates


def _has_column(conn: sqlite3.Connection, table: str, column: str) -> bool:
    return any(row[1] == column for row in conn.execute(f"PRAGMA table_info({table})").fetchall())


def _row_intended_mode(row: sqlite3.Row, *, has_intended_mode_column: bool) -> str:
    if has_intended_mode_column:
        return str(row["intended_mode"] or "error")
    details = _load_details(row["details"])
    if details:
        return str(details.get("intended_mode") or "error")
    return "error"


def _find_collisions(conn: sqlite3.Connection, candidates: list[Candidate]) -> list[tuple[Candidate, int]]:
    collisions: list[tuple[Candidate, int]] = []
    has_intended_mode_column = _has_column(conn, "eval_result", "intended_mode")
    for candidate in candidates:
        if has_intended_mode_column:
            row = conn.execute(
                """
                SELECT id
                FROM eval_result
                WHERE run_id = ?
                  AND package_name = ?
                  AND version = ?
                  AND artifact_filename = ?
                  AND experiment_mode = 'error'
                  AND intended_mode = ?
                  AND prompt_strategy = ?
                  AND detector = ?
                  AND id != ?
                LIMIT 1
                """,
                (
                    candidate.run_id,
                    candidate.package_name,
                    candidate.version,
                    candidate.artifact_filename,
                    candidate.experiment_mode,
                    candidate.prompt_strategy,
                    candidate.detector,
                    candidate.id,
                ),
            ).fetchone()
            if row is not None:
                collisions.append((candidate, int(row["id"])))
            continue

        rows = conn.execute(
            """
            SELECT id, details
            FROM eval_result
            WHERE run_id = ?
              AND package_name = ?
              AND version = ?
              AND artifact_filename = ?
              AND experiment_mode = 'error'
              AND prompt_strategy = ?
              AND detector = ?
              AND id != ?
            """,
            (
                candidate.run_id,
                candidate.package_name,
                candidate.version,
                candidate.artifact_filename,
                candidate.prompt_strategy,
                candidate.detector,
                candidate.id,
            ),
        ).fetchall()
        for row in rows:
            if _row_intended_mode(row, has_intended_mode_column=False) == candidate.experiment_mode:
                collisions.append((candidate, int(row["id"])))
                break
    return collisions


def _backup_db(db_path: Path) -> Path:
    backup_path = db_path.with_name(f"{db_path.name}.before-protocol-normalize-{_utc_timestamp()}")
    backup_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            dest = sqlite3.connect(backup_path)
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
    except sqlite3.Error:
        shutil.copy2(db_path, backup_path)
    return backup_path


def _updated_details(candidate: Candidate) -> dict:
    details = dict(candidate.details)
    details.setdefault("original_experiment_mode", candidate.experiment_mode)
    details.setdefault("intended_mode", candidate.experiment_mode)
    details["protocol_failure"] = True
    details["normalized_from_raw_result"] = True
    details["error"] = candidate.error
    details["retryable"] = candidate.retryable
    details["raw"] = candidate.raw
    return details


def _ensure_schema_current(db_path: Path) -> None:
    from src.data.db_manager import DBManager

    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
        db.close()
    finally:
        DBManager.DB_PATH = original


def normalize_llm_protocol_failures(
    db_path: Path = DEFAULT_DB_PATH,
    *,
    run_id: str | None = None,
    apply: bool = False,
    backup: bool = True,
) -> NormalizationReport:
    db_path = db_path.resolve()
    if not db_path.exists():
        raise SystemExit(f"HALT: DB does not exist: {db_path}")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        candidates = _iter_candidates(conn, run_id=run_id)
        collisions = _find_collisions(conn, candidates)
        report = NormalizationReport(
            db_path=db_path,
            applied=apply,
            candidates=candidates,
            collisions=collisions,
        )
        if collisions:
            return report

        if not apply or not candidates:
            return report
    finally:
        conn.close()

    if backup:
        report.backup_path = _backup_db(db_path)
    _ensure_schema_current(db_path)

    conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True)
    try:
        conn.row_factory = sqlite3.Row
        candidates = _iter_candidates(conn, run_id=run_id)
        collisions = _find_collisions(conn, candidates)
        report.candidates = candidates
        report.collisions = collisions
        if collisions:
            return report

        for candidate in candidates:
            conn.execute(
                """
                UPDATE eval_result
                SET experiment_mode = 'error',
                    intended_mode = ?,
                    verdict = 0,
                    details = ?
                WHERE id = ?
                """,
                (
                    candidate.experiment_mode,
                    json.dumps(_updated_details(candidate), sort_keys=True),
                    candidate.id,
                ),
            )
        conn.commit()
        return report
    finally:
        conn.close()


def _print_report(report: NormalizationReport) -> None:
    action = "Updated" if report.applied else "Would update"
    print(f"DB: {report.db_path}")
    print(f"{action}: {report.would_update} row(s)")
    print(f"  empty_model_response       : {report.empty_count}")
    print(f"  unparseable_model_response : {report.unparseable_count}")
    if report.backup_path:
        print(f"Backup: {report.backup_path}")
    if report.collisions:
        print("HALT: normalization would collide with existing error rows:")
        for candidate, existing_id in report.collisions[:20]:
            print(
                "  "
                f"id={candidate.id} existing_error_id={existing_id} "
                f"{candidate.run_id} {candidate.package_name}=={candidate.version} "
                f"{candidate.artifact_filename} "
                f"{candidate.detector}:{candidate.experiment_mode}:{candidate.prompt_strategy}"
            )
        if len(report.collisions) > 20:
            print(f"  ... {len(report.collisions) - 20} additional collision(s)")
        return
    if report.by_key:
        print("Breakdown:")
        for (detector, mode, strategy, error), count in sorted(report.by_key.items()):
            print(f"  {count:5d}  {detector}:{mode}:{strategy}:{error}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert historical non-error LLM rows with raw/unparseable model output "
            "into explicit experiment_mode='error' protocol-failure rows. Dry-run by default."
        )
    )
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="Evaluation DB path")
    parser.add_argument("--run-id", help="Limit normalization to one run_id")
    parser.add_argument("--apply", action="store_true", help="Mutate the DB after creating a backup")
    parser.add_argument("--no-backup", action="store_true", help="Do not create a backup before --apply")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = normalize_llm_protocol_failures(
        args.db,
        run_id=args.run_id,
        apply=args.apply,
        backup=not args.no_backup,
    )
    _print_report(report)
    return 1 if report.collisions else 0


if __name__ == "__main__":
    raise SystemExit(main())
