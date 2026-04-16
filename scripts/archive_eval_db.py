#!/usr/bin/env python3
"""Archive the evaluation SQLite DB and initialize a clean replacement."""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src.data.db_manager import DBManager  # noqa: E402

DEFAULT_DB_PATH = _REPO_ROOT / "src" / "data" / "eval_results.db"
DEFAULT_ARCHIVE_DIR = _REPO_ROOT / "src" / "data" / "eval_db_archive"


@dataclass(frozen=True)
class ArchivePlan:
    db_path: Path
    archive_dir: Path
    archive_db_path: Path
    moves: tuple[tuple[Path, Path], ...]
    initialize: bool


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _sidecar_paths(db_path: Path) -> tuple[Path, Path]:
    return (
        db_path.with_name(db_path.name + "-wal"),
        db_path.with_name(db_path.name + "-shm"),
    )


def _candidate_archive_db_path(
    db_path: Path,
    archive_dir: Path,
    timestamp: str,
    counter: int,
) -> Path:
    suffix = db_path.suffix
    stem = db_path.stem if suffix else db_path.name
    extra = "" if counter == 0 else f"-{counter}"
    return archive_dir / f"{stem}-{timestamp}{extra}{suffix}"


def _archive_db_path(db_path: Path, archive_dir: Path, timestamp: str) -> Path:
    counter = 0
    while True:
        candidate = _candidate_archive_db_path(db_path, archive_dir, timestamp, counter)
        candidate_sidecars = _sidecar_paths(candidate)
        if not candidate.exists() and not any(path.exists() for path in candidate_sidecars):
            return candidate
        counter += 1


def build_archive_plan(
    db_path: Path = DEFAULT_DB_PATH,
    archive_dir: Path = DEFAULT_ARCHIVE_DIR,
    *,
    timestamp: str | None = None,
    initialize: bool = True,
) -> ArchivePlan:
    db_path = db_path.resolve()
    archive_dir = archive_dir.resolve()
    archive_db = _archive_db_path(db_path, archive_dir, timestamp or _utc_timestamp())

    moves: list[tuple[Path, Path]] = []
    if db_path.exists():
        moves.append((db_path, archive_db))
    for source, dest in zip(_sidecar_paths(db_path), _sidecar_paths(archive_db), strict=True):
        if source.exists():
            moves.append((source, dest))

    return ArchivePlan(
        db_path=db_path,
        archive_dir=archive_dir,
        archive_db_path=archive_db,
        moves=tuple(moves),
        initialize=initialize,
    )


def _checkpoint_wal(db_path: Path) -> None:
    if not db_path.exists():
        return
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=rw", uri=True, timeout=1.0)
        try:
            conn.execute("PRAGMA busy_timeout=1000")
            row = conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
            if row and int(row[0]) != 0:
                raise RuntimeError(f"database is locked or busy during WAL checkpoint: {row}")
        finally:
            conn.close()
    except (sqlite3.Error, RuntimeError) as exc:
        raise SystemExit(
            f"HALT: could not checkpoint {db_path}. Is an evaluation still running? {exc}"
        ) from exc


def _initialize_fresh_db(db_path: Path) -> None:
    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
        db.close()
    finally:
        DBManager.DB_PATH = original


def archive_eval_db(
    db_path: Path = DEFAULT_DB_PATH,
    archive_dir: Path = DEFAULT_ARCHIVE_DIR,
    *,
    timestamp: str | None = None,
    initialize: bool = True,
    dry_run: bool = False,
) -> ArchivePlan:
    plan = build_archive_plan(
        db_path=db_path,
        archive_dir=archive_dir,
        timestamp=timestamp,
        initialize=initialize,
    )

    if not plan.moves:
        print(f"No existing eval DB or sidecars found at {plan.db_path}")
    for source, dest in plan.moves:
        print(f"{'Would move' if dry_run else 'Moving'} {source} -> {dest}")
    if initialize:
        print(f"{'Would initialize' if dry_run else 'Initializing'} fresh eval DB at {plan.db_path}")

    if dry_run:
        return plan

    _checkpoint_wal(plan.db_path)
    plan.archive_dir.mkdir(parents=True, exist_ok=True)
    for source, dest in plan.moves:
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(source), str(dest))
    if initialize:
        _initialize_fresh_db(plan.db_path)

    return plan


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Archive src/data/eval_results.db and create a clean replacement."
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions without moving or creating files")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB_PATH, help="Evaluation DB path")
    parser.add_argument("--archive-dir", type=Path, default=DEFAULT_ARCHIVE_DIR, help="Archive destination directory")
    parser.add_argument("--no-init", action="store_true", help="Archive only; do not initialize a fresh DB")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    archive_eval_db(
        db_path=args.db,
        archive_dir=args.archive_dir,
        initialize=not args.no_init,
        dry_run=args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
