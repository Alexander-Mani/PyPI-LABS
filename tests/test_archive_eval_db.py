"""Tests for the eval DB archive helper."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts.archive_eval_db import archive_eval_db  # noqa: E402
from src.data.db_manager import DBManager  # noqa: E402


def _table_names(db_path: Path) -> set[str]:
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    return {row[0] for row in rows}


def _row_count(db_path: Path, table: str) -> int:
    with sqlite3.connect(db_path) as conn:
        return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _create_eval_db(db_path: Path) -> None:
    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
        db.create_eval_run("old-run", "budget")
        db.close()
    finally:
        DBManager.DB_PATH = original


def test_archives_existing_db_and_initializes_fresh_schema(tmp_path):
    db_path = tmp_path / "eval_results.db"
    archive_dir = tmp_path / "archive"
    _create_eval_db(db_path)

    plan = archive_eval_db(
        db_path=db_path,
        archive_dir=archive_dir,
        timestamp="20260416-120000",
    )

    archived = archive_dir / "eval_results-20260416-120000.db"
    assert plan.archive_db_path == archived
    assert archived.exists()
    assert db_path.exists()
    assert _row_count(archived, "eval_run") == 1
    assert _row_count(db_path, "eval_run") == 0
    assert {"eval_run", "eval_result"} <= _table_names(db_path)


def test_archives_sidecars_when_present_without_db(tmp_path):
    db_path = tmp_path / "eval_results.db"
    archive_dir = tmp_path / "archive"
    wal = db_path.with_name(db_path.name + "-wal")
    shm = db_path.with_name(db_path.name + "-shm")
    wal.write_text("wal", encoding="utf-8")
    shm.write_text("shm", encoding="utf-8")

    archive_eval_db(
        db_path=db_path,
        archive_dir=archive_dir,
        timestamp="20260416-120000",
        initialize=False,
    )

    assert not wal.exists()
    assert not shm.exists()
    assert (archive_dir / "eval_results-20260416-120000.db-wal").read_text(encoding="utf-8") == "wal"
    assert (archive_dir / "eval_results-20260416-120000.db-shm").read_text(encoding="utf-8") == "shm"
    assert not db_path.exists()


def test_missing_db_initializes_fresh_schema(tmp_path):
    db_path = tmp_path / "eval_results.db"

    archive_eval_db(
        db_path=db_path,
        archive_dir=tmp_path / "archive",
        timestamp="20260416-120000",
    )

    assert db_path.exists()
    assert {"eval_run", "eval_result"} <= _table_names(db_path)


def test_dry_run_does_not_move_or_initialize(tmp_path):
    db_path = tmp_path / "eval_results.db"
    archive_dir = tmp_path / "archive"
    _create_eval_db(db_path)

    archive_eval_db(
        db_path=db_path,
        archive_dir=archive_dir,
        timestamp="20260416-120000",
        dry_run=True,
    )

    assert db_path.exists()
    assert _row_count(db_path, "eval_run") == 1
    assert not archive_dir.exists()


def test_archive_name_collision_gets_suffix(tmp_path):
    db_path = tmp_path / "eval_results.db"
    archive_dir = tmp_path / "archive"
    archive_dir.mkdir()
    (archive_dir / "eval_results-20260416-120000.db").write_text("old", encoding="utf-8")
    _create_eval_db(db_path)

    archive_eval_db(
        db_path=db_path,
        archive_dir=archive_dir,
        timestamp="20260416-120000",
        initialize=False,
    )

    assert (archive_dir / "eval_results-20260416-120000.db").read_text(encoding="utf-8") == "old"
    assert (archive_dir / "eval_results-20260416-120000-1.db").exists()
