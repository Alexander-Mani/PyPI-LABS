"""
metadata.py — SQLite-backed metadata store for the PyPI Simulator.

Tracks which (project, version, filename) tuples have been uploaded
so the simulator can enforce version-bump rules and answer the
Analyzer's /api/versions/<project> queries.
"""

import sqlite3
from pathlib import Path

from packaging.utils import canonicalize_name


_SCHEMA = """
CREATE TABLE IF NOT EXISTS package (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    filename    TEXT    NOT NULL,
    uploaded_at TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(name, version, filename)
);
"""


def _normalize(name: str) -> str:
    return str(canonicalize_name(name.strip()))


class MetadataStore:
    """Lightweight SQLite store for simulator package metadata."""

    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def version_exists(self, name: str, version: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM package WHERE name=? AND version=? LIMIT 1",
            (_normalize(name), version),
        )
        return cur.fetchone() is not None

    def file_exists(self, name: str, version: str, filename: str) -> bool:
        cur = self._conn.execute(
            "SELECT 1 FROM package WHERE name=? AND version=? AND filename=? LIMIT 1",
            (_normalize(name), version, filename),
        )
        return cur.fetchone() is not None

    def list_versions(self, name: str) -> list[str]:
        cur = self._conn.execute(
            "SELECT DISTINCT version FROM package WHERE name=? ORDER BY uploaded_at",
            (_normalize(name),),
        )
        return [row[0] for row in cur.fetchall()]

    def list_files(self, name: str) -> list[dict[str, str]]:
        cur = self._conn.execute(
            "SELECT version, filename FROM package WHERE name=? ORDER BY uploaded_at, filename",
            (_normalize(name),),
        )
        return [{"version": row[0], "filename": row[1]} for row in cur.fetchall()]

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record(self, name: str, version: str, filename: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO package (name, version, filename) VALUES (?, ?, ?)",
            (_normalize(name), version, filename),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()
