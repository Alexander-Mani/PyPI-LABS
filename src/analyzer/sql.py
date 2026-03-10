"""
sql.py — SQLite CRUD abstraction for the Analyzer results database.

Stores detection run results so they can be evaluated later against
ground-truth labels (which never enter the Analyzer itself).
"""

import sqlite3
import json
from pathlib import Path


_SCHEMA = """
CREATE TABLE IF NOT EXISTS run (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS result (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id          TEXT    NOT NULL,
    project         TEXT    NOT NULL,
    version_before  TEXT    NOT NULL,
    version_after   TEXT    NOT NULL,
    detector        TEXT    NOT NULL,   -- e.g. "bandit", "semgrep", "anthropic"
    verdict         TEXT    NOT NULL,   -- "malicious" | "benign" | "error"
    confidence      REAL,              -- 0.0-1.0, NULL for static tools
    details         TEXT,              -- JSON blob with findings
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (run_id) REFERENCES run(run_id)
);

CREATE INDEX IF NOT EXISTS idx_result_run    ON result(run_id);
CREATE INDEX IF NOT EXISTS idx_result_project ON result(project);
"""


class SQL:
    """
    Thin wrapper around sqlite3 for the Analyzer results database.
    All public methods correspond directly to CRUD operations.
    """

    def __init__(self, db_path: str | Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ------------------------------------------------------------------
    # Run management
    # ------------------------------------------------------------------

    def create_run(self, run_id: str) -> None:
        self._conn.execute(
            "INSERT OR IGNORE INTO run (run_id) VALUES (?)", (run_id,)
        )
        self._conn.commit()

    def list_runs(self) -> list[dict]:
        cur = self._conn.execute(
            "SELECT run_id, created_at FROM run ORDER BY created_at DESC"
        )
        return [dict(r) for r in cur.fetchall()]

    # ------------------------------------------------------------------
    # Result write
    # ------------------------------------------------------------------

    def insert_result(
        self,
        run_id: str,
        project: str,
        version_before: str,
        version_after: str,
        detector: str,
        verdict: str,
        confidence: float | None = None,
        details: dict | None = None,
    ) -> int:
        cur = self._conn.execute(
            """
            INSERT INTO result
                (run_id, project, version_before, version_after,
                 detector, verdict, confidence, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id, project, version_before, version_after,
                detector, verdict, confidence,
                json.dumps(details) if details else None,
            ),
        )
        self._conn.commit()
        return cur.lastrowid  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Result read
    # ------------------------------------------------------------------

    def get_results_for_run(self, run_id: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM result WHERE run_id=? ORDER BY created_at",
            (run_id,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r["details"]:
                r["details"] = json.loads(r["details"])
        return rows

    def get_results_for_project(self, project: str) -> list[dict]:
        cur = self._conn.execute(
            "SELECT * FROM result WHERE project=? ORDER BY created_at",
            (project,),
        )
        rows = [dict(r) for r in cur.fetchall()]
        for r in rows:
            if r["details"]:
                r["details"] = json.loads(r["details"])
        return rows

    # ------------------------------------------------------------------
    # Teardown
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()
