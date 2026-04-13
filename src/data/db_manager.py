# file: data/db_manager.py
import json
from typing import Optional, Iterable, Dict, Any
from .db_core import DBCore

# ---------------------------------------------------------------------------
# Evaluation pipeline schema
# ---------------------------------------------------------------------------

_EVAL_SCHEMA = """
CREATE TABLE IF NOT EXISTS eval_run (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id     TEXT NOT NULL UNIQUE,
    tier       TEXT NOT NULL DEFAULT 'unknown',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS eval_result (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id           TEXT    NOT NULL,
    package_name     TEXT    NOT NULL,
    version          TEXT    NOT NULL,
    experiment_mode  TEXT    NOT NULL,
    prompt_strategy  TEXT    NOT NULL DEFAULT 'zero_shot',
    detector         TEXT    NOT NULL,
    artifact_filename TEXT   NOT NULL DEFAULT '',
    artifact_url      TEXT,
    source_index_url  TEXT,
    sample_role       TEXT,
    attack_vector     TEXT,
    resolver_policy   TEXT,
    verdict          INTEGER NOT NULL,
    ground_truth     INTEGER,
    heuristic_flags  TEXT    NOT NULL,
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    exec_time_ms     INTEGER NOT NULL,
    api_cost_usd     REAL    NOT NULL,
    details          TEXT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),

    UNIQUE(run_id, package_name, version, artifact_filename,
           experiment_mode, prompt_strategy, detector)
);

CREATE INDEX IF NOT EXISTS idx_eval_result_run  ON eval_result(run_id);
CREATE INDEX IF NOT EXISTS idx_eval_result_pkg  ON eval_result(package_name);
CREATE INDEX IF NOT EXISTS idx_eval_result_mode ON eval_result(run_id, experiment_mode);
CREATE INDEX IF NOT EXISTS idx_eval_result_sample
    ON eval_result(run_id, package_name, version, artifact_filename);

PRAGMA user_version = 3;
"""


class DBManager(DBCore):
    """
    Inherits all connection logic from DBCore.
    Adds specific methods for the evaluation pipeline.
    Uses a separate database (eval_results.db) independent of url_metadata.db.
    """

    # Point to a dedicated eval DB — does not share url_metadata.db.
    DB_PATH = DBCore.BASE_DIR / "data" / "eval_results.db"

    def __init__(self):
        super().__init__()
        self._init_eval_schema()

    def initialize_db(self) -> None:
        # DBCore.initialize_db() reads schema.sql for the url table which is
        # not used here. Skip it entirely; _init_eval_schema handles our tables.
        pass

    def _init_eval_schema(self) -> None:
        if self._needs_v3_migration():
            self._migrate_eval_result_v3()
        self.cursor.executescript(_EVAL_SCHEMA)
        self.conn.commit()

    def _needs_v3_migration(self) -> bool:
        version = self.cursor.execute("PRAGMA user_version").fetchone()[0]
        table = self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='eval_result'"
        ).fetchone()
        return bool(table and version < 3)

    def _migrate_eval_result_v3(self) -> None:
        """
        Rebuild eval_result so version/artifact identity is part of the UNIQUE key.
        SQLite cannot alter UNIQUE constraints in place.
        """
        self.cursor.executescript(
            """
            ALTER TABLE eval_result RENAME TO eval_result_v2;

            CREATE TABLE eval_result (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id           TEXT    NOT NULL,
                package_name     TEXT    NOT NULL,
                version          TEXT    NOT NULL,
                experiment_mode  TEXT    NOT NULL,
                prompt_strategy  TEXT    NOT NULL DEFAULT 'zero_shot',
                detector         TEXT    NOT NULL,
                artifact_filename TEXT   NOT NULL DEFAULT '',
                artifact_url      TEXT,
                source_index_url  TEXT,
                sample_role       TEXT,
                attack_vector     TEXT,
                resolver_policy   TEXT,
                verdict          INTEGER NOT NULL,
                ground_truth     INTEGER,
                heuristic_flags  TEXT    NOT NULL,
                input_tokens     INTEGER NOT NULL DEFAULT 0,
                output_tokens    INTEGER NOT NULL DEFAULT 0,
                exec_time_ms     INTEGER NOT NULL,
                api_cost_usd     REAL    NOT NULL,
                details          TEXT,
                created_at       TEXT    NOT NULL DEFAULT (datetime('now')),

                UNIQUE(run_id, package_name, version, artifact_filename,
                       experiment_mode, prompt_strategy, detector)
            );

            INSERT OR REPLACE INTO eval_result
                (id, run_id, package_name, version, experiment_mode, prompt_strategy,
                 detector, artifact_filename, artifact_url, source_index_url,
                 sample_role, attack_vector, resolver_policy, verdict, ground_truth,
                 heuristic_flags, input_tokens, output_tokens, exec_time_ms,
                 api_cost_usd, details, created_at)
            SELECT
                 id, run_id, package_name, version, experiment_mode, prompt_strategy,
                 detector, '', NULL, NULL, NULL, NULL, 'legacy-local-archive',
                 verdict, ground_truth, heuristic_flags, input_tokens, output_tokens,
                 exec_time_ms, api_cost_usd, details, created_at
            FROM eval_result_v2;

            DROP TABLE eval_result_v2;
            PRAGMA user_version = 3;
            """
        )
        self.conn.commit()

    # ------------------------------------------------------------------
    # Evaluation pipeline CRUD
    # ------------------------------------------------------------------

    def create_eval_run(self, run_id: str, tier: str = "unknown") -> None:
        self.write_one(
            "INSERT OR IGNORE INTO eval_run (run_id, tier) VALUES (?, ?)",
            (run_id, tier),
        )

    def insert_eval_result(
        self,
        run_id: str,
        package_name: str,
        version: str,
        experiment_mode: str,
        prompt_strategy: str,
        detector: str,
        artifact_filename: str = "",
        artifact_url: str | None = None,
        source_index_url: str | None = None,
        sample_role: str | None = None,
        attack_vector: str | None = None,
        resolver_policy: str | None = None,
        verdict: bool = False,
        ground_truth: bool | None = None,
        heuristic_flags: list | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
        exec_time_ms: int = 0,
        api_cost_usd: float = 0.0,
        details: dict | None = None,
    ) -> int | None:
        return self.write_one(
            """INSERT OR REPLACE INTO eval_result
               (run_id, package_name, version, experiment_mode, prompt_strategy,
                detector, artifact_filename, artifact_url, source_index_url,
                sample_role, attack_vector, resolver_policy, verdict, ground_truth,
                heuristic_flags, input_tokens, output_tokens, exec_time_ms,
                api_cost_usd, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                package_name,
                version,
                experiment_mode,
                prompt_strategy,
                detector,
                artifact_filename,
                artifact_url,
                source_index_url,
                sample_role,
                attack_vector,
                resolver_policy,
                int(verdict),
                int(ground_truth) if ground_truth is not None else None,
                json.dumps(heuristic_flags or []),
                input_tokens,
                output_tokens,
                exec_time_ms,
                api_cost_usd,
                json.dumps(details) if details else None,
            ),
        )

    def get_eval_results_for_run(self, run_id: str) -> list[dict]:
        rows = self.fetch_many(
            "SELECT * FROM eval_result WHERE run_id=? ORDER BY id",
            (run_id,),
        )
        for r in rows:
            if r.get("heuristic_flags"):
                r["heuristic_flags"] = json.loads(r["heuristic_flags"])
            if r.get("details"):
                r["details"] = json.loads(r["details"])
        return rows

    def get_eval_summary(self, run_id: str) -> dict[str, dict]:
        rows = self.fetch_many(
            """SELECT detector, experiment_mode, prompt_strategy,
                      SUM(CASE WHEN verdict=1 THEN 1 ELSE 0 END) AS malicious_count,
                      SUM(CASE WHEN verdict=0 THEN 1 ELSE 0 END) AS benign_count,
                      SUM(CASE WHEN ground_truth=1 AND verdict=1 THEN 1 ELSE 0 END) AS tp,
                      SUM(CASE WHEN ground_truth=0 AND verdict=1 THEN 1 ELSE 0 END) AS fp,
                      SUM(CASE WHEN ground_truth=1 AND verdict=0 THEN 1 ELSE 0 END) AS fn,
                      SUM(CASE WHEN ground_truth=0 AND verdict=0 THEN 1 ELSE 0 END) AS tn,
                      COUNT(*) AS total
               FROM eval_result
               WHERE run_id=? AND experiment_mode != 'error'
               GROUP BY detector, experiment_mode, prompt_strategy""",
            (run_id,),
        )
        return {
            f"{r['detector']}:{r['experiment_mode']}:{r['prompt_strategy']}": dict(r)
            for r in rows
        }
