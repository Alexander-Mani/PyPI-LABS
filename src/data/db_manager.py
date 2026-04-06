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
    verdict          INTEGER NOT NULL,
    ground_truth     INTEGER,
    heuristic_flags  TEXT    NOT NULL,
    input_tokens     INTEGER NOT NULL DEFAULT 0,
    output_tokens    INTEGER NOT NULL DEFAULT 0,
    exec_time_ms     INTEGER NOT NULL,
    api_cost_usd     REAL    NOT NULL,
    details          TEXT,
    created_at       TEXT    NOT NULL DEFAULT (datetime('now')),

    UNIQUE(run_id, package_name, experiment_mode, prompt_strategy, detector)
);

CREATE INDEX IF NOT EXISTS idx_eval_result_run  ON eval_result(run_id);
CREATE INDEX IF NOT EXISTS idx_eval_result_pkg  ON eval_result(package_name);
CREATE INDEX IF NOT EXISTS idx_eval_result_mode ON eval_result(run_id, experiment_mode);

PRAGMA user_version = 2;
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
        self.cursor.executescript(_EVAL_SCHEMA)
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
        verdict: bool,
        ground_truth: bool | None,
        heuristic_flags: list,
        input_tokens: int,
        output_tokens: int,
        exec_time_ms: int,
        api_cost_usd: float,
        details: dict | None = None,
    ) -> int | None:
        return self.write_one(
            """INSERT OR REPLACE INTO eval_result
               (run_id, package_name, version, experiment_mode, prompt_strategy,
                detector, verdict, ground_truth, heuristic_flags,
                input_tokens, output_tokens, exec_time_ms, api_cost_usd, details)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                package_name,
                version,
                experiment_mode,
                prompt_strategy,
                detector,
                int(verdict),
                int(ground_truth) if ground_truth is not None else None,
                json.dumps(heuristic_flags),
                input_tokens,
                output_tokens,
                exec_time_ms,
                api_cost_usd,
                json.dumps(details) if details else None,
            ),
        )

    def get_eval_results_for_run(self, run_id: str) -> list[dict]:
        rows = self.fetch_many(
            "SELECT * FROM eval_result WHERE run_id=? ORDER BY created_at",
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
               WHERE run_id=?
               GROUP BY detector, experiment_mode, prompt_strategy""",
            (run_id,),
        )
        return {
            f"{r['detector']}:{r['experiment_mode']}:{r['prompt_strategy']}": dict(r)
            for r in rows
        }

# Examples from prev project
    # def _to_text_or_json(self, v):
    #     if v is None:
    #         return None
    #     if isinstance(v, (str, int, float)):
    #         return str(v)
    #     return json.dumps(v, ensure_ascii=False)
    #
    # def upsert_urls(self, rows):
    #     q = """
    #     INSERT INTO url (
    #         url, url_uuid, content_hash, http_status_code, object_type,
    #         disa_rating, vse_status, source, source_original, extracted_urls,
    #         last_updated
    #     )
    #     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    #     ON CONFLICT(url) DO UPDATE SET
    #         url_uuid = COALESCE(excluded.url_uuid, url.url_uuid),
    #         content_hash = COALESCE(excluded.content_hash, url.content_hash),
    #         http_status_code = COALESCE(excluded.http_status_code, url.http_status_code),
    #         object_type = COALESCE(excluded.object_type, url.object_type),
    #         disa_rating = COALESCE(excluded.disa_rating, url.disa_rating),
    #         vse_status = COALESCE(excluded.vse_status, url.vse_status),
    #         source = COALESCE(excluded.source, url.source),
    #         source_original = COALESCE(excluded.source_original, url.source_original),
    #         extracted_urls = COALESCE(excluded.extracted_urls, url.extracted_urls),
    #         last_updated = CURRENT_TIMESTAMP
    #     ;
    #     """
    #
    #     params = []
    #     for r in rows:
    #         params.append((
    #             r.get(".extra_info.linkfunnel.url"),
    #             r.get(".extra_info.linkfunnel.url_uuid5"),
    #             r.get(".sha256"),
    #             r.get(".extra_info.linkfunnel.result.http_status_code"),
    #             self._to_text_or_json(r.get(".doc.disa.object_types")),
    #             r.get(".doc.disa.rating"),
    #             r.get(".doc.vse.status"),
    #             r.get(".extra_info.linkfunnel.source"),
    #             r.get(".source_original"),
    #             json.dumps(r.get(".doc.extracted_urls"), ensure_ascii=False)
    #             if r.get(".doc.extracted_urls") is not None else None,
    #         ))
    #
    #     if params:
    #         self.write_many(q, params)
    #
    #
    # def print_recent_urls(self, limit: int = 10) -> None:
    #     q = """
    #         SELECT id, url, http_status_code, source, created_at, last_updated
    #         FROM url
    #         ORDER BY created_at DESC
    #         LIMIT ?
    #     """
    #     rows = self.fetch_many(q, (limit,))
    #
    #     if not rows:
    #         print("No rows found.")
    #         return
    #
    #     for row in rows:
    #         print(
    #             f"[{row['id']}] "
    #             f"url={row['url']} "
    #             f"http_status={row['http_status_code']} "
    #             f"source={row['source']} "
    #             f"created={row['created_at']}"
    #         )
    #
    # def add_url(self, url: str) -> Optional[int]:
    #     q = "INSERT OR IGNORE INTO url (url) VALUES (?)"
    #     return self.write_one(q, (url,))
    #
    # def get_next_target(self) -> Optional[UrlModel]:
    #     q = """
    #         SELECT *
    #         FROM url
    #         WHERE visited = 0
    #         ORDER BY created_at ASC
    #         LIMIT 1
    #     """
    #     row = self.fetch_one(q)
    #
    #     if row:
    #         # return UrlModel.from_row(row)
    #         pass
    #
    #     return None
    #
    # def mark_visited(self, url_id: int, http_status_code: int | None) -> None:
    #     q = """
    #         UPDATE url
    #         SET visited = 1,
    #             http_status_code = ?,
    #             last_updated = CURRENT_TIMESTAMP
    #         WHERE id = ?
    #     """
    #     self.write_one(q, (http_status_code, url_id))
