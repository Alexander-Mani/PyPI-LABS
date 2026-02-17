# file: data/db_manager.py
import json
from typing import Optional, Iterable, Dict, Any
from .db_core import DBCore
# Probably agood idea to maybe create a model fro something

class DBManager(DBCore):
    """
    Inherits all connection logic from DBCore.
    Adds specific methods for the ingestion and scanning pipeline.
    """

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
