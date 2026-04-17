"""
raw_experiment_log.py - Append-only raw experiment flight recorder.

The normal log is for humans and the SQLite DB is for metrics. This module
records raw, machine-readable evidence so an experiment can be sanity-checked
with jq/Python without reading the analyzer implementation.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_SECRET_KEY_RE = re.compile(
    r"(api[_-]?key|authorization|bearer|access[_-]?token|refresh[_-]?token|auth[_-]?token|secret|password|credential|github[_-]?token|twine[_-]?password)",
    re.IGNORECASE,
)
_SECRET_VALUE_RE = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD)[A-Z0-9_]*)=([^\s,;]+)"
)
_SAFE_NONSECRET_KEYS = {"bad_password_files", "skipped_bad_password"}


def _utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return {"bytes_hex": value.hex(), "bytes": len(value)}
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return sorted(_json_safe(item) for item in value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _is_secret_key(key: str) -> bool:
    return key.lower() not in _SAFE_NONSECRET_KEYS and bool(_SECRET_KEY_RE.search(key))


def _redact(value: Any, *, parent_key: str = "") -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_s = str(key)
            if _is_secret_key(key_s):
                redacted[key_s] = "<redacted>"
            else:
                redacted[key_s] = _redact(item, parent_key=key_s)
        return redacted
    if isinstance(value, list):
        return [_redact(item, parent_key=parent_key) for item in value]
    if isinstance(value, tuple):
        return [_redact(item, parent_key=parent_key) for item in value]
    if isinstance(value, str):
        if _is_secret_key(parent_key):
            return "<redacted>"
        return _SECRET_VALUE_RE.sub(r"\1=<redacted>", value)
    return value


def _clean_suffix(suffix: str) -> str:
    if not suffix.startswith("."):
        suffix = "." + suffix
    cleaned = re.sub(r"[^A-Za-z0-9_.-]", "_", suffix)
    return cleaned or ".blob"


class RawExperimentLog:
    """Thread-safe JSONL writer plus content-addressed blob storage."""

    def __init__(self, run_id: str, root_dir: Path):
        self.run_id = run_id
        self.root_dir = Path(root_dir)
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.root_dir / f"{run_id}.jsonl"
        self.blob_dir = self.root_dir / f"{run_id}.blobs"
        self.blob_dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._event_count = 0
        self._blob_bytes = 0
        self._closed = False

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def total_blob_bytes(self) -> int:
        return self._blob_bytes

    def emit(self, event: str, payload: dict[str, Any] | None = None, **fields: Any) -> None:
        """Append one redacted JSON event line."""
        with self._lock:
            if self._closed:
                return
            self._seq += 1
            record: dict[str, Any] = {
                "seq": self._seq,
                "ts": _utc_now(),
                "run_id": self.run_id,
                "event": event,
            }
            record.update(_redact(_json_safe(fields)))
            record["payload"] = _redact(_json_safe(payload or {}))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
            self._event_count += 1

    def blob_text(
        self,
        kind: str,
        text: str,
        *,
        suffix: str = ".txt",
        encoding: str = "utf-8",
    ) -> dict[str, Any]:
        data = text.encode(encoding, errors="replace")
        ref = self._write_blob(kind, data, suffix=suffix)
        ref["encoding"] = encoding
        return ref

    def blob_json(self, kind: str, value: Any, *, suffix: str = ".json") -> dict[str, Any]:
        text = json.dumps(_json_safe(value), ensure_ascii=False, sort_keys=True, indent=2)
        return self.blob_text(kind, text, suffix=suffix)

    def blob_bytes(self, kind: str, data: bytes, *, suffix: str = ".bin") -> dict[str, Any]:
        return self._write_blob(kind, data, suffix=suffix)

    def close(self, status: str | None = None, payload: dict[str, Any] | None = None) -> None:
        if status is not None:
            self.emit(
                "run.done",
                payload={
                    **(payload or {}),
                    "status": status,
                    "event_count_before_done": self.event_count,
                    "blob_bytes": self.total_blob_bytes,
                },
            )
        with self._lock:
            self._closed = True

    def _write_blob(self, kind: str, data: bytes, *, suffix: str) -> dict[str, Any]:
        digest = hashlib.sha256(data).hexdigest()
        path = self.blob_dir / f"{digest}{_clean_suffix(suffix)}"
        with self._lock:
            if not path.exists():
                path.write_bytes(data)
                self._blob_bytes += len(data)
        return {
            "kind": kind,
            "sha256": digest,
            "bytes": len(data),
            "path": str(path),
        }
