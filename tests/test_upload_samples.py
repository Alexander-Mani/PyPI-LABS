"""
test_upload_samples.py - Regression tests for idempotent sample uploads.

The simulator deliberately rejects duplicate package versions. The injector must
therefore skip already-uploaded local simulator versions before calling twine.
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))


class _FakeLogger:
    def remove(self):
        return None

    def add(self, *args, **kwargs):
        return None

    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None

    def debug(self, *args, **kwargs):
        return None


sys.modules.setdefault("loguru", types.SimpleNamespace(logger=_FakeLogger()))

from src.injector import upload_samples  # noqa: E402


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self) -> bytes:
        return self._body


def test_local_existing_version_skips_twine(monkeypatch, tmp_path):
    archive = tmp_path / "colorama-0.1.1.tar.gz"
    archive.write_text("placeholder", encoding="utf-8")

    def fake_urlopen(url, timeout):
        assert url == "http://127.0.0.1:8080/api/versions/colorama"
        assert timeout == 5
        return _FakeResponse(b'{"project": "colorama", "versions": ["0.1.1"]}')

    def fail_run(*args, **kwargs):
        raise AssertionError("twine should not run for an existing simulator version")

    monkeypatch.setattr(upload_samples.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(upload_samples.subprocess, "run", fail_run)

    result = upload_samples._twine_upload(
        archive,
        "http://127.0.0.1:8080",
        dry_run=False,
    )

    assert result == "skipped"


def test_local_new_version_uploads_without_skip_existing(monkeypatch, tmp_path):
    archive = tmp_path / "colorama-0.1.2.tar.gz"
    archive.write_text("placeholder", encoding="utf-8")
    captured = {}

    def fake_urlopen(url, timeout):
        return _FakeResponse(b'{"project": "colorama", "versions": ["0.1.1"]}')

    def fake_run(cmd, capture_output, text):
        captured["cmd"] = cmd
        assert capture_output is True
        assert text is True
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(upload_samples.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(upload_samples.subprocess, "run", fake_run)

    result = upload_samples._twine_upload(
        archive,
        "http://127.0.0.1:8080",
        dry_run=False,
    )

    assert result == "uploaded"
    assert "--skip-existing" not in captured["cmd"]
    assert "http://127.0.0.1:8080/legacy/" in captured["cmd"]


def test_warehouse_upload_uses_skip_existing_without_precheck(monkeypatch, tmp_path):
    archive = tmp_path / "colorama-0.1.2.tar.gz"
    archive.write_text("placeholder", encoding="utf-8")
    captured = {}

    def fail_precheck(*args, **kwargs):
        raise AssertionError("Warehouse uploads should not call simulator precheck")

    def fake_run(cmd, capture_output, text):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(upload_samples, "_simulator_has_version", fail_precheck)
    monkeypatch.setattr(upload_samples.subprocess, "run", fake_run)

    result = upload_samples._twine_upload(
        archive,
        "https://upload.pypi.org",
        dry_run=False,
    )

    assert result == "uploaded"
    assert "--skip-existing" in captured["cmd"]
    assert "https://upload.pypi.org/legacy/" in captured["cmd"]
