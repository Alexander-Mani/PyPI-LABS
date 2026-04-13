"""
test_upload_samples.py - Regression tests for idempotent sample uploads.

The simulator deliberately rejects duplicate package versions. The injector must
therefore skip already-uploaded local simulator versions before calling twine.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

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


def test_local_existing_artifact_skips_twine(monkeypatch, tmp_path):
    archive = tmp_path / "colorama-0.1.1.tar.gz"
    archive.write_text("placeholder", encoding="utf-8")

    def fake_urlopen(url, timeout):
        assert url == "http://127.0.0.1:8080/api/files/colorama"
        assert timeout == 5
        return _FakeResponse(
            b'{"project": "colorama", "files": [{"version": "0.1.1", "filename": "colorama-0.1.1.tar.gz"}]}'
        )

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


def test_local_new_artifact_uploads_without_skip_existing(monkeypatch, tmp_path):
    archive = tmp_path / "colorama-0.1.2.tar.gz"
    archive.write_text("placeholder", encoding="utf-8")
    captured = {}

    def fake_urlopen(url, timeout):
        return _FakeResponse(
            b'{"project": "colorama", "files": [{"version": "0.1.2", "filename": "colorama-0.1.2.whl"}]}'
        )

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

    monkeypatch.setattr(upload_samples, "_simulator_has_artifact", fail_precheck)
    monkeypatch.setattr(upload_samples.subprocess, "run", fake_run)

    result = upload_samples._twine_upload(
        archive,
        "https://upload.pypi.org",
        dry_run=False,
    )

    assert result == "uploaded"
    assert "--skip-existing" in captured["cmd"]
    assert "https://upload.pypi.org/legacy/" in captured["cmd"]


def test_archive_name_version_falls_back_for_noncanonical_wheel(tmp_path):
    filename = (
        "torchtriton-2.0.0+0d7e753227-cp310-cp310-"
        "manylinux-2-17-x86-64.manylinux2014-x86-64.whl"
    )
    archive = (
        tmp_path
        / filename
    )
    archive.write_text("placeholder", encoding="utf-8")

    assert upload_samples._archive_name_version(archive) == (
        "torchtriton",
        "2.0.0+0d7e753227",
    )


def test_malicious_category_uploads_extracted_bundle_archives(monkeypatch, tmp_path):
    malicious_dir = tmp_path / "malware_backstabbers_knife"
    (malicious_dir / "colourama" / "0.1.6").mkdir(parents=True)
    (malicious_dir / "secmeasure" / "0.1.0").mkdir(parents=True)
    colourama = malicious_dir / "colourama" / "0.1.6" / "colourama-0.1.6.tar.gz"
    secmeasure = malicious_dir / "secmeasure" / "0.1.0" / "secmeasure-0.1.0-py3-none-any.whl"
    legacy_container = malicious_dir / "legacy-container.zip"
    colourama.write_text("placeholder", encoding="utf-8")
    secmeasure.write_text("placeholder", encoding="utf-8")
    legacy_container.write_text("placeholder", encoding="utf-8")
    uploaded = []

    def fake_twine_upload(archive, simulator_url, dry_run):
        uploaded.append(archive.relative_to(malicious_dir).as_posix())
        assert simulator_url == "http://127.0.0.1:8080"
        assert dry_run is False
        return "uploaded"

    monkeypatch.setattr(upload_samples, "_twine_upload", fake_twine_upload)
    monkeypatch.setattr(upload_samples, "_extract_malicious_zip", lambda path: None)

    result = upload_samples._upload_malicious_category(
        malicious_dir,
        "http://127.0.0.1:8080",
        dry_run=False,
    )

    assert result == (2, 0, 1)
    assert uploaded == [
        "colourama/0.1.6/colourama-0.1.6.tar.gz",
        "secmeasure/0.1.0/secmeasure-0.1.0-py3-none-any.whl",
    ]


def test_controls_dir_falls_back_to_nested_benign_controls(tmp_path):
    samples_dir = tmp_path / "samples"
    (samples_dir / "controls").mkdir(parents=True)
    nested = samples_dir / "benign" / "controls"
    nested.mkdir(parents=True)

    assert upload_samples._controls_dir(samples_dir) == nested
