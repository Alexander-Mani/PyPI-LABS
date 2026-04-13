"""Regression tests for simulator metadata release/artifact semantics."""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src" / "simulator"))

from metadata import MetadataStore  # noqa: E402


def test_metadata_allows_multiple_files_for_same_release(tmp_path):
    store = MetadataStore(tmp_path / "sim.db")
    store.record("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
    store.record("pkg", "1.0.0", "pkg-1.0.0.tar.gz")

    assert store.version_exists("pkg", "1.0.0") is True
    assert store.file_exists("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl") is True
    assert store.file_exists("pkg", "1.0.0", "pkg-1.0.0.zip") is False
    assert store.list_files("pkg") == [
        {"version": "1.0.0", "filename": "pkg-1.0.0-py3-none-any.whl"},
        {"version": "1.0.0", "filename": "pkg-1.0.0.tar.gz"},
    ]
