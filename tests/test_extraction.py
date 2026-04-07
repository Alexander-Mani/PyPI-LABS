"""
test_extraction.py — Minimum-viable extraction tests.

Verifies that:
  1. pyproject.toml is extracted from a .tar.gz archive (was broken before Phase 1 fix).
  2. AST import resolution works up to 3 levels deep (Phase 4 fix).
  3. bad_password_files is populated when a zip member fails due to bad password.

Run from repo root:
    pytest tests/test_extraction.py
"""

from __future__ import annotations

import io
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

# Ensure repo root is on sys.path so src.* imports resolve.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from entry_extractor import EntryPointExtractor, PackageInfo


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_targz(members: dict[str, str], pkg_name: str = "testpkg-1.0.0") -> Path:
    """Write an in-memory .tar.gz to a tmp file and return its path."""
    import tempfile, os
    tmp = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    tmp.close()
    with tarfile.open(tmp.name, "w:gz") as tf:
        for rel_path, content in members.items():
            full = f"{pkg_name}/{rel_path}"
            data = content.encode()
            info = tarfile.TarInfo(name=full)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return Path(tmp.name)


def _make_zip(members: dict[str, str], pkg_name: str = "testpkg-1.0.0",
              password: bytes | None = None) -> Path:
    import tempfile
    tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
    tmp.close()
    with zipfile.ZipFile(tmp.name, "w") as zf:
        for rel_path, content in members.items():
            full = f"{pkg_name}/{rel_path}"
            zf.writestr(full, content)
    return Path(tmp.name)


# ---------------------------------------------------------------------------
# pyproject.toml extraction
# ---------------------------------------------------------------------------

class TestPyprojectTomlExtraction:

    def test_pyproject_toml_included_from_targz(self, tmp_path):
        """pyproject.toml must be extracted alongside .py files."""
        archive = _make_targz({
            "setup.py": "# setup\n",
            "pyproject.toml": "[build-system]\nrequires = []\n",
        })
        try:
            pkg = EntryPointExtractor().extract(archive)
            file_basenames = {Path(p).name for p in pkg.files}
            assert "pyproject.toml" in file_basenames, (
                "pyproject.toml not found in extracted files — check _extract_tar filter"
            )
            assert "setup.py" in file_basenames
        finally:
            archive.unlink(missing_ok=True)

    def test_plain_py_archive_no_pyproject(self, tmp_path):
        """Archive with only .py files should not raise even if pyproject.toml is absent."""
        archive = _make_targz({"setup.py": "x = 1\n"})
        try:
            pkg = EntryPointExtractor().extract(archive)
            assert "setup.py" in {Path(p).name for p in pkg.files}
        finally:
            archive.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# AST import resolution depth
# ---------------------------------------------------------------------------

class TestImportResolution:

    def test_two_level_import_chain(self):
        """
        setup.py → payload.py → exfil.py should all be included (3-level BFS).
        """
        archive = _make_targz({
            "setup.py":  "import payload\n",
            "payload.py": "import exfil\n",
            "exfil.py":  "import socket\n",   # socket is stdlib — not in archive
            "unrelated.py": "# never imported\n",
        })
        try:
            pkg = EntryPointExtractor().extract(archive)
            basenames = {Path(p).name for p in pkg.files}
            assert "setup.py"  in basenames
            assert "payload.py" in basenames, "Level-1 import not resolved"
            assert "exfil.py"   in basenames, "Level-2 import not resolved"
            assert "unrelated.py" not in basenames, "Unreachable file should not be included"
        finally:
            archive.unlink(missing_ok=True)

    def test_import_resolution_no_cycle_hang(self):
        """Circular imports must not cause infinite BFS."""
        archive = _make_targz({
            "setup.py": "import a\n",
            "a.py":     "import b\n",
            "b.py":     "import a\n",   # cycle
        })
        try:
            pkg = EntryPointExtractor().extract(archive)   # must return, not hang
            basenames = {Path(p).name for p in pkg.files}
            assert "a.py" in basenames
            assert "b.py" in basenames
        finally:
            archive.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Bad-password tracking
# ---------------------------------------------------------------------------

class TestBadPasswordHandling:

    def test_bad_password_files_empty_for_plain_zip(self):
        """No bad_password_files for an unencrypted zip."""
        archive = _make_zip({"setup.py": "x = 1\n"})
        try:
            pkg = EntryPointExtractor().extract(archive)
            assert pkg.bad_password_files == []
        finally:
            archive.unlink(missing_ok=True)

    def test_bad_password_files_populated_on_wrong_password(self, monkeypatch):
        """
        When zf.read() raises RuntimeError('Bad password for file ...'),
        the filename must be recorded in pkg.bad_password_files.
        """
        import zipfile as _zf

        archive = _make_zip({"setup.py": "x = 1\n"})
        original_read = _zf.ZipFile.read

        def _raise_bad_password(self_zf, name, *args, **kwargs):
            # Simulate the error zipfile raises for wrong ZipCrypto password.
            raise RuntimeError(f"Bad password for file {name!r}")

        monkeypatch.setattr(_zf.ZipFile, "read", _raise_bad_password)
        try:
            pkg = EntryPointExtractor().extract(archive)
            assert len(pkg.bad_password_files) >= 1, (
                "Expected at least one entry in bad_password_files"
            )
            assert any("setup.py" in f for f in pkg.bad_password_files)
        finally:
            monkeypatch.setattr(_zf.ZipFile, "read", original_read)
            archive.unlink(missing_ok=True)
