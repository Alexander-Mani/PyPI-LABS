"""
test_ground_truth.py — Verify folder-based ground truth labelling.

Checks that _discover_benign() returns is_malicious=False and
_discover_malware() returns is_malicious=True, using temporary fixture
directories that mirror the real samples/ layout.

Run from repo root:
    pytest tests/test_ground_truth.py
"""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _write_targz(dest: Path, pkg_stem: str, members: dict[str, str]) -> Path:
    """Write a minimal .tar.gz archive to *dest* and return its path."""
    archive = dest / f"{pkg_stem}.tar.gz"
    with tarfile.open(str(archive), "w:gz") as tf:
        for name, content in members.items():
            data = content.encode()
            info = tarfile.TarInfo(name=f"{pkg_stem}/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return archive


def _write_manifest(pkg_dir: Path, filename: str, version: str) -> None:
    manifest = [{"filename": filename, "version": version}]
    (pkg_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBenignGroundTruth:

    def test_benign_label_is_false(self, tmp_path):
        """Archives discovered from benign/ must carry is_malicious=False."""
        # Build samples/benign/fakepkg/
        pkg_dir = tmp_path / "samples" / "benign" / "fakepkg"
        pkg_dir.mkdir(parents=True)
        archive = _write_targz(pkg_dir, "fakepkg-1.0.0", {"setup.py": "x = 1\n"})
        _write_manifest(pkg_dir, archive.name, "1.0.0")

        # Patch the runner's samples_root to point at tmp_path/samples
        from evaluate import EvaluationRunner
        runner = EvaluationRunner.__new__(EvaluationRunner)
        runner._samples_root = tmp_path / "samples"
        runner._benign_cache  = None
        runner._malware_cache = None

        results = runner._discover_benign()
        assert len(results) == 1
        path, name, version, is_malicious = results[0]
        assert is_malicious is False, "Benign archive mislabelled as malicious"
        assert name == "fakepkg"
        assert version == "1.0.0"

    def test_benign_controls_subdirectory_skipped(self, tmp_path):
        """Archives inside benign/controls/ must be excluded from discover_benign."""
        controls_dir = tmp_path / "samples" / "benign" / "controls" / "somepkg"
        controls_dir.mkdir(parents=True)
        archive = _write_targz(controls_dir, "somepkg-1.0.0", {"setup.py": ""})
        _write_manifest(controls_dir, archive.name, "1.0.0")

        from evaluate import EvaluationRunner
        runner = EvaluationRunner.__new__(EvaluationRunner)
        runner._samples_root = tmp_path / "samples"
        runner._benign_cache  = None
        runner._malware_cache = None

        assert runner._discover_benign() == [], "controls/ package should be skipped"


class TestMalwareGroundTruth:

    def test_malware_label_is_true(self, tmp_path):
        """Archives discovered from malware_backstabbers_knife/ must carry is_malicious=True."""
        malware_dir = tmp_path / "samples" / "malware_backstabbers_knife"
        malware_dir.mkdir(parents=True)
        _write_targz(malware_dir, "evil-pkg-1.0.0", {"setup.py": "import os; os.system('id')\n"})

        from evaluate import EvaluationRunner
        runner = EvaluationRunner.__new__(EvaluationRunner)
        runner._samples_root = tmp_path / "samples"
        runner._benign_cache  = None
        runner._malware_cache = None

        results = runner._discover_malware()
        assert len(results) == 1
        _, name, version, is_malicious = results[0]
        assert is_malicious is True, "Malware archive mislabelled as benign"
        assert name == "evil-pkg"
        assert version == "1.0.0"

    def test_missing_malware_dir_returns_empty(self, tmp_path):
        """_discover_malware() must return [] gracefully when the directory is absent."""
        from evaluate import EvaluationRunner
        runner = EvaluationRunner.__new__(EvaluationRunner)
        runner._samples_root = tmp_path / "samples"   # directory does not exist
        runner._benign_cache  = None
        runner._malware_cache = None

        assert runner._discover_malware() == []

    def test_discovery_result_is_cached(self, tmp_path):
        """Second call to _discover_malware() must return the cached list, not re-scan."""
        malware_dir = tmp_path / "samples" / "malware_backstabbers_knife"
        malware_dir.mkdir(parents=True)
        _write_targz(malware_dir, "evil-pkg-1.0.0", {"setup.py": ""})

        from evaluate import EvaluationRunner
        runner = EvaluationRunner.__new__(EvaluationRunner)
        runner._samples_root = tmp_path / "samples"
        runner._benign_cache  = None
        runner._malware_cache = None

        first  = runner._discover_malware()
        # Now add another archive — should NOT appear in second call (cache hit)
        _write_targz(malware_dir, "late-pkg-2.0.0", {"setup.py": ""})
        second = runner._discover_malware()
        assert first is second, "Cache miss: second call returned a different object"
        assert len(second) == 1, "Cache miss: late archive was picked up unexpectedly"
