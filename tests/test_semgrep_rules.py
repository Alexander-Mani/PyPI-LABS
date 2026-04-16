"""Real Semgrep regression tests for the offline PyPI-SCADA ruleset."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_RULES = _REPO_ROOT / "src" / "analyzer" / "static_rules" / "semgrep_python.yml"
_FIXTURES = _REPO_ROOT / "tests" / "fixtures" / "semgrep"


def _semgrep_bin() -> str:
    explicit = os.environ.get("SEMGREP_BIN")
    if explicit:
        return explicit
    from_path = shutil.which("semgrep")
    if from_path:
        return from_path
    repo_venv = _REPO_ROOT / ".venv" / "bin" / "semgrep"
    if repo_venv.exists():
        return str(repo_venv)
    pytest.fail("semgrep executable not found; install project requirements or set SEMGREP_BIN")


def _run_semgrep(target: Path, tmp_path: Path) -> set[str]:
    scan_target = tmp_path / "scan-target"
    shutil.copytree(target, scan_target)
    env = {
        **os.environ,
        "SEMGREP_SETTINGS_FILE": str(tmp_path / "settings.yml"),
        "SEMGREP_LOG_FILE": str(tmp_path / "semgrep.log"),
        "SEMGREP_SEND_METRICS": "off",
    }
    proc = subprocess.run(
        [
            _semgrep_bin(),
            "scan",
            "--config",
            str(_RULES),
            "--json",
            "--metrics",
            "off",
            "--disable-version-check",
            "--no-git-ignore",
            "--quiet",
            str(scan_target),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(proc.stdout or "{}")
    assert data.get("errors") in ([], None), data.get("errors")
    return {
        str(result["check_id"]).split(".")[-1]
        for result in data.get("results", [])
    }


def _expected_rules(fixture: Path) -> set[str]:
    expected_path = fixture / "expected_rules.txt"
    return {
        line.strip()
        for line in expected_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


MALICIOUS_FIXTURES = sorted((_FIXTURES / "malicious").iterdir())
BENIGN_FIXTURES = sorted((_FIXTURES / "benign").iterdir())
BORDERLINE_FIXTURES = sorted((_FIXTURES / "borderline").iterdir())


@pytest.mark.parametrize("fixture", MALICIOUS_FIXTURES, ids=lambda p: p.name)
def test_semgrep_malicious_fixtures_hit_expected_rules(fixture: Path, tmp_path: Path):
    observed = _run_semgrep(fixture, tmp_path)
    expected = _expected_rules(fixture)
    assert expected <= observed


@pytest.mark.parametrize("fixture", BENIGN_FIXTURES, ids=lambda p: p.name)
def test_semgrep_benign_fixtures_are_quiet(fixture: Path, tmp_path: Path):
    assert _run_semgrep(fixture, tmp_path) == set()


@pytest.mark.parametrize("fixture", BORDERLINE_FIXTURES, ids=lambda p: p.name)
def test_semgrep_borderline_fixtures_document_expected_findings(
    fixture: Path,
    tmp_path: Path,
):
    observed = _run_semgrep(fixture, tmp_path)
    expected = _expected_rules(fixture)
    assert expected <= observed
