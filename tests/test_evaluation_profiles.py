"""Regression tests for evaluation profile resolver settings."""

from __future__ import annotations

import sys
import types
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from evaluate import (  # noqa: E402
    EvaluationRunner,
    GroundTruthLabel,
    ResolvedPackage,
    _aggregate_package_version_metrics,
    _load_evaluation_profile,
    _make_run_id,
)
from simulator_resolver import IndexArtifact  # noqa: E402

_PROFILE_CONFIG = _REPO_ROOT / "configs" / "evaluation_profiles.yaml"


def _profile_block(name: str) -> str:
    lines = _PROFILE_CONFIG.read_text(encoding="utf-8").splitlines()
    start = next(i for i, line in enumerate(lines) if line == f"  {name}:")
    end = next(
        (i for i in range(start + 1, len(lines)) if lines[i].startswith("  ") and not lines[i].startswith("    ")),
        len(lines),
    )
    return "\n".join(lines[start:end])


def _artifact(project: str, version: str, filename: str) -> IndexArtifact:
    return IndexArtifact(
        project=project,
        version=version,
        filename=filename,
        url=f"http://127.0.0.1:8080/packages/{project}/{filename}",
        kind="wheel" if filename.endswith(".whl") else "sdist",
    )


def _package(name: str, role: str, malicious: bool = False) -> ResolvedPackage:
    return ResolvedPackage(
        project=name,
        version="1.0.0",
        label=GroundTruthLabel(is_malicious=malicious, sample_role=role),
        artifacts=[_artifact(name, "1.0.0", f"{name}-1.0.0.tar.gz")],
    )


def _patch_profile(monkeypatch, profile):
    monkeypatch.setitem(
        sys.modules,
        "yaml",
        types.SimpleNamespace(safe_load=lambda _f: {"profiles": {"test": profile}}),
    )


def test_test_profiles_enable_controls_and_limit_to_four_packages():
    test_block = _profile_block("test")
    test_no_gemini_block = _profile_block("test_no_gemini")

    for block in (test_block, test_no_gemini_block):
        assert "include_controls: true" in block
        assert "package_limits:" in block
        assert "malicious: 2" in block
        assert "control: 2" in block
        assert "benign: 0" in block


def test_package_limits_keep_two_malicious_two_controls_and_skip_benign():
    runner = EvaluationRunner.__new__(EvaluationRunner)
    runner._package_limits = {"malicious": 2, "control": 2, "benign": 0}

    limited = runner._apply_package_limits([
        _package("benign-a", "benign"),
        _package("control-a", "control"),
        _package("control-b", "control"),
        _package("control-c", "control"),
        _package("malware-a", "malware", malicious=True),
        _package("malware-b", "malware", malicious=True),
        _package("malware-c", "malware", malicious=True),
    ])

    assert [package.project for package in limited] == [
        "control-a",
        "control-b",
        "malware-a",
        "malware-b",
    ]


def test_profile_loader_accepts_package_limits(monkeypatch):
    _patch_profile(monkeypatch, {
        "tier": "budget",
        "configs": ["gpt_nano"],
        "resolver": {
            "include_controls": True,
            "package_limits": {"malicious": 2, "control": 2, "benign": 0},
        },
    })

    profile = _load_evaluation_profile("test")

    assert profile.include_controls is True
    assert profile.package_limits == {"malicious": 2, "control": 2, "benign": 0}


def test_profile_loader_rejects_invalid_resolver(monkeypatch):
    _patch_profile(monkeypatch, {
        "tier": "budget",
        "configs": ["gpt_nano"],
        "resolver": [],
    })

    try:
        _load_evaluation_profile("test")
    except SystemExit as exc:
        assert "resolver section must be a mapping" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("invalid resolver should halt")


def test_profile_loader_rejects_invalid_package_limits(monkeypatch):
    invalid_profiles = [
        {"resolver": {"package_limits": []}, "message": "package_limits must be a mapping"},
        {"resolver": {"package_limits": {"weird": 1}}, "message": "unknown package limit role"},
        {"resolver": {"package_limits": {"malicious": -1}}, "message": "must be a non-negative integer"},
        {"resolver": {"include_controls": "yes"}, "message": "include_controls must be true or false"},
    ]

    for case in invalid_profiles:
        _patch_profile(monkeypatch, {
            "tier": "budget",
            "configs": ["gpt_nano"],
            "resolver": case["resolver"],
        })
        try:
            _load_evaluation_profile("test")
        except SystemExit as exc:
            assert case["message"] in str(exc)
        else:  # pragma: no cover - defensive failure path
            raise AssertionError(f"invalid profile should halt: {case}")


def test_make_run_id_prefixes_main_and_validation_runs():
    run_id = _make_run_id("canonical-v2")
    validation_id = _make_run_id("canonical-v2", validation=True)

    assert run_id.startswith("canonical-v2-")
    assert validation_id.startswith("canonical-v2-airgap-")


def test_make_run_id_rejects_invalid_prefix():
    try:
        _make_run_id("../bad")
    except SystemExit as exc:
        assert "--run-id-prefix" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("invalid run id prefix should halt")


def test_metrics_aggregate_multiple_artifacts_to_one_package_version():
    rows = [
        _row("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl", False, False),
        _row("pkg", "1.0.0", "pkg-1.0.0.tar.gz", False, True),
        _row("clean", "2.0.0", "clean-2.0.0.tar.gz", False, False),
        _row("bad", "3.0.0", "bad-3.0.0.tar.gz", True, False),
    ]

    stats, error_rows, excluded_groups, unknown_pkgs = _aggregate_package_version_metrics(rows)

    assert stats["bandit:static:zero_shot"] == {"TP": 0, "TN": 1, "FP": 1, "FN": 1}
    assert error_rows == 0
    assert excluded_groups == 0
    assert unknown_pkgs == set()


def test_metrics_exclude_all_error_package_version_groups():
    rows = [
        {
            **_row("pkg", "1.0.0", "pkg-1.0.0.tar.gz", True, False),
            "experiment_mode": "error",
            "details": {"intended_mode": "hybrid"},
        },
    ]

    stats, error_rows, excluded_groups, unknown_pkgs = _aggregate_package_version_metrics(rows)

    assert stats == {}
    assert error_rows == 1
    assert excluded_groups == 1
    assert unknown_pkgs == set()


def test_metrics_keep_mixed_success_error_group():
    rows = [
        _row("pkg", "1.0.0", "pkg-1.0.0.whl", True, True),
        {
            **_row("pkg", "1.0.0", "pkg-1.0.0.tar.gz", True, False),
            "experiment_mode": "error",
            "details": {"intended_mode": "static"},
        },
    ]

    stats, error_rows, excluded_groups, unknown_pkgs = _aggregate_package_version_metrics(rows)

    assert stats["bandit:static:zero_shot"] == {"TP": 1, "TN": 0, "FP": 0, "FN": 0}
    assert error_rows == 1
    assert excluded_groups == 0
    assert unknown_pkgs == set()


def test_metrics_reject_conflicting_ground_truth():
    rows = [
        _row("pkg", "1.0.0", "pkg-1.0.0.whl", True, True),
        _row("pkg", "1.0.0", "pkg-1.0.0.tar.gz", False, False),
    ]

    try:
        _aggregate_package_version_metrics(rows)
    except SystemExit as exc:
        assert "conflicting ground truth" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("conflicting ground truth should halt")


def test_metrics_report_unknown_ground_truth():
    rows = [_row("pkg", "1.0.0", "pkg-1.0.0.whl", True, True)]
    rows[0]["ground_truth"] = None

    stats, error_rows, excluded_groups, unknown_pkgs = _aggregate_package_version_metrics(rows)

    assert stats == {}
    assert error_rows == 0
    assert excluded_groups == 0
    assert unknown_pkgs == {"pkg"}


def _row(
    package: str,
    version: str,
    artifact: str,
    ground_truth: bool,
    verdict: bool,
) -> dict:
    return {
        "package_name": package,
        "version": version,
        "artifact_filename": artifact,
        "ground_truth": int(ground_truth),
        "verdict": int(verdict),
        "detector": "bandit",
        "experiment_mode": "static",
        "prompt_strategy": "zero_shot",
        "details": {},
    }
