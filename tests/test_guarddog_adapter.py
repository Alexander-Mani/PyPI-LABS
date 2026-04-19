"""GuardDog adapter regression tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

import adapters  # noqa: E402
from adapters import (  # noqa: E402
    GUARDDOG_SOURCE_RULES,
    SEMGREP_RULES_PATH,
    GuardDogAdapter,
    StaticAdapter,
)
from entry_extractor import PackageInfo  # noqa: E402


def _pkg() -> PackageInfo:
    return PackageInfo(
        name="demo",
        version="1.0.0",
        files={"setup.py": "from setuptools import setup\nsetup(name='demo')\n"},
        files_raw={},
        heuristic_flags=["shell_execution"],
    )


def test_guarddog_uses_source_only_rule_allowlist(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")
    calls: list[list[str]] = []

    def fake_run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        target = Path(cmd[3])
        assert (target / "setup.py").exists()
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps([{"rule": "exec-base64", "path": "setup.py"}]),
            stderr="",
        )

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    result = GuardDogAdapter().run(
        _pkg(),
        prompt_strategy="few_shot",
        system_prompt="ignored",
        template_override="ignored",
    )

    cmd = calls[0]
    assert Path(cmd[0]).name == "guarddog"
    assert cmd[1:3] == ["pypi", "scan"]
    assert "--output-format=json" in cmd
    assert "--exclude-rules" not in cmd
    assert "typosquatting" not in cmd
    assert "release_zero" not in cmd
    assert cmd.count("--rules") == len(GUARDDOG_SOURCE_RULES)
    for rule in GUARDDOG_SOURCE_RULES:
        assert rule in cmd

    assert result.detector == "guarddog"
    assert result.experiment_mode == "static"
    assert result.verdict is True
    assert result.heuristic_flags == ["shell_execution"]
    assert result.details["finding_count"] == 1
    assert result.details["guarddog_version"] == adapters.GUARDDOG_VERSION


def test_guarddog_parses_dict_output(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps({"results": [{"rule": "code-execution"}]}),
            stderr="",
        )

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    result = GuardDogAdapter().run(_pkg())

    assert result.experiment_mode == "static"
    assert result.verdict is True
    assert result.details["finding_count"] == 1


def test_guarddog_empty_findings_are_benign_static(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, 0, stdout=json.dumps({"results": []}), stderr="")

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    result = GuardDogAdapter().run(_pkg())

    assert result.detector == "guarddog"
    assert result.experiment_mode == "static"
    assert result.verdict is False
    assert result.details["finding_count"] == 0


def test_guarddog_subprocess_failure_is_error(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(cmd, 2, stdout="", stderr="network unavailable")

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    result = GuardDogAdapter().run(_pkg())

    assert result.detector == "guarddog"
    assert result.experiment_mode == "error"
    assert result.verdict is False
    assert "guarddog exited without JSON output" in result.details["error"]
    assert result.details["stderr"] == "network unavailable"


def test_guarddog_reported_rule_errors_are_errors(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")

    def fake_run(cmd, capture_output, text, timeout):
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps({
                "results": {},
                "errors": {"rules-all": "unable to find semgrep binary"},
            }),
            stderr="",
        )

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    result = GuardDogAdapter().run(_pkg())

    assert result.detector == "guarddog"
    assert result.experiment_mode == "error"
    assert "rule execution errors" in result.details["error"]
    assert "unable to find semgrep binary" in result.details["stdout"]


def test_semgrep_uses_checked_in_offline_rules(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")
    calls: list[list[str]] = []

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        calls.append(cmd)
        env = kwargs.get("env") or {}
        assert env["SEMGREP_SETTINGS_FILE"].endswith("settings.yml")
        assert env["SEMGREP_LOG_FILE"].endswith("semgrep.log")
        assert env["SEMGREP_SEND_METRICS"] == "off"
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps({"results": []}),
            stderr="",
        )

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    result = StaticAdapter("semgrep").run(_pkg())

    cmd = calls[0]
    assert Path(cmd[0]).name == "semgrep"
    assert cmd[1:4] == ["scan", "--config", str(SEMGREP_RULES_PATH)]
    assert SEMGREP_RULES_PATH.is_file()
    assert "p/python" not in cmd
    assert "--metrics" in cmd
    assert cmd[cmd.index("--metrics") + 1] == "off"
    assert "--disable-version-check" in cmd
    assert "--no-git-ignore" in cmd
    assert result.detector == "semgrep"
    assert result.experiment_mode == "static"
    assert result.verdict is False


def test_static_tool_subprocess_exceptions_are_errors(monkeypatch):
    monkeypatch.setattr(adapters, "_resolve_tool_executable", lambda tool: f"/venv/bin/{tool}")

    def fake_run(cmd, capture_output, text, timeout, **kwargs):
        raise FileNotFoundError(f"{cmd[0]} missing")

    monkeypatch.setattr(adapters.subprocess, "run", fake_run)

    bandit = StaticAdapter("bandit").run(_pkg())
    semgrep = StaticAdapter("semgrep").run(_pkg())

    assert bandit.experiment_mode == "error"
    assert semgrep.experiment_mode == "error"
    assert "missing" in bandit.details["error"]
    assert "missing" in semgrep.details["error"]


def test_static_tool_resolves_from_active_python_bin(monkeypatch, tmp_path):
    bin_dir = tmp_path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    tool = bin_dir / "bandit"
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)

    monkeypatch.setattr(adapters.shutil, "which", lambda name: None)
    monkeypatch.setattr(adapters.sys, "executable", str(bin_dir / "python"))

    assert adapters._resolve_tool_executable("bandit") == str(tool)


def test_static_tool_missing_error_lists_checked_paths(monkeypatch, tmp_path):
    bin_dir = tmp_path / "venv" / "bin"
    bin_dir.mkdir(parents=True)
    monkeypatch.setattr(adapters.shutil, "which", lambda name: None)
    monkeypatch.setattr(adapters.sys, "executable", str(bin_dir / "python"))

    try:
        adapters._resolve_tool_executable("semgrep")
    except FileNotFoundError as exc:
        message = str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("missing tool should raise")

    assert "semgrep" in message
    assert str(bin_dir / "semgrep") in message
    assert "active venv" in message
