"""Tests for the sectioned review TUI action registry."""

from __future__ import annotations

import sqlite3
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import review_tui  # noqa: E402


def test_sections_are_registered_with_expected_preflight():
    sections = review_tui.build_sections()
    by_id = {section.id: section for section in sections}

    assert [section.id for section in sections] == [
        review_tui.SECTION_EXPERIMENT,
        review_tui.SECTION_DATABASE,
        review_tui.SECTION_LOGS,
        review_tui.SECTION_TESTS,
    ]
    assert by_id[review_tui.SECTION_EXPERIMENT].title == "Run Experiment Suite"
    assert by_id[review_tui.SECTION_EXPERIMENT].preflight == "clean-db"
    assert by_id[review_tui.SECTION_DATABASE].preflight is None


def test_action_registry_contains_expected_sectioned_actions(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    by_id = {action.id: action for action in actions}

    expected = {
        "models-preview-all",
        "models-smoke-all",
        "models-smoke-budget",
        "models-smoke-medium",
        "models-smoke-frontier",
        "models-smoke-all-models",
        "analyzer-dry-run-test",
        "experiment-tiny-test",
        "experiment-dry-run-budget",
        "experiment-dry-run-medium",
        "experiment-dry-run-frontier",
        "experiment-dry-run-all-models",
        "experiment-full-budget",
        "experiment-full-medium",
        "experiment-full-frontier",
        "experiment-full-all-models",
        "deployment-smoke-test",
        "deployment-full-budget",
        "deployment-full-medium",
        "deployment-full-frontier",
        "deployment-full-all-models",
        "db-status",
        "archive-db-dry-run",
        "archive-db",
        "archive-db-no-init",
        "db-runs",
        "db-recent",
        "db-errors",
        "db-detector-summary",
        "logs-list",
        "logs-tail-analyzer",
        "logs-tail-injector",
        "logs-tail-simulator",
        "logs-tail-litellm",
        "logs-search-errors",
        "tests-review",
        "tests-static-detectors",
        "tests-db-archive",
        "tests-litellm-smoke",
        "tests-all",
        "syntax-checks",
    }
    assert expected <= set(by_id)
    assert not any("no-gemini" in action.id for action in actions)
    assert by_id["experiment-full-all-models"].section == review_tui.SECTION_EXPERIMENT
    assert by_id["db-status"].section == review_tui.SECTION_DATABASE
    assert by_id["logs-tail-litellm"].section == review_tui.SECTION_LOGS
    assert by_id["syntax-checks"].section == review_tui.SECTION_TESTS


def test_actions_for_section_filters_registry(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    experiment_actions = review_tui.actions_for_section(review_tui.SECTION_EXPERIMENT, actions)
    database_actions = review_tui.actions_for_section(review_tui.SECTION_DATABASE, actions)

    assert experiment_actions
    assert database_actions
    assert {action.section for action in experiment_actions} == {review_tui.SECTION_EXPERIMENT}
    assert {action.section for action in database_actions} == {review_tui.SECTION_DATABASE}


def test_safety_and_confirmation_policy(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    by_id = {action.id: action for action in actions}

    assert by_id["models-preview-all"].safety == review_tui.SAFETY_SAFE
    assert by_id["models-preview-all"].confirm is False
    assert by_id["models-smoke-all"].safety == review_tui.SAFETY_API_COST
    assert by_id["models-smoke-all"].confirm is True
    assert by_id["experiment-full-budget"].requires_clean_db is True
    assert by_id["experiment-full-budget"].confirm is True
    assert by_id["experiment-full-budget"].double_confirm is False
    assert by_id["experiment-full-frontier"].double_confirm is True
    assert by_id["experiment-full-all-models"].double_confirm is True
    assert by_id["deployment-full-all-models"].safety == review_tui.SAFETY_DEPLOYMENT
    assert by_id["deployment-full-all-models"].double_confirm is True
    assert by_id["archive-db"].safety == review_tui.SAFETY_MUTATES_DB
    assert by_id["archive-db"].confirm is True
    assert by_id["tests-all"].safety == review_tui.SAFETY_LONG_RUNNING


def test_python_commands_use_repo_paths_and_requested_interpreter(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/custom/python")
    smoke = review_tui.action_by_id("models-preview-all", actions)
    analyzer = review_tui.action_by_id("analyzer-dry-run-test", actions)

    assert smoke.command[:2] == ("/custom/python", str(tmp_path / "scripts" / "litellm_smoke.py"))
    assert "--all-models" in smoke.command
    assert "--dry-run" in smoke.command
    assert "--gemini" in smoke.command
    assert analyzer.command[:2] == ("/custom/python", str(tmp_path / "src" / "analyzer" / "evaluate.py"))
    assert "test" in analyzer.command
    assert "--dry-run-resolution" in analyzer.command


def test_gemini_toggle_changes_generated_commands(tmp_path):
    enabled = review_tui.build_actions(tmp_path, python_executable="/py", gemini_enabled=True)
    disabled = review_tui.build_actions(tmp_path, python_executable="/py", gemini_enabled=False)

    enabled_eval = review_tui.action_by_id("experiment-full-budget", enabled)
    disabled_eval = review_tui.action_by_id("experiment-full-budget", disabled)
    enabled_smoke = review_tui.action_by_id("models-smoke-all", enabled)
    disabled_smoke = review_tui.action_by_id("models-smoke-all", disabled)
    enabled_deploy = review_tui.action_by_id("deployment-full-budget", enabled)
    disabled_deploy = review_tui.action_by_id("deployment-full-budget", disabled)

    assert enabled_eval.command[enabled_eval.command.index("--gemini") + 1] == "on"
    assert disabled_eval.command[disabled_eval.command.index("--gemini") + 1] == "off"
    assert enabled_smoke.command[enabled_smoke.command.index("--gemini") + 1] == "on"
    assert disabled_smoke.command[disabled_smoke.command.index("--gemini") + 1] == "off"
    assert "GEMINI=on" in enabled_deploy.command[2]
    assert "GEMINI=off" in disabled_deploy.command[2]


def test_deployment_actions_are_shell_wrapped_and_profiled(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py", gemini_enabled=False)
    deployment = review_tui.action_by_id("deployment-smoke-test", actions)

    assert deployment.command[:2] == ("bash", "-lc")
    assert "MODEL_PROFILE=test" in deployment.command[2]
    assert "GEMINI=off" in deployment.command[2]
    assert "UPLOAD_CATEGORIES='controls malicious'" in deployment.command[2]
    assert deployment.double_confirm is True


def test_safe_action_executes_with_repo_root_cwd_through_runner(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    action = review_tui.action_by_id("models-preview-all", actions)
    calls = []

    def fake_runner(command, cwd):
        calls.append((command, cwd))
        return subprocess.CompletedProcess(command, 0)

    rc = review_tui.execute_action(action, repo_root=tmp_path, runner=fake_runner)

    assert rc == 0
    assert calls == [(action.command, tmp_path)]


def test_sqlite_actions_use_readonly_immutable_db_urls(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    db_actions = [
        review_tui.action_by_id("db-runs", actions),
        review_tui.action_by_id("db-recent", actions),
        review_tui.action_by_id("db-errors", actions),
        review_tui.action_by_id("db-detector-summary", actions),
    ]

    for action in db_actions:
        assert action.command[0] == "sqlite3"
        assert "mode=ro&immutable=1" in action.command[3]
        assert str(tmp_path / "src" / "data" / "eval_results.db") in action.command[3]
    assert "limit 30" in review_tui.action_by_id("db-recent", actions).command[4].lower()
    assert "experiment_mode = 'error'" in review_tui.action_by_id("db-errors", actions).command[4]


def test_db_archive_warning_detects_existing_result_rows(tmp_path):
    data_dir = tmp_path / "src" / "data"
    data_dir.mkdir(parents=True)
    db_path = data_dir / "eval_results.db"

    assert review_tui.db_result_count(tmp_path) == 0
    assert review_tui.db_needs_archive_warning(tmp_path) is False

    with sqlite3.connect(db_path) as conn:
        conn.execute("create table eval_result (id integer primary key)")
        conn.execute("insert into eval_result default values")

    assert review_tui.db_result_count(tmp_path) == 1
    assert review_tui.db_needs_archive_warning(tmp_path) is True


def test_db_archive_warning_treats_invalid_db_as_clean_for_tui_preflight(tmp_path):
    data_dir = tmp_path / "src" / "data"
    data_dir.mkdir(parents=True)
    (data_dir / "eval_results.db").write_text("not sqlite", encoding="utf-8")

    assert review_tui.db_result_count(tmp_path) == 0
    assert review_tui.db_needs_archive_warning(tmp_path) is False


def test_numeric_id_back_and_quit_choice_resolution(tmp_path):
    sections = review_tui.build_sections()
    actions = review_tui.build_actions(tmp_path, python_executable="/py")

    assert review_tui._resolve_choice("1", sections) == sections[0]
    assert review_tui._resolve_choice("database", sections).id == review_tui.SECTION_DATABASE
    assert review_tui._resolve_choice("1", actions) == actions[0]
    assert review_tui._resolve_choice("models-preview-all", actions).id == "models-preview-all"
    assert review_tui._resolve_choice("b", actions) == "back"
    assert review_tui._resolve_choice("q", actions) is None


def test_context_status_action_registered(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    action = review_tui.action_by_id("context-status", actions)

    assert action.section == review_tui.SECTION_DATABASE
    assert "Context:" in review_tui.command_preview(action.command)


def test_auto_context_prefers_deployed_when_available(tmp_path):
    deployed = tmp_path / "deployed"
    deployed_python = deployed / "venv" / "bin" / "python"
    deployed_python.parent.mkdir(parents=True)
    deployed_python.write_text("", encoding="utf-8")
    deployed.mkdir(exist_ok=True)
    local = tmp_path / "local"
    local.mkdir()
    config = tmp_path / "review_tui.yaml"
    config.write_text(
        f"""
default_context: auto
contexts:
  deployed:
    repo_root: {deployed}
    python: {deployed_python}
    runner_user: pypi-runner
    litellm_log: /tmp/litellm.log
    deployment_cwd: {local}
    deployment_script: {local / 'deployment.sh'}
  local:
    repo_root: {local}
    python: {sys.executable}
    runner_user: null
    litellm_log: /tmp/litellm.log
    deployment_cwd: {local}
    deployment_script: {local / 'deployment.sh'}
""".strip(),
        encoding="utf-8",
    )

    context = review_tui.resolve_review_context("auto", config_path=config)

    assert context.name == "deployed"
    assert context.repo_root == deployed.resolve()
    assert context.python_executable == str(deployed_python.resolve())
    assert context.runner_user == "pypi-runner"


def test_deployed_context_commands_use_deployed_repo_and_python(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    deployed_python = deployed / "venv" / "bin" / "python"
    context = review_tui.ReviewContext(
        name="deployed",
        repo_root=deployed,
        python_executable=str(deployed_python),
        runner_user="pypi-runner",
        litellm_log=tmp_path / "litellm.log",
        deployment_cwd=tmp_path,
        deployment_script=tmp_path / "deployment.sh",
    )

    actions = review_tui.build_actions(context=context)
    smoke = review_tui.action_by_id("models-preview-all", actions)
    analyzer = review_tui.action_by_id("analyzer-dry-run-test", actions)
    db_status = review_tui.action_by_id("db-status", actions)

    for action in (smoke, analyzer, db_status):
        preview = review_tui.command_preview(action.command)
        assert action.command[:3] == ("sudo", "-u", "pypi-runner")
        assert str(deployed) in preview
        assert str(deployed_python) in preview or action.id == "db-status"
        assert str(review_tui._REPO_ROOT) not in preview


def test_mixed_root_warning_detects_local_script_with_deployed_python(tmp_path):
    deployed = tmp_path / "deployed"
    context = review_tui.ReviewContext(
        name="deployed",
        repo_root=deployed,
        python_executable=str(deployed / "venv" / "bin" / "python"),
        runner_user="pypi-runner",
    )
    mixed = (
        str(deployed / "venv" / "bin" / "python"),
        str(review_tui._REPO_ROOT / "scripts" / "litellm_smoke.py"),
    )
    actions = review_tui.build_actions(context=context)
    clean = review_tui.action_by_id("models-preview-all", actions).command

    assert review_tui._command_mentions_mixed_roots(mixed, context) is True
    assert review_tui._command_mentions_mixed_roots(clean, context) is False
