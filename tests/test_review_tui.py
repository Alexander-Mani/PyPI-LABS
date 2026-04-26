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
        review_tui.SECTION_DEPLOYMENT,
        review_tui.SECTION_DRY_RUNS,
        review_tui.SECTION_EXPERIMENT,
        review_tui.SECTION_DATABASE,
        review_tui.SECTION_LOGS,
        review_tui.SECTION_TESTS,
    ]
    assert by_id[review_tui.SECTION_EXPERIMENT].title == "Run Experiment Suite"
    assert by_id[review_tui.SECTION_EXPERIMENT].preflight is None
    assert by_id[review_tui.SECTION_DEPLOYMENT].title == "Deployment"
    assert by_id[review_tui.SECTION_DRY_RUNS].title == "Dry Runs"
    assert by_id[review_tui.SECTION_DATABASE].preflight is None


def test_action_registry_contains_expected_sectioned_actions(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    by_id = {action.id: action for action in actions}

    expected = {
        "models-preview-all",
        "memory-probe-preview",
        "memory-probe-production-preview",
        "models-smoke-all",
        "models-smoke-budget",
        "models-smoke-medium",
        "models-smoke-frontier",
        "models-smoke-all-models",
        "memory-probe-budget",
        "memory-probe-frontier",
        "memory-probe-all-models",
        "analyzer-dry-run-test",
        "analyzer-dry-run-test-no-gemini",
        "experiment-tiny-test",
        "experiment-static-baseline",
        "experiment-identity-alias-probe",
        "experiment-production-memory-probe-all-models",
        "experiment-non-agentic-budget",
        "experiment-non-agentic-medium",
        "experiment-non-agentic-frontier",
        "experiment-non-agentic-all-models",
        "experiment-agentic-budget",
        "experiment-agentic-medium",
        "experiment-agentic-frontier",
        "experiment-agentic-all-models",
        "experiment-dry-run-budget",
        "experiment-dry-run-medium",
        "experiment-dry-run-frontier",
        "experiment-dry-run-all-models",
        "experiment-dry-run-gemini-only",
        "experiment-dry-run-gemini-only-test",
        "experiment-dry-run-frontier-bakeoff",
        "experiment-full-budget",
        "experiment-full-medium",
        "experiment-full-frontier",
        "experiment-full-all-models",
        "experiment-gemini-only-full",
        "experiment-gemini-only-test",
        "experiment-frontier-bakeoff",
        "deployment-setup",
        "deployment-setup-no-upload",
        "deployment-smoke-test",
        "deployment-restart-services",
        "db-status",
        "db-production-repair-dry-run",
        "db-production-repair-apply",
        "db-production-summary",
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
    assert not any(action.id.startswith("experiment-full-") and "no-gemini" in action.id for action in actions)
    assert by_id["experiment-full-all-models"].section == review_tui.SECTION_EXPERIMENT
    assert by_id["experiment-dry-run-budget"].section == review_tui.SECTION_DRY_RUNS
    assert by_id["deployment-setup"].section == review_tui.SECTION_DEPLOYMENT
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
    assert by_id["memory-probe-preview"].safety == review_tui.SAFETY_SAFE
    assert by_id["memory-probe-production-preview"].safety == review_tui.SAFETY_SAFE
    assert by_id["memory-probe-budget"].safety == review_tui.SAFETY_API_COST
    assert by_id["memory-probe-budget"].confirm is True
    assert by_id["models-smoke-all"].safety == review_tui.SAFETY_API_COST
    assert by_id["models-smoke-all"].confirm is True
    assert by_id["experiment-full-budget"].requires_clean_db is True
    assert by_id["experiment-full-budget"].confirm is True
    assert by_id["experiment-full-budget"].double_confirm is False
    assert by_id["experiment-full-frontier"].double_confirm is True
    assert by_id["experiment-full-all-models"].double_confirm is True
    assert by_id["experiment-identity-alias-probe"].requires_clean_db is True
    assert by_id["experiment-identity-alias-probe"].double_confirm is True
    assert by_id["experiment-production-memory-probe-all-models"].double_confirm is True
    assert by_id["deployment-setup"].safety == review_tui.SAFETY_DEPLOYMENT
    assert by_id["deployment-setup"].double_confirm is True
    assert by_id["deployment-smoke-test"].requires_clean_db is True
    assert by_id["archive-db"].safety == review_tui.SAFETY_MUTATES_DB
    assert by_id["archive-db"].confirm is True
    assert by_id["db-production-repair-dry-run"].safety == review_tui.SAFETY_SAFE
    assert by_id["db-production-repair-apply"].safety == review_tui.SAFETY_API_COST
    assert by_id["db-production-repair-apply"].confirm is True
    assert by_id["db-production-repair-apply"].double_confirm is True
    assert by_id["db-production-summary"].safety == review_tui.SAFETY_SAFE
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
    enabled_probe = review_tui.action_by_id("memory-probe-budget", enabled)
    disabled_probe = review_tui.action_by_id("memory-probe-budget", disabled)
    enabled_alias = review_tui.action_by_id("experiment-identity-alias-probe", enabled)
    disabled_alias = review_tui.action_by_id("experiment-identity-alias-probe", disabled)
    enabled_deploy = review_tui.action_by_id("deployment-setup", enabled)
    disabled_deploy = review_tui.action_by_id("deployment-setup", disabled)

    assert enabled_eval.command[enabled_eval.command.index("--gemini") + 1] == "on"
    assert disabled_eval.command[disabled_eval.command.index("--gemini") + 1] == "off"
    assert enabled_smoke.command[enabled_smoke.command.index("--gemini") + 1] == "on"
    assert disabled_smoke.command[disabled_smoke.command.index("--gemini") + 1] == "off"
    assert enabled_probe.command[enabled_probe.command.index("--gemini") + 1] == "on"
    assert disabled_probe.command[disabled_probe.command.index("--gemini") + 1] == "off"
    assert enabled_alias.command[enabled_alias.command.index("--gemini") + 1] == "on"
    assert disabled_alias.command[disabled_alias.command.index("--gemini") + 1] == "off"
    assert "GEMINI=on" in enabled_deploy.command[2]
    assert "GEMINI=off" in disabled_deploy.command[2]


def test_deployment_actions_are_shell_wrapped_and_profiled(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py", gemini_enabled=False)
    deployment = review_tui.action_by_id("deployment-smoke-test", actions)

    assert deployment.command[:2] == ("bash", "-lc")
    assert "DEPLOY_PHASE=smoke" in deployment.command[2]
    assert "MODEL_PROFILE=test" in deployment.command[2]
    assert "GEMINI=off" in deployment.command[2]
    assert "UPLOAD_CATEGORIES='controls malicious'" in deployment.command[2]
    assert deployment.double_confirm is True

    setup = review_tui.action_by_id("deployment-setup", actions)
    assert "DEPLOY_PHASE=setup" in setup.command[2]
    assert "UPLOAD_CATEGORIES" not in setup.command[2]

    no_upload = review_tui.action_by_id("deployment-setup-no-upload", actions)
    assert "DEPLOY_PHASE=setup" in no_upload.command[2]
    assert "UPLOAD_CATEGORIES=none" in no_upload.command[2]


def test_experiment_suite_has_deduplicated_lanes(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")

    static = review_tui.action_by_id("experiment-static-baseline", actions)
    full = review_tui.action_by_id("experiment-full-budget", actions)
    non_agentic = review_tui.action_by_id("experiment-non-agentic-budget", actions)
    agentic = review_tui.action_by_id("experiment-agentic-budget", actions)

    assert "--sast-only" in static.command
    assert "--run-id-prefix" in static.command
    assert "canonical-v2-static" in static.command
    assert "--skip-static" in full.command
    assert "--sast-only" not in full.command
    assert "--skip-agentic" not in full.command
    assert "--skip-static" in non_agentic.command
    assert "--skip-agentic" in non_agentic.command
    assert "--only-agentic" in agentic.command


def test_gemini_only_actions_force_gemini_and_skip_static_agentic(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py", gemini_enabled=False)

    full = review_tui.action_by_id("experiment-gemini-only-full", actions)
    tiny = review_tui.action_by_id("experiment-gemini-only-test", actions)
    dry_run = review_tui.action_by_id("experiment-dry-run-gemini-only", actions)

    for action in (full, tiny, dry_run):
        assert action.command[action.command.index("--gemini") + 1] == "on"
    assert "--skip-static" in full.command
    assert "--skip-agentic" in full.command
    assert "--skip-static" in tiny.command
    assert "--skip-agentic" in tiny.command
    assert "--dry-run-resolution" in dry_run.command


def test_frontier_bakeoff_actions_force_gemini_off_and_skip_static_agentic(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py", gemini_enabled=True)

    dry_run = review_tui.action_by_id("experiment-dry-run-frontier-bakeoff", actions)
    run = review_tui.action_by_id("experiment-frontier-bakeoff", actions)

    for action in (dry_run, run):
        assert action.command[action.command.index("--gemini") + 1] == "off"
        assert "--skip-static" in action.command
        assert "--skip-agentic" in action.command
        assert "--max-tokens" in action.command
        assert action.command[action.command.index("--max-tokens") + 1] == "8192"
        assert action.command[action.command.index("--profile") + 1] == "frontier_together_bakeoff"
    assert "--dry-run-resolution" in dry_run.command
    assert "--run-id-prefix" in run.command
    assert "frontier-bakeoff" in run.command


def test_frontier_and_all_models_smoke_actions_use_8192_tokens(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")

    frontier = review_tui.action_by_id("models-smoke-frontier", actions)
    all_models = review_tui.action_by_id("models-smoke-all-models", actions)
    medium = review_tui.action_by_id("models-smoke-medium", actions)

    for action in (frontier, all_models):
        assert "--max-tokens" in action.command
        assert action.command[action.command.index("--max-tokens") + 1] == "8192"

    assert "--max-tokens" not in medium.command


def test_identity_alias_probe_is_standalone_all_models_action(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    alias = review_tui.action_by_id("experiment-identity-alias-probe", actions)

    assert alias.section == review_tui.SECTION_EXPERIMENT
    assert alias.command[:2] == ("/py", str(tmp_path / "src" / "analyzer" / "evaluate.py"))
    assert alias.command[alias.command.index("--profile") + 1] == "all_models"
    assert alias.command[alias.command.index("--sample-set") + 1] == "dataset"
    assert "--identity-alias-probe" in alias.command
    assert "--sast-only" not in alias.command
    assert "--only-agentic" not in alias.command
    assert "--skip-agentic" not in alias.command
    assert "identity alias probe" in alias.title


def test_model_memory_probe_actions_are_source_free_sidecars(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")

    preview = review_tui.action_by_id("memory-probe-preview", actions)
    budget = review_tui.action_by_id("memory-probe-budget", actions)
    frontier = review_tui.action_by_id("memory-probe-frontier", actions)
    all_models = review_tui.action_by_id("memory-probe-all-models", actions)
    production_preview = review_tui.action_by_id("memory-probe-production-preview", actions)
    production_run = review_tui.action_by_id("experiment-production-memory-probe-all-models", actions)

    assert preview.section == review_tui.SECTION_DRY_RUNS
    assert "--dry-run" in preview.command
    assert preview.command[preview.command.index("--scope") + 1] == "curated"
    assert production_preview.section == review_tui.SECTION_DRY_RUNS
    assert production_preview.command[production_preview.command.index("--scope") + 1] == "production"
    assert production_preview.command[production_preview.command.index("--profile") + 1] == "all_models"
    assert production_preview.command[production_preview.command.index("--max-tokens") + 1] == "8192"
    assert production_preview.command[production_preview.command.index("--timeout") + 1] == "120"
    assert production_preview.command[production_preview.command.index("--retries") + 1] == "2"
    assert production_preview.command[production_preview.command.index("--retry-delay") + 1] == "20"
    assert budget.section == review_tui.SECTION_DEPLOYMENT
    assert budget.command[:2] == ("/py", str(tmp_path / "scripts" / "model_memory_probe.py"))
    assert budget.command[budget.command.index("--scope") + 1] == "curated"
    assert budget.command[budget.command.index("--profile") + 1] == "budget"
    assert frontier.double_confirm is True
    assert all_models.double_confirm is True
    assert production_run.section == review_tui.SECTION_EXPERIMENT
    assert production_run.command[production_run.command.index("--scope") + 1] == "production"
    assert production_run.command[production_run.command.index("--sample-set") + 1] == "dataset"
    assert production_run.command[production_run.command.index("--max-tokens") + 1] == "8192"
    assert production_run.command[production_run.command.index("--timeout") + 1] == "120"
    assert production_run.command[production_run.command.index("--retries") + 1] == "2"
    assert production_run.command[production_run.command.index("--retry-delay") + 1] == "20"
    assert "--progress" in production_run.command


def test_full_model_runs_skip_static_for_every_profile(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")

    for profile, _label in review_tui.EXPERIMENT_PROFILES:
        action = review_tui.action_by_id(f"experiment-full-{review_tui._profile_slug(profile)}", actions)
        assert "--skip-static" in action.command
        assert "--sast-only" not in action.command
        assert action.title.endswith("model run")

    static_actions = [
        action for action in actions
        if action.section == review_tui.SECTION_EXPERIMENT and "--sast-only" in action.command
    ]
    assert [action.id for action in static_actions] == ["experiment-static-baseline"]


def test_sample_set_is_applied_to_canonical_experiment_actions_only(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py", sample_set="controls")

    full = review_tui.action_by_id("experiment-full-budget", actions)
    static = review_tui.action_by_id("experiment-static-baseline", actions)
    alias = review_tui.action_by_id("experiment-identity-alias-probe", actions)
    production_probe = review_tui.action_by_id("experiment-production-memory-probe-all-models", actions)
    gemini_only = review_tui.action_by_id("experiment-gemini-only-full", actions)
    bakeoff = review_tui.action_by_id("experiment-frontier-bakeoff", actions)

    for action in (full, static, alias, production_probe):
        assert action.command[action.command.index("--sample-set") + 1] == "controls"

    assert "--sample-set" not in gemini_only.command
    assert "--sample-set" not in bakeoff.command


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


def test_production_db_actions_target_configured_analysis_db(tmp_path):
    actions = review_tui.build_actions(tmp_path, python_executable="/py")
    preview = review_tui.action_by_id("db-production-repair-dry-run", actions)
    apply = review_tui.action_by_id("db-production-repair-apply", actions)
    summary = review_tui.action_by_id("db-production-summary", actions)

    expected_db = str(tmp_path / "src" / "data" / "eval_results.db")

    for action in (preview, apply, summary):
        assert action.command[0] == "/py"
        assert expected_db in action.command

    assert preview.command[:2] == ("/py", str(tmp_path / "scripts" / "error_correct_production_data.py"))
    assert "--dry-run" in preview.command
    assert "--apply" not in preview.command

    assert apply.command[:2] == ("/py", str(tmp_path / "scripts" / "error_correct_production_data.py"))
    assert "--apply" in apply.command
    assert "--dry-run" not in apply.command

    assert summary.command[:2] == ("/py", str(tmp_path / "scripts" / "summarize_thesis_eval_db.py"))
    assert "--db" in summary.command
    assert preview.title == "Preview all DB error reruns"
    assert apply.title == "Create all DB error reruns"
    assert summary.title == "Summarize thesis DB raw + cleaned views"


def test_context_config_analysis_db_path_overrides_repo_default(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    deployed_python = deployed / "venv" / "bin" / "python"
    deployed_python.parent.mkdir(parents=True)
    deployed_python.write_text("", encoding="utf-8")
    configured_db = tmp_path / "shared" / "analysis.db"
    config = tmp_path / "review_tui.yaml"
    config.write_text(
        f"""
default_context: deployed
contexts:
  deployed:
    repo_root: {deployed}
    python: {deployed_python}
    runner_user: pypi-runner
    analysis_db_path: {configured_db}
    litellm_log: /tmp/litellm.log
    deployment_cwd: {tmp_path}
    deployment_script: {tmp_path / 'deployment.sh'}
""".strip(),
        encoding="utf-8",
    )

    context = review_tui.resolve_review_context("deployed", config_path=config)
    actions = review_tui.build_actions(context=context)
    preview = review_tui.action_by_id("db-production-repair-dry-run", actions)

    assert context.db_path == configured_db.resolve()
    assert str(configured_db.resolve()) in review_tui.command_preview(preview.command)


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

    assert action.section == review_tui.SECTION_DEPLOYMENT
    preview = review_tui.command_preview(action.command)
    assert "Context:" in preview
    assert "Configured Python:" in preview
    assert "Effective Python:" in preview


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


def test_runner_context_defaults_to_repo_venv_python(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    deployed_python = deployed / "venv" / "bin" / "python"
    deployed_python.parent.mkdir(parents=True)
    deployed_python.write_text("", encoding="utf-8")
    config = tmp_path / "review_tui.yaml"
    config.write_text(
        f"""
default_context: deployed
contexts:
  deployed:
    repo_root: {deployed}
    python: null
    runner_user: pypi-runner
    litellm_log: /tmp/litellm.log
    deployment_cwd: {tmp_path}
    deployment_script: {tmp_path / 'deployment.sh'}
""".strip(),
        encoding="utf-8",
    )

    context = review_tui.resolve_review_context("deployed", config_path=config)

    assert context.python_executable == str(deployed_python.resolve())
    assert context.warnings
    assert "No Python configured" in context.warnings[0]


def test_auto_context_keeps_deployed_runner_even_when_venv_missing(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    local = tmp_path / "local"
    local.mkdir()
    config = tmp_path / "review_tui.yaml"
    config.write_text(
        f"""
default_context: auto
contexts:
  deployed:
    repo_root: {deployed}
    python: null
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
    assert context.runner_user == "pypi-runner"
    assert context.python_executable == str(deployed / "venv" / "bin" / "python")
    assert any("does not exist yet" in warning for warning in context.warnings)


def test_deployed_context_repairs_system_python_config(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    deployed_python = deployed / "venv" / "bin" / "python"
    deployed_python.parent.mkdir(parents=True)
    deployed_python.write_text("", encoding="utf-8")
    config = tmp_path / "review_tui.yaml"
    config.write_text(
        f"""
default_context: deployed
contexts:
  deployed:
    repo_root: {deployed}
    python: {sys.executable}
    runner_user: pypi-runner
    litellm_log: /tmp/litellm.log
    deployment_cwd: {tmp_path}
    deployment_script: {tmp_path / 'deployment.sh'}
""".strip(),
        encoding="utf-8",
    )

    context = review_tui.resolve_review_context("deployed", config_path=config)

    assert context.configured_python == sys.executable
    assert context.python_executable == str(deployed_python)
    assert any("outside" in warning and "using repo venv" in warning for warning in context.warnings)


def test_deployed_context_warns_but_keeps_menu_usable_without_venv(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    config = tmp_path / "review_tui.yaml"
    config.write_text(
        f"""
default_context: deployed
contexts:
  deployed:
    repo_root: {deployed}
    python: {sys.executable}
    runner_user: pypi-runner
    litellm_log: /tmp/litellm.log
    deployment_cwd: {tmp_path}
    deployment_script: {tmp_path / 'deployment.sh'}
""".strip(),
        encoding="utf-8",
    )

    context = review_tui.resolve_review_context("deployed", config_path=config)

    assert context.python_executable == str(Path(sys.executable).resolve())
    assert any("expected repo venv is missing" in warning for warning in context.warnings)


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


def test_context_shell_prepends_selected_python_bin_to_path(tmp_path):
    deployed = tmp_path / "deployed"
    deployed.mkdir()
    deployed_python = deployed / "venv" / "bin" / "python"
    context = review_tui.ReviewContext(
        name="deployed",
        repo_root=deployed,
        python_executable=str(deployed_python),
        runner_user="pypi-runner",
    )

    command = review_tui._shell_in_context(context, "python src/analyzer/evaluate.py", user="pypi-runner")
    preview = review_tui.command_preview(command)

    assert command[:3] == ("sudo", "-u", "pypi-runner")
    assert f"export PATH={deployed_python.parent}:$PATH" in preview
    assert "python src/analyzer/evaluate.py" in preview
