"""Review TUI action catalog.

The interactive menu flow lives in ``review_tui.py``. This module owns the
large static action catalog so the TUI entrypoint remains readable.
"""

from __future__ import annotations


def build_actions(
    tui,
    repo_root,
    *,
    python_executable,
    gemini_enabled: bool = True,
    sample_set: str = "dataset",
    context=None,
):
    ReviewAction = tui.ReviewAction
    ReviewContext = tui.ReviewContext
    SECTION_DEPLOYMENT = tui.SECTION_DEPLOYMENT
    SECTION_DRY_RUNS = tui.SECTION_DRY_RUNS
    SECTION_EXPERIMENT = tui.SECTION_EXPERIMENT
    SECTION_DATABASE = tui.SECTION_DATABASE
    SECTION_LOGS = tui.SECTION_LOGS
    SECTION_TESTS = tui.SECTION_TESTS
    SAFETY_MUTATES_DB = tui.SAFETY_MUTATES_DB
    SAFETY_API_COST = tui.SAFETY_API_COST
    SAFETY_DEPLOYMENT = tui.SAFETY_DEPLOYMENT
    SAFETY_LONG_RUNNING = tui.SAFETY_LONG_RUNNING
    EXPERIMENT_PROFILES = tui.EXPERIMENT_PROFILES
    HIGH_COST_PROFILES = tui.HIGH_COST_PROFILES
    _REPO_ROOT = tui._REPO_ROOT
    _context_db_shell = tui._context_db_shell
    _context_python_module = tui._context_python_module
    _context_script = tui._context_script
    _context_sqlite = tui._context_sqlite
    _db_status_command = tui._db_status_command
    _default_local_context = tui._default_local_context
    _deployment_command = tui._deployment_command
    _gemini_value = tui._gemini_value
    _litellm_tail_command = tui._litellm_tail_command
    _profile_slug = tui._profile_slug
    _restart_services_command = tui._restart_services_command
    _shell = tui._shell
    _sqlite_detector_summary_query = tui._sqlite_detector_summary_query
    _sqlite_error_query = tui._sqlite_error_query
    _sqlite_recent_query = tui._sqlite_recent_query
    _sqlite_runs_query = tui._sqlite_runs_query
    shlex = tui.shlex

    context = context or _default_local_context(repo_root, python_executable)
    gemini = _gemini_value(gemini_enabled)

    def evaluate(profile: str, *args: str, sample_set_override: str | None = None) -> tuple[str, ...]:
        extra_args: tuple[str, ...] = ()
        if sample_set_override is not None:
            extra_args = ("--sample-set", sample_set_override)
        return _context_script(
            context,
            "src/analyzer/evaluate.py",
            "--profile",
            profile,
            "--gemini",
            gemini,
            *extra_args,
            *args,
        )

    def smoke(*args: str) -> tuple[str, ...]:
        return _context_script(context, "scripts/litellm_smoke.py", *args, "--gemini", gemini)

    def memory_probe(*args: str, sample_set_override: str | None = None) -> tuple[str, ...]:
        extra_args: tuple[str, ...] = ()
        if sample_set_override is not None:
            extra_args = ("--sample-set", sample_set_override)
        return _context_script(context, "scripts/model_memory_probe.py", *args, *extra_args, "--gemini", gemini)

    def deploy(
        profile: str,
        *,
        phase: str = "full",
        upload_categories: str | None = None,
    ) -> tuple[str, ...]:
        return _deployment_command(
            context,
            profile,
            gemini,
            phase=phase,
            upload_categories=upload_categories,
        )

    actions: list[ReviewAction] = [
        ReviewAction(
            id="context-status",
            section=SECTION_DEPLOYMENT,
            title="Show active deployment context",
            description="Show target repo, Python, analysis DB, runner user, and LiteLLM log paths.",
            command=_shell(
                "printf '%s\n' "
                + shlex.join([
                    f"Context: {context.name}",
                    f"Repo root: {context.repo_root}",
                    f"Configured Python: {context.configured_python or 'not set'}",
                    f"Effective Python: {context.python_executable}",
                    f"Runner user: {context.runner_user or 'current user'}",
                    f"Analysis DB: {context.db_path}",
                    f"LiteLLM log: {context.litellm_log}",
                    f"Deployment cwd: {context.deployment_cwd}",
                    f"Deployment script: {context.deployment_script}",
                    f"Warnings: {'; '.join(context.warnings) if context.warnings else 'none'}",
                ])
            ),
        ),
        ReviewAction(
            id="models-preview-all",
            section=SECTION_DRY_RUNS,
            title="Preview all LiteLLM models",
            description="List configured LiteLLM models without API calls; Gemini follows toggle.",
            command=smoke("--all-models", "--dry-run"),
        ),
        ReviewAction(
            id="memory-probe-preview",
            section=SECTION_DRY_RUNS,
            title="Preview curated model memory probe",
            description="Show selected models and the curated name/version incident-recognition cases without API calls.",
            command=memory_probe("--scope", "curated", "--profile", "budget", "--dry-run"),
        ),
        ReviewAction(
            id="memory-probe-production-preview",
            section=SECTION_DRY_RUNS,
            title="Preview production model memory probe",
            description="Show the full production package/version set and canonical non-agentic models without API calls.",
            command=memory_probe(
                "--scope",
                "production",
                "--profile",
                "all_models",
                "--resolver-profile",
                "all_models",
                "--max-tokens",
                "8192",
                "--timeout",
                "120",
                "--retries",
                "2",
                "--retry-delay",
                "20",
                "--dry-run",
            ),
        ),
        ReviewAction(
            id="models-smoke-all",
            section=SECTION_DEPLOYMENT,
            title="Smoke all LiteLLM models",
            description="Send the minimal OK request to every configured model; Gemini follows toggle.",
            command=smoke("--all-models", "--retries", "3", "--retry-delay", "20"),
            safety=SAFETY_API_COST,
            confirm=True,
        ),
        ReviewAction(
            id="deployment-setup",
            section=SECTION_DEPLOYMENT,
            title="Deploy / refresh VM environment",
            description="Run setup, service startup, model smoke, and all sample uploads; skip evaluation.",
            command=deploy("budget", phase="setup"),
            safety=SAFETY_DEPLOYMENT,
            confirm=True,
            double_confirm=True,
        ),
        ReviewAction(
            id="deployment-setup-no-upload",
            section=SECTION_DEPLOYMENT,
            title="Deploy / refresh VM without upload",
            description="Run setup, service startup, and model smoke; skip sample upload and evaluation.",
            command=deploy("budget", phase="setup", upload_categories="none"),
            safety=SAFETY_DEPLOYMENT,
            confirm=True,
            double_confirm=True,
        ),
        ReviewAction(
            id="deployment-smoke-test",
            section=SECTION_DEPLOYMENT,
            title="Deployment smoke run, four packages",
            description="Run setup, controls+malicious upload, and the test profile evaluation.",
            command=deploy("test", phase="smoke", upload_categories="controls malicious"),
            safety=SAFETY_DEPLOYMENT,
            confirm=True,
            double_confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="deployment-restart-services",
            section=SECTION_DEPLOYMENT,
            title="Restart LiteLLM and simulator",
            description="Restart the already-installed proxy and simulator services without repo setup.",
            command=_restart_services_command(context),
            safety=SAFETY_DEPLOYMENT,
            confirm=True,
            double_confirm=True,
        ),
    ]

    for profile, label in EXPERIMENT_PROFILES:
        slug = _profile_slug(profile)
        high_cost = profile in HIGH_COST_PROFILES
        smoke_args: list[str] = ["--profile", profile, "--retries", "3", "--retry-delay", "20"]
        if profile in {"frontier", "all_models"}:
            smoke_args.extend(["--max-tokens", "8192"])
        actions.append(ReviewAction(
            id=f"models-smoke-{slug}",
            section=SECTION_DEPLOYMENT,
            title=f"Smoke {label} profile",
            description=f"Check routing for the {profile} profile; Gemini follows toggle.",
            command=smoke(*smoke_args),
            safety=SAFETY_API_COST,
            confirm=True,
        ))
        if profile in {"budget", "frontier", "all_models"}:
            actions.append(ReviewAction(
                id=f"memory-probe-{slug}",
                section=SECTION_DEPLOYMENT,
                title=f"Run {label} curated model memory probe",
                description="Curated source-free name/version probe for public incident recognition; writes JSONL, not DB rows.",
                command=memory_probe("--scope", "curated", "--profile", profile),
                safety=SAFETY_API_COST,
                confirm=True,
                double_confirm=high_cost,
            ))
        actions.append(ReviewAction(
            id=f"experiment-dry-run-{slug}",
            section=SECTION_DRY_RUNS,
            title=f"Dry-run full {label} experiment",
            description="Resolve all selected latest package versions/artifacts without scanning.",
            command=evaluate(profile, "--dry-run-resolution", "--skip-validation"),
        ))
        actions.append(ReviewAction(
            id=f"experiment-full-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"Full {label} model run",
            description="Run hybrid, raw LLM, and agentic adapters only; static baseline is a separate action.",
            command=evaluate(
                profile,
                "--skip-static",
                "--run-id-prefix",
                "canonical-v2",
                "--progress",
                "always",
                sample_set_override=sample_set,
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=high_cost,
            requires_clean_db=True,
        ))
        actions.append(ReviewAction(
            id=f"experiment-non-agentic-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"{label} non-agentic LLM run",
            description="Run hybrid/raw LLM adapters only; assumes static baseline is already run once.",
            command=evaluate(
                profile,
                "--skip-static",
                "--skip-agentic",
                "--run-id-prefix",
                f"canonical-v2-{slug}",
                "--progress",
                "always",
                sample_set_override=sample_set,
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=high_cost,
            requires_clean_db=True,
        ))
        actions.append(ReviewAction(
            id=f"experiment-agentic-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"{label} agentic-only run",
            description="Run only the selected profile's agentic adapters; static and non-agentic LLMs are skipped.",
            command=evaluate(
                profile,
                "--only-agentic",
                "--run-id-prefix",
                f"canonical-v2-{slug}-agentic",
                "--progress",
                "always",
                sample_set_override=sample_set,
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=high_cost,
            requires_clean_db=True,
        ))

    actions.extend([
        ReviewAction(
            id="experiment-dry-run-gemini-only",
            section=SECTION_DRY_RUNS,
            title="Dry-run full Gemini-only experiment",
            description="Resolve the full canonical corpus for the dedicated Gemini-only non-agentic profile.",
            command=_context_script(
                context,
                "src/analyzer/evaluate.py",
                "--profile",
                "gemini_only",
                "--gemini",
                "on",
                "--dry-run-resolution",
                "--skip-validation",
            ),
        ),
        ReviewAction(
            id="experiment-dry-run-gemini-only-test",
            section=SECTION_DRY_RUNS,
            title="Dry-run tiny Gemini-only experiment",
            description="Resolve the four-package Gemini-only non-agentic test profile without scanning.",
            command=_context_script(
                context,
                "src/analyzer/evaluate.py",
                "--profile",
                "gemini_only_test",
                "--gemini",
                "on",
                "--dry-run-resolution",
                "--skip-validation",
            ),
        ),
        ReviewAction(
            id="experiment-dry-run-frontier-bakeoff",
            section=SECTION_DRY_RUNS,
            title="Dry-run frontier Together bake-off",
            description="Resolve the four-package Together frontier candidate benchmark profile without scanning.",
            command=_context_script(
                context,
                "src/analyzer/evaluate.py",
                "--profile",
                "frontier_together_bakeoff",
                "--gemini",
                "off",
                "--skip-static",
                "--skip-agentic",
                "--max-tokens",
                "8192",
                "--dry-run-resolution",
                "--skip-validation",
            ),
        ),
        ReviewAction(
            id="experiment-gemini-only-full",
            section=SECTION_EXPERIMENT,
            title="Gemini-only full run",
            description="Run the dedicated Gemini-only medium+frontier profile; no static and no agentic adapters.",
            command=_context_script(
                context,
                "src/analyzer/evaluate.py",
                "--profile",
                "gemini_only",
                "--gemini",
                "on",
                "--skip-static",
                "--skip-agentic",
                "--run-id-prefix",
                "canonical-v2-gemini-only",
                "--progress",
                "always",
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="experiment-gemini-only-test",
            section=SECTION_EXPERIMENT,
            title="Gemini-only tiny test",
            description="Run the four-package Gemini-only non-agentic test profile with long Google retry behavior.",
            command=_context_script(
                context,
                "src/analyzer/evaluate.py",
                "--profile",
                "gemini_only_test",
                "--gemini",
                "on",
                "--skip-static",
                "--skip-agentic",
                "--run-id-prefix",
                "debug-gemini-only",
                "--progress",
                "never",
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="experiment-frontier-bakeoff",
            section=SECTION_EXPERIMENT,
            title="Frontier Together candidate bake-off",
            description="Run the four-package Together frontier benchmark across Kimi, GLM, Qwen 397B, and MiniMax; no static and no agentic adapters.",
            command=_context_script(
                context,
                "src/analyzer/evaluate.py",
                "--profile",
                "frontier_together_bakeoff",
                "--gemini",
                "off",
                "--skip-static",
                "--skip-agentic",
                "--max-tokens",
                "8192",
                "--run-id-prefix",
                "frontier-bakeoff",
                "--progress",
                "always",
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="experiment-static-baseline",
            section=SECTION_EXPERIMENT,
            title="Static baseline once",
            description="Run Bandit, Semgrep, and GuardDog once over the selected sample set.",
            command=evaluate(
                "budget",
                "--sast-only",
                "--run-id-prefix",
                "canonical-v2-static",
                "--progress",
                "always",
                sample_set_override=sample_set,
            ),
            safety=SAFETY_LONG_RUNNING,
            confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="experiment-identity-alias-probe",
            section=SECTION_EXPERIMENT,
            title="Validity: identity alias probe, all models",
            description=(
                "Run one masked-identity hybrid zero-shot call per non-agentic "
                "model; no static, no raw, no agentic."
            ),
            command=evaluate(
                "all_models",
                "--identity-alias-probe",
                "--progress",
                "always",
                sample_set_override=sample_set,
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="experiment-production-memory-probe-all-models",
            section=SECTION_EXPERIMENT,
            title="Validity: production model memory probe, all models",
            description=(
                "Run the source-free name/version probe across the full resolved production "
                "package set for every canonical non-agentic model; no DB rows."
            ),
            command=memory_probe(
                "--scope",
                "production",
                "--profile",
                "all_models",
                "--resolver-profile",
                "all_models",
                "--max-tokens",
                "8192",
                "--timeout",
                "120",
                "--retries",
                "2",
                "--retry-delay",
                "20",
                "--progress",
                "always",
                sample_set_override=sample_set,
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=True,
        ),
        ReviewAction(
            id="analyzer-dry-run-test",
            section=SECTION_DRY_RUNS,
            title="Analyzer dry-run, tiny test profile",
            description="Resolve the four-package test profile without scanning; Gemini follows toggle.",
            command=evaluate("test", "--dry-run-resolution", "--skip-validation"),
        ),
        ReviewAction(
            id="analyzer-dry-run-test-no-gemini",
            section=SECTION_DRY_RUNS,
            title="Analyzer dry-run, tiny no-Gemini profile",
            description="Resolve the four-package no-Gemini test profile without scanning.",
            command=evaluate("test_no_gemini", "--dry-run-resolution", "--skip-validation"),
        ),
        ReviewAction(
            id="experiment-tiny-test",
            section=SECTION_EXPERIMENT,
            title="Tiny experiment, four packages",
            description="Run the test profile with debug run_id prefix; Gemini follows toggle.",
            command=evaluate("test", "--run-id-prefix", "debug", "--progress", "never"),
            safety=SAFETY_API_COST,
            confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="db-status",
            section=SECTION_DATABASE,
            title="DB status",
            description="Show DB path, counts, and latest run metadata.",
            command=_db_status_command(context),
        ),
        ReviewAction(
            id="db-production-repair-dry-run",
            section=SECTION_DATABASE,
            title="Preview DB error reruns",
            description="Preview all non-validation non-agentic error rows in the configured analysis DB by default, show compact preflight counts, and list append-only :repair runs when verbose preview is enabled.",
            command=(
                *_context_script(
                    context,
                    "scripts/error_correct_production_data.py",
                    "--db",
                    str(context.db_path),
                    "--dry-run",
                    "--include-agentic",
                    "off",
                ),
            ),
        ),
        ReviewAction(
            id="db-production-repair-apply",
            section=SECTION_DATABASE,
            title="Create DB error reruns",
            description="Rerun all non-validation non-agentic error rows in the configured analysis DB by default, use aggressive recovery settings, stream compact live progress, and write detailed engine logs to a separate repair log file.",
            command=(
                *_context_script(
                    context,
                    "scripts/error_correct_production_data.py",
                    "--db",
                    str(context.db_path),
                    "--apply",
                    "--include-agentic",
                    "off",
                    "--progress",
                    "always",
                ),
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=True,
        ),
        ReviewAction(
            id="db-production-repair-agentic-dry-run",
            section=SECTION_DATABASE,
            title="Preview legacy agentic DB reruns",
            description="Preview legacy agentic-only error reruns in the configured analysis DB. Use this only for historical frontier-agentic rows.",
            command=(
                *_context_script(
                    context,
                    "scripts/error_correct_production_data.py",
                    "--db",
                    str(context.db_path),
                    "--dry-run",
                    "--include-agentic",
                    "on",
                    "--intended-mode",
                    "agentic",
                ),
            ),
        ),
        ReviewAction(
            id="db-production-repair-agentic-apply",
            section=SECTION_DATABASE,
            title="Create legacy agentic DB reruns",
            description="Rerun only legacy agentic error rows in the configured analysis DB, use aggressive recovery settings, and keep the results in append-only :repair runs.",
            command=(
                *_context_script(
                    context,
                    "scripts/error_correct_production_data.py",
                    "--db",
                    str(context.db_path),
                    "--apply",
                    "--include-agentic",
                    "on",
                    "--intended-mode",
                    "agentic",
                    "--progress",
                    "always",
                ),
            ),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=True,
        ),
        ReviewAction(
            id="db-production-summary",
            section=SECTION_DATABASE,
            title="Summarize thesis DB raw + cleaned views",
            description="Generate canonical thesis-analysis artifacts from the configured analysis DB, including repair overlays when present for thesis-primary source runs.",
            command=(
                *_context_script(
                    context,
                    "scripts/summarize_thesis_eval_db.py",
                    "--db",
                    str(context.db_path),
                ),
            ),
        ),
        ReviewAction(
            id="archive-db-dry-run",
            section=SECTION_DATABASE,
            title="Preview DB archive",
            description="Show how eval_results.db would be archived without changing files.",
            command=(*_context_script(context, "scripts/archive_eval_db.py"), "--dry-run"),
        ),
        ReviewAction(
            id="archive-db",
            section=SECTION_DATABASE,
            title="Archive DB and create clean DB",
            description="Move eval_results.db plus sidecars into timestamped archive and initialize a fresh schema.",
            command=_context_script(context, "scripts/archive_eval_db.py"),
            safety=SAFETY_MUTATES_DB,
            confirm=True,
        ),
        ReviewAction(
            id="archive-db-no-init",
            section=SECTION_DATABASE,
            title="Archive DB only",
            description="Archive eval_results.db without creating a fresh replacement.",
            command=(*_context_script(context, "scripts/archive_eval_db.py"), "--no-init"),
            safety=SAFETY_MUTATES_DB,
            confirm=True,
        ),
        ReviewAction(
            id="db-runs",
            section=SECTION_DATABASE,
            title="List recent eval runs",
            description="Show latest eval_run rows.",
            command=_context_sqlite(context, _sqlite_runs_query()),
        ),
        ReviewAction(
            id="db-recent",
            section=SECTION_DATABASE,
            title="Show recent DB rows",
            description="Inspect latest eval_result rows using read-only immutable SQLite.",
            command=_context_sqlite(context, _sqlite_recent_query()),
        ),
        ReviewAction(
            id="db-errors",
            section=SECTION_DATABASE,
            title="Show DB error rows",
            description="Inspect eval_result rows where experiment_mode='error'.",
            command=_context_sqlite(context, _sqlite_error_query()),
        ),
        ReviewAction(
            id="db-normalize-protocol-dry-run",
            section=SECTION_DATABASE,
            title="Preview LLM protocol-error normalization",
            description="Show non-error LLM rows with raw malformed/empty outputs that would become error rows.",
            command=_context_script(context, "scripts/normalize_llm_protocol_failures.py"),
        ),
        ReviewAction(
            id="db-normalize-protocol",
            section=SECTION_DATABASE,
            title="Normalize LLM protocol errors",
            description="Back up eval_results.db, then convert malformed/empty raw LLM outputs to explicit error rows.",
            command=(*_context_script(context, "scripts/normalize_llm_protocol_failures.py"), "--apply"),
            safety=SAFETY_MUTATES_DB,
            confirm=True,
        ),
        ReviewAction(
            id="db-detector-summary",
            section=SECTION_DATABASE,
            title="Show detector summary",
            description="Group persisted rows by run, detector, mode, and strategy.",
            command=_context_sqlite(context, _sqlite_detector_summary_query()),
        ),
        ReviewAction(
            id="logs-list",
            section=SECTION_LOGS,
            title="List newest logs",
            description="List known log directories sorted by modification time.",
            command=_context_db_shell(context, "ls -lt logs src/injector/logs src/analyzer/logs src/simulator/logs 2>/dev/null || true"),
        ),
        ReviewAction(
            id="logs-tail-analyzer",
            section=SECTION_LOGS,
            title="Tail latest analyzer log",
            description="Show last 80 lines from newest analyzer log.",
            command=_context_db_shell(context, "f=$(ls -t src/analyzer/logs/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && tail -n 80 \"$f\" || echo 'No analyzer logs found'"),
        ),
        ReviewAction(
            id="logs-tail-injector",
            section=SECTION_LOGS,
            title="Tail latest injector log",
            description="Show last 80 lines from newest injector log.",
            command=_context_db_shell(context, "f=$(ls -t src/injector/logs/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && tail -n 80 \"$f\" || echo 'No injector logs found'"),
        ),
        ReviewAction(
            id="logs-tail-simulator",
            section=SECTION_LOGS,
            title="Tail simulator log",
            description="Show last 80 lines from simulator logs.",
            command=_context_db_shell(context, "f=$(ls -t src/simulator/logs/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && tail -n 80 \"$f\" || echo 'No simulator logs found'"),
        ),
        ReviewAction(
            id="logs-tail-litellm",
            section=SECTION_LOGS,
            title="Tail LiteLLM VM log",
            description="Show /home/proxy-runner/litellm.log if available.",
            command=_litellm_tail_command(context),
        ),
        ReviewAction(
            id="logs-search-errors",
            section=SECTION_LOGS,
            title="Search recent log errors",
            description="Search known logs for ERROR/HALT/Traceback/Exception/FAIL.",
            command=_context_db_shell(context, f"rg -n 'ERROR|HALT|Traceback|Exception|FAIL' logs src/*/logs {shlex.quote(str(context.litellm_log))} 2>/dev/null || true"),
        ),
        ReviewAction(
            id="tests-review",
            section=SECTION_TESTS,
            title="Run targeted review tests",
            description="Run resolver/profile/DB/static/model-smoke/TUI tests.",
            command=_context_python_module(
                context,
                "pytest",
                "tests/test_simulator_resolver.py",
                "tests/test_evaluation_profiles.py",
                "tests/test_eval_db_schema.py",
                "tests/test_guarddog_adapter.py",
                "tests/test_semgrep_rules.py",
                "tests/test_financial_validation.py",
                "tests/test_litellm_smoke.py",
                "tests/test_model_memory_probe.py",
                "tests/test_identity_alias_probe.py",
                "tests/test_adapters.py",
                "tests/test_normalize_llm_protocol_failures.py",
                "tests/test_review_tui.py",
                "-q",
            ),
            safety=SAFETY_LONG_RUNNING,
            confirm=True,
        ),
        ReviewAction(
            id="tests-static-detectors",
            section=SECTION_TESTS,
            title="Run static detector tests",
            description="Run GuardDog adapter and Semgrep rule tests.",
            command=_context_python_module(context, "pytest", "tests/test_guarddog_adapter.py", "tests/test_semgrep_rules.py", "-q"),
            safety=SAFETY_LONG_RUNNING,
            confirm=True,
        ),
        ReviewAction(
            id="tests-db-archive",
            section=SECTION_TESTS,
            title="Run DB/archive tests",
            description="Run DB schema, archive, and protocol-normalizer helper tests.",
            command=_context_python_module(
                context,
                "pytest",
                "tests/test_eval_db_schema.py",
                "tests/test_archive_eval_db.py",
                "tests/test_normalize_llm_protocol_failures.py",
                "-q",
            ),
        ),
        ReviewAction(
            id="tests-litellm-smoke",
            section=SECTION_TESTS,
            title="Run LiteLLM helper tests",
            description="Run unit tests for LiteLLM smoke and model-memory probe helpers.",
            command=_context_python_module(context, "pytest", "tests/test_litellm_smoke.py", "tests/test_model_memory_probe.py", "-q"),
        ),
        ReviewAction(
            id="tests-all",
            section=SECTION_TESTS,
            title="Run full test suite",
            description="Run all pytest tests.",
            command=_context_python_module(context, "pytest", "tests/", "-q"),
            safety=SAFETY_LONG_RUNNING,
            confirm=True,
        ),
        ReviewAction(
            id="syntax-checks",
            section=SECTION_TESTS,
            title="Run syntax checks",
            description="Check deployment shell syntax and compile helper scripts.",
            command=_context_db_shell(
                context,
                "bash -n deployment.sh && bash -n scripts/review_tui_telemetry.sh && "
                f"{shlex.quote(context.python_executable)} -m py_compile "
                "scripts/review_tui.py scripts/litellm_smoke.py scripts/model_memory_probe.py "
                "scripts/check_identity_alias_leaks.py scripts/archive_eval_db.py "
                "scripts/normalize_llm_protocol_failures.py "
                "src/analyzer/evaluate.py",
            ),
        ),
    ])
    return tuple(actions)
