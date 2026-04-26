#!/usr/bin/env python3
"""Interactive review runner for PyPI-SCADA."""

from __future__ import annotations

import argparse
import shlex
import sqlite3
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_CONFIG = _REPO_ROOT / "configs" / "review_tui.yaml"

SECTION_DEPLOYMENT = "deployment"
SECTION_DRY_RUNS = "dry_runs"
SECTION_EXPERIMENT = "experiment"
SECTION_DATABASE = "database"
SECTION_LOGS = "logs"
SECTION_TESTS = "tests"

SAFETY_SAFE = "safe"
SAFETY_MUTATES_DB = "mutates DB"
SAFETY_API_COST = "may spend API money"
SAFETY_DEPLOYMENT = "deployment / sudo / VM state"
SAFETY_LONG_RUNNING = "long running"

SAFETY_STYLES = {
    SAFETY_SAFE: "green",
    SAFETY_MUTATES_DB: "yellow",
    SAFETY_API_COST: "magenta",
    SAFETY_DEPLOYMENT: "red",
    SAFETY_LONG_RUNNING: "cyan",
}

EXPERIMENT_PROFILES: tuple[tuple[str, str], ...] = (
    ("budget", "Budget"),
    ("medium", "Medium"),
    ("frontier", "Frontier"),
    ("all_models", "All models"),
)
HIGH_COST_PROFILES = {"frontier", "all_models"}


@dataclass(frozen=True)
class Section:
    id: str
    title: str
    description: str
    style: str = "cyan"
    preflight: str | None = None


@dataclass(frozen=True)
class ReviewAction:
    id: str
    section: str
    title: str
    description: str
    command: tuple[str, ...]
    safety: str = SAFETY_SAFE
    confirm: bool = False
    double_confirm: bool = False
    requires_clean_db: bool = False


@dataclass(frozen=True)
class ReviewContext:
    name: str
    repo_root: Path
    python_executable: str
    configured_python: str | None = None
    runner_user: str | None = None
    litellm_log: Path = Path("/home/proxy-runner/litellm.log")
    deployment_cwd: Path = _REPO_ROOT
    deployment_script: Path = _REPO_ROOT / "deployment.sh"
    warnings: tuple[str, ...] = ()

    @property
    def db_path(self) -> Path:
        return self.repo_root / "src" / "data" / "eval_results.db"

    @property
    def deployed(self) -> bool:
        return self.runner_user is not None


def _default_local_context(repo_root: Path = _REPO_ROOT, python_executable: str = sys.executable) -> ReviewContext:
    repo_root = Path(repo_root).resolve()
    return ReviewContext(
        name="local",
        repo_root=repo_root,
        python_executable=str(python_executable),
        configured_python=str(python_executable),
        runner_user=None,
        litellm_log=Path("/home/proxy-runner/litellm.log"),
        deployment_cwd=repo_root,
        deployment_script=repo_root / "deployment.sh",
    )


def _clean_config_value(value: str) -> str | None:
    value = value.strip().strip('"\'')
    if value in {"", "null", "None", "~"}:
        return None
    return value


def _parse_review_tui_config(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        import yaml  # type: ignore

        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(loaded, dict):
            contexts = loaded.get("contexts")
            if contexts is None or isinstance(contexts, dict):
                loaded.setdefault("contexts", {})
                return loaded
    except Exception:
        # Keep the tiny fallback parser so the TUI can run in minimal Python
        # environments where PyYAML is not installed.
        pass

    data: dict = {"contexts": {}}
    current_context: str | None = None
    in_contexts = False
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line == "contexts:":
            in_contexts = True
            current_context = None
            continue
        if not raw_line.startswith(" ") and ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = _clean_config_value(value)
            in_contexts = False
            current_context = None
            continue
        if in_contexts and raw_line.startswith("  ") and not raw_line.startswith("    ") and line.endswith(":"):
            current_context = line.strip()[:-1]
            data["contexts"][current_context] = {}
            continue
        if in_contexts and current_context and raw_line.startswith("    ") and ":" in line:
            key, value = line.strip().split(":", 1)
            data["contexts"][current_context][key.strip()] = _clean_config_value(value)
    return data


def _resolve_path(value: str | None, *, base: Path, default: Path | None = None) -> Path:
    if value is None:
        if default is None:
            raise ValueError("missing required path value")
        return default.resolve()
    path = Path(value)
    if not path.is_absolute():
        path = base / path
    return path.resolve()


def _context_from_config(name: str, config: dict, *, base: Path, python_fallback: str) -> ReviewContext:
    contexts = config.get("contexts", {})
    raw = contexts.get(name)
    if raw is None:
        if name == "local":
            return _default_local_context(_REPO_ROOT, python_fallback)
        raise SystemExit(f"HALT: unknown review TUI context '{name}'")
    repo_root = _resolve_path(raw.get("repo_root"), base=base, default=_REPO_ROOT)
    runner_user = raw.get("runner_user")
    configured_python = raw.get("python")
    warnings: list[str] = []

    if configured_python is None and runner_user:
        venv_python = repo_root / "venv" / "bin" / "python"
        python_path = str(venv_python)
        warnings.append(f"No Python configured for runner context; using repo venv: {venv_python}")
    elif configured_python is None:
        python_path = python_fallback
    else:
        candidate = _resolve_path(configured_python, base=base)
        python_path = str(candidate)
        if runner_user:
            try:
                candidate.resolve().relative_to(repo_root.resolve())
            except ValueError:
                venv_python = repo_root / "venv" / "bin" / "python"
                if venv_python.exists():
                    python_path = str(venv_python)
                    warnings.append(
                        f"Configured Python {candidate} is outside {repo_root}; using repo venv: {venv_python}"
                    )
                else:
                    warnings.append(
                        f"Configured Python {candidate} is outside {repo_root}; expected repo venv is missing: {venv_python}"
                    )

    python_candidate = Path(python_path)
    if runner_user and not python_candidate.exists():
        warnings.append(
            f"Runner Python does not exist yet: {python_candidate}. Deployment setup can recreate the venv."
        )
    return ReviewContext(
        name=name,
        repo_root=repo_root,
        python_executable=python_path,
        configured_python=configured_python,
        runner_user=runner_user,
        litellm_log=_resolve_path(raw.get("litellm_log"), base=base, default=Path("/home/proxy-runner/litellm.log")),
        deployment_cwd=_resolve_path(raw.get("deployment_cwd"), base=base, default=_REPO_ROOT),
        deployment_script=_resolve_path(raw.get("deployment_script"), base=base, default=_REPO_ROOT / "deployment.sh"),
        warnings=tuple(warnings),
    )


def _context_ready(context: ReviewContext) -> bool:
    if context.runner_user:
        return context.repo_root.exists()
    return context.repo_root.exists() and Path(context.python_executable).exists()


def resolve_review_context(
    requested: str = "auto",
    *,
    config_path: Path = _DEFAULT_CONFIG,
    repo_root_override: Path | None = None,
    python_override: str | None = None,
) -> ReviewContext:
    config_path = Path(config_path)
    config = _parse_review_tui_config(config_path)
    base = _REPO_ROOT
    fallback_python = python_override or sys.executable
    if requested == "auto":
        requested = str(config.get("default_context") or "auto")
    if requested == "auto":
        deployed = _context_from_config("deployed", config, base=base, python_fallback=fallback_python)
        requested = "deployed" if _context_ready(deployed) else "local"
        context = deployed if requested == "deployed" else _context_from_config("local", config, base=base, python_fallback=fallback_python)
    else:
        context = _context_from_config(requested, config, base=base, python_fallback=fallback_python)
        if requested == "deployed" and not _context_ready(context):
            raise SystemExit(
                "HALT: deployed context selected but repo root or Python is missing: "
                f"{context.repo_root} / {context.python_executable}"
            )
    if repo_root_override is not None or python_override is not None:
        warnings = list(context.warnings)
        effective_python = context.python_executable
        configured_python = context.configured_python
        if python_override is not None:
            configured_python = str(python_override)
            override_path = Path(python_override)
            effective_python = str(override_path)
            if context.runner_user:
                try:
                    override_path.resolve().relative_to(context.repo_root.resolve())
                except ValueError:
                    venv_python = context.repo_root / "venv" / "bin" / "python"
                    if venv_python.exists():
                        effective_python = str(venv_python)
                        warnings.append(
                            f"Python override {override_path} is outside {context.repo_root}; using repo venv: {venv_python}"
                        )
                    else:
                        warnings.append(
                            f"Python override {override_path} is outside {context.repo_root}; expected repo venv is missing: {venv_python}"
                        )
        context = ReviewContext(
            name=context.name,
            repo_root=Path(repo_root_override).resolve() if repo_root_override is not None else context.repo_root,
            python_executable=effective_python,
            configured_python=configured_python,
            runner_user=context.runner_user,
            litellm_log=context.litellm_log,
            deployment_cwd=context.deployment_cwd,
            deployment_script=context.deployment_script,
            warnings=tuple(warnings),
        )
    return context


def context_summary(context: ReviewContext) -> str:
    return (
        f"context={context.name} repo={context.repo_root} "
        f"python={context.python_executable} db={context.db_path}"
    )


def context_warnings(context: ReviewContext) -> list[str]:
    warnings: list[str] = list(context.warnings)
    python_path = Path(context.python_executable)
    try:
        python_path.relative_to(context.repo_root)
    except ValueError:
        warnings.append(
            "Python executable is outside the selected repo root; verify this is intentional: "
            f"{python_path}"
        )
    if context.name == "deployed" and not context.deployed:
        warnings.append("Deployed context has no runner_user configured.")
    return warnings


def build_sections() -> tuple[Section, ...]:
    return (
        Section(
            id=SECTION_DEPLOYMENT,
            title="Deployment",
            description="Prepare or refresh the VM environment, services, uploads, and model routing.",
            style="red",
        ),
        Section(
            id=SECTION_DRY_RUNS,
            title="Dry Runs",
            description="Resolve sample plans and preview model config without writing experiment rows.",
            style="cyan",
        ),
        Section(
            id=SECTION_EXPERIMENT,
            title="Run Experiment Suite",
            description="Actual analyzer runs that write eval_results rows and may spend API money.",
            style="magenta",
        ),
        Section(
            id=SECTION_DATABASE,
            title="Database",
            description="Archive, inspect, and summarize eval_results.db.",
            style="yellow",
        ),
        Section(
            id=SECTION_LOGS,
            title="Logs",
            description="Tail and search known runtime logs.",
            style="blue",
        ),
        Section(
            id=SECTION_TESTS,
            title="Tests",
            description="Targeted and full validation commands.",
            style="green",
        ),
    )


def _eval_db_path(repo_root: Path) -> Path:
    return repo_root / "src" / "data" / "eval_results.db"


def _sqlite_recent_query() -> str:
    return """
select
  run_id,
  package_name,
  version,
  artifact_filename,
  detector,
  experiment_mode,
  prompt_strategy,
  verdict,
  ground_truth,
  substr(details, 1, 300) as details
from eval_result
order by id desc
limit 30;
""".strip()


def _sqlite_error_query() -> str:
    return """
select
  package_name,
  version,
  artifact_filename,
  detector,
  prompt_strategy,
  substr(details, 1, 500) as details
from eval_result
where experiment_mode = 'error'
order by id desc;
""".strip()


def _sqlite_runs_query() -> str:
    return """
select run_id, tier, created_at
from eval_run
order by id desc
limit 20;
""".strip()


def _sqlite_detector_summary_query() -> str:
    return """
select
  run_id,
  detector,
  experiment_mode,
  prompt_strategy,
  count(*) as rows,
  sum(case when verdict = 1 then 1 else 0 end) as flagged,
  sum(case when experiment_mode = 'error' then 1 else 0 end) as errors,
  round(sum(api_cost_usd), 6) as cost_usd
from eval_result
group by run_id, detector, experiment_mode, prompt_strategy
order by run_id desc, detector, experiment_mode, prompt_strategy;
""".strip()


def _shell(command: str) -> tuple[str, ...]:
    return ("bash", "-lc", command)


def _context_path_prefix(context: ReviewContext) -> str:
    python_dir = Path(context.python_executable).parent
    return f"export PATH={shlex.quote(str(python_dir))}:$PATH"


def _shell_in_context(context: ReviewContext, command: str, *, user: str | None = None, cwd: Path | None = None) -> tuple[str, ...]:
    cwd = cwd or context.repo_root
    wrapped = f"cd {shlex.quote(str(cwd))} && {_context_path_prefix(context)} && {command}"
    if user:
        return ("sudo", "-u", user, "bash", "-lc", wrapped)
    return ("bash", "-lc", wrapped)


def _context_script(context: ReviewContext, *parts_and_args: str) -> tuple[str, ...]:
    if not parts_and_args:
        raise ValueError("missing script path")
    script = context.repo_root.joinpath(parts_and_args[0])
    args = parts_and_args[1:]
    if context.runner_user:
        return _shell_in_context(
            context,
            shlex.join([context.python_executable, str(script), *args]),
            user=context.runner_user,
        )
    return (context.python_executable, str(script), *args)


def _context_python_module(context: ReviewContext, *args: str) -> tuple[str, ...]:
    if context.runner_user:
        return _shell_in_context(
            context,
            shlex.join([context.python_executable, "-m", *args]),
            user=context.runner_user,
        )
    return (context.python_executable, "-m", *args)


def _context_sqlite(context: ReviewContext, query: str) -> tuple[str, ...]:
    uri = f"file:{context.db_path}?mode=ro&immutable=1"
    cmd = ("sqlite3", "-header", "-column", uri, query)
    if context.runner_user:
        return ("sudo", "-u", context.runner_user, *cmd)
    return cmd


def _context_db_shell(context: ReviewContext, command: str) -> tuple[str, ...]:
    if context.runner_user:
        return _shell_in_context(context, command, user=context.runner_user)
    return _shell_in_context(context, command)


def _db_status_command(context: ReviewContext) -> tuple[str, ...]:
    query = (
        "select "
        "(select count(*) from eval_run) as eval_runs, "
        "(select count(*) from eval_result) as eval_results, "
        "(select run_id from eval_run order by id desc limit 1) as latest_run_id, "
        "(select created_at from eval_run order by id desc limit 1) as latest_created_at;"
    )
    db = shlex.quote(str(context.db_path))
    sqlite = shlex.join(["sqlite3", "-header", "-column", f"file:{context.db_path}?mode=ro&immutable=1", query])
    return _context_db_shell(
        context,
        f"echo 'DB path: {context.db_path}'; "
        f"if [ ! -f {db} ]; then echo 'DB missing'; exit 0; fi; "
        f"{sqlite}",
    )


def _litellm_tail_command(context: ReviewContext) -> tuple[str, ...]:
    path = str(context.litellm_log)
    if context.name == "deployed":
        return ("sudo", "-u", "proxy-runner", "tail", "-n", "80", path)
    return _shell(f"tail -n 80 {shlex.quote(path)} 2>/dev/null || echo 'LiteLLM VM log unavailable'")


def _deployment_command(
    context: ReviewContext,
    profile: str,
    gemini: str,
    *,
    phase: str = "full",
    upload_categories: str | None = None,
) -> tuple[str, ...]:
    env_parts = [
        f"DEPLOY_PHASE={phase}",
        f"MODEL_PROFILE={profile}",
        f"GEMINI={gemini}",
        "EVAL_PROGRESS=always",
    ]
    if upload_categories:
        env_parts.append(f"UPLOAD_CATEGORIES={shlex.quote(upload_categories)}")
    command = " ".join(env_parts + ["bash", shlex.quote(str(context.deployment_script))])
    return _shell_in_context(context, command, cwd=context.deployment_cwd)


def _restart_services_command(context: ReviewContext) -> tuple[str, ...]:
    command = """
set -euo pipefail
sudo -u proxy-runner bash -lc '
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  existing_litellm_pids=$(pgrep -x litellm || true)
  if [ -n "$existing_litellm_pids" ]; then
    echo "Stopping existing LiteLLM PIDs: $existing_litellm_pids"
    kill $existing_litellm_pids 2>/dev/null || true
    sleep 1
  fi
  nohup litellm --config /home/proxy-runner/litellm_config.yaml --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
'
sudo -u pypi-runner bash -lc '
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo/src/simulator
  existing_sim_pids=$(pgrep -u pypi-runner -f "python main.py" | grep -vw "$$" || true)
  if [ -n "$existing_sim_pids" ]; then
    echo "Stopping existing simulator PIDs: $existing_sim_pids"
    kill $existing_sim_pids 2>/dev/null || true
    sleep 1
  fi
  nohup python main.py > /home/pypi-runner/simulator.log 2>&1 &
'
echo "Services restarted."
""".strip()
    return _shell(command)


def _command_mentions_mixed_roots(command: Sequence[str], context: ReviewContext) -> bool:
    preview = command_preview(command)
    active_root = str(context.repo_root)
    launch_root = str(_REPO_ROOT)
    return active_root in preview and launch_root in preview and active_root != launch_root


def _profile_slug(profile: str) -> str:
    return profile.replace("_", "-")


def _gemini_value(gemini_enabled: bool) -> str:
    return "on" if gemini_enabled else "off"


def _gemini_label(gemini_enabled: bool) -> str:
    return "ON" if gemini_enabled else "OFF"


def _section_has_gemini_toggle(section_id: str) -> bool:
    return section_id in {SECTION_DEPLOYMENT, SECTION_DRY_RUNS, SECTION_EXPERIMENT}


def build_actions(
    repo_root: Path = _REPO_ROOT,
    *,
    python_executable: str = sys.executable,
    gemini_enabled: bool = True,
    context: ReviewContext | None = None,
) -> tuple[ReviewAction, ...]:
    context = context or _default_local_context(repo_root, python_executable)
    gemini = _gemini_value(gemini_enabled)

    def evaluate(profile: str, *args: str) -> tuple[str, ...]:
        return _context_script(
            context,
            "src/analyzer/evaluate.py",
            "--profile",
            profile,
            "--gemini",
            gemini,
            *args,
        )

    def smoke(*args: str) -> tuple[str, ...]:
        return _context_script(context, "scripts/litellm_smoke.py", *args, "--gemini", gemini)

    def memory_probe(*args: str) -> tuple[str, ...]:
        return _context_script(context, "scripts/model_memory_probe.py", *args, "--gemini", gemini)

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
            description="Show target repo, Python, DB, runner user, and LiteLLM log paths.",
            command=_shell(
                "printf '%s\n' "
                + shlex.join([
                    f"Context: {context.name}",
                    f"Repo root: {context.repo_root}",
                    f"Configured Python: {context.configured_python or 'not set'}",
                    f"Effective Python: {context.python_executable}",
                    f"Runner user: {context.runner_user or 'current user'}",
                    f"DB: {context.db_path}",
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
                "4096",
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
            command=evaluate(profile, "--skip-static", "--run-id-prefix", "canonical-v2", "--progress", "always"),
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
            description="Run Bandit, Semgrep, and GuardDog once over the canonical artifact set.",
            command=evaluate("budget", "--sast-only", "--run-id-prefix", "canonical-v2-static", "--progress", "always"),
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
            command=evaluate("all_models", "--identity-alias-probe", "--progress", "always"),
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
                "4096",
                "--progress",
                "always",
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


def actions_for_section(section_id: str, actions: Sequence[ReviewAction]) -> tuple[ReviewAction, ...]:
    return tuple(action for action in actions if action.section == section_id)


def action_by_id(action_id: str, actions: Sequence[ReviewAction]) -> ReviewAction:
    for action in actions:
        if action.id == action_id:
            return action
    known = ", ".join(action.id for action in actions)
    raise KeyError(f"unknown action {action_id!r}; known: {known}")


def section_by_id(section_id: str, sections: Sequence[Section]) -> Section:
    for section in sections:
        if section.id == section_id:
            return section
    known = ", ".join(section.id for section in sections)
    raise KeyError(f"unknown section {section_id!r}; known: {known}")


def command_preview(command: Sequence[str]) -> str:
    return shlex.join(command)


def _db_result_count_path(db_path: Path) -> int:
    if not db_path.exists():
        return 0
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True) as conn:
            row = conn.execute("select count(*) from eval_result").fetchone()
            return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0


def db_result_count(repo_root: Path = _REPO_ROOT) -> int:
    return _db_result_count_path(_eval_db_path(repo_root))


def db_result_count_for_context(context: ReviewContext) -> int:
    if not context.runner_user:
        return _db_result_count_path(context.db_path)
    if not context.db_path.exists():
        return 0
    query = "select count(*) from eval_result"
    uri = f"file:{context.db_path}?mode=ro&immutable=1"
    try:
        result = subprocess.run(
            ("sudo", "-n", "-u", context.runner_user, "sqlite3", uri, query),
            cwd=context.repo_root,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return 0
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        return 0


def db_needs_archive_warning(repo_root: Path = _REPO_ROOT, *, context: ReviewContext | None = None) -> bool:
    if context is not None:
        return db_result_count_for_context(context) > 0
    return db_result_count(repo_root) > 0


def execute_action(
    action: ReviewAction,
    *,
    repo_root: Path = _REPO_ROOT,
    context: ReviewContext | None = None,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> int:
    cwd = context.repo_root if context is not None else repo_root
    result = runner(action.command, cwd=cwd)
    return int(result.returncode)


class _PlainUI:
    rich = False

    def print(self, message: str = "") -> None:
        print(_strip_markup(message))

    def confirm(self, message: str, *, default: bool = False) -> bool:
        suffix = "Y/n" if default else "y/N"
        answer = input(f"{_strip_markup(message)} [{suffix}] ").strip().lower()
        if not answer:
            return default
        return answer in {"y", "yes"}

    def choose_section(self, sections: Sequence[Section]) -> str:
        print("\nPyPI-SCADA Review Runner")
        for index, section in enumerate(sections, start=1):
            print(f"{index}. {section.title} - {section.description}")
        print("q. Quit")
        return input("Select section: ").strip().lower()

    def choose_action(
        self,
        section: Section,
        actions: Sequence[ReviewAction],
        *,
        gemini_enabled: bool | None = None,
    ) -> str:
        print(f"\n{section.title}")
        if gemini_enabled is not None:
            print(f"Gemini: {_gemini_label(gemini_enabled)}")
        for index, action in enumerate(actions, start=1):
            print(f"{index}. {action.title} [{action.safety}] - {action.description}")
        if gemini_enabled is not None:
            print("g. Toggle Gemini")
        print("b. Back")
        print("q. Quit")
        return input("Select action: ").strip().lower()


class _RichUI:
    rich = True

    def __init__(self):
        from rich.console import Console
        from rich.prompt import Confirm, Prompt
        from rich.table import Table

        self.console = Console()
        self.Prompt = Prompt
        self.Confirm = Confirm
        self.Table = Table

    def print(self, message: str = "") -> None:
        self.console.print(message)

    def confirm(self, message: str, *, default: bool = False) -> bool:
        return bool(self.Confirm.ask(message, default=default))

    def choose_section(self, sections: Sequence[Section]) -> str:
        table = self.Table(title="PyPI-SCADA Review Runner")
        table.add_column("#", justify="right")
        table.add_column("Section")
        table.add_column("Description")
        for index, section in enumerate(sections, start=1):
            table.add_row(str(index), f"[{section.style}]{section.title}[/{section.style}]", section.description)
        table.add_row("q", "Quit", "")
        self.console.print(table)
        return str(self.Prompt.ask("Select section")).strip().lower()

    def choose_action(
        self,
        section: Section,
        actions: Sequence[ReviewAction],
        *,
        gemini_enabled: bool | None = None,
    ) -> str:
        title = f"[{section.style}]{section.title}[/{section.style}]"
        if gemini_enabled is not None:
            gemini_style = "green" if gemini_enabled else "yellow"
            title += f"  |  Gemini: [{gemini_style}]{_gemini_label(gemini_enabled)}[/{gemini_style}]"
        table = self.Table(title=title)
        table.add_column("#", justify="right")
        table.add_column("Action")
        table.add_column("Safety")
        table.add_column("Description")
        for index, action in enumerate(actions, start=1):
            style = SAFETY_STYLES.get(action.safety, "white")
            table.add_row(str(index), action.title, f"[{style}]{action.safety}[/{style}]", action.description)
        if gemini_enabled is not None:
            table.add_row("g", "Toggle Gemini", "", "Switch Gemini/Google models on or off for experiment actions")
        table.add_row("b", "Back", "", "")
        table.add_row("q", "Quit", "", "")
        self.console.print(table)
        return str(self.Prompt.ask("Select action")).strip().lower()


def _strip_markup(message: str) -> str:
    for token in (
        "[red]", "[/red]", "[yellow]", "[/yellow]", "[bold]", "[/bold]",
        "[green]", "[/green]", "[magenta]", "[/magenta]", "[cyan]", "[/cyan]",
    ):
        message = message.replace(token, "")
    return message


def _make_ui(no_rich: bool):
    if no_rich:
        return _PlainUI()
    try:
        return _RichUI()
    except Exception:
        return _PlainUI()


def _resolve_choice(choice: str, items: Sequence[Section] | Sequence[ReviewAction]):
    if choice in {"q", "quit", "exit"}:
        return None
    if choice in {"b", "back"}:
        return "back"
    if choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(items):
            return items[index]
        raise ValueError(f"choice out of range: {choice}")
    for item in items:
        if item.id == choice:
            return item
    known = ", ".join(item.id for item in items)
    raise KeyError(f"unknown choice {choice!r}; known: {known}")


def _experiment_preflight(ui, context: ReviewContext, actions: Sequence[ReviewAction]) -> bool:
    if not db_needs_archive_warning(context=context):
        return True

    ui.print("[yellow]Active eval DB contains previous rows.[/yellow]")
    ui.print("Archive it before canonical/debug runs unless you intentionally want mixed runs.")
    archive = action_by_id("archive-db", actions)
    preview = action_by_id("archive-db-dry-run", actions)

    while True:
        choice = input("Choose: [a]rchive now, [p]review archive, [c]ontinue anyway, [b]ack: ").strip().lower()
        if choice in {"a", "archive"}:
            ui.print(command_preview(archive.command))
            if ui.confirm("Archive DB now?", default=False):
                return execute_action(archive, context=context) == 0
        elif choice in {"p", "preview"}:
            ui.print(command_preview(preview.command))
            execute_action(preview, context=context)
        elif choice in {"c", "continue"}:
            return True
        elif choice in {"b", "back"}:
            return False
        else:
            ui.print("Invalid choice.")


def _confirm_action(ui, action: ReviewAction) -> bool:
    if action.confirm and not ui.confirm("Run this action?", default=False):
        return False
    if action.double_confirm and not ui.confirm(
        "This changes VM/deployment state or may spend substantial API money. Confirm again?",
        default=False,
    ):
        return False
    return True


def run_menu(
    *,
    no_rich: bool = False,
    repo_root: Path = _REPO_ROOT,
    context: ReviewContext | None = None,
) -> int:
    context = context or _default_local_context(repo_root, sys.executable)
    sections = build_sections()
    gemini_enabled = True
    ui = _make_ui(no_rich)
    ui.print(f"[cyan]Active context:[/cyan] {context_summary(context)}")
    for warning in context_warnings(context):
        ui.print(f"[yellow]Context warning:[/yellow] {warning}")

    while True:
        actions = build_actions(context=context, gemini_enabled=gemini_enabled)
        ui.print()
        try:
            section = _resolve_choice(ui.choose_section(sections), sections)
        except (KeyError, ValueError) as exc:
            ui.print(f"[red]Invalid selection:[/red] {exc}")
            continue
        if section is None:
            return 0
        if section == "back":
            continue

        if section.preflight == "clean-db" and not _experiment_preflight(ui, context, actions):
            continue

        while True:
            actions = build_actions(context=context, gemini_enabled=gemini_enabled)
            section_actions = actions_for_section(section.id, actions)
            raw_choice = ui.choose_action(
                section,
                section_actions,
                gemini_enabled=gemini_enabled if _section_has_gemini_toggle(section.id) else None,
            )
            if _section_has_gemini_toggle(section.id) and raw_choice in {"g", "gemini", "toggle"}:
                gemini_enabled = not gemini_enabled
                ui.print(f"Gemini is now {_gemini_label(gemini_enabled)}.")
                continue
            try:
                action = _resolve_choice(raw_choice, section_actions)
            except (KeyError, ValueError) as exc:
                ui.print(f"[red]Invalid selection:[/red] {exc}")
                continue
            if action is None:
                return 0
            if action == "back":
                break

            ui.print(f"\nAction: {action.title}")
            ui.print(f"Safety: {action.safety}")
            if _section_has_gemini_toggle(section.id):
                ui.print(f"Gemini: {_gemini_label(gemini_enabled)}")
            if action.requires_clean_db and db_needs_archive_warning(context=context):
                ui.print("[yellow]Warning: active DB contains previous result rows.[/yellow]")
            ui.print("Command:")
            ui.print(command_preview(action.command))
            if action.id != "context-status" and _command_mentions_mixed_roots(action.command, context):
                ui.print("[yellow]Warning: command mentions both local and active repo roots; inspect before running.[/yellow]")
            if not _confirm_action(ui, action):
                ui.print("Skipped.")
                continue

            rc = execute_action(action, context=context)
            ui.print(f"Exit code: {rc}")
            if not ui.confirm("Return to this section?", default=True):
                return rc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-rich", action="store_true", help="Use plain prompts instead of Rich UI")
    parser.add_argument(
        "--context",
        choices=("auto", "deployed", "local"),
        default="auto",
        help="Target context. auto prefers the deployed VM checkout when available.",
    )
    parser.add_argument("--config", type=Path, default=_DEFAULT_CONFIG, help="Review TUI context config path")
    parser.add_argument("--repo-root", type=Path, help="Override selected context repo root")
    parser.add_argument("--python", dest="python_executable", help="Override selected context Python executable")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    context = resolve_review_context(
        args.context,
        config_path=args.config,
        repo_root_override=args.repo_root,
        python_override=args.python_executable,
    )
    return run_menu(no_rich=args.no_rich, context=context)


if __name__ == "__main__":
    raise SystemExit(main())
