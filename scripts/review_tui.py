#!/usr/bin/env python3
"""Interactive review runner for PyPI-LABS."""

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
SAMPLE_SET_SEQUENCE: tuple[str, ...] = ("dataset", "controls", "both")


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
    analysis_db_path: Path | None = None
    litellm_log: Path = Path("/home/proxy-runner/litellm.log")
    deployment_cwd: Path = _REPO_ROOT
    deployment_script: Path = _REPO_ROOT / "deployment.sh"
    warnings: tuple[str, ...] = ()

    @property
    def db_path(self) -> Path:
        if self.analysis_db_path is None:
            return (self.repo_root / "src" / "data" / "eval_results.db").resolve()
        path = Path(self.analysis_db_path)
        if not path.is_absolute():
            path = self.repo_root / path
        return path.resolve()

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
        analysis_db_path=repo_root / "src" / "data" / "eval_results.db",
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
    analysis_db_path = _resolve_path(
        raw.get("analysis_db_path"),
        base=base,
        default=repo_root / "src" / "data" / "eval_results.db",
    )
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
        analysis_db_path=analysis_db_path,
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
        effective_repo_root = Path(repo_root_override).resolve() if repo_root_override is not None else context.repo_root
        effective_analysis_db_path = context.db_path
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
        if repo_root_override is not None:
            default_db_path = (context.repo_root / "src" / "data" / "eval_results.db").resolve()
            if context.db_path == default_db_path:
                effective_analysis_db_path = effective_repo_root / "src" / "data" / "eval_results.db"
        context = ReviewContext(
            name=context.name,
            repo_root=effective_repo_root,
            python_executable=effective_python,
            configured_python=configured_python,
            runner_user=context.runner_user,
            analysis_db_path=effective_analysis_db_path,
            litellm_log=context.litellm_log,
            deployment_cwd=context.deployment_cwd,
            deployment_script=context.deployment_script,
            warnings=tuple(warnings),
        )
    return context


def context_summary(context: ReviewContext) -> str:
    return (
        f"context={context.name} repo={context.repo_root} "
        f"python={context.python_executable} analysis_db={context.db_path}"
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
            description="Archive, inspect, repair, and summarize the configured analysis DB.",
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
        f"echo 'Analysis DB path: {context.db_path}'; "
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


def _sample_set_label(sample_set: str) -> str:
    return sample_set.replace("_", " ").title()


def _section_has_sample_set_toggle(section_id: str) -> bool:
    return section_id == SECTION_EXPERIMENT


def _next_sample_set(sample_set: str) -> str:
    try:
        index = SAMPLE_SET_SEQUENCE.index(sample_set)
    except ValueError:
        return SAMPLE_SET_SEQUENCE[0]
    return SAMPLE_SET_SEQUENCE[(index + 1) % len(SAMPLE_SET_SEQUENCE)]


def build_actions(
    repo_root: Path = _REPO_ROOT,
    *,
    python_executable: str = sys.executable,
    gemini_enabled: bool = True,
    sample_set: str = "dataset",
    context: ReviewContext | None = None,
) -> tuple[ReviewAction, ...]:
    try:
        from scripts.review_actions import build_actions as _build_actions
    except ImportError:  # Running as ``python scripts/review_tui.py``.
        from review_actions import build_actions as _build_actions

    return _build_actions(
        sys.modules[__name__],
        repo_root,
        python_executable=python_executable,
        gemini_enabled=gemini_enabled,
        sample_set=sample_set,
        context=context,
    )

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
        print("\nPyPI-LABS Review Runner")
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
        sample_set: str | None = None,
        db_path: Path | None = None,
    ) -> str:
        print(f"\n{section.title}")
        if gemini_enabled is not None:
            print(f"Gemini: {_gemini_label(gemini_enabled)}")
        if sample_set is not None:
            print(f"Sample set: {_sample_set_label(sample_set)}")
        if db_path is not None:
            print(f"Analysis DB: {db_path}")
        for index, action in enumerate(actions, start=1):
            print(f"{index}. {action.title} [{action.safety}] - {action.description}")
        if gemini_enabled is not None:
            print("g. Toggle Gemini")
        if sample_set is not None:
            print("s. Toggle Sample Set")
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
        table = self.Table(title="PyPI-LABS Review Runner")
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
        sample_set: str | None = None,
        db_path: Path | None = None,
    ) -> str:
        title = f"[{section.style}]{section.title}[/{section.style}]"
        if gemini_enabled is not None:
            gemini_style = "green" if gemini_enabled else "yellow"
            title += f"  |  Gemini: [{gemini_style}]{_gemini_label(gemini_enabled)}[/{gemini_style}]"
        if sample_set is not None:
            title += f"  |  Sample Set: [cyan]{_sample_set_label(sample_set)}[/cyan]"
        if db_path is not None:
            title += f"  |  Analysis DB: [cyan]{db_path}[/cyan]"
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
        if sample_set is not None:
            table.add_row("s", "Toggle Sample Set", "", "Cycle experiment sample set: Dataset, Controls, Both")
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
    sample_set = "dataset"
    ui = _make_ui(no_rich)
    ui.print(f"[cyan]Active context:[/cyan] {context_summary(context)}")
    for warning in context_warnings(context):
        ui.print(f"[yellow]Context warning:[/yellow] {warning}")

    while True:
        actions = build_actions(context=context, gemini_enabled=gemini_enabled, sample_set=sample_set)
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
            actions = build_actions(context=context, gemini_enabled=gemini_enabled, sample_set=sample_set)
            section_actions = actions_for_section(section.id, actions)
            raw_choice = ui.choose_action(
                section,
                section_actions,
                gemini_enabled=gemini_enabled if _section_has_gemini_toggle(section.id) else None,
                sample_set=sample_set if _section_has_sample_set_toggle(section.id) else None,
                db_path=context.db_path if section.id == SECTION_DATABASE else None,
            )
            if _section_has_gemini_toggle(section.id) and raw_choice in {"g", "gemini", "toggle"}:
                gemini_enabled = not gemini_enabled
                ui.print(f"Gemini is now {_gemini_label(gemini_enabled)}.")
                continue
            if _section_has_sample_set_toggle(section.id) and raw_choice in {"s", "sample", "sample-set"}:
                sample_set = _next_sample_set(sample_set)
                ui.print(f"Sample set is now {_sample_set_label(sample_set)}.")
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
            if _section_has_sample_set_toggle(section.id):
                ui.print(f"Sample set: {_sample_set_label(sample_set)}")
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
