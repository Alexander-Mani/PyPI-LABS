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


def build_sections() -> tuple[Section, ...]:
    return (
        Section(
            id=SECTION_EXPERIMENT,
            title="Run Experiment Suite",
            description="Model checks, analyzer dry-runs, tiny experiments, and deployment smoke/full runs.",
            style="magenta",
            preflight="clean-db",
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


def _sqlite_uri(repo_root: Path) -> str:
    return f"file:{_eval_db_path(repo_root)}?mode=ro&immutable=1"


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


def _py(py: str, repo_root: Path, *parts: str) -> tuple[str, ...]:
    return (py, str(repo_root.joinpath(*parts)))


def _profile_slug(profile: str) -> str:
    return profile.replace("_", "-")


def _gemini_value(gemini_enabled: bool) -> str:
    return "on" if gemini_enabled else "off"


def _gemini_label(gemini_enabled: bool) -> str:
    return "ON" if gemini_enabled else "OFF"


def build_actions(
    repo_root: Path = _REPO_ROOT,
    *,
    python_executable: str = sys.executable,
    gemini_enabled: bool = True,
) -> tuple[ReviewAction, ...]:
    py = python_executable
    repo_root = repo_root.resolve()
    sqlite_uri = _sqlite_uri(repo_root)
    gemini = _gemini_value(gemini_enabled)

    def evaluate(profile: str, *args: str) -> tuple[str, ...]:
        return (
            py,
            str(repo_root / "src" / "analyzer" / "evaluate.py"),
            "--profile",
            profile,
            "--gemini",
            gemini,
            *args,
        )

    def smoke(*args: str) -> tuple[str, ...]:
        return (*_py(py, repo_root, "scripts", "litellm_smoke.py"), *args, "--gemini", gemini)

    def deploy(profile: str, *, upload_categories: str | None = None) -> tuple[str, ...]:
        env_parts = [f"MODEL_PROFILE={profile}", f"GEMINI={gemini}", "EVAL_PROGRESS=always"]
        if upload_categories:
            env_parts.append(f"UPLOAD_CATEGORIES={shlex.quote(upload_categories)}")
        return _shell(" ".join(env_parts) + " bash deployment.sh")

    actions: list[ReviewAction] = [
        ReviewAction(
            id="models-preview-all",
            section=SECTION_EXPERIMENT,
            title="Preview all LiteLLM models",
            description="List configured LiteLLM models without API calls; Gemini follows toggle.",
            command=smoke("--all-models", "--dry-run"),
        ),
        ReviewAction(
            id="models-smoke-all",
            section=SECTION_EXPERIMENT,
            title="Smoke all LiteLLM models",
            description="Send the minimal OK request to every configured model; Gemini follows toggle.",
            command=smoke("--all-models", "--retries", "3", "--retry-delay", "20"),
            safety=SAFETY_API_COST,
            confirm=True,
        ),
    ]

    for profile, label in EXPERIMENT_PROFILES:
        slug = _profile_slug(profile)
        high_cost = profile in HIGH_COST_PROFILES
        actions.append(ReviewAction(
            id=f"models-smoke-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"Smoke {label} profile",
            description=f"Check routing for the {profile} profile; Gemini follows toggle.",
            command=smoke("--profile", profile, "--retries", "3", "--retry-delay", "20"),
            safety=SAFETY_API_COST,
            confirm=True,
        ))
        actions.append(ReviewAction(
            id=f"experiment-dry-run-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"Dry-run full {label} experiment",
            description="Resolve all selected latest package versions/artifacts without scanning.",
            command=evaluate(profile, "--dry-run-resolution", "--skip-validation"),
        ))
        actions.append(ReviewAction(
            id=f"experiment-full-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"Full {label} experiment, all packages",
            description="Run all selected latest package versions/artifacts; Gemini follows toggle.",
            command=evaluate(profile, "--run-id-prefix", "canonical-v2", "--progress", "always"),
            safety=SAFETY_API_COST,
            confirm=True,
            double_confirm=high_cost,
            requires_clean_db=True,
        ))
        actions.append(ReviewAction(
            id=f"deployment-full-{slug}",
            section=SECTION_EXPERIMENT,
            title=f"Deployment full {label} run",
            description="Run full VM deployment/evaluation for this profile; Gemini follows toggle.",
            command=deploy(profile),
            safety=SAFETY_DEPLOYMENT,
            confirm=True,
            double_confirm=True,
            requires_clean_db=True,
        ))

    actions.extend([
        ReviewAction(
            id="analyzer-dry-run-test",
            section=SECTION_EXPERIMENT,
            title="Analyzer dry-run, tiny test profile",
            description="Resolve the four-package test profile without scanning; Gemini follows toggle.",
            command=evaluate("test", "--dry-run-resolution", "--skip-validation"),
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
            id="deployment-smoke-test",
            section=SECTION_EXPERIMENT,
            title="Deployment smoke run, four packages",
            description="Run deployment with controls+malicious upload and the test profile.",
            command=deploy("test", upload_categories="controls malicious"),
            safety=SAFETY_DEPLOYMENT,
            confirm=True,
            double_confirm=True,
            requires_clean_db=True,
        ),
        ReviewAction(
            id="db-status",
            section=SECTION_DATABASE,
            title="DB status",
            description="Show DB path, counts, and latest run metadata.",
            command=_shell(
                "db='src/data/eval_results.db'; "
                "echo \"DB path: $PWD/$db\"; "
                "if [ ! -f \"$db\" ]; then echo 'DB missing'; exit 0; fi; "
                "sqlite3 -header -column \"file:$db?mode=ro&immutable=1\" \""
                "select "
                "(select count(*) from eval_run) as eval_runs, "
                "(select count(*) from eval_result) as eval_results, "
                "(select run_id from eval_run order by id desc limit 1) as latest_run_id, "
                "(select created_at from eval_run order by id desc limit 1) as latest_created_at;\""
            ),
        ),
        ReviewAction(
            id="archive-db-dry-run",
            section=SECTION_DATABASE,
            title="Preview DB archive",
            description="Show how eval_results.db would be archived without changing files.",
            command=(*_py(py, repo_root, "scripts", "archive_eval_db.py"), "--dry-run"),
        ),
        ReviewAction(
            id="archive-db",
            section=SECTION_DATABASE,
            title="Archive DB and create clean DB",
            description="Move eval_results.db plus sidecars into timestamped archive and initialize a fresh schema.",
            command=_py(py, repo_root, "scripts", "archive_eval_db.py"),
            safety=SAFETY_MUTATES_DB,
            confirm=True,
        ),
        ReviewAction(
            id="archive-db-no-init",
            section=SECTION_DATABASE,
            title="Archive DB only",
            description="Archive eval_results.db without creating a fresh replacement.",
            command=(*_py(py, repo_root, "scripts", "archive_eval_db.py"), "--no-init"),
            safety=SAFETY_MUTATES_DB,
            confirm=True,
        ),
        ReviewAction(
            id="db-runs",
            section=SECTION_DATABASE,
            title="List recent eval runs",
            description="Show latest eval_run rows.",
            command=("sqlite3", "-header", "-column", sqlite_uri, _sqlite_runs_query()),
        ),
        ReviewAction(
            id="db-recent",
            section=SECTION_DATABASE,
            title="Show recent DB rows",
            description="Inspect latest eval_result rows using read-only immutable SQLite.",
            command=("sqlite3", "-header", "-column", sqlite_uri, _sqlite_recent_query()),
        ),
        ReviewAction(
            id="db-errors",
            section=SECTION_DATABASE,
            title="Show DB error rows",
            description="Inspect eval_result rows where experiment_mode='error'.",
            command=("sqlite3", "-header", "-column", sqlite_uri, _sqlite_error_query()),
        ),
        ReviewAction(
            id="db-detector-summary",
            section=SECTION_DATABASE,
            title="Show detector summary",
            description="Group persisted rows by run, detector, mode, and strategy.",
            command=("sqlite3", "-header", "-column", sqlite_uri, _sqlite_detector_summary_query()),
        ),
        ReviewAction(
            id="logs-list",
            section=SECTION_LOGS,
            title="List newest logs",
            description="List known log directories sorted by modification time.",
            command=_shell("ls -lt logs src/injector/logs src/analyzer/logs src/simulator/logs 2>/dev/null || true"),
        ),
        ReviewAction(
            id="logs-tail-analyzer",
            section=SECTION_LOGS,
            title="Tail latest analyzer log",
            description="Show last 80 lines from newest analyzer log.",
            command=_shell("f=$(ls -t src/analyzer/logs/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && tail -n 80 \"$f\" || echo 'No analyzer logs found'"),
        ),
        ReviewAction(
            id="logs-tail-injector",
            section=SECTION_LOGS,
            title="Tail latest injector log",
            description="Show last 80 lines from newest injector log.",
            command=_shell("f=$(ls -t src/injector/logs/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && tail -n 80 \"$f\" || echo 'No injector logs found'"),
        ),
        ReviewAction(
            id="logs-tail-simulator",
            section=SECTION_LOGS,
            title="Tail simulator log",
            description="Show last 80 lines from simulator logs.",
            command=_shell("f=$(ls -t src/simulator/logs/*.log 2>/dev/null | head -1); [ -n \"$f\" ] && tail -n 80 \"$f\" || echo 'No simulator logs found'"),
        ),
        ReviewAction(
            id="logs-tail-litellm",
            section=SECTION_LOGS,
            title="Tail LiteLLM VM log",
            description="Show /home/proxy-runner/litellm.log if available.",
            command=_shell("tail -n 80 /home/proxy-runner/litellm.log 2>/dev/null || echo 'LiteLLM VM log unavailable'"),
        ),
        ReviewAction(
            id="logs-search-errors",
            section=SECTION_LOGS,
            title="Search recent log errors",
            description="Search known logs for ERROR/HALT/Traceback/Exception/FAIL.",
            command=_shell("rg -n 'ERROR|HALT|Traceback|Exception|FAIL' logs src/*/logs /home/proxy-runner/litellm.log 2>/dev/null || true"),
        ),
        ReviewAction(
            id="tests-review",
            section=SECTION_TESTS,
            title="Run targeted review tests",
            description="Run resolver/profile/DB/static/model-smoke/TUI tests.",
            command=(
                py,
                "-m",
                "pytest",
                "tests/test_simulator_resolver.py",
                "tests/test_evaluation_profiles.py",
                "tests/test_eval_db_schema.py",
                "tests/test_guarddog_adapter.py",
                "tests/test_semgrep_rules.py",
                "tests/test_financial_validation.py",
                "tests/test_litellm_smoke.py",
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
            command=(py, "-m", "pytest", "tests/test_guarddog_adapter.py", "tests/test_semgrep_rules.py", "-q"),
            safety=SAFETY_LONG_RUNNING,
            confirm=True,
        ),
        ReviewAction(
            id="tests-db-archive",
            section=SECTION_TESTS,
            title="Run DB/archive tests",
            description="Run DB schema and archive helper tests.",
            command=(py, "-m", "pytest", "tests/test_eval_db_schema.py", "tests/test_archive_eval_db.py", "-q"),
        ),
        ReviewAction(
            id="tests-litellm-smoke",
            section=SECTION_TESTS,
            title="Run LiteLLM smoke tests",
            description="Run unit tests for LiteLLM smoke helper.",
            command=(py, "-m", "pytest", "tests/test_litellm_smoke.py", "-q"),
        ),
        ReviewAction(
            id="tests-all",
            section=SECTION_TESTS,
            title="Run full test suite",
            description="Run all pytest tests.",
            command=(py, "-m", "pytest", "tests/", "-q"),
            safety=SAFETY_LONG_RUNNING,
            confirm=True,
        ),
        ReviewAction(
            id="syntax-checks",
            section=SECTION_TESTS,
            title="Run syntax checks",
            description="Check deployment shell syntax and compile helper scripts.",
            command=(
                "bash",
                "-lc",
                f"bash -n deployment.sh && {shlex.quote(py)} -m py_compile "
                "scripts/review_tui.py scripts/litellm_smoke.py scripts/archive_eval_db.py src/analyzer/evaluate.py",
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


def db_result_count(repo_root: Path = _REPO_ROOT) -> int:
    db_path = _eval_db_path(repo_root)
    if not db_path.exists():
        return 0
    try:
        with sqlite3.connect(f"file:{db_path}?mode=ro&immutable=1", uri=True) as conn:
            row = conn.execute("select count(*) from eval_result").fetchone()
            return int(row[0]) if row else 0
    except sqlite3.Error:
        return 0


def db_needs_archive_warning(repo_root: Path = _REPO_ROOT) -> bool:
    return db_result_count(repo_root) > 0


def execute_action(
    action: ReviewAction,
    *,
    repo_root: Path = _REPO_ROOT,
    runner: Callable[..., subprocess.CompletedProcess] = subprocess.run,
) -> int:
    result = runner(action.command, cwd=repo_root)
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


def _experiment_preflight(ui, repo_root: Path, actions: Sequence[ReviewAction]) -> bool:
    if not db_needs_archive_warning(repo_root):
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
                return execute_action(archive, repo_root=repo_root) == 0
        elif choice in {"p", "preview"}:
            ui.print(command_preview(preview.command))
            execute_action(preview, repo_root=repo_root)
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


def run_menu(*, no_rich: bool = False, repo_root: Path = _REPO_ROOT) -> int:
    sections = build_sections()
    gemini_enabled = True
    ui = _make_ui(no_rich)

    while True:
        actions = build_actions(repo_root, gemini_enabled=gemini_enabled)
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

        if section.preflight == "clean-db" and not _experiment_preflight(ui, repo_root, actions):
            continue

        while True:
            actions = build_actions(repo_root, gemini_enabled=gemini_enabled)
            section_actions = actions_for_section(section.id, actions)
            raw_choice = ui.choose_action(
                section,
                section_actions,
                gemini_enabled=gemini_enabled if section.id == SECTION_EXPERIMENT else None,
            )
            if section.id == SECTION_EXPERIMENT and raw_choice in {"g", "gemini", "toggle"}:
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
            if section.id == SECTION_EXPERIMENT:
                ui.print(f"Gemini: {_gemini_label(gemini_enabled)}")
            if action.requires_clean_db and db_needs_archive_warning(repo_root):
                ui.print("[yellow]Warning: active DB contains previous result rows.[/yellow]")
            ui.print("Command:")
            ui.print(command_preview(action.command))
            if not _confirm_action(ui, action):
                ui.print("Skipped.")
                continue

            rc = execute_action(action, repo_root=repo_root)
            ui.print(f"Exit code: {rc}")
            if not ui.confirm("Return to this section?", default=True):
                return rc


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-rich", action="store_true", help="Use plain prompts instead of Rich UI")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    return run_menu(no_rich=args.no_rich)


if __name__ == "__main__":
    raise SystemExit(main())
