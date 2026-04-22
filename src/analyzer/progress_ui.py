"""
progress_ui.py - Compact live progress display for analyzer evaluation runs.

The dashboard is intentionally presentation-only. The file log remains the
authoritative audit trail for package, detector, error, and cost details.
"""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from src.utils.logger import get_logger

log = get_logger()

try:
    from rich.console import Console, Group
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
except ImportError:  # pragma: no cover - deployment dependency guard
    Console = None
    Group = None
    Live = None
    Panel = None
    Table = None


PROVIDERS = ("anthropic", "openai", "google", "together", "other")
MAX_VISIBLE_DETECTOR_ROWS = 18
MIN_REFRESH_INTERVAL_S = 0.75


def should_use_progress(mode: str, *, dry_run_resolution: bool) -> bool:
    """Return whether the live analyzer dashboard should be enabled."""
    if dry_run_resolution or mode == "never":
        return False
    if Live is None:
        if mode == "always":
            log.warning("Rich is not installed; falling back to plain analyzer logs")
        return False
    if mode == "always":
        return True
    return sys.stderr.isatty()


def provider_for_model(model_name: str | None) -> str:
    """Map a LiteLLM model name to the provider bucket shown in the console."""
    model = (model_name or "").strip()
    if not model:
        return "other"
    lowered = model.lower()
    if lowered.startswith("claude-") or lowered.startswith("anthropic/"):
        return "anthropic"
    if lowered.startswith(("gpt-", "o1-", "o3-")) or lowered.startswith("openai/"):
        return "openai"
    if lowered.startswith("gemini-") or lowered.startswith("google/") or lowered.startswith("gemini/"):
        return "google"
    if lowered.startswith("together_ai/") or lowered.startswith("together/"):
        return "together"
    return "other"


@dataclass
class CostLedger:
    totals: dict[str, float] = field(default_factory=lambda: {p: 0.0 for p in PROVIDERS})
    unknown_models: set[str] = field(default_factory=set)

    def add(self, model_name: str | None, cost_usd: float) -> tuple[str, bool]:
        provider = provider_for_model(model_name)
        if cost_usd > 0:
            self.totals[provider] = self.totals.get(provider, 0.0) + cost_usd
        first_unknown = False
        if provider == "other" and model_name:
            first_unknown = model_name not in self.unknown_models
            self.unknown_models.add(model_name)
        return provider, first_unknown

    @property
    def total(self) -> float:
        return sum(self.totals.values())


@dataclass
class _DetectorRow:
    detector: str
    mode: str
    strategy: str
    state: str = "queued/running"
    started_at: float = field(default_factory=time.monotonic)
    elapsed_s: float | None = None
    verdict: str = ""
    model: str = ""
    cost_usd: float = 0.0
    error: str = ""


class AnalyzerProgress:
    """Single-owner live dashboard for the analyzer main evaluation loop."""

    def __init__(
        self,
        *,
        enabled: bool,
        total_samples: int,
        run_id: str,
        run_label: str,
    ):
        self.enabled = bool(enabled and total_samples > 0 and Live is not None)
        self.total_samples = total_samples
        self.run_id = run_id
        self.run_label = run_label
        self.completed_samples = 0
        self.current_index = 0
        self.current_sample = ""
        self.current_label = ""
        self.decoded_summary = "pending extraction"
        self.heuristics = "pending"
        self.package_verdict = ""
        self._rows: dict[tuple[str, str, str], _DetectorRow] = {}
        self._costs = CostLedger()
        self._lock = threading.RLock()
        self._last_refresh = 0.0
        self._console = Console(stderr=True) if self.enabled and Console is not None else None
        self._live = None

    @property
    def active(self) -> bool:
        return self.enabled and self._live is not None

    def __enter__(self) -> "AnalyzerProgress":
        if self.enabled and Live is not None:
            self._live = Live(
                self,
                console=self._console,
                auto_refresh=False,
                transient=False,
                vertical_overflow="ellipsis",
            )
            self._live.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        if self._live is not None:
            self._live.stop()
        return False

    def __rich_console__(self, console, options):
        yield self._render()

    def start_package(self, index: int, sample: Any) -> None:
        if not self.enabled:
            return
        label = "malicious" if sample.ground_truth else sample.sample_role
        with self._lock:
            self.current_index = index
            self.current_sample = (
                f"{sample.package_name}=={sample.version} "
                f"({sample.artifact_filename})"
            )
            self.current_label = label
            self.decoded_summary = "extracting"
            self.heuristics = "pending"
            self.package_verdict = ""
            self._rows.clear()
        self.refresh(force=True)

    def set_detector_tasks(self, tasks: list[dict[str, str]]) -> None:
        if not self.enabled:
            return
        now = time.monotonic()
        with self._lock:
            self._rows = {
                self._key(task["detector"], task["mode"], task["strategy"]): _DetectorRow(
                    detector=task["detector"],
                    mode=task["mode"],
                    strategy=task["strategy"],
                    state="queued/running",
                    started_at=now,
                )
                for task in tasks
            }
        self.refresh(force=True)

    def record_extraction(
        self,
        *,
        decoded_files: int,
        entry_points: int,
        bad_password_files: list[str],
    ) -> None:
        if not self.enabled:
            return
        suffix = f", bad-password={len(bad_password_files)}" if bad_password_files else ""
        with self._lock:
            self.decoded_summary = (
                f"decoded={decoded_files}, entry_points={entry_points}{suffix}"
            )
        self.refresh()

    def record_heuristics(self, flags: list[str]) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.heuristics = ", ".join(flags) if flags else "none"
        self.refresh()

    def record_result(self, result: Any, strategy: str, intended_mode: str) -> None:
        if not self.enabled:
            return
        model = str(
            result.details.get("model")
            or result.details.get("actual_model")
            or result.details.get("selected_model")
            or ""
        )
        litellm_model_id = str(result.details.get("litellm_model_id") or "")
        provider, first_unknown = self._costs.add(model, float(result.api_cost_usd or 0.0))
        if first_unknown:
            log.bind(file_only=True).warning(
                f"Analyzer progress cost provider fallback: model={model!r} "
                f"mapped to provider={provider!r} "
                f"(litellm_model_id={litellm_model_id or 'n/a'})"
            )

        key = self._key(result.detector, intended_mode, strategy)
        verdict = (
            "ERROR"
            if result.experiment_mode == "error"
            else "MALICIOUS" if result.verdict else "benign"
        )
        with self._lock:
            row = self._rows.get(key)
            if row is None:
                row = _DetectorRow(
                    detector=result.detector,
                    mode=intended_mode,
                    strategy=strategy,
                    started_at=time.monotonic(),
                )
                self._rows[key] = row
            row.state = "done" if result.experiment_mode != "error" else "error"
            row.elapsed_s = result.exec_time_ms / 1000
            row.verdict = verdict
            row.model = model
            row.cost_usd = float(result.api_cost_usd or 0.0)
            row.error = self._collapse_error(result.details) if row.state == "error" else ""
        self.refresh()

    def complete_package(self, *, valid_results: int, flagged_results: int) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.completed_samples += 1
            self.package_verdict = (
                f"{flagged_results}/{valid_results} detector(s) flagged malicious"
            )
        self.refresh()

    def fail_package(self, filename: str, exc: Exception) -> None:
        if not self.enabled:
            return
        with self._lock:
            self.completed_samples += 1
            self.package_verdict = f"FAILED {filename}: {exc}"
            self._rows.clear()
        self.refresh()

    def refresh(self, *, force: bool = False) -> None:
        if self._live is None:
            return
        now = time.monotonic()
        if not force and now - self._last_refresh < MIN_REFRESH_INTERVAL_S:
            return
        self._last_refresh = now
        self._live.refresh()

    def _render(self):
        if Group is None or Panel is None or Table is None:
            return ""
        with self._lock:
            return Group(
                self._header_panel(),
                self._detector_table(),
                self._cost_table(),
            )

    def _header_panel(self):
        remaining = max(self.total_samples - self.completed_samples, 0)
        bar = self._progress_bar(self.completed_samples, self.total_samples)
        table = Table.grid(expand=True)
        table.add_column(ratio=1)
        table.add_column(ratio=1)
        table.add_row("Run", self.run_id)
        table.add_row("Profile", self.run_label)
        table.add_row(
            "Artifacts",
            f"{self.completed_samples}/{self.total_samples} {bar} remaining={remaining}",
        )
        table.add_row("Current", f"{self.current_index}/{self.total_samples} {self.current_sample}")
        table.add_row("Label", self.current_label)
        table.add_row("Extraction", self.decoded_summary)
        table.add_row("Heuristics", self.heuristics)
        if self.package_verdict:
            table.add_row("Last verdict", self.package_verdict)
        return Panel(table, title="PyPI-SCADA Evaluation", border_style="cyan")

    def _detector_table(self):
        table = Table(title="Current Artifact Detectors", expand=True)
        table.add_column("Detector", no_wrap=True)
        table.add_column("Mode", no_wrap=True)
        table.add_column("Strategy", no_wrap=True)
        table.add_column("State", no_wrap=True)
        table.add_column("Elapsed", justify="right")
        table.add_column("Cost", justify="right")
        table.add_column("Model / Error", overflow="fold")

        rows = sorted(self._rows.values(), key=lambda r: (r.detector, r.mode, r.strategy))
        if not rows:
            table.add_row("-", "-", "-", "pending", "-", "-", "")
            return table

        visible_rows, hidden = self._visible_detector_rows(rows)
        now = time.monotonic()
        for row in visible_rows:
            elapsed = row.elapsed_s
            if elapsed is None:
                elapsed = max(now - row.started_at, 0.0)
            state = row.verdict or row.state
            detail = row.error or row.model
            table.add_row(
                row.detector,
                row.mode,
                row.strategy,
                state,
                f"{elapsed:.1f}s",
                f"${row.cost_usd:.5f}" if row.cost_usd else "-",
                detail,
            )
        if hidden:
            table.add_row(
                "...",
                "...",
                "...",
                f"showing {len(visible_rows)}/{len(rows)}",
                "-",
                "-",
                "Full detector details are in the analyzer log and raw trace.",
            )
        return table

    def _cost_table(self):
        table = Table(title="Accumulated API Cost", expand=True)
        for provider in PROVIDERS:
            table.add_column(provider, justify="right")
        table.add_column("total", justify="right")
        table.add_row(
            *[f"${self._costs.totals.get(provider, 0.0):.4f}" for provider in PROVIDERS],
            f"${self._costs.total:.4f}",
        )
        return table


    @staticmethod
    def _visible_detector_rows(rows: list[_DetectorRow]) -> tuple[list[_DetectorRow], int]:
        if len(rows) <= MAX_VISIBLE_DETECTOR_ROWS:
            return rows, 0

        priority = {"error": 0, "queued/running": 1, "done": 2}

        def sort_key(row: _DetectorRow):
            state_key = priority.get(row.state, 3)
            elapsed = row.elapsed_s if row.elapsed_s is not None else time.monotonic() - row.started_at
            return (state_key, -elapsed, row.detector, row.mode, row.strategy)

        selected = sorted(rows, key=sort_key)[:MAX_VISIBLE_DETECTOR_ROWS]
        selected_keys = {(r.detector, r.mode, r.strategy) for r in selected}
        ordered = [row for row in rows if (row.detector, row.mode, row.strategy) in selected_keys]
        return ordered, len(rows) - len(ordered)

    @staticmethod
    def _key(detector: str, mode: str, strategy: str) -> tuple[str, str, str]:
        return detector, mode, strategy

    @staticmethod
    def _progress_bar(completed: int, total: int, width: int = 28) -> str:
        if total <= 0:
            return "[" + "-" * width + "]"
        filled = int(width * min(completed, total) / total)
        return "[" + "#" * filled + "-" * (width - filled) + "]"

    @staticmethod
    def _collapse_error(details: dict, limit: int = 80) -> str:
        message = str(details.get("error") or details)
        qualifier = str(details.get("protocol_category") or details.get("parse_error") or "").strip()
        if qualifier:
            message = f"{message} ({qualifier})"
        collapsed = " ".join(message.split())
        if len(collapsed) <= limit:
            return collapsed
        return collapsed[:limit] + "..."
