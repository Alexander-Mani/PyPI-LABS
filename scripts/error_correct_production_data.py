#!/usr/bin/env python3
"""Repair selected production eval_result error rows into append-only correction runs."""

from __future__ import annotations

import argparse
import copy
import json
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ANALYZER_DIR = _REPO_ROOT / "src" / "analyzer"
_ANALYZER_CONFIG = _ANALYZER_DIR / "config.yaml"
for _path in (_REPO_ROOT, _ANALYZER_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from scripts.production_eval_db_common import load_run_inventory  # noqa: E402
from src.analyzer.adapters import (  # noqa: E402
    AgenticAdapter,
    DetectorAdapter,
    GuardDogAdapter,
    LLMAdapter,
    LLMRawAdapter,
    StaticAdapter,
)
from src.analyzer.entry_extractor import EntryPointExtractor, PackageInfo  # noqa: E402
from src.analyzer.heuristic_filter import HeuristicFilter  # noqa: E402
from src.analyzer.identity_mask import mask_package_identity  # noqa: E402
from src.analyzer.prompt_manager import PromptManager  # noqa: E402
from src.data.db_manager import DBManager  # noqa: E402
from src.utils.logger import get_active_log_path, setup_logger  # noqa: E402

REPAIR_TIER_SUFFIX = ":repair"
DEFAULT_MAX_TOKENS = 16384
DEFAULT_LLM_RETRY_ATTEMPTS = 5
DEFAULT_LLM_RETRY_DELAY_SECONDS = 45.0
DEFAULT_AGENTIC_RETRY_ATTEMPTS = 5
DEFAULT_AGENTIC_RETRY_DELAY_SECONDS = 60.0
DEFAULT_PROGRESS_MODE = "auto"
DEFAULT_VERBOSE_PREVIEW = False
DEFAULT_VERBOSE_RESULTS = False
DEFAULT_ENGINE_CONSOLE_LOGS = "off"
TRANSPORT_RETRY_CATEGORIES = {
    "client_timeout",
    "provider_or_proxy_transient",
    "provider_overload",
    "rate_limit",
}
PROTOCOL_RETRY_ERRORS = {
    "empty_model_response",
    "unparseable_model_response",
}
MIN_REFRESH_INTERVAL_S = 0.75
PLAIN_HEARTBEAT_INTERVAL_S = 15.0

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


@dataclass(frozen=True)
class RepairCandidate:
    row_id: int
    run_id: str
    tier: str
    sample_set: str
    detector: str
    prompt_strategy: str
    experiment_mode: str
    intended_mode: str
    package_name: str
    version: str
    artifact_filename: str
    artifact_url: str
    source_index_url: str | None
    sample_role: str | None
    attack_vector: str | None
    resolver_policy: str | None
    ground_truth: bool | None
    details: dict[str, Any]

    @property
    def row_key(self) -> tuple[str, str, str, str, str, str, str, str]:
        return (
            self.run_id,
            self.package_name,
            self.version,
            self.artifact_filename,
            self.detector,
            self.prompt_strategy,
            self.experiment_mode,
            self.intended_mode,
        )


@dataclass
class RepairOutcome:
    candidate: RepairCandidate
    repair_run_id: str
    final_mode: str
    success: bool
    attempts: int
    api_cost_usd: float
    exec_time_ms: int
    model_name: str
    details: dict[str, Any]


@dataclass(frozen=True)
class RepairRunPlan:
    source_run_id: str
    source_tier: str
    sample_set: str
    repair_run_id: str
    repair_tier: str
    candidate_count: int


@dataclass(frozen=True)
class RepairPolicy:
    max_tokens: int
    llm_retry_attempts: int
    llm_retry_delay_seconds: float
    agentic_retry_attempts: int
    agentic_retry_delay_seconds: float


@dataclass(frozen=True)
class SkippedCandidate:
    candidate: RepairCandidate
    reason: str


@dataclass
class RepairProgressOutcome:
    success: bool
    cost_usd: float
    elapsed_s: float
    final_mode: str
    detector: str
    model_name: str
    package_label: str
    run_label: str


def _should_use_progress(mode: str) -> bool:
    if mode == "never":
        return False
    if Live is None:
        return False
    if mode == "always":
        return True
    return sys.stderr.isatty()


def _provider_for_model(model_name: str | None) -> str:
    model = (model_name or "").strip().lower()
    if not model:
        return "other"
    if model.startswith("claude-") or model.startswith("anthropic/"):
        return "anthropic"
    if model.startswith(("gpt-", "o1-", "o3-")) or model.startswith("openai/"):
        return "openai"
    if model.startswith("gemini-") or model.startswith("google/") or model.startswith("gemini/"):
        return "google"
    if model.startswith("together_ai/") or model.startswith("together/"):
        return "together"
    return "other"


class RepairProgress:
    def __init__(self, *, enabled: bool, total_rows: int, plain_enabled: bool = False):
        self.enabled = enabled and total_rows > 0
        self.total_rows = total_rows
        self.completed = 0
        self.repaired = 0
        self.still_error = 0
        self.skipped = 0
        self.total_cost_usd = 0.0
        self.total_elapsed_s = 0.0
        self.provider_costs = {name: 0.0 for name in ("anthropic", "openai", "google", "together", "other")}
        self.current_package = ""
        self.current_detector = ""
        self.current_run = ""
        self.current_result = ""
        self.current_stage = "idle"
        self.current_attempt = 0
        self.current_retry_wait_s = 0.0
        self._current_started_at = 0.0
        self._console = Console(stderr=True) if self.enabled and Console is not None else None
        self._live = None
        self._last_refresh = 0.0
        self._plain_enabled = bool(plain_enabled and not self.enabled)
        self._last_plain_heartbeat = 0.0
        self._stop_event = threading.Event()
        self._ticker: threading.Thread | None = None

    @property
    def active(self) -> bool:
        return self.enabled and self._live is not None

    def __enter__(self) -> "RepairProgress":
        if self.enabled and Live is not None:
            self._live = Live(
                self,
                console=self._console,
                auto_refresh=False,
                transient=False,
                vertical_overflow="ellipsis",
            )
            self._live.start()
        self._stop_event.clear()
        self._ticker = threading.Thread(target=self._tick_loop, name="repair-progress", daemon=True)
        self._ticker.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self._stop_event.set()
        if self._ticker is not None:
            self._ticker.join(timeout=1.0)
        if self._live is not None:
            self._live.stop()
        return False

    def __rich_console__(self, console, options):
        yield self._render()

    def start_candidate(self, candidate: RepairCandidate) -> None:
        self.current_package = f"{candidate.package_name}=={candidate.version} [{candidate.artifact_filename}]"
        self.current_detector = f"{candidate.detector}:{candidate.intended_mode}:{candidate.prompt_strategy}"
        self.current_run = candidate.run_id
        self.current_result = "running"
        self.current_stage = "queued"
        self.current_attempt = 0
        self.current_retry_wait_s = 0.0
        self._current_started_at = time.monotonic()
        self.refresh(force=True)

    def update_stage(
        self,
        stage: str,
        *,
        attempt: int | None = None,
        retry_wait_s: float | None = None,
        current_result: str | None = None,
    ) -> None:
        self.current_stage = stage
        if attempt is not None:
            self.current_attempt = attempt
        if retry_wait_s is not None:
            self.current_retry_wait_s = max(float(retry_wait_s), 0.0)
        elif stage != "retrying":
            self.current_retry_wait_s = 0.0
        if current_result is not None:
            self.current_result = current_result
        self.refresh(force=True)

    def record(self, outcome: RepairProgressOutcome) -> None:
        self.completed += 1
        if outcome.success:
            self.repaired += 1
        else:
            self.still_error += 1
        self.total_cost_usd += outcome.cost_usd
        self.total_elapsed_s += outcome.elapsed_s
        provider = _provider_for_model(outcome.model_name)
        self.provider_costs[provider] = self.provider_costs.get(provider, 0.0) + outcome.cost_usd
        self.current_result = "repaired" if outcome.success else "still error"
        self.current_package = outcome.package_label
        self.current_detector = outcome.detector
        self.current_run = outcome.run_label
        self.current_stage = "done"
        self.current_retry_wait_s = 0.0
        if self.active:
            self.refresh()
            return
        if self._plain_enabled and (self.completed == self.total_rows or self.completed % 10 == 0 or not outcome.success):
            print(
                f"Progress: {self.completed}/{self.total_rows} "
                f"repaired={self.repaired} still_error={self.still_error} "
                f"cost=${self.total_cost_usd:.4f} current={self.current_package}"
            )

    def refresh(self, *, force: bool = False) -> None:
        if not self.active:
            return
        now = time.monotonic()
        if not force and now - self._last_refresh < MIN_REFRESH_INTERVAL_S:
            return
        self._last_refresh = now
        self._live.refresh()

    def _tick_loop(self) -> None:
        while not self._stop_event.wait(1.0):
            if self._current_started_at <= 0:
                continue
            if self.active:
                self.refresh(force=True)
                continue
            if not self._plain_enabled:
                continue
            now = time.monotonic()
            if now - self._last_plain_heartbeat < PLAIN_HEARTBEAT_INTERVAL_S:
                continue
            self._last_plain_heartbeat = now
            elapsed_s = max(now - self._current_started_at, 0.0)
            attempt = self.current_attempt or 1
            retry_note = (
                f" retry_wait={self.current_retry_wait_s:.0f}s"
                if self.current_stage == "retrying" and self.current_retry_wait_s > 0
                else ""
            )
            print(
                f"Heartbeat: {self.completed}/{self.total_rows} "
                f"stage={self.current_stage} attempt={attempt} elapsed={elapsed_s:.0f}s"
                f"{retry_note} current={self.current_package}"
            )

    def _render(self):
        header = Table.grid(expand=True)
        header.add_column(style="bold")
        header.add_column()
        header.add_row("Rows", f"{self.completed}/{self.total_rows}")
        header.add_row("Current", self.current_package or "waiting")
        header.add_row("Detector", self.current_detector or "waiting")
        header.add_row("Source Run", self.current_run or "waiting")
        header.add_row("Stage", self.current_stage or "idle")
        header.add_row("Attempt", str(self.current_attempt or 0))

        stats = Table.grid(expand=True)
        stats.add_column(style="bold")
        stats.add_column(justify="right")
        stats.add_row("Repaired", str(self.repaired))
        stats.add_row("Still error", str(self.still_error))
        stats.add_row("Skipped", str(self.skipped))
        stats.add_row("API Cost", f"${self.total_cost_usd:.4f}")
        row_elapsed = max(time.monotonic() - self._current_started_at, 0.0) if self._current_started_at > 0 else 0.0
        stats.add_row("Row Elapsed", f"{row_elapsed:.1f}s")
        if self.current_stage == "retrying" and self.current_retry_wait_s > 0:
            stats.add_row("Retry Wait", f"{self.current_retry_wait_s:.0f}s")
        avg = self.total_elapsed_s / self.completed if self.completed else 0.0
        remaining = max(self.total_rows - self.completed, 0)
        eta = avg * remaining
        stats.add_row("Avg / ETA", f"{avg:.1f}s / {eta:.0f}s")

        providers = Table.grid(expand=True)
        providers.add_column(style="bold")
        providers.add_column(justify="right")
        for name in ("anthropic", "openai", "google", "together", "other"):
            providers.add_row(name, f"${self.provider_costs[name]:.4f}")

        return Group(
            Panel(header, title="DB Error Reruns", border_style="cyan"),
            Panel(stats, title="Outcome", border_style="green"),
            Panel(providers, title="Provider Cost", border_style="magenta"),
        )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _utc_compact_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")



def _copy_package(pkg: PackageInfo) -> PackageInfo:
    return PackageInfo(
        name=pkg.name,
        version=pkg.version,
        files=dict(pkg.files),
        files_raw=dict(pkg.files_raw),
        heuristic_flags=list(pkg.heuristic_flags),
        bad_password_files=list(pkg.bad_password_files),
    )



def _load_details(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}



def _ensure_db_shape(db_path: Path) -> None:
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    required = {"eval_run", "eval_result"}
    if not required.issubset(tables):
        raise SystemExit(f"HALT: DB is missing required tables {sorted(required - tables)}: {db_path}")



def _backup_db(db_path: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = db_path.with_name(f"{db_path.name}.before-error-correct-{stamp}")
    try:
        source = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            dest = sqlite3.connect(backup_path)
            try:
                source.backup(dest)
            finally:
                dest.close()
        finally:
            source.close()
    except sqlite3.Error:
        shutil.copy2(db_path, backup_path)
    return backup_path



def load_repair_candidates(
    db_path: Path,
    *,
    sample_set: str = "any",
    run_ids: list[str] | None = None,
    detectors: list[str] | None = None,
    intended_modes: list[str] | None = None,
    include_agentic: bool = False,
    include_validation: bool = False,
    include_repair_runs: bool = False,
) -> list[RepairCandidate]:
    params: list[Any] = []
    with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as conn:
        conn.row_factory = sqlite3.Row
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(eval_run)").fetchall()
        }
        sample_set_expr = "eru.sample_set" if "sample_set" in columns else "'dataset'"
        where_parts = ["er.experiment_mode = 'error'"]
        if sample_set != "any":
            where_parts.append(f"{sample_set_expr} = ?")
            params.append(sample_set)
        if run_ids:
            placeholders = ", ".join("?" for _ in run_ids)
            where_parts.append(f"er.run_id IN ({placeholders})")
            params.extend(run_ids)
        if detectors:
            placeholders = ", ".join("?" for _ in detectors)
            where_parts.append(f"er.detector IN ({placeholders})")
            params.extend(detectors)
        if intended_modes:
            placeholders = ", ".join("?" for _ in intended_modes)
            where_parts.append(f"COALESCE(er.intended_mode, er.experiment_mode) IN ({placeholders})")
            params.extend(intended_modes)
        if not include_agentic:
            where_parts.append("COALESCE(er.intended_mode, er.experiment_mode) != 'agentic'")
        if not include_validation:
            where_parts.append("eru.tier NOT LIKE '%-validation'")
        if not include_repair_runs:
            where_parts.append("eru.tier NOT LIKE '%:repair'")
        query = f"""
            SELECT
                er.id,
                er.run_id,
                eru.tier,
                {sample_set_expr} AS sample_set,
                er.detector,
                er.prompt_strategy,
                er.experiment_mode,
                er.intended_mode,
                er.package_name,
                er.version,
                er.artifact_filename,
                er.artifact_url,
                er.source_index_url,
                er.sample_role,
                er.attack_vector,
                er.resolver_policy,
                er.ground_truth,
                er.details
            FROM eval_result AS er
            JOIN eval_run AS eru
              ON eru.run_id = er.run_id
            WHERE {" AND ".join(where_parts)}
            ORDER BY eru.created_at DESC, er.run_id, er.detector, er.package_name, er.version, er.prompt_strategy, er.artifact_filename
        """
        rows = conn.execute(query, params).fetchall()
    candidates: list[RepairCandidate] = []
    for row in rows:
        candidates.append(
            RepairCandidate(
                row_id=int(row["id"]),
                run_id=str(row["run_id"]),
                tier=str(row["tier"]),
                sample_set=str(row["sample_set"] or "dataset"),
                detector=str(row["detector"]),
                prompt_strategy=str(row["prompt_strategy"]),
                experiment_mode=str(row["experiment_mode"]),
                intended_mode=str(row["intended_mode"] or row["experiment_mode"]),
                package_name=str(row["package_name"]),
                version=str(row["version"]),
                artifact_filename=str(row["artifact_filename"] or ""),
                artifact_url=str(row["artifact_url"] or "").strip(),
                source_index_url=str(row["source_index_url"] or "") or None,
                sample_role=str(row["sample_role"] or "") or None,
                attack_vector=str(row["attack_vector"] or "") or None,
                resolver_policy=str(row["resolver_policy"] or "") or None,
                ground_truth=(None if row["ground_truth"] is None else bool(int(row["ground_truth"]))),
                details=_load_details(row["details"]),
            )
        )
    return candidates


def build_repair_run_plans(
    candidates: list[RepairCandidate],
    *,
    stamp: str | None = None,
) -> dict[str, RepairRunPlan]:
    if stamp is None:
        stamp = _utc_compact_stamp()
    grouped: dict[str, tuple[str, str, int]] = {}
    for candidate in candidates:
        tier, sample_set, count = grouped.get(candidate.run_id, (candidate.tier, candidate.sample_set, 0))
        grouped[candidate.run_id] = (tier, sample_set, count + 1)
    return {
        source_run_id: RepairRunPlan(
            source_run_id=source_run_id,
            source_tier=source_tier,
            sample_set=sample_set,
            repair_run_id=f"{source_run_id}--repair-{stamp}",
            repair_tier=f"{source_tier}{REPAIR_TIER_SUFFIX}",
            candidate_count=count,
        )
        for source_run_id, (source_tier, sample_set, count) in grouped.items()
    }


def _candidate_config_path(candidate: RepairCandidate) -> Path:
    return _REPO_ROOT / "src" / "analyzer" / "configs" / f"{candidate.detector}.yaml"


def _candidate_skip_reason(candidate: RepairCandidate) -> str | None:
    if not candidate.artifact_url:
        return "missing_artifact_url"

    if bool(candidate.details.get("alias_probe")):
        alias_name = str(candidate.details.get("alias_name") or "").strip()
        alias_version = str(candidate.details.get("alias_version") or "").strip()
        if not alias_name or not alias_version:
            return "invalid_alias_metadata"

    if candidate.intended_mode == "static":
        if candidate.detector in {"bandit", "semgrep", "guarddog"}:
            return None
        return "unsupported_static_detector"

    if candidate.intended_mode not in {"hybrid", "llm_raw", "agentic"}:
        return "unsupported_intended_mode"

    if not _candidate_config_path(candidate).exists():
        return "missing_detector_config"

    try:
        _prompt_overrides(candidate.intended_mode, candidate.prompt_strategy)
    except KeyError:
        return "unsupported_prompt_strategy"
    return None


def partition_repair_candidates(
    candidates: list[RepairCandidate],
) -> tuple[list[RepairCandidate], list[SkippedCandidate]]:
    rerunnable: list[RepairCandidate] = []
    skipped: list[SkippedCandidate] = []
    for candidate in candidates:
        reason = _candidate_skip_reason(candidate)
        if reason is None:
            rerunnable.append(candidate)
        else:
            skipped.append(SkippedCandidate(candidate=candidate, reason=reason))
    return rerunnable, skipped


def _print_candidate_list(
    header: str,
    rows: list[str],
    *,
    limit: int = 20,
) -> None:
    if not rows:
        return
    print(header)
    for line in rows[:limit]:
        print(f"  {line}")
    if len(rows) > limit:
        print(f"  ... {len(rows) - limit} more")


def _load_repair_logging_config(*, engine_console_logs: bool) -> dict[str, Any]:
    with _ANALYZER_CONFIG.open(encoding="utf-8") as handle:
        cfg = yaml.safe_load(handle)
    cfg.setdefault("logging", {})
    cfg["logging"]["file"] = str(_REPO_ROOT / "logs" / "repair" / "error_correct_production_data.log")
    cfg["logging"]["level"] = "INFO"
    cfg["logging"]["console_output"] = bool(engine_console_logs)
    cfg["logging"]["per_run"] = True
    return cfg


def _count_by(candidates: list[RepairCandidate], attr: str) -> list[tuple[str, int]]:
    counts = Counter(str(getattr(candidate, attr) or "") for candidate in candidates)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _print_count_block(title: str, rows: list[tuple[str, int]], *, limit: int = 12) -> None:
    if not rows:
        return
    print(f"{title}:")
    for name, count in rows[:limit]:
        print(f"  {name}: {count}")
    if len(rows) > limit:
        print(f"  ... {len(rows) - limit} more")



def _download_artifact(url: str, target_dir: Path, cache: dict[str, Path]) -> Path:
    if url in cache:
        return cache[url]
    parsed = urllib.parse.urlparse(url)
    filename = Path(parsed.path).name or "artifact.bin"
    dest = target_dir / filename
    with urllib.request.urlopen(url) as resp, dest.open("wb") as handle:
        shutil.copyfileobj(resp, handle)
    cache[url] = dest
    return dest



def _extract_package(archive_path: Path, cache: dict[Path, PackageInfo]) -> PackageInfo:
    if archive_path in cache:
        return _copy_package(cache[archive_path])
    pkg = EntryPointExtractor().extract(archive_path)
    pkg = HeuristicFilter().scan(pkg)
    cache[archive_path] = _copy_package(pkg)
    return _copy_package(pkg)



def _prepare_package(candidate: RepairCandidate, pkg: PackageInfo) -> tuple[PackageInfo, dict[str, Any] | None]:
    alias_probe = bool(candidate.details.get("alias_probe"))
    if not alias_probe:
        return pkg, None
    alias_name = str(candidate.details.get("alias_name") or "").strip()
    alias_version = str(candidate.details.get("alias_version") or "").strip()
    if not alias_name or not alias_version:
        raise SystemExit(
            "HALT: alias probe row is missing alias_name/alias_version: "
            f"{candidate.run_id} {candidate.detector} {candidate.package_name}=={candidate.version}"
        )
    masked = mask_package_identity(pkg, alias_name=alias_name, alias_version=alias_version)
    return masked.package, masked.details()



def _build_adapter(detector: str, intended_mode: str) -> DetectorAdapter:
    if detector in {"bandit", "semgrep"}:
        return StaticAdapter(detector)
    if detector == "guarddog":
        return GuardDogAdapter()
    config_path = _REPO_ROOT / "src" / "analyzer" / "configs" / f"{detector}.yaml"
    if not config_path.exists():
        raise SystemExit(f"HALT: missing model config for detector '{detector}': {config_path}")
    if intended_mode == "hybrid":
        return LLMAdapter(config_path)
    if intended_mode == "llm_raw":
        return LLMRawAdapter(config_path)
    if intended_mode == "agentic":
        return AgenticAdapter(config_path)
    raise SystemExit(f"HALT: unsupported intended_mode '{intended_mode}' for detector '{detector}'")



def _tune_adapter(adapter: DetectorAdapter, intended_mode: str, policy: RepairPolicy) -> None:
    if isinstance(adapter, (LLMAdapter, LLMRawAdapter)):
        adapter._max_tokens = max(int(getattr(adapter, "_max_tokens", 0) or 0), policy.max_tokens)
        adapter._retry_attempts = max(int(getattr(adapter, "_retry_attempts", 0) or 0), policy.llm_retry_attempts)
        adapter._retry_delay_seconds = max(
            float(getattr(adapter, "_retry_delay_seconds", 0.0) or 0.0),
            policy.llm_retry_delay_seconds,
        )
        adapter._retry_protocol_errors = set(getattr(adapter, "_retry_protocol_errors", set()) or set())
        adapter._retry_protocol_errors.update(PROTOCOL_RETRY_ERRORS)
        adapter._retry_unparseable = True
        adapter._retry_transport_categories = set(
            getattr(adapter, "_retry_transport_categories", set()) or set()
        )
        adapter._retry_transport_categories.update(TRANSPORT_RETRY_CATEGORIES)
        return
    if isinstance(adapter, AgenticAdapter):
        adapter._max_tokens = max(int(getattr(adapter, "_max_tokens", 0) or 0), policy.max_tokens)
        return


def _instrument_adapter_with_progress(
    adapter: DetectorAdapter,
    progress: RepairProgress | None,
) -> None:
    if progress is None:
        return

    if isinstance(adapter, (LLMAdapter, LLMRawAdapter)):
        original_call_api = adapter._call_api
        original_retry_sleep = adapter._retry_sleep
        original_generic_retry_sleep = adapter._generic_protocol_retry_sleep

        def wrapped_call_api(system, user, **kwargs):
            attempt = int(kwargs.get("attempt") or 1)
            progress.update_stage("running", attempt=attempt, current_result="running")
            return original_call_api(system, user, **kwargs)

        def wrapped_retry_sleep():
            progress.update_stage(
                "retrying",
                attempt=max(progress.current_attempt or 1, 1),
                retry_wait_s=float(getattr(adapter, "_retry_delay_seconds", 0.0) or 0.0),
                current_result="retrying",
            )
            return original_retry_sleep()

        def wrapped_generic_retry_sleep():
            progress.update_stage(
                "retrying",
                attempt=max(progress.current_attempt or 1, 1),
                current_result="retrying",
            )
            return original_generic_retry_sleep()

        adapter._call_api = wrapped_call_api
        adapter._retry_sleep = wrapped_retry_sleep
        adapter._generic_protocol_retry_sleep = wrapped_generic_retry_sleep
        return

    if isinstance(adapter, AgenticAdapter):
        original_make_api_call = adapter._make_api_call

        def wrapped_make_api_call(messages, system_prompt=None, **kwargs):
            turn = int(kwargs.get("turn") or 0)
            phase = str(kwargs.get("phase") or "turn")
            progress.update_stage(
                f"agentic_{phase}",
                attempt=turn + 1,
                current_result="running",
            )
            return original_make_api_call(messages, system_prompt=system_prompt, **kwargs)

        adapter._make_api_call = wrapped_make_api_call


def _looks_retryable(result_details: dict[str, Any]) -> bool:
    if not result_details:
        return False
    if bool(result_details.get("retryable")):
        return True
    error_text = str(result_details.get("error") or "").lower()
    protocol_category = str(result_details.get("protocol_category") or "").lower()
    return any(token in error_text for token in ("429", "rate limit", "no deployments available", "try again in")) or protocol_category in {
        "empty_finish_reason_length",
        "empty_null_content",
        "empty_blank_content",
    }



def _prompt_overrides(intended_mode: str, prompt_strategy: str) -> tuple[str | None, str | None]:
    if intended_mode == "static":
        return None, None
    pm = PromptManager.instance()
    if intended_mode in {"hybrid", "llm_raw"}:
        return pm.get_llm_strategy(prompt_strategy)
    if intended_mode == "agentic":
        return pm.get_agentic_strategy(prompt_strategy)
    raise SystemExit(f"HALT: unsupported intended_mode for prompt lookup: {intended_mode}")



def _repair_single_candidate(
    candidate: RepairCandidate,
    *,
    policy: RepairPolicy,
    download_dir: Path,
    download_cache: dict[str, Path],
    package_cache: dict[Path, PackageInfo],
    progress: RepairProgress | None = None,
) -> tuple[Any, dict[str, Any], int, dict[str, Any] | None]:
    if progress is not None:
        progress.update_stage("downloading", current_result="running")
    archive_path = _download_artifact(candidate.artifact_url, download_dir, download_cache)
    if progress is not None:
        progress.update_stage("extracting", current_result="running")
    pkg = _extract_package(archive_path, package_cache)
    if progress is not None:
        progress.update_stage("preparing package", current_result="running")
    detector_pkg, alias_details = _prepare_package(candidate, pkg)
    adapter = _build_adapter(candidate.detector, candidate.intended_mode)
    _tune_adapter(adapter, candidate.intended_mode, policy)
    _instrument_adapter_with_progress(adapter, progress)
    system_prompt, template_override = _prompt_overrides(candidate.intended_mode, candidate.prompt_strategy)

    attempts = policy.agentic_retry_attempts if candidate.intended_mode == "agentic" else 1
    last_result = None
    for attempt in range(1, attempts + 1):
        if progress is not None:
            progress.update_stage("running", attempt=attempt, current_result="running")
        result = adapter.run(
            detector_pkg,
            candidate.prompt_strategy,
            system_prompt,
            template_override,
        )
        last_result = result
        if result.experiment_mode != "error" or not _looks_retryable(result.details):
            return result, result.details or {}, attempt, alias_details
        if attempt < attempts:
            if progress is not None:
                progress.update_stage(
                    "retrying",
                    attempt=attempt + 1,
                    retry_wait_s=policy.agentic_retry_delay_seconds,
                    current_result="retrying",
                )
            time.sleep(policy.agentic_retry_delay_seconds)
    if last_result is None:  # pragma: no cover - defensive
        raise RuntimeError("repair rerun produced no result")
    return last_result, last_result.details or {}, attempts, alias_details



def _merged_details(
    candidate: RepairCandidate,
    result_details: dict[str, Any],
    *,
    alias_details: dict[str, Any] | None,
    repair_attempts: int,
) -> dict[str, Any]:
    merged = dict(result_details or {})
    if alias_details:
        merged.update(alias_details)
    merged["repair_script"] = "error_correct_production_data"
    merged["repair_timestamp"] = _utc_now()
    merged["repair_attempts"] = repair_attempts
    merged["repaired_from_error"] = True
    merged["repair_source_run_id"] = candidate.run_id
    merged["repair_source_tier"] = candidate.tier
    merged["repair_source_row_id"] = candidate.row_id
    merged["repair_source_experiment_mode"] = candidate.experiment_mode
    merged["original_error_details"] = copy.deepcopy(candidate.details)
    if candidate.intended_mode and "intended_mode" not in merged:
        merged["intended_mode"] = candidate.intended_mode
    return merged



def _with_db_manager(db_path: Path):
    original = DBManager.DB_PATH
    DBManager.DB_PATH = db_path
    try:
        db = DBManager()
    finally:
        DBManager.DB_PATH = original
    return db, original



def apply_repairs(
    db_path: Path,
    candidates: list[RepairCandidate],
    *,
    policy: RepairPolicy,
    dry_run: bool,
    progress: RepairProgress | None = None,
) -> list[RepairOutcome]:
    repair_plans = build_repair_run_plans(candidates)
    if dry_run:
        return [
            RepairOutcome(
                candidate=candidate,
                repair_run_id=repair_plans[candidate.run_id].repair_run_id,
                final_mode=candidate.experiment_mode,
                success=False,
                attempts=0,
                api_cost_usd=0.0,
                exec_time_ms=0,
                model_name="",
                details=candidate.details,
            )
            for candidate in candidates
        ]

    db, original_db_path = _with_db_manager(db_path)
    outcomes: list[RepairOutcome] = []
    try:
        download_cache: dict[str, Path] = {}
        package_cache: dict[Path, PackageInfo] = {}
        with tempfile.TemporaryDirectory(prefix="error-correct-") as tmpdir:
            download_dir = Path(tmpdir)
            for plan in repair_plans.values():
                db.create_eval_run(
                    plan.repair_run_id,
                    tier=plan.repair_tier,
                    sample_set=plan.sample_set,
                )
            for candidate in candidates:
                if progress is not None:
                    progress.start_candidate(candidate)
                plan = repair_plans[candidate.run_id]
                result, result_details, repair_attempts, alias_details = _repair_single_candidate(
                    candidate,
                    policy=policy,
                    download_dir=download_dir,
                    download_cache=download_cache,
                    package_cache=package_cache,
                    progress=progress,
                )
                merged_details = _merged_details(
                    candidate,
                    result_details,
                    alias_details=alias_details,
                    repair_attempts=repair_attempts,
                )
                if result.heuristic_flags is None:
                    heuristic_flags: list[str] = []
                else:
                    heuristic_flags = list(result.heuristic_flags)
                if progress is not None:
                    progress.update_stage("writing result", attempt=repair_attempts, current_result="writing")
                db.insert_eval_result(
                    run_id=plan.repair_run_id,
                    package_name=candidate.package_name,
                    version=candidate.version,
                    experiment_mode=result.experiment_mode,
                    intended_mode=candidate.intended_mode,
                    prompt_strategy=candidate.prompt_strategy,
                    detector=candidate.detector,
                    artifact_filename=candidate.artifact_filename,
                    artifact_url=candidate.artifact_url,
                    source_index_url=candidate.source_index_url,
                    sample_role=candidate.sample_role,
                    attack_vector=candidate.attack_vector,
                    resolver_policy=candidate.resolver_policy,
                    verdict=bool(result.verdict),
                    ground_truth=candidate.ground_truth,
                    heuristic_flags=heuristic_flags,
                    input_tokens=int(getattr(result, "input_tokens", 0) or 0),
                    output_tokens=int(getattr(result, "output_tokens", 0) or 0),
                    exec_time_ms=int(getattr(result, "exec_time_ms", 0) or 0),
                    api_cost_usd=float(getattr(result, "api_cost_usd", 0.0) or 0.0),
                    details=merged_details,
                )
                outcomes.append(
                    RepairOutcome(
                        candidate=candidate,
                        repair_run_id=plan.repair_run_id,
                        final_mode=result.experiment_mode,
                        success=result.experiment_mode != "error",
                        attempts=repair_attempts,
                        api_cost_usd=float(getattr(result, "api_cost_usd", 0.0) or 0.0),
                        exec_time_ms=int(getattr(result, "exec_time_ms", 0) or 0),
                        model_name=str(
                            merged_details.get("actual_model")
                            or merged_details.get("selected_model")
                            or merged_details.get("model")
                            or ""
                        ),
                        details=merged_details,
                    )
                )
                if progress is not None:
                    progress.record(
                        RepairProgressOutcome(
                            success=result.experiment_mode != "error",
                            cost_usd=float(getattr(result, "api_cost_usd", 0.0) or 0.0),
                            elapsed_s=float(int(getattr(result, "exec_time_ms", 0) or 0)) / 1000.0,
                            final_mode=result.experiment_mode,
                            detector=f"{candidate.detector}:{candidate.intended_mode}:{candidate.prompt_strategy}",
                            model_name=str(
                                merged_details.get("actual_model")
                                or merged_details.get("selected_model")
                                or merged_details.get("model")
                                or ""
                            ),
                            package_label=(
                                f"{candidate.package_name}=={candidate.version} "
                                f"[{candidate.artifact_filename}]"
                            ),
                            run_label=plan.repair_run_id,
                        )
                    )
    finally:
        db.close()
        DBManager.DB_PATH = original_db_path
    return outcomes



def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, required=True, help="Path to the production eval_results.db")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Create append-only correction runs. Without this flag the script only reports targets.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Explicitly request preview mode. This is also the default when --apply is omitted.",
    )
    parser.add_argument(
        "--include-agentic",
        choices=["on", "off"],
        default="off",
        help="Include agentic error rows in the repair scope (default: off)",
    )
    parser.add_argument(
        "--include-validation",
        choices=["on", "off"],
        default="off",
        help="Include validation tiers in the repair scope (default: off).",
    )
    parser.add_argument(
        "--include-repair-runs",
        choices=["on", "off"],
        default="off",
        help="Include existing :repair rows in the repair scope (default: off).",
    )
    parser.add_argument(
        "--sample-set",
        choices=("any", "dataset", "controls", "both"),
        default="any",
        help="Filter repair scope by sample set (default: any).",
    )
    parser.add_argument(
        "--run-id",
        action="append",
        default=[],
        help="Restrict repair scope to specific source run_id values. Repeat to target multiple runs.",
    )
    parser.add_argument(
        "--detector",
        action="append",
        default=[],
        help="Restrict repair scope to specific detector names. Repeat to target multiple detectors.",
    )
    parser.add_argument(
        "--intended-mode",
        action="append",
        default=[],
        help="Restrict repair scope to specific intended modes. Repeat to target multiple modes.",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=DEFAULT_MAX_TOKENS,
        help=f"Minimum max_tokens to force on rerun adapters (default: {DEFAULT_MAX_TOKENS}).",
    )
    parser.add_argument(
        "--llm-retries",
        type=int,
        default=DEFAULT_LLM_RETRY_ATTEMPTS,
        help=f"Minimum same-model retry count for non-agentic LLM reruns (default: {DEFAULT_LLM_RETRY_ATTEMPTS}).",
    )
    parser.add_argument(
        "--llm-retry-delay",
        type=float,
        default=DEFAULT_LLM_RETRY_DELAY_SECONDS,
        help=f"Minimum retry delay in seconds for non-agentic LLM reruns (default: {DEFAULT_LLM_RETRY_DELAY_SECONDS}).",
    )
    parser.add_argument(
        "--agentic-retries",
        type=int,
        default=DEFAULT_AGENTIC_RETRY_ATTEMPTS,
        help=f"Outer retry count for agentic reruns (default: {DEFAULT_AGENTIC_RETRY_ATTEMPTS}).",
    )
    parser.add_argument(
        "--agentic-retry-delay",
        type=float,
        default=DEFAULT_AGENTIC_RETRY_DELAY_SECONDS,
        help=f"Retry delay in seconds for agentic reruns (default: {DEFAULT_AGENTIC_RETRY_DELAY_SECONDS}).",
    )
    parser.add_argument(
        "--progress",
        choices=("auto", "always", "never"),
        default=DEFAULT_PROGRESS_MODE,
        help=f"Live repair progress display mode (default: {DEFAULT_PROGRESS_MODE}).",
    )
    parser.add_argument(
        "--verbose-preview",
        action="store_true",
        default=DEFAULT_VERBOSE_PREVIEW,
        help="Print detailed matched-run and per-row previews instead of compact grouped preflight counts.",
    )
    parser.add_argument(
        "--verbose-results",
        action="store_true",
        default=DEFAULT_VERBOSE_RESULTS,
        help="Print a line for every rerun result instead of only failures and summary totals.",
    )
    parser.add_argument(
        "--engine-console-logs",
        choices=("on", "off"),
        default=DEFAULT_ENGINE_CONSOLE_LOGS,
        help="Mirror analyzer engine INFO logs to the console during reruns (default: off).",
    )
    return parser.parse_args(argv)



def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    db_path = args.db.resolve()
    _ensure_db_shape(db_path)
    inventory = load_run_inventory(db_path)
    inventory_by_run_id = {run.run_id: run for run in inventory}
    policy = RepairPolicy(
        max_tokens=args.max_tokens,
        llm_retry_attempts=args.llm_retries,
        llm_retry_delay_seconds=args.llm_retry_delay,
        agentic_retry_attempts=args.agentic_retries,
        agentic_retry_delay_seconds=args.agentic_retry_delay,
    )
    matched_candidates = load_repair_candidates(
        db_path,
        sample_set=args.sample_set,
        run_ids=list(args.run_id),
        detectors=list(args.detector),
        intended_modes=list(args.intended_mode),
        include_agentic=args.include_agentic == "on",
        include_validation=args.include_validation == "on",
        include_repair_runs=args.include_repair_runs == "on",
    )
    excluded_agentic_rows = 0
    if args.include_agentic == "off":
        all_mode_candidates = load_repair_candidates(
            db_path,
            sample_set=args.sample_set,
            run_ids=list(args.run_id),
            detectors=list(args.detector),
            intended_modes=list(args.intended_mode),
            include_agentic=True,
            include_validation=args.include_validation == "on",
            include_repair_runs=args.include_repair_runs == "on",
        )
        excluded_agentic_rows = sum(
            1 for candidate in all_mode_candidates if candidate.intended_mode == "agentic"
        )
    rerunnable_candidates, skipped_candidates = partition_repair_candidates(matched_candidates)
    repair_plans = build_repair_run_plans(rerunnable_candidates)
    matched_run_ids = sorted({candidate.run_id for candidate in matched_candidates})

    print(f"DB: {db_path}")
    print("Filters:")
    print(f"  sample_set={args.sample_set}")
    print(f"  include_agentic={args.include_agentic}")
    print(f"  include_validation={args.include_validation}")
    print(f"  include_repair_runs={args.include_repair_runs}")
    if args.run_id:
        print(f"  run_ids={', '.join(args.run_id)}")
    if args.detector:
        print(f"  detectors={', '.join(args.detector)}")
    if args.intended_mode:
        print(f"  intended_modes={', '.join(args.intended_mode)}")
    print(
        "  aggressive_policy="
        f"max_tokens={policy.max_tokens} "
        f"llm_retries={policy.llm_retry_attempts} "
        f"llm_retry_delay={policy.llm_retry_delay_seconds}s "
        f"agentic_retries={policy.agentic_retry_attempts} "
        f"agentic_retry_delay={policy.agentic_retry_delay_seconds}s"
    )
    print("Preflight:")
    print(f"  matched_source_runs={len(matched_run_ids)}")
    print(f"  matched_error_rows={len(matched_candidates)}")
    print(f"  rerunnable_rows={len(rerunnable_candidates)}")
    print(f"  skipped_rows={len(skipped_candidates)}")
    print(f"  planned_repair_runs={len(repair_plans)}")
    if args.include_agentic == "off":
        print(f"  excluded_agentic_rows={excluded_agentic_rows}")

    skipped_counts = Counter(item.reason for item in skipped_candidates)
    for reason, count in sorted(skipped_counts.items()):
        print(f"  skipped[{reason}]={count}")

    _print_count_block("By sample set", _count_by(rerunnable_candidates, "sample_set"))
    _print_count_block("By source tier", _count_by(rerunnable_candidates, "tier"))
    _print_count_block("By detector", _count_by(rerunnable_candidates, "detector"))
    _print_count_block("By intended mode", _count_by(rerunnable_candidates, "intended_mode"))

    if args.verbose_preview:
        print("Matched source runs:")
        for run_id in matched_run_ids:
            run = inventory_by_run_id.get(run_id)
            if run is None:
                print(f"  {run_id}: metadata unavailable")
                continue
            print(
                f"  {run.run_id} tier={run.tier} sample_set={run.sample_set} "
                f"pkg_versions={run.pkg_versions} rows={run.row_count} created_at={run.created_at}"
            )
        if repair_plans:
            print("Planned correction runs:")
            for source_run_id, plan in sorted(repair_plans.items()):
                print(
                    f"  {plan.repair_run_id} <= {source_run_id} "
                    f"tier={plan.repair_tier} targeted_rows={plan.candidate_count}"
                )
        _print_candidate_list(
            "Rerunnable preview:",
            [
                f"{candidate.run_id} {candidate.detector}:{candidate.intended_mode}:{candidate.prompt_strategy} "
                f"{candidate.package_name}=={candidate.version} [{candidate.artifact_filename}]"
                for candidate in rerunnable_candidates
            ],
        )
        _print_candidate_list(
            "Skipped preview:",
            [
                f"{item.reason} :: {item.candidate.run_id} "
                f"{item.candidate.detector}:{item.candidate.intended_mode}:{item.candidate.prompt_strategy} "
                f"{item.candidate.package_name}=={item.candidate.version} [{item.candidate.artifact_filename}]"
                for item in skipped_candidates
            ],
        )

    if not matched_candidates:
        print("HALT: no error rows matched the requested filters.")
        return 1
    if not rerunnable_candidates:
        print("HALT: matched error rows exist, but none are rerunnable after preflight checks.")
        return 1

    if not args.apply:
        print("Dry-run only. Re-run with --apply to create correction runs.")
        return 0

    logger_cfg = _load_repair_logging_config(engine_console_logs=args.engine_console_logs == "on")
    setup_logger(logger_cfg)
    log_path = get_active_log_path()
    if log_path is not None:
        print(f"Detailed repair log: {log_path}")
    backup_path = _backup_db(db_path)
    print(f"Backup: {backup_path}")
    live_enabled = _should_use_progress(args.progress)
    plain_progress = args.progress != "never" and not live_enabled
    with RepairProgress(
        enabled=live_enabled,
        total_rows=len(rerunnable_candidates),
        plain_enabled=plain_progress,
    ) as progress:
        progress.skipped = len(skipped_candidates)
        outcomes = apply_repairs(
            db_path,
            rerunnable_candidates,
            policy=policy,
            dry_run=False,
            progress=progress,
        )

    repaired = sum(1 for outcome in outcomes if outcome.success)
    remaining = len(outcomes) - repaired
    total_cost = sum(outcome.api_cost_usd for outcome in outcomes)
    print("Final summary:")
    print(f"  attempted_reruns={len(outcomes)}")
    print(f"  repaired_rows={repaired}")
    print(f"  still_error_rows={remaining}")
    if skipped_candidates:
        print(f"  skipped_rows={len(skipped_candidates)}")
    if args.include_agentic == "off":
        print(f"  excluded_agentic_rows={excluded_agentic_rows}")
    print(f"  api_cost_usd=${total_cost:.4f}")
    print(
        f"  exit_status={'0 (all reruns repaired)' if remaining == 0 else '1 (one or more reruns still failed)'}"
    )
    for outcome in outcomes:
        if outcome.success and not args.verbose_results:
            continue
        status = "OK" if outcome.success else "ERROR"
        print(
            f"  {status} {outcome.repair_run_id} <= {outcome.candidate.run_id} "
            f"{outcome.candidate.detector}:{outcome.candidate.intended_mode}:{outcome.candidate.prompt_strategy} "
            f"{outcome.candidate.package_name}=={outcome.candidate.version} "
            f"attempts={outcome.attempts} final_mode={outcome.final_mode} "
            f"cost=${outcome.api_cost_usd:.4f}"
        )
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
