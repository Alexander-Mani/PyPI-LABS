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
import time
import urllib.parse
import urllib.request
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_ANALYZER_DIR = _REPO_ROOT / "src" / "analyzer"
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

REPAIR_TIER_SUFFIX = ":repair"
DEFAULT_MAX_TOKENS = 16384
DEFAULT_LLM_RETRY_ATTEMPTS = 5
DEFAULT_LLM_RETRY_DELAY_SECONDS = 45.0
DEFAULT_AGENTIC_RETRY_ATTEMPTS = 5
DEFAULT_AGENTIC_RETRY_DELAY_SECONDS = 60.0
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
    include_agentic: bool = True,
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
) -> tuple[Any, dict[str, Any], int, dict[str, Any] | None]:
    archive_path = _download_artifact(candidate.artifact_url, download_dir, download_cache)
    pkg = _extract_package(archive_path, package_cache)
    detector_pkg, alias_details = _prepare_package(candidate, pkg)
    adapter = _build_adapter(candidate.detector, candidate.intended_mode)
    _tune_adapter(adapter, candidate.intended_mode, policy)
    system_prompt, template_override = _prompt_overrides(candidate.intended_mode, candidate.prompt_strategy)

    attempts = policy.agentic_retry_attempts if candidate.intended_mode == "agentic" else 1
    last_result = None
    for attempt in range(1, attempts + 1):
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
                plan = repair_plans[candidate.run_id]
                result, result_details, repair_attempts, alias_details = _repair_single_candidate(
                    candidate,
                    policy=policy,
                    download_dir=download_dir,
                    download_cache=download_cache,
                    package_cache=package_cache,
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
                        details=merged_details,
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
        default="on",
        help="Include agentic error rows in the repair scope (default: on)",
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
    )
    rerunnable_candidates, skipped_candidates = partition_repair_candidates(matched_candidates)
    repair_plans = build_repair_run_plans(rerunnable_candidates)

    print(f"DB: {db_path}")
    print("Filters:")
    print(f"  sample_set={args.sample_set}")
    print(f"  include_agentic={args.include_agentic}")
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

    matched_run_ids = sorted({candidate.run_id for candidate in matched_candidates})
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
    print(f"Matched error rows: {len(matched_candidates)}")
    print(f"Rerunnable rows: {len(rerunnable_candidates)}")
    print(f"Skipped rows: {len(skipped_candidates)}")

    skipped_counts = Counter(item.reason for item in skipped_candidates)
    for reason, count in sorted(skipped_counts.items()):
        print(f"  skipped[{reason}]={count}")

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

    backup_path = _backup_db(db_path)
    print(f"Backup: {backup_path}")
    outcomes = apply_repairs(db_path, rerunnable_candidates, policy=policy, dry_run=False)

    repaired = sum(1 for outcome in outcomes if outcome.success)
    remaining = len(outcomes) - repaired
    print(f"Repaired rows: {repaired}")
    print(f"Still error rows after rerun: {remaining}")
    if skipped_candidates:
        print(f"Skipped rows (not attempted): {len(skipped_candidates)}")
    for outcome in outcomes:
        status = "OK" if outcome.success else "ERROR"
        print(
            f"  {status} {outcome.repair_run_id} <= {outcome.candidate.run_id} "
            f"{outcome.candidate.detector}:{outcome.candidate.intended_mode}:{outcome.candidate.prompt_strategy} "
            f"{outcome.candidate.package_name}=={outcome.candidate.version} attempts={outcome.attempts} final_mode={outcome.final_mode}"
        )
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
