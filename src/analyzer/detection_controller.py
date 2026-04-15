"""
detection_controller.py — Entry-point scanning evaluation orchestration.

EvalController reads tier-tagged YAML model configs, instantiates adapter
tracks (static SAST, LLM single-shot, LLM-raw, agentic), runs them in
parallel via ThreadPoolExecutor, and writes results to the DB.
"""

from __future__ import annotations

import os as _os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

from src.utils.logger import get_logger
from entry_extractor import PackageInfo
from adapters import (
    EvalDetectionResult,
    DetectorAdapter,
    StaticAdapter,
    GuardDogAdapter,
    LLMAdapter,
    LLMRawAdapter,
    AgenticAdapter,
)

log = get_logger()

TaskDescriptor = dict[str, str]


def _summarize_error(details: dict | None, limit: int = 500) -> str:
    if not details:
        return "no error details"
    message = str(details.get("error") or details)
    collapsed = " ".join(message.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def _adapter_name(adapter: DetectorAdapter) -> str:
    return (
        getattr(adapter, "_tool", None)
        or getattr(adapter, "_detector_name", None)
        or "unknown"
    )


def _adapter_mode(adapter: DetectorAdapter) -> str:
    explicit = getattr(adapter, "_experiment_mode", None)
    if explicit:
        return str(explicit)
    if isinstance(adapter, StaticAdapter):
        return "static"
    if isinstance(adapter, LLMRawAdapter):
        return "llm_raw"
    if isinstance(adapter, LLMAdapter):
        return "hybrid"
    if isinstance(adapter, AgenticAdapter):
        return "agentic"
    return "unknown"


def _task_descriptor(adapter: DetectorAdapter, strategy: str) -> TaskDescriptor:
    return {
        "detector": _adapter_name(adapter),
        "mode": _adapter_mode(adapter),
        "strategy": strategy,
    }


def _log_result(
    res: EvalDetectionResult,
    strategy: str,
    *,
    quiet_console: bool,
) -> None:
    target_log = log.bind(file_only=True) if quiet_console else log
    elapsed = res.exec_time_ms / 1000
    verdict_str = (
        "ERROR"
        if res.experiment_mode == "error"
        else "MALICIOUS" if res.verdict else "benign"
    )
    target_log.info(
        f"    ✓ {res.detector}:{res.experiment_mode}:{strategy}"
        f" -> {verdict_str} ({elapsed:.1f}s)"
    )
    if res.experiment_mode == "error":
        target_log.warning(f"      error detail: {_summarize_error(res.details)}")


# ---------------------------------------------------------------------------
# EvalController — orchestrates all adapter tracks in parallel
# ---------------------------------------------------------------------------

class EvalController:

    def __init__(
        self,
        configs_dir: str | Path,
        db,
        tier: str = "budget",
        model_config_stems: set[str] | None = None,
    ):
        # Lazy import to avoid cross-package issues at module load time.
        from src.data.db_manager import DBManager  # noqa: F401 (type reference)
        import yaml as _yaml
        self._db = db
        configs_dir = Path(configs_dir)
        selected_stems = set(model_config_stems) if model_config_stems is not None else None
        loaded_stems: set[str] = set()

        self._static: list[DetectorAdapter] = [
            StaticAdapter("bandit"),
            StaticAdapter("semgrep"),
            GuardDogAdapter(),
        ]

        self._llm: list[LLMAdapter] = []
        self._llm_raw: list[LLMRawAdapter] = []
        self._agentic: list[AgenticAdapter] = []

        for yaml_path in sorted(configs_dir.glob("*.yaml")):
            if yaml_path.stem == "prompts":
                continue  # strategy registry, not a model config
            with open(yaml_path, encoding="utf-8") as f:
                cfg = _yaml.safe_load(f)
            if selected_stems is None:
                cfg_tier = cfg.get("tier", "frontier")
                if cfg_tier != tier:
                    continue
            elif yaml_path.stem not in selected_stems:
                continue

            loaded_stems.add(yaml_path.stem)
            if "agentic" in yaml_path.stem:
                self._agentic.append(AgenticAdapter(yaml_path))
            else:
                self._llm.append(LLMAdapter(yaml_path))
                self._llm_raw.append(LLMRawAdapter(yaml_path))

        if selected_stems is not None:
            missing = sorted(selected_stems - loaded_stems)
            if missing:
                raise ValueError(
                    "Model profile references missing analyzer config(s): "
                    + ", ".join(missing)
                )

    def expected_non_static_detectors(self) -> set[str]:
        return {
            getattr(adapter, "_detector_name")
            for adapter in [*self._llm, *self._llm_raw, *self._agentic]
        }

    def _build_tasks(self, sast_only: bool = False) -> list[tuple]:
        # Build a uniform task list: (adapter, strategy, sys_override, tpl_override).
        # All adapters share the DetectorAdapter.run() signature so they can be
        # dispatched identically. Static adapters ignore the prompt params.
        tasks: list[tuple] = []
        for a in self._static:
            tasks.append((a, "zero_shot", None, None))

        if sast_only:
            return tasks

        from prompt_manager import PromptManager
        pm = PromptManager.instance()

        for a in self._llm:
            for s in pm.llm_strategy_names():
                sp, ut = pm.get_llm_strategy(s)
                tasks.append((a, s, sp, ut))
        for a in self._llm_raw:
            for s in pm.llm_strategy_names():
                sp, ut = pm.get_llm_strategy(s)
                tasks.append((a, s, sp, ut))
        for a in self._agentic:
            for s in pm.agentic_strategy_names():
                sp, im = pm.get_agentic_strategy(s)
                tasks.append((a, s, sp, im))

        return tasks

    def run(
        self,
        run_id: str,
        pkg: PackageInfo,
        ground_truth: bool | None = None,
        sast_only: bool = False,
        artifact_filename: str | None = None,
        artifact_url: str | None = None,
        source_index_url: str | None = None,
        sample_role: str | None = None,
        attack_vector: str | None = None,
        resolver_policy: str | None = None,
        on_tasks_prepared: Callable[[list[TaskDescriptor]], None] | None = None,
        on_result: Callable[[EvalDetectionResult, str, str], None] | None = None,
        quiet_console: bool = False,
    ) -> list[EvalDetectionResult]:
        tasks = self._build_tasks(sast_only=sast_only)
        if on_tasks_prepared is not None:
            on_tasks_prepared([
                _task_descriptor(adapter, strategy)
                for adapter, strategy, _sys_p, _tpl in tasks
            ])

        results: list[EvalDetectionResult] = []
        gt_label = ground_truth  # bool | None — derived from dataset labels

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures: dict = {
                pool.submit(a.run, pkg, strategy, sys_p, tpl): (a, strategy)
                for a, strategy, sys_p, tpl in tasks
            }

            for future in as_completed(futures):
                adapter, strategy = futures[future]
                intended_mode = _adapter_mode(adapter)
                try:
                    res = future.result()
                    _log_result(res, strategy, quiet_console=quiet_console)
                except Exception as exc:
                    name = _adapter_name(adapter)
                    res = EvalDetectionResult(
                        detector=name, experiment_mode="error",
                        verdict=False, confidence=None,
                        heuristic_flags=list(pkg.heuristic_flags),
                        exec_time_ms=0, api_cost_usd=0.0,
                        details={"error": str(exc)},
                    )
                    _log_result(res, strategy, quiet_console=quiet_console)

                results.append(res)
                if on_result is not None:
                    on_result(res, strategy, intended_mode)
                res.details.setdefault("intended_mode", intended_mode)
                # Propagate extractor-level bad-password skips into the result details.
                if pkg.bad_password_files:
                    res.details["skipped_bad_password"] = pkg.bad_password_files
                self._db.insert_eval_result(
                    run_id=run_id,
                    package_name=pkg.name,
                    version=pkg.version,
                    experiment_mode=res.experiment_mode,
                    prompt_strategy=strategy,
                    detector=res.detector,
                    artifact_filename=artifact_filename or "",
                    artifact_url=artifact_url,
                    source_index_url=source_index_url,
                    sample_role=sample_role,
                    attack_vector=attack_vector,
                    resolver_policy=resolver_policy,
                    verdict=res.verdict,
                    ground_truth=gt_label,
                    heuristic_flags=res.heuristic_flags,
                    input_tokens=res.input_tokens,
                    output_tokens=res.output_tokens,
                    exec_time_ms=res.exec_time_ms,
                    api_cost_usd=res.api_cost_usd,
                    details=res.details,
                )

        return results
