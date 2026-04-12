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

from src.utils.logger import get_logger
from entry_extractor import PackageInfo
from adapters import (
    EvalDetectionResult,
    DetectorAdapter,
    StaticAdapter,
    LLMAdapter,
    LLMRawAdapter,
    AgenticAdapter,
)

log = get_logger()


# ---------------------------------------------------------------------------
# EvalController — orchestrates all adapter tracks in parallel
# ---------------------------------------------------------------------------

class EvalController:

    def __init__(self, configs_dir: str | Path, db, tier: str = "budget"):
        # Lazy import to avoid cross-package issues at module load time.
        from src.data.db_manager import DBManager  # noqa: F401 (type reference)
        import yaml as _yaml
        self._db = db
        configs_dir = Path(configs_dir)

        self._static: list[StaticAdapter] = [
            StaticAdapter("bandit"),
            StaticAdapter("semgrep"),
        ]

        self._llm: list[LLMAdapter] = []
        self._llm_raw: list[LLMRawAdapter] = []
        self._agentic: list[AgenticAdapter] = []

        for yaml_path in sorted(configs_dir.glob("*.yaml")):
            if yaml_path.stem == "prompts":
                continue  # strategy registry, not a model config
            with open(yaml_path, encoding="utf-8") as f:
                cfg = _yaml.safe_load(f)
            cfg_tier = cfg.get("tier", "frontier")
            if cfg_tier != tier:
                continue
            if "agentic" in yaml_path.stem:
                self._agentic.append(AgenticAdapter(yaml_path))
            else:
                self._llm.append(LLMAdapter(yaml_path))
                self._llm_raw.append(LLMRawAdapter(yaml_path))

    def run(
        self,
        run_id: str,
        pkg: PackageInfo,
        ground_truth: bool | None = None,
        sast_only: bool = False,
    ) -> list[EvalDetectionResult]:
        from prompt_manager import PromptManager
        pm = PromptManager.instance()

        # Build a uniform task list: (adapter, strategy, sys_override, tpl_override).
        # All adapters share the DetectorAdapter.run() signature so they can be
        # dispatched identically. Static adapters ignore the prompt params.
        tasks: list[tuple] = []
        for a in self._static:
            tasks.append((a, "zero_shot", None, None))

        if not sast_only:
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

        results: list[EvalDetectionResult] = []
        gt_label = ground_truth  # bool | None — derived from folder membership

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures: dict = {
                pool.submit(a.run, pkg, strategy, sys_p, tpl): (a, strategy)
                for a, strategy, sys_p, tpl in tasks
            }

            for future in as_completed(futures):
                adapter, strategy = futures[future]
                try:
                    res = future.result()
                    elapsed = res.exec_time_ms / 1000
                    verdict_str = "MALICIOUS" if res.verdict else "benign"
                    log.info(
                        f"    ✓ {res.detector}:{res.experiment_mode}:{strategy}"
                        f" → {verdict_str} ({elapsed:.1f}s)"
                    )
                except Exception as exc:
                    name = getattr(adapter, "_tool", None) or getattr(adapter, "_detector_name", None) or "unknown"
                    res = EvalDetectionResult(
                        detector=name, experiment_mode="error",
                        verdict=False, confidence=None,
                        heuristic_flags=list(pkg.heuristic_flags),
                        exec_time_ms=0, api_cost_usd=0.0,
                        details={"error": str(exc)},
                    )

                results.append(res)
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
