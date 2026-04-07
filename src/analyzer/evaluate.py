"""
evaluate.py — Run the full entry-point scanning pipeline against all sample
archives and report per-detector precision / recall / F1.

Ground truth labels are derived from folder membership: archives in
samples/benign/ are labelled False (benign), archives in
samples/malware_backstabbers_knife/ are labelled True (malicious).
Labels are stored at insert time and never passed to extractors or adapters.

Usage:
    python src/analyzer/evaluate.py [--config PATH] [--tier budget|medium|frontier]
                                    [--skip-validation] [--sast-only]

See CONCERNS.md for known limitations before interpreting results.
"""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path

import yaml
from rich.console import Console
from rich.table import Table

# Ensure repo root and src/analyzer/ are on sys.path (mirrors existing main.py pattern).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_ANALYZER_DIR = Path(__file__).resolve().parent
for _p in (_REPO_ROOT, _ANALYZER_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from src.utils.logger import get_logger, setup_logger
from src.data.db_manager import DBManager
from entry_extractor import EntryPointExtractor, _STEM_RE
from heuristic_filter import HeuristicFilter
from detection_controller import EvalController

log = get_logger()


# ---------------------------------------------------------------------------
# Financial air-gap constants — loaded from configs/models.json
# ---------------------------------------------------------------------------

with open(_REPO_ROOT / "configs" / "models.json", encoding="utf-8") as _f:
    _models_cfg = json.load(_f)

# {litellm_model_name: (input_price_per_1m_usd, output_price_per_1m_usd)}
_TOKEN_PRICES: dict[str, tuple[float, float]] = {
    k: (float(v[0]), float(v[1]))
    for k, v in _models_cfg.get("token_prices", {}).items()
}

_BUDGET_HARD_CAP_USD = 10.00


# ---------------------------------------------------------------------------
# EvaluationRunner
# ---------------------------------------------------------------------------

class EvaluationRunner:

    def __init__(self, config: dict, tier: str = "budget"):
        self._cfg  = config
        self._tier = tier
        self._db   = DBManager()
        self._extractor = EntryPointExtractor()
        self._filter    = HeuristicFilter()
        self._controller = EvalController(
            configs_dir=_ANALYZER_DIR / "configs",
            db=self._db,
            tier=tier,
        )
        self._samples_root = _REPO_ROOT / "samples"
        self._benign_cache:  list[tuple[Path, str, str, bool]] | None = None
        self._malware_cache: list[tuple[Path, str, str, bool]] | None = None

    # ------------------------------------------------------------------
    # Sample discovery (results cached after first call)
    # ------------------------------------------------------------------

    def _discover_benign(self) -> list[tuple[Path, str, str, bool]]:
        """
        Return (archive_path, name, version, is_malicious=False) for the latest
        version of each benign package. Skips the controls/ subdirectory.
        Result is cached after the first call to avoid double filesystem scan.
        """
        if self._benign_cache is not None:
            return self._benign_cache
        results: list[tuple[Path, str, str, bool]] = []
        for manifest_path in sorted(self._samples_root.glob("benign/*/manifest.json")):
            # Skip high-volume controls — they are for latency benchmarking.
            if "controls" in manifest_path.parts:
                continue
            try:
                entries = json.loads(manifest_path.read_text(encoding="utf-8"))
                if not entries:
                    continue
                latest = entries[-1]
                archive = manifest_path.parent / latest["filename"]
                if not archive.exists():
                    log.warning(f"Benign archive missing on disk: {archive}")
                    continue
                results.append((
                    archive,
                    manifest_path.parent.name,
                    latest.get("version", "unknown"),
                    False,
                ))
            except Exception as exc:
                log.warning(f"Could not read {manifest_path}: {exc}")
        self._benign_cache = results
        return results

    def _discover_malware(self) -> list[tuple[Path, str, str, bool]]:
        """
        Return (archive_path, name, version, is_malicious=True) for every malware
        archive (.zip, .tar.gz, .whl). Returns [] if the directory does not exist;
        the hard gate in run() handles it. See CONCERNS.md §2.
        Result is cached after the first call to avoid double filesystem scan.
        """
        if self._malware_cache is not None:
            return self._malware_cache
        malware_dir = self._samples_root / "malware_backstabbers_knife"
        if not malware_dir.exists():
            self._malware_cache = []
            return []
        archives = sorted(
            list(malware_dir.rglob("*.zip")) +
            list(malware_dir.rglob("*.tar.gz")) +
            list(malware_dir.rglob("*.whl"))
        )
        results: list[tuple[Path, str, str, bool]] = []
        for archive_path in archives:
            stem = archive_path.name
            for suffix in (".tar.gz", ".tar.bz2", ".tar.xz"):
                if stem.endswith(suffix):
                    stem = stem[: -len(suffix)]
                    break
            else:
                stem = Path(stem).stem  # strips .whl or .zip
            m = _STEM_RE.match(stem)
            if m:
                name, version = m.group(1), m.group(2)
            else:
                name, version = stem, "unknown"
            results.append((archive_path, name, version, True))
        self._malware_cache = results
        return results

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(self, skip_validation: bool = False, sast_only: bool = False) -> None:
        run_id = str(uuid.uuid4())
        log.info(f"EvaluationRunner start — run_id={run_id}  tier={self._tier}  sast_only={sast_only}")
        self._db.create_eval_run(run_id, tier=self._tier if not sast_only else "sast-only")

        if not skip_validation and not sast_only:
            self._validate_financial_airgap()

        benign_archives  = self._discover_benign()
        malware_archives = self._discover_malware()

        if not malware_archives and not sast_only:
            raise SystemExit(
                "HALT: samples/malware_backstabbers_knife/ is missing or contains no "
                ".zip/.tar.gz/.whl archives. Cannot compute Recall or F1 without "
                "malware samples. Stage the dataset first. Use --sast-only to run a "
                "false-positive benchmark without malware."
            )

        all_archives = benign_archives + malware_archives
        log.info(
            f"Archives: {len(benign_archives)} benign, "
            f"{len(malware_archives)} malware, "
            f"{len(all_archives)} total"
        )

        for archive_path, name, version, is_malicious in all_archives:
            log.info(f"  Processing {name} {version} ({archive_path.name})")
            try:
                pkg = self._extractor.extract(archive_path)
                # Override name/version with manifest values (more reliable than
                # archive-stem parsing for benign packages).
                pkg.name    = name
                pkg.version = version
                pkg = self._filter.scan(pkg)
                self._controller.run(
                    run_id=run_id, pkg=pkg,
                    ground_truth=is_malicious, sast_only=sast_only,
                )
            except Exception as exc:
                log.error(f"  Failed {archive_path.name}: {exc}")

        self._print_metrics(run_id)

    # ------------------------------------------------------------------
    # Financial air-gap validation
    # ------------------------------------------------------------------

    def _validate_financial_airgap(self) -> None:
        """
        Run one benign package through all active LLM adapters.
        Compare LiteLLM-reported cost against token-math estimate.
        Project to full dataset and HALT if projection > hard cap
        or if actual/expected diverge by > 20%.
        """
        benign = self._discover_benign()
        if not benign:
            log.warning("Financial validation: no benign archives found, skipping.")
            return

        archive_path, name, version, _ = benign[0]
        log.info(f"Financial validation: {name} {version} on tier={self._tier}")

        val_id = f"airgap-{uuid.uuid4()}"
        self._db.create_eval_run(val_id, tier=f"{self._tier}-validation")
        pkg = self._extractor.extract(archive_path)
        pkg.name    = name
        pkg.version = version
        pkg = self._filter.scan(pkg)
        results = self._controller.run(run_id=val_id, pkg=pkg)

        actual_total   = sum(r.api_cost_usd for r in results)
        expected_total = 0.0
        for r in results:
            model = r.details.get("model", "")
            if model in _TOKEN_PRICES:
                pin, pout = _TOKEN_PRICES[model]
                expected_total += (r.input_tokens * pin + r.output_tokens * pout) / 1_000_000

        log.info(
            f"Validation — actual cost: ${actual_total:.4f}  "
            f"expected: ${expected_total:.4f}"
        )

        if expected_total > 0 and actual_total > 0:
            divergence = abs(actual_total - expected_total) / expected_total
            if divergence > 0.20:
                raise SystemExit(
                    f"HALT: LiteLLM-reported cost (${actual_total:.4f}) diverges "
                    f"from token-math estimate (${expected_total:.4f}) by "
                    f"{divergence * 100:.1f}% > 20%. "
                    "Check model routing or pricing table."
                )

        n_packages = len(self._discover_benign()) + len(self._discover_malware())
        per_pkg    = actual_total if actual_total > 0 else expected_total
        projected  = per_pkg * n_packages
        log.info(
            f"Projected full-run cost: ${projected:.2f} "
            f"({n_packages} packages × ${per_pkg:.4f})"
        )
        if projected > _BUDGET_HARD_CAP_USD:
            raise SystemExit(
                f"HALT: projected cost ${projected:.2f} exceeds hard cap "
                f"${_BUDGET_HARD_CAP_USD}. Use --tier budget or --skip-validation."
            )

        log.info("Financial validation passed.")

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    def _print_metrics(self, run_id: str) -> None:
        results = self._db.get_eval_results_for_run(run_id)
        if not results:
            log.warning("No results stored — nothing to report.")
            return

        # Ground truth is stored per-row at insert time (folder-based labelling).
        # Rows with NULL ground_truth (legacy runs) are skipped and logged.
        # Rows with experiment_mode="error" (API/proxy failures) are excluded from
        # metrics — they are stored in the DB for debugging but are not real verdicts.
        stats: dict[str, dict[str, int]] = {}
        unknown_pkgs: set[str] = set()
        error_rows: set[str] = set()

        for r in results:
            if r.get("experiment_mode") == "error":
                error_rows.add(f"{r['detector']}:{r['prompt_strategy']}")
                continue
            stored_gt = r.get("ground_truth")
            if stored_gt is None:
                unknown_pkgs.add(r["package_name"])
                continue
            true_label = bool(stored_gt)

            key = f"{r['detector']}:{r['experiment_mode']}:{r['prompt_strategy']}"
            if key not in stats:
                stats[key] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

            predicted = bool(r["verdict"])
            if predicted and true_label:
                stats[key]["TP"] += 1
            elif not predicted and not true_label:
                stats[key]["TN"] += 1
            elif predicted and not true_label:
                stats[key]["FP"] += 1
            else:
                stats[key]["FN"] += 1

        if error_rows:
            log.warning(
                f"Excluded {len(error_rows)} error row(s) from metrics "
                f"(API/proxy failures): {sorted(error_rows)}"
            )
        if unknown_pkgs:
            log.warning(f"Ground truth missing for: {sorted(unknown_pkgs)}")

        table = Table(title=f"Evaluation Results  |  run_id: {run_id}", show_lines=True)
        table.add_column("Detector : Mode : Strategy", style="cyan", no_wrap=True)
        table.add_column("TP",  justify="right")
        table.add_column("TN",  justify="right")
        table.add_column("FP",  justify="right", style="red")
        table.add_column("FN",  justify="right", style="yellow")
        table.add_column("Precision", justify="right")
        table.add_column("Recall",    justify="right")
        table.add_column("F1",        justify="right")

        for key in sorted(stats):
            s  = stats[key]
            tp, tn, fp, fn = s["TP"], s["TN"], s["FP"], s["FN"]
            prec = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
            rec  = tp / (tp + fn) if (tp + fn) > 0 else float("nan")
            f1   = (2 * prec * rec / (prec + rec)
                    if (prec + rec) > 0 else float("nan"))
            table.add_row(
                key,
                str(tp), str(tn), str(fp), str(fn),
                f"{prec:.2f}" if prec == prec else "n/a",
                f"{rec:.2f}"  if rec  == rec  else "n/a",
                f"{f1:.2f}"   if f1   == f1   else "n/a",
            )

        Console().print(table)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="PyPi-SCADA entry-point evaluation pipeline"
    )
    parser.add_argument(
        "--config", default=str(_ANALYZER_DIR / "config.yaml"),
        help="Path to analyzer config YAML",
    )
    parser.add_argument(
        "--tier", choices=["budget", "medium", "frontier"], default="budget",
        help="Model tier to use (default: budget)",
    )
    parser.add_argument(
        "--skip-validation", action="store_true",
        help="Skip the financial air-gap validation run",
    )
    parser.add_argument(
        "--sast-only", action="store_true",
        help="Run only static tools (Bandit/Semgrep), skip all LLM/agentic adapters",
    )
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    setup_logger(cfg)
    EvaluationRunner(cfg, tier=args.tier).run(
        skip_validation=args.skip_validation,
        sast_only=args.sast_only,
    )
