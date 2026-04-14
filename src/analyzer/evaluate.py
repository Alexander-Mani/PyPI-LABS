"""
evaluate.py — Run the full entry-point scanning pipeline against artifacts
resolved from the local PyPI simulator and report per-detector precision /
recall / F1.

Ground truth labels are derived from folder membership: archives in
samples/benign/ are labelled False (benign), archives in
samples/malware_backstabbers_knife/ are labelled True (malicious).
The analyzer downloads matching artifacts from the simulator before scanning;
labels are stored at insert time and never passed to extractors or adapters.

Usage:
    python src/analyzer/evaluate.py [--config PATH] [--tier budget|medium|frontier]
                                    [--skip-validation] [--sast-only]
                                    [--dry-run-resolution] [--verbose]

See CONCERNS.md for known limitations before interpreting results.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

# Ensure repo root and src/analyzer/ are on sys.path (mirrors existing main.py pattern).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_ANALYZER_DIR = Path(__file__).resolve().parent
for _p in (_REPO_ROOT, _ANALYZER_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from src.utils.logger import get_logger, setup_logger
from src.data.db_manager import DBManager
from entry_extractor import EntryPointExtractor
from heuristic_filter import HeuristicFilter
from detection_controller import EvalController
from simulator_resolver import (
    IndexArtifact,
    ResolvedSample,
    SimpleIndexError,
    SimulatorResolver,
    dist_suffix,
    normalize_project_name,
    parse_archive_name_version,
)

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
_STEM_RE = re.compile(r"^(.+?)-(\d[^-]*)(?:-.*)?$")


@dataclass(frozen=True)
class GroundTruthLabel:
    is_malicious: bool
    sample_role: str
    attack_vector: str | None = None
    baseline_target: str | None = None


# ---------------------------------------------------------------------------
# EvaluationRunner
# ---------------------------------------------------------------------------

class EvaluationRunner:

    def __init__(
        self,
        config: dict,
        tier: str = "budget",
        versions_per_project: int = 2,
        artifact_policy: str = "pip+sdist",
        include_controls: bool = False,
    ):
        self._cfg  = config
        self._tier = tier
        if versions_per_project < 1:
            raise ValueError("versions_per_project must be >= 1")
        self._versions_per_project = versions_per_project
        self._artifact_policy = artifact_policy
        self._include_controls = include_controls
        self._db   = DBManager()
        self._extractor = EntryPointExtractor()
        self._filter    = HeuristicFilter()
        self._controller = EvalController(
            configs_dir=_ANALYZER_DIR / "configs",
            db=self._db,
            tier=tier,
        )
        self._samples_root = _REPO_ROOT / "samples"
        self._simulator_url = config.get("simulator", {}).get("base_url", "http://127.0.0.1:8080")
        self._resolver = SimulatorResolver(
            base_url=self._simulator_url,
            cache_dir=_REPO_ROOT / ".cache" / "simulator-artifacts",
        )
        self._benign_cache:  list[tuple[Path, str, str, bool]] | None = None
        self._malware_cache: list[tuple[Path, str, str, bool]] | None = None
        self._truth_cache: dict[tuple[str, str], GroundTruthLabel] | None = None
        self._lkgr_cache: dict[str, set[str]] | None = None
        self._resolved_cache: list[ResolvedSample] | None = None

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
    # Simulator-resolved sample planning
    # ------------------------------------------------------------------

    def _read_meta(self, package_dir: Path) -> dict:
        meta_path = package_dir / "meta.json"
        if not meta_path.exists():
            return {}
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning(f"Could not read {meta_path}: {exc}")
            return {}

    def _load_dataset_csv(self) -> tuple[dict[str, str], dict[str, set[str]]]:
        vector_by_project: dict[str, str] = {}
        lkgr_by_project: dict[str, set[str]] = {}
        csv_path = self._samples_root / "samples_last_version.csv"
        if not csv_path.exists():
            return vector_by_project, lkgr_by_project

        with csv_path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                project = row.get("Package_Name")
                if not project:
                    continue
                key = normalize_project_name(project)
                attack_vector = row.get("Attack_Vector") or ""
                if attack_vector:
                    vector_by_project[key] = attack_vector
                lkgr = (row.get("LKGR") or "").strip()
                if lkgr and lkgr.upper() != "N/A":
                    lkgr_by_project.setdefault(key, set()).add(lkgr)

        return vector_by_project, lkgr_by_project

    def _record_truth(
        self,
        truth: dict[tuple[str, str], GroundTruthLabel],
        *,
        project: str,
        version: str,
        label: GroundTruthLabel,
    ) -> None:
        key = (normalize_project_name(project), version)
        existing = truth.get(key)
        if existing and existing.is_malicious != label.is_malicious:
            raise SystemExit(
                "HALT: conflicting ground truth for "
                f"{key[0]}=={key[1]} ({existing.sample_role} vs {label.sample_role})"
            )
        truth[key] = label

    def _build_ground_truth_index(self) -> tuple[dict[tuple[str, str], GroundTruthLabel], dict[str, set[str]]]:
        """
        Build version-aware labels from dataset metadata. These labels drive
        metrics only; the scanned artifact bytes are fetched from the simulator.
        """
        if self._truth_cache is not None and self._lkgr_cache is not None:
            return self._truth_cache, self._lkgr_cache

        vector_by_project, lkgr_by_project = self._load_dataset_csv()
        truth: dict[tuple[str, str], GroundTruthLabel] = {}

        def _add_manifest(manifest_path: Path, sample_role: str) -> None:
            package_dir = manifest_path.parent
            meta = self._read_meta(package_dir)
            project = package_dir.name
            attack_vector = meta.get("attack_vector") or vector_by_project.get(
                normalize_project_name(project)
            )
            baseline_target = meta.get("malicious_package") or meta.get("target_package")
            try:
                entries = json.loads(manifest_path.read_text(encoding="utf-8"))
            except Exception as exc:
                log.warning(f"Could not read {manifest_path}: {exc}")
                return

            for entry in entries:
                version = str(entry.get("version", "")).strip()
                if not version:
                    continue
                self._record_truth(
                    truth,
                    project=project,
                    version=version,
                    label=GroundTruthLabel(
                        is_malicious=False,
                        sample_role=sample_role,
                        attack_vector=attack_vector,
                        baseline_target=baseline_target,
                    ),
                )

        for manifest_path in sorted(self._samples_root.glob("benign/*/manifest.json")):
            if "controls" in manifest_path.parts:
                continue
            _add_manifest(manifest_path, "benign")

        if self._include_controls:
            control_roots = [
                self._samples_root / "controls",
                self._samples_root / "benign" / "controls",
            ]
            for control_root in control_roots:
                for manifest_path in sorted(control_root.glob("*/manifest.json")):
                    _add_manifest(manifest_path, "control")

        malware_dir = self._samples_root / "malware_backstabbers_knife"
        if malware_dir.exists():
            archives = sorted(
                list(malware_dir.rglob("*.zip")) +
                list(malware_dir.rglob("*.tar.gz")) +
                list(malware_dir.rglob("*.whl"))
            )
            for archive_path in archives:
                parsed = parse_archive_name_version(archive_path.name)
                if parsed is None:
                    log.warning(f"Skipping malware archive with unparseable name: {archive_path}")
                    continue
                project, version = parsed
                self._record_truth(
                    truth,
                    project=project,
                    version=version,
                    label=GroundTruthLabel(
                        is_malicious=True,
                        sample_role="malware",
                        attack_vector=vector_by_project.get(project),
                        baseline_target=None,
                    ),
                )

        self._truth_cache = truth
        self._lkgr_cache = lkgr_by_project
        return truth, lkgr_by_project

    def _resolve_simulator_samples(self, download: bool = True) -> list[ResolvedSample]:
        if download and self._resolved_cache is not None:
            return self._resolved_cache

        truth, lkgr_by_project = self._build_ground_truth_index()
        if not truth:
            raise SystemExit("HALT: no labelled dataset versions found under samples/.")

        resolved: list[ResolvedSample] = []
        projects = sorted({project for project, _ in truth})
        for project in projects:
            try:
                artifacts = self._resolver.list_project_artifacts(project)
            except SimpleIndexError as exc:
                raise SystemExit(f"HALT: {exc}") from exc
            if not artifacts:
                continue

            index_versions = {artifact.version for artifact in artifacts}
            labelled_versions = {version for p, version in truth if p == project}
            selectable_versions = index_versions.intersection(labelled_versions)
            selected_versions = self._resolver.select_versions(
                selectable_versions,
                count=self._versions_per_project,
                extra_versions=lkgr_by_project.get(project, set()),
            )
            if not selected_versions:
                log.warning(
                    f"No labelled simulator versions selected for {project}; "
                    f"index={sorted(index_versions)} labelled={sorted(labelled_versions)}"
                )
                continue

            for version in selected_versions:
                label = truth.get((project, version))
                if label is None:
                    log.warning(f"Skipping unlabelled simulator version: {project}=={version}")
                    continue
                version_artifacts = [artifact for artifact in artifacts if artifact.version == version]
                selected_artifacts = self._resolver.select_artifacts(
                    version_artifacts,
                    policy=self._artifact_policy,
                )
                for artifact in selected_artifacts:
                    archive_path = (
                        self._resolver.download_artifact(artifact)
                        if download
                        else self._resolver.cache_dir / artifact.project / artifact.version / artifact.filename
                    )
                    resolved.append(ResolvedSample(
                        archive_path=archive_path,
                        package_name=project,
                        version=version,
                        ground_truth=label.is_malicious,
                        artifact_filename=artifact.filename,
                        artifact_url=artifact.url,
                        source_index_url=self._resolver.project_index_url(project),
                        sample_role=label.sample_role,
                        attack_vector=label.attack_vector,
                        resolver_policy=json.dumps({
                            "version_strategy": "latest_n_stable_plus_lkgr",
                            "versions_per_project": self._versions_per_project,
                            "artifact_policy": self._artifact_policy,
                            "pre_release_policy": "ignore_unless_no_stable",
                        }, sort_keys=True),
                    ))

        if download:
            self._resolved_cache = resolved
        return resolved

    def _log_sample_plan(self, samples: list[ResolvedSample]) -> None:
        projects = {s.package_name for s in samples}
        versions = {(s.package_name, s.version) for s in samples}
        malicious_projects = {s.package_name for s in samples if s.ground_truth}
        malicious_versions = {(s.package_name, s.version) for s in samples if s.ground_truth}
        benign_versions = {(s.package_name, s.version) for s in samples if not s.ground_truth}

        log.info(
            "Simulator-resolved samples: "
            f"{len(projects)} project(s), {len(versions)} version(s), "
            f"{len(samples)} artifact(s)"
        )
        log.info(
            "  Ground truth split: "
            f"{len(malicious_projects)} malicious project(s), "
            f"{len(malicious_versions)} malicious version(s), "
            f"{len(benign_versions)} benign/control version(s)"
        )

    def _download_sample(self, sample: ResolvedSample) -> Path:
        artifact = IndexArtifact(
            project=sample.package_name,
            version=sample.version,
            filename=sample.artifact_filename,
            url=sample.artifact_url,
            kind="wheel" if dist_suffix(sample.artifact_filename) == ".whl" else "sdist",
        )
        return self._resolver.download_artifact(artifact)

    # ------------------------------------------------------------------
    # Main loop
    # ------------------------------------------------------------------

    def run(
        self,
        skip_validation: bool = False,
        sast_only: bool = False,
        dry_run_resolution: bool = False,
    ) -> None:
        run_id = str(uuid.uuid4())
        log.info(f"EvaluationRunner start — run_id={run_id}  tier={self._tier}  sast_only={sast_only}")
        self._db.create_eval_run(run_id, tier=self._tier if not sast_only else "sast-only")

        if not skip_validation and not sast_only and not dry_run_resolution:
            self._validate_financial_airgap()

        samples = self._resolve_simulator_samples(download=not dry_run_resolution)
        self._log_sample_plan(samples)

        if not any(sample.ground_truth for sample in samples) and not sast_only:
            raise SystemExit(
                "HALT: no labelled malicious versions were resolved from the simulator. "
                "Cannot compute Recall or F1 without malware samples. Stage and upload "
                "the dataset first. Use --sast-only for a false-positive benchmark."
            )

        if dry_run_resolution:
            for sample in samples:
                label = "malicious" if sample.ground_truth else sample.sample_role
                log.info(
                    f"  would fetch {sample.package_name}=={sample.version} "
                    f"{sample.artifact_filename} [{label}]"
                )
            return

        for sample in samples:
            log.info(
                f"  Processing {sample.package_name} {sample.version} "
                f"({sample.artifact_filename})"
            )
            try:
                pkg = self._extractor.extract(sample.archive_path)
                # Override name/version with simulator-resolved values.
                pkg.name    = sample.package_name
                pkg.version = sample.version
                log.info(
                    f"    Decoded {len(pkg.files)} file(s) "
                    f"({len(pkg.files_raw)} entry point(s))"
                    + (f"  [bad-password: {pkg.bad_password_files}]"
                       if pkg.bad_password_files else "")
                )
                pkg = self._filter.scan(pkg)
                if pkg.heuristic_flags:
                    log.info(f"    Heuristic flags: {', '.join(pkg.heuristic_flags)}")
                results = self._controller.run(
                    run_id=run_id, pkg=pkg,
                    ground_truth=sample.ground_truth, sast_only=sast_only,
                    artifact_filename=sample.artifact_filename,
                    artifact_url=sample.artifact_url,
                    source_index_url=sample.source_index_url,
                    sample_role=sample.sample_role,
                    attack_vector=sample.attack_vector,
                    resolver_policy=sample.resolver_policy,
                )
                n_valid   = sum(1 for r in results if r.experiment_mode != "error")
                n_flagged = sum(1 for r in results if r.verdict and r.experiment_mode != "error")
                log.info(f"    Verdict: {n_flagged}/{n_valid} detector(s) flagged malicious")
            except Exception as exc:
                log.error(f"  Failed {sample.artifact_filename}: {exc}")

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
        samples = self._resolve_simulator_samples(download=False)
        benign_sample = next((sample for sample in samples if not sample.ground_truth), None)
        if benign_sample is None:
            log.warning("Financial validation: no benign simulator sample found, skipping.")
            return

        log.info(
            f"Financial validation: {benign_sample.package_name} "
            f"{benign_sample.version} on tier={self._tier}"
        )

        val_id = f"airgap-{uuid.uuid4()}"
        self._db.create_eval_run(val_id, tier=f"{self._tier}-validation")
        validation_archive = self._download_sample(benign_sample)
        pkg = self._extractor.extract(validation_archive)
        pkg.name    = benign_sample.package_name
        pkg.version = benign_sample.version
        pkg = self._filter.scan(pkg)
        results = self._controller.run(
            run_id=val_id,
            pkg=pkg,
            ground_truth=benign_sample.ground_truth,
            artifact_filename=benign_sample.artifact_filename,
            artifact_url=benign_sample.artifact_url,
            source_index_url=benign_sample.source_index_url,
            sample_role=benign_sample.sample_role,
            attack_vector=benign_sample.attack_vector,
            resolver_policy=benign_sample.resolver_policy,
        )

        llm_results = [r for r in results if r.experiment_mode != "static"]
        successful_llm_results = [r for r in llm_results if r.experiment_mode != "error"]
        tokenized_llm_results = [
            r for r in successful_llm_results
            if (r.input_tokens + r.output_tokens) > 0
        ]

        if not llm_results:
            raise SystemExit(
                "HALT: financial validation did not run any LLM/agentic adapters. "
                "Check tier selection and analyzer model configs."
            )
        if not successful_llm_results:
            raise SystemExit(
                "HALT: financial validation produced no successful LLM/agentic "
                "results. Check LiteLLM proxy readiness and model routing."
            )
        if not tokenized_llm_results:
            raise SystemExit(
                "HALT: financial validation produced successful LLM/agentic rows "
                "with zero token usage. Check LiteLLM proxy/model routing."
            )

        missing_price_models = sorted(
            {
                str(r.details.get("model", ""))
                for r in tokenized_llm_results
                if str(r.details.get("model", "")) not in _TOKEN_PRICES
            }
        )
        if missing_price_models:
            raise SystemExit(
                "HALT: missing token price configuration for model(s): "
                + ", ".join(missing_price_models)
            )

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
        elif expected_total > 0:
            log.warning(
                "LiteLLM reported zero cost for nonzero LLM token usage; "
                "using token-math estimate for budget projection."
            )

        n_packages = len(samples)
        per_pkg    = actual_total if actual_total > 0 else expected_total
        projected  = per_pkg * n_packages
        log.info(
            f"Projected full-run cost: ${projected:.2f} "
            f"({n_packages} selected artifact(s) × ${per_pkg:.4f})"
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
        from rich.console import Console
        from rich.table import Table

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
        error_rows: list[str] = []

        for r in results:
            if r.get("experiment_mode") == "error":
                error_rows.append(
                    f"{r['package_name']}=={r['version']}:"
                    f"{r.get('artifact_filename', '')}:"
                    f"{r['detector']}:{r['prompt_strategy']}"
                )
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
                f"(API/proxy failures)."
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
    import yaml

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
    parser.add_argument(
        "--dry-run-resolution",
        action="store_true",
        help="Resolve simulator samples and print the selected artifacts without scanning",
    )
    parser.add_argument(
        "--versions-per-project",
        type=int,
        default=2,
        help="PEP 440 latest-N stable versions to evaluate per project (default: 2)",
    )
    parser.add_argument(
        "--artifact-policy",
        choices=["pip", "pip+sdist", "sdist"],
        default="pip+sdist",
        help="Artifact selection per selected version (default: pip+sdist)",
    )
    parser.add_argument(
        "--include-controls",
        action="store_true",
        help="Include high-volume controls in simulator-resolved evaluation",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG-level logging (raw prompts, responses, per-file extraction)",
    )
    args = parser.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)
    if args.verbose:
        # Preserve configured sinks; just raise their level before first setup.
        cfg.setdefault("logging", {})["level"] = "DEBUG"
    setup_logger(cfg)
    EvaluationRunner(
        cfg,
        tier=args.tier,
        versions_per_project=args.versions_per_project,
        artifact_policy=args.artifact_policy,
        include_controls=args.include_controls,
    ).run(
        skip_validation=args.skip_validation,
        sast_only=args.sast_only,
        dry_run_resolution=args.dry_run_resolution,
    )
