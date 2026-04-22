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
    python src/analyzer/evaluate.py [--config PATH] [--profile budget]
                                    [--tier budget|medium|frontier]
                                    [--gemini on|off]
                                    [--skip-validation] [--sast-only]
                                    [--skip-static] [--skip-agentic]
                                    [--only-agentic]
                                    [--identity-alias-probe]
                                    [--dry-run-resolution]
                                    [--progress auto|always|never]
                                    [--run-id-prefix PREFIX]
                                    [--verbose]

See CONCERNS.md for known limitations before interpreting results.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import uuid
from dataclasses import dataclass, replace
from pathlib import Path

# Ensure repo root and src/analyzer/ are on sys.path (mirrors existing main.py pattern).
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_ANALYZER_DIR = Path(__file__).resolve().parent
for _p in (_REPO_ROOT, _ANALYZER_DIR):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from src.utils.logger import get_active_log_path, get_logger, setup_logger
from src.data.db_manager import DBManager
from entry_extractor import EntryPointExtractor
from heuristic_filter import HeuristicFilter
from identity_mask import mask_package_identity
from detection_controller import EvalController
from progress_ui import AnalyzerProgress, should_use_progress
from raw_experiment_log import RawExperimentLog
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
_COST_DIVERGENCE_WARN_THRESHOLD = 0.20
_STEM_RE = re.compile(r"^(.+?)-(\d[^-]*)(?:-.*)?$")
_RUN_ID_PREFIX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_PROFILES_PATH = _REPO_ROOT / "configs" / "evaluation_profiles.yaml"


@dataclass(frozen=True)
class GroundTruthLabel:
    is_malicious: bool
    sample_role: str
    attack_vector: str | None = None
    baseline_target: str | None = None


@dataclass(frozen=True)
class EvaluationProfile:
    name: str
    tier: str
    config_stems: set[str]
    include_controls: bool | None = None
    package_limits: dict[str, int] | None = None


@dataclass(frozen=True)
class ResolvedPackage:
    project: str
    version: str
    label: GroundTruthLabel
    artifacts: list[IndexArtifact]


def _make_run_id(prefix: str | None = None, *, validation: bool = False) -> str:
    suffix = str(uuid.uuid4())
    if validation:
        suffix = f"airgap-{suffix}"
    if prefix:
        if not _RUN_ID_PREFIX_RE.fullmatch(prefix):
            raise SystemExit(
                "HALT: --run-id-prefix must start with an alphanumeric character "
                "and contain only letters, digits, '.', '_' or '-' (max 64 chars)."
            )
        return f"{prefix}-{suffix}"
    return suffix


def _load_evaluation_profile(profile_name: str) -> EvaluationProfile:
    import yaml as _yaml

    with open(_PROFILES_PATH, encoding="utf-8") as f:
        data = _yaml.safe_load(f) or {}

    profiles = data.get("profiles", {})
    profile = profiles.get(profile_name)
    if profile is None:
        known = ", ".join(sorted(profiles)) or "none"
        raise SystemExit(f"HALT: unknown evaluation profile '{profile_name}'. Known: {known}")

    tier = str(profile.get("tier", "budget"))
    configs = profile.get("configs") or []
    if not isinstance(configs, list) or not all(isinstance(item, str) for item in configs):
        raise SystemExit(
            f"HALT: evaluation profile '{profile_name}' must define a non-empty "
            "list of analyzer config stems under 'configs'."
        )
    if not configs:
        raise SystemExit(f"HALT: evaluation profile '{profile_name}' selects no model configs.")

    resolver_cfg = profile.get("resolver", {})
    if not isinstance(resolver_cfg, dict):
        raise SystemExit(
            f"HALT: evaluation profile '{profile_name}' resolver section must be a mapping."
        )

    include_controls = resolver_cfg.get("include_controls")
    if include_controls is not None and not isinstance(include_controls, bool):
        raise SystemExit(
            f"HALT: evaluation profile '{profile_name}' resolver.include_controls "
            "must be true or false."
        )

    raw_limits = resolver_cfg.get("package_limits")
    package_limits: dict[str, int] | None = None
    if raw_limits is not None:
        if not isinstance(raw_limits, dict):
            raise SystemExit(
                f"HALT: evaluation profile '{profile_name}' resolver.package_limits "
                "must be a mapping."
            )
        valid_roles = {"malicious", "benign", "control"}
        package_limits = {}
        for role, limit in raw_limits.items():
            if role not in valid_roles:
                raise SystemExit(
                    f"HALT: evaluation profile '{profile_name}' has unknown "
                    f"package limit role '{role}'. Valid roles: {sorted(valid_roles)}"
                )
            if not isinstance(limit, int) or limit < 0:
                raise SystemExit(
                    f"HALT: evaluation profile '{profile_name}' package limit for "
                    f"'{role}' must be a non-negative integer."
                )
            package_limits[role] = limit

    return EvaluationProfile(
        name=profile_name,
        tier=tier,
        config_stems=set(configs),
        include_controls=include_controls,
        package_limits=package_limits,
    )


def _load_model_config(stem: str) -> dict:
    import yaml as _yaml

    cfg_path = _ANALYZER_DIR / "configs" / f"{stem}.yaml"
    if not cfg_path.exists():
        raise SystemExit(f"HALT: analyzer config does not exist: {stem}")
    with cfg_path.open(encoding="utf-8") as f:
        cfg = _yaml.safe_load(f) or {}
    return cfg


def _is_gemini_config(stem: str) -> bool:
    cfg = _load_model_config(stem)
    model_name = str(cfg.get("model_name", "")).lower()
    return stem.lower().startswith("gemini") or model_name.startswith(("gemini-", "gemini/"))


def _config_stems_for_tier(tier: str) -> set[str]:
    stems: set[str] = set()
    for cfg_path in sorted((_ANALYZER_DIR / "configs").glob("*.yaml")):
        if cfg_path.stem == "prompts":
            continue
        cfg = _load_model_config(cfg_path.stem)
        if str(cfg.get("tier", "frontier")) == tier:
            stems.add(cfg_path.stem)
    if not stems:
        raise SystemExit(f"HALT: no analyzer configs found for tier '{tier}'.")
    return stems


def _apply_gemini_toggle(stems: set[str], *, gemini_enabled: bool) -> set[str]:
    if gemini_enabled:
        return set(stems)
    filtered = {stem for stem in stems if not _is_gemini_config(stem)}
    if not filtered:
        raise SystemExit("HALT: --gemini off removed every selected analyzer config.")
    return filtered


def _collapse_error(details: dict, limit: int = 300) -> str:
    message = str(details.get("error") or details)
    qualifier = str(details.get("protocol_category") or details.get("parse_error") or "").strip()
    if qualifier:
        message = f"{message} ({qualifier})"
    collapsed = " ".join(message.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def _aggregate_package_version_metrics(
    results: list[dict],
) -> tuple[dict[str, dict[str, int]], int, int, set[str]]:
    """
    Collapse artifact-level rows into package-version metrics.
    Any successful artifact verdict marks that package-version detector group
    malicious; all-error groups are excluded.
    """
    stats: dict[str, dict[str, int]] = {}
    unknown_pkgs: set[str] = set()
    grouped: dict[tuple[str, str, str, str, str], dict] = {}
    error_rows = 0

    for r in results:
        stored_gt = r.get("ground_truth")
        if stored_gt is None:
            unknown_pkgs.add(r["package_name"])
            continue
        true_label = bool(stored_gt)
        mode = str(r.get("experiment_mode") or "unknown")
        if mode == "error":
            details = r.get("details") or {}
            mode = str(details.get("intended_mode") or "error")

        group_key = (
            r["package_name"],
            r["version"],
            r["detector"],
            mode,
            r["prompt_strategy"],
        )
        group = grouped.setdefault(group_key, {
            "ground_truth": true_label,
            "verdict": False,
            "success_rows": 0,
            "error_rows": 0,
        })
        if group["ground_truth"] != true_label:
            raise SystemExit(
                "HALT: conflicting ground truth rows inside metric group: "
                f"{group_key} existing={int(group['ground_truth'])} "
                f"new={int(true_label)}"
            )
        if r.get("experiment_mode") == "error":
            group["error_rows"] += 1
            error_rows += 1
            continue

        group["success_rows"] += 1
        group["verdict"] = group["verdict"] or bool(r["verdict"])

    excluded_groups = 0
    for (_pkg, _version, detector, mode, strategy), group in grouped.items():
        if group["success_rows"] == 0:
            excluded_groups += 1
            continue
        key = f"{detector}:{mode}:{strategy}"
        if key not in stats:
            stats[key] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0}

        predicted = bool(group["verdict"])
        true_label = bool(group["ground_truth"])
        if predicted and true_label:
            stats[key]["TP"] += 1
        elif not predicted and not true_label:
            stats[key]["TN"] += 1
        elif predicted and not true_label:
            stats[key]["FP"] += 1
        else:
            stats[key]["FN"] += 1

    return stats, error_rows, excluded_groups, unknown_pkgs


# ---------------------------------------------------------------------------
# EvaluationRunner
# ---------------------------------------------------------------------------

class EvaluationRunner:

    def __init__(
        self,
        config: dict,
        tier: str = "budget",
        profile: str | None = None,
        model_config_stems: set[str] | None = None,
        include_controls: bool = False,
        package_limits: dict[str, int] | None = None,
        progress_enabled: bool = False,
        run_id_prefix: str | None = None,
        gemini_enabled: bool = True,
        raw_experiment_log: bool = True,
        identity_alias_probe: bool = False,
        cli_args: dict | None = None,
    ):
        self._cfg  = config
        self._tier = tier
        self._profile = profile
        self._gemini_enabled = gemini_enabled
        base_run_label = f"profile:{profile}" if profile else f"tier:{tier}"
        self._run_label = base_run_label if gemini_enabled else f"{base_run_label}:gemini-off"
        self._include_controls = include_controls
        self._package_limits = package_limits or {}
        self._progress_enabled = progress_enabled
        self._run_id_prefix = run_id_prefix
        self._raw_experiment_log = raw_experiment_log
        self._identity_alias_probe = identity_alias_probe
        self._identity_aliases: dict[tuple[str, str], tuple[str, str]] = {}
        self._raw_log = None
        self._cli_args = cli_args or {}
        self._model_config_stems = sorted(model_config_stems) if model_config_stems is not None else None
        self._db   = DBManager()
        self._extractor = EntryPointExtractor()
        self._filter    = HeuristicFilter()
        self._controller = EvalController(
            configs_dir=_ANALYZER_DIR / "configs",
            db=self._db,
            tier=tier,
            model_config_stems=model_config_stems,
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

    def _identity_alias_for(self, package_name: str, version: str) -> tuple[str, str]:
        key = (package_name, version)
        if key not in self._identity_aliases:
            index = len(self._identity_aliases) + 1
            self._identity_aliases[key] = (f"X{index:03d}", f"V{index:03d}")
        return self._identity_aliases[key]

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

        truth, _lkgr_by_project = self._build_ground_truth_index()
        if not truth:
            raise SystemExit("HALT: no labelled dataset versions found under samples/.")

        packages: list[ResolvedPackage] = []
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
                count=1,
            )
            if not selected_versions:
                log.warning(
                    f"No labelled simulator versions selected for {project}; "
                    f"index={sorted(index_versions)} labelled={sorted(labelled_versions)}"
                )
                continue

            version = selected_versions[0]
            label = truth.get((project, version))
            if label is None:
                log.warning(f"Skipping unlabelled simulator version: {project}=={version}")
                continue
            version_artifacts = [artifact for artifact in artifacts if artifact.version == version]
            selected_artifacts = self._resolver.select_artifacts(
                version_artifacts,
                policy="all",
            )
            if self._raw_log is not None:
                self._raw_log.emit(
                    "resolver.artifacts.selected",
                    package=project,
                    version=version,
                    payload={
                        "labelled_versions": sorted(labelled_versions),
                        "simulator_versions": sorted(index_versions),
                        "selectable_versions": sorted(selectable_versions),
                        "selected_version": version,
                        "artifact_policy": "all",
                        "all_version_artifacts": [a.__dict__ for a in version_artifacts],
                        "selected_artifacts": [a.__dict__ for a in selected_artifacts],
                        "ground_truth": label.is_malicious,
                        "sample_role": label.sample_role,
                        "attack_vector": label.attack_vector,
                    },
                )
            if not selected_artifacts:
                log.warning(f"No artifacts selected for {project}=={version}")
                continue
            packages.append(ResolvedPackage(
                project=project,
                version=version,
                label=label,
                artifacts=selected_artifacts,
            ))

        packages = self._apply_package_limits(packages)
        resolved: list[ResolvedSample] = []
        for package in packages:
            resolver_policy = json.dumps({
                "version_strategy": "latest_labelled_stable",
                "artifact_policy": "all",
                "package_limits": self._package_limits,
                "pre_release_policy": "ignore_unless_no_stable",
                "metric_unit": "package_version",
                "gemini": "on" if self._gemini_enabled else "off",
            }, sort_keys=True)
            for artifact in package.artifacts:
                resolved.append(ResolvedSample(
                    archive_path=(
                        self._resolver.cache_dir
                        / artifact.project
                        / artifact.version
                        / artifact.filename
                    ),
                    package_name=package.project,
                    version=package.version,
                    ground_truth=package.label.is_malicious,
                    artifact_filename=artifact.filename,
                    artifact_url=artifact.url,
                    source_index_url=self._resolver.project_index_url(package.project),
                    sample_role=package.label.sample_role,
                    attack_vector=package.label.attack_vector,
                    resolver_policy=resolver_policy,
                ))

        if download:
            resolved = [
                replace(sample, archive_path=self._download_sample(sample))
                for sample in resolved
            ]
            self._resolved_cache = resolved
        return resolved

    def _package_limit_role(self, package: ResolvedPackage) -> str:
        if package.label.is_malicious:
            return "malicious"
        return package.label.sample_role

    def _apply_package_limits(self, packages: list[ResolvedPackage]) -> list[ResolvedPackage]:
        """
        Apply optional profile-level package caps before artifact expansion.
        Limits count packages, while all artifacts for each kept latest version
        are scanned.
        """
        if not self._package_limits:
            return packages

        kept: list[ResolvedPackage] = []
        counts = {role: 0 for role in self._package_limits}
        skipped = {role: 0 for role in self._package_limits}

        for package in packages:
            role = self._package_limit_role(package)
            limit = self._package_limits.get(role)
            if limit is not None and counts.get(role, 0) >= limit:
                skipped[role] = skipped.get(role, 0) + 1
                continue
            kept.append(package)
            if limit is not None:
                counts[role] = counts.get(role, 0) + 1

        summary = ", ".join(
            f"{role}={counts.get(role, 0)}/{limit}"
            for role, limit in sorted(self._package_limits.items())
        )
        skipped_total = sum(skipped.values())
        log.info(
            f"Profile package limits applied: {summary}; "
            f"kept {len(kept)}/{len(packages)} package(s)"
            + (f", skipped {skipped_total}" if skipped_total else "")
        )
        for role, limit in sorted(self._package_limits.items()):
            if counts.get(role, 0) < limit:
                log.warning(
                    f"Profile package limit for {role} requested {limit} package(s) "
                    f"but only {counts.get(role, 0)} were available after resolution."
                )
        return kept

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
        skip_static: bool = False,
        skip_agentic: bool = False,
        only_agentic: bool = False,
        dry_run_resolution: bool = False,
    ) -> None:
        if sast_only and skip_static:
            raise SystemExit("HALT: --sast-only cannot be combined with --skip-static.")
        if sast_only and only_agentic:
            raise SystemExit("HALT: --sast-only cannot be combined with --only-agentic.")
        if only_agentic and skip_agentic:
            raise SystemExit("HALT: --only-agentic cannot be combined with --skip-agentic.")
        if self._identity_alias_probe:
            if sast_only or only_agentic:
                raise SystemExit(
                    "HALT: --identity-alias-probe cannot be combined with --sast-only "
                    "or --only-agentic."
                )
            skip_static = True
            skip_agentic = True

        run_id = _make_run_id(getattr(self, "_run_id_prefix", None))
        task_scope = (
            "identity-alias-probe" if self._identity_alias_probe else
            "sast-only" if sast_only else
            "agentic-only" if only_agentic else
            "llm-no-agentic" if skip_agentic and skip_static else
            "no-agentic" if skip_agentic else
            "no-static" if skip_static else
            "all"
        )
        log.info(
            f"EvaluationRunner start - run_id={run_id}  "
            f"profile={self._profile or 'tier-filter'}  tier={self._tier}  "
            f"task_scope={task_scope}"
        )
        run_label = self._run_label if not sast_only else "sast-only"
        if self._identity_alias_probe:
            run_label = f"{run_label}:identity-alias-probe"
        elif not sast_only and task_scope != "all":
            run_label = f"{run_label}:{task_scope}"
        self._db.create_eval_run(run_id, tier=run_label)

        if (
            not skip_validation
            and not sast_only
            and not dry_run_resolution
            and not self._identity_alias_probe
        ):
            self._validate_financial_airgap(
                skip_agentic=skip_agentic,
                only_agentic=only_agentic,
            )
            log.info("Starting main artifact evaluation.")

        raw_log = None
        package_failures = 0
        if self._raw_experiment_log and not dry_run_resolution:
            raw_log = RawExperimentLog(run_id, _REPO_ROOT / "logs" / "experiments")
            self._raw_log = raw_log
            self._resolver.raw_log = raw_log
            log.info(f"Raw experiment log: {raw_log.path}")
            raw_log.emit(
                "run.start",
                payload={
                    "cli_args": self._cli_args,
                    "profile": self._profile,
                    "tier": self._tier,
                    "run_label": run_label,
                    "sast_only": sast_only,
                    "skip_static": skip_static,
                    "skip_agentic": skip_agentic,
                    "only_agentic": only_agentic,
                    "task_scope": task_scope,
                    "identity_alias_probe": self._identity_alias_probe,
                    "gemini": "on" if self._gemini_enabled else "off",
                    "model_config_stems": self._model_config_stems,
                    "simulator_base_url": self._simulator_url,
                    "samples_root": self._samples_root,
                    "db_path": DBManager.DB_PATH,
                    "human_log_path": get_active_log_path(),
                    "package_limits": self._package_limits,
                    "include_controls": self._include_controls,
                },
            )

        try:
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

            with AnalyzerProgress(
                enabled=self._progress_enabled,
                total_samples=len(samples),
                run_id=run_id,
                run_label=run_label,
            ) as progress:
                run_log = log.bind(file_only=True) if progress.active else log
                for index, sample in enumerate(samples, start=1):
                    progress.start_package(index, sample)
                    sample_ctx = {
                        "package": sample.package_name,
                        "version": sample.version,
                        "artifact_filename": sample.artifact_filename,
                    }
                    if raw_log is not None:
                        raw_log.emit(
                            "package.start",
                            **sample_ctx,
                            payload={
                                "index": index,
                                "total": len(samples),
                                "artifact_url": sample.artifact_url,
                                "source_index_url": sample.source_index_url,
                                "ground_truth": sample.ground_truth,
                                "sample_role": sample.sample_role,
                                "attack_vector": sample.attack_vector,
                                "resolver_policy": sample.resolver_policy,
                                "archive_path": sample.archive_path,
                            },
                        )
                    run_log.info(
                        f"  Processing {sample.package_name} {sample.version} "
                        f"({sample.artifact_filename})"
                    )
                    try:
                        pkg = self._extractor.extract(
                            sample.archive_path,
                            raw_log=raw_log,
                            trace_context=sample_ctx,
                        )
                        # Override name/version with simulator-resolved values.
                        pkg.name    = sample.package_name
                        pkg.version = sample.version
                        progress.record_extraction(
                            decoded_files=len(pkg.files),
                            entry_points=len(pkg.files_raw),
                            bad_password_files=pkg.bad_password_files,
                        )
                        run_log.info(
                            f"    Decoded {len(pkg.files)} file(s) "
                            f"({len(pkg.files_raw)} entry point(s))"
                            + (f"  [bad-password: {pkg.bad_password_files}]"
                               if pkg.bad_password_files else "")
                        )
                        pkg = self._filter.scan(pkg)
                        progress.record_heuristics(pkg.heuristic_flags)
                        if raw_log is not None:
                            raw_log.emit(
                                "heuristic.scan",
                                **sample_ctx,
                                payload={
                                    "files": sorted(pkg.files),
                                    "heuristic_flags": list(pkg.heuristic_flags),
                                },
                            )
                        if pkg.heuristic_flags:
                            run_log.info(f"    Heuristic flags: {', '.join(pkg.heuristic_flags)}")
                        detector_pkg = pkg
                        result_details_extra = None
                        if self._identity_alias_probe:
                            alias_name, alias_version = self._identity_alias_for(
                                sample.package_name, sample.version
                            )
                            masked = mask_package_identity(
                                pkg,
                                alias_name=alias_name,
                                alias_version=alias_version,
                            )
                            detector_pkg = masked.package
                            result_details_extra = masked.details()
                            if raw_log is not None:
                                raw_log.emit(
                                    "identity_alias.mask",
                                    **sample_ctx,
                                    payload={
                                        "alias_name": alias_name,
                                        "alias_version": alias_version,
                                        "original_terms": masked.original_terms,
                                        "replacement_counts": masked.replacement_counts,
                                        "model_visible_files": sorted(detector_pkg.files),
                                    },
                                )
                        results = self._controller.run(
                            run_id=run_id, pkg=detector_pkg,
                            ground_truth=sample.ground_truth, sast_only=sast_only,
                            skip_static=skip_static,
                            skip_agentic=skip_agentic,
                            only_agentic=only_agentic,
                            hybrid_zero_shot_only=self._identity_alias_probe,
                            artifact_filename=sample.artifact_filename,
                            artifact_url=sample.artifact_url,
                            source_index_url=sample.source_index_url,
                            sample_role=sample.sample_role,
                            attack_vector=sample.attack_vector,
                            resolver_policy=sample.resolver_policy,
                            record_package_name=sample.package_name,
                            record_version=sample.version,
                            result_details_extra=result_details_extra,
                            on_tasks_prepared=(
                                progress.set_detector_tasks if progress.active else None
                            ),
                            on_result=(
                                progress.record_result if progress.active else None
                            ),
                            quiet_console=progress.active,
                            raw_log=raw_log,
                        )
                        n_valid   = sum(1 for r in results if r.experiment_mode != "error")
                        n_flagged = sum(1 for r in results if r.verdict and r.experiment_mode != "error")
                        progress.complete_package(valid_results=n_valid, flagged_results=n_flagged)
                        if raw_log is not None:
                            raw_log.emit(
                                "package.done",
                                **sample_ctx,
                                payload={
                                    "valid_results": n_valid,
                                    "flagged_results": n_flagged,
                                    "error_results": sum(1 for r in results if r.experiment_mode == "error"),
                                    "result_count": len(results),
                                },
                            )
                        run_log.info(f"    Verdict: {n_flagged}/{n_valid} detector(s) flagged malicious")
                    except Exception as exc:
                        package_failures += 1
                        progress.fail_package(sample.artifact_filename, exc)
                        if raw_log is not None:
                            raw_log.emit("package.error", **sample_ctx, payload={"error": str(exc)})
                        run_log.error(f"  Failed {sample.artifact_filename}: {exc}")

            self._print_metrics(run_id)
        except Exception as exc:
            if raw_log is not None:
                raw_log.emit("run.error", payload={"error": str(exc), "error_type": type(exc).__name__})
                raw_log.close("failed")
            raise
        else:
            if raw_log is not None:
                try:
                    row_count = len(self._db.get_eval_results_for_run(run_id))
                except Exception:  # pragma: no cover - best-effort trace summary
                    row_count = None
                raw_log.close(
                    "completed_with_errors" if package_failures else "completed",
                    payload={"package_failures": package_failures, "db_result_rows": row_count},
                )
        finally:
            self._raw_log = None
            self._resolver.raw_log = None

    # ------------------------------------------------------------------
    # Financial air-gap validation
    # ------------------------------------------------------------------

    def _validate_financial_airgap(
        self,
        *,
        skip_agentic: bool = False,
        only_agentic: bool = False,
    ) -> None:
        """
        Run one benign package through all active LLM adapters.
        Compare LiteLLM-reported cost against token-math estimate.
        Project to full dataset and HALT if projection > hard cap.
        Token-math divergence is logged as a sanity-check warning because the
        LiteLLM-reported actual cost is the authoritative budget value.
        """
        samples = self._resolve_simulator_samples(download=False)
        benign_sample = next((sample for sample in samples if not sample.ground_truth), None)
        if benign_sample is None:
            log.warning("Financial validation: no benign simulator sample found, skipping.")
            return

        log.info(
            f"Financial validation: {benign_sample.package_name} "
            f"{benign_sample.version} on {self._run_label}"
        )

        val_id = _make_run_id(getattr(self, "_run_id_prefix", None), validation=True)
        self._db.create_eval_run(val_id, tier=f"{self._run_label}-validation")
        validation_archive = self._download_sample(benign_sample)
        pkg = self._extractor.extract(validation_archive)
        pkg.name    = benign_sample.package_name
        pkg.version = benign_sample.version
        pkg = self._filter.scan(pkg)
        results = self._controller.run(
            run_id=val_id,
            pkg=pkg,
            ground_truth=benign_sample.ground_truth,
            skip_static=True,
            skip_agentic=skip_agentic,
            only_agentic=only_agentic,
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
                "Check profile/tier selection and analyzer model configs."
            )

        expected_detectors = self._controller.expected_non_static_detectors(
            skip_agentic=skip_agentic,
            only_agentic=only_agentic,
        )
        successful_detectors = {r.detector for r in successful_llm_results}
        failed_detectors = sorted(expected_detectors - successful_detectors)
        if failed_detectors:
            details: list[str] = []
            for detector in failed_detectors:
                error_row = next(
                    (
                        r for r in llm_results
                        if r.detector == detector and r.experiment_mode == "error"
                    ),
                    None,
                )
                if error_row is None:
                    details.append(f"{detector}: no result rows")
                    continue
                model = str(error_row.details.get("model") or "unknown-model")
                details.append(f"{detector} ({model}): {_collapse_error(error_row.details)}")
            if self._profile and self._profile.startswith("gemini_only"):
                guidance = (
                    "The Gemini-only profile already retries 429/high-demand failures "
                    "with the configured long backoff. Rerun later only if the exhausted "
                    "attempts still point to temporary Google-side instability."
                )
            else:
                guidance = (
                    "If this is a temporary provider outage, rerun with "
                    "--gemini off or a reduced profile such as --profile budget_no_gemini."
                )
            raise SystemExit(
                "HALT: financial validation failed for selected model profile "
                f"{self._run_label}: "
                + " | ".join(details)
                + ". "
                + guidance
            )
        if not tokenized_llm_results:
            raise SystemExit(
                "HALT: financial validation produced successful LLM/agentic rows "
                "with zero token usage. Check LiteLLM proxy/model routing."
            )

        missing_price_models: set[str] = set()
        actual_total = sum(r.api_cost_usd for r in results)
        expected_total = 0.0
        for r in results:
            breakdown = r.details.get("pricing_breakdown")
            if isinstance(breakdown, list) and breakdown:
                for item in breakdown:
                    if not isinstance(item, dict):
                        continue
                    model = str(item.get("model", ""))
                    if model not in _TOKEN_PRICES:
                        if model:
                            missing_price_models.add(model)
                        continue
                    pin, pout = _TOKEN_PRICES[model]
                    expected_total += (
                        int(item.get("input_tokens", 0)) * pin
                        + int(item.get("output_tokens", 0)) * pout
                    ) / 1_000_000
                continue

            model = str(r.details.get("model", ""))
            if model not in _TOKEN_PRICES:
                if model:
                    missing_price_models.add(model)
                continue
            pin, pout = _TOKEN_PRICES[model]
            expected_total += (r.input_tokens * pin + r.output_tokens * pout) / 1_000_000

        log.info(
            f"Validation — actual cost: ${actual_total:.4f}  "
            f"expected: ${expected_total:.4f}"
        )

        if missing_price_models:
            log.warning(
                "Missing token price configuration for fallback/preview model(s): "
                + ", ".join(sorted(missing_price_models))
                + "; excluding them from token-math estimate and relying on LiteLLM actual cost."
            )

        if expected_total > 0 and actual_total > 0:
            divergence = abs(actual_total - expected_total) / expected_total
            if divergence > _COST_DIVERGENCE_WARN_THRESHOLD:
                log.warning(
                    f"LiteLLM-reported cost (${actual_total:.4f}) diverges "
                    f"from token-math estimate (${expected_total:.4f}) by "
                    f"{divergence * 100:.1f}% > "
                    f"{_COST_DIVERGENCE_WARN_THRESHOLD * 100:.0f}%; "
                    "using LiteLLM actual cost for budget projection."
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
                f"${_BUDGET_HARD_CAP_USD}. Use --profile budget or --skip-validation."
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

        stats, error_rows, excluded_groups, unknown_pkgs = (
            _aggregate_package_version_metrics(results)
        )

        if error_rows:
            log.warning(
                f"Ignored {error_rows} artifact-level error row(s) while "
                "aggregating package-version metrics."
            )
        if excluded_groups:
            log.warning(
                f"Excluded {excluded_groups} package-version detector group(s) "
                "with no successful artifact rows."
            )
        if unknown_pkgs:
            log.warning(f"Ground truth missing for: {sorted(unknown_pkgs)}")

        table = Table(
            title=f"Evaluation Results (package-version metrics)  |  run_id: {run_id}",
            show_lines=True,
        )
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
        "--profile",
        default=None,
        help="Evaluation model profile from configs/evaluation_profiles.yaml (default: budget)",
    )
    parser.add_argument(
        "--tier", choices=["budget", "medium", "frontier"], default=None,
        help="Legacy model-tier filter; ignored when --profile is set unless matching profile tier",
    )
    parser.add_argument(
        "--gemini",
        choices=["on", "off"],
        default="on",
        help="Include Gemini/Google model configs in selected profile or tier (default: on)",
    )
    parser.add_argument(
        "--skip-validation", action="store_true",
        help="Skip the financial air-gap validation run",
    )
    parser.add_argument(
        "--sast-only", action="store_true",
        help="Run only static tools (Bandit/Semgrep/GuardDog), skip all LLM/agentic adapters",
    )
    parser.add_argument(
        "--skip-static", action="store_true",
        help="Skip static tools. Use after a separate --sast-only baseline run.",
    )
    parser.add_argument(
        "--skip-agentic", action="store_true",
        help="Skip agentic adapters while keeping static, hybrid, and raw LLM adapters.",
    )
    parser.add_argument(
        "--only-agentic", action="store_true",
        help="Run only agentic adapters for the selected profile.",
    )
    parser.add_argument(
        "--identity-alias-probe",
        action="store_true",
        help=(
            "Run the cheap masked-identity validity probe: hybrid zero-shot only, "
            "no static, no raw LLM, no agentic, and no financial validation."
        ),
    )
    parser.add_argument(
        "--dry-run-resolution",
        action="store_true",
        help="Resolve simulator samples and print the selected artifacts without scanning",
    )
    parser.add_argument(
        "--include-controls",
        action="store_true",
        help="Include high-volume controls in simulator-resolved evaluation",
    )
    parser.add_argument(
        "--progress",
        choices=["auto", "always", "never"],
        default="auto",
        help="Live analyzer progress display: auto, always, or never",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Enable DEBUG-level logging (raw prompts, responses, per-file extraction)",
    )
    parser.add_argument(
        "--run-id-prefix",
        default=None,
        help="Optional prefix for generated run_id values, e.g. canonical-v2",
    )
    parser.add_argument(
        "--raw-experiment-log",
        choices=["on", "off"],
        default="on",
        help="Write raw JSONL experiment flight recorder for real runs (default: on)",
    )
    args = parser.parse_args()
    if args.sast_only and args.skip_static:
        raise SystemExit("HALT: --sast-only cannot be combined with --skip-static.")
    if args.sast_only and args.only_agentic:
        raise SystemExit("HALT: --sast-only cannot be combined with --only-agentic.")
    if args.only_agentic and args.skip_agentic:
        raise SystemExit("HALT: --only-agentic cannot be combined with --skip-agentic.")
    if args.identity_alias_probe:
        if args.sast_only or args.only_agentic:
            raise SystemExit(
                "HALT: --identity-alias-probe cannot be combined with --sast-only "
                "or --only-agentic."
            )
        args.skip_static = True
        args.skip_agentic = True
        args.skip_validation = True
        if args.run_id_prefix is None:
            args.run_id_prefix = "canonical-v2-alias"
    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    profile_name = args.profile
    tier = args.tier
    model_config_stems: set[str] | None = None
    profile_include_controls: bool | None = None
    profile_package_limits: dict[str, int] | None = None
    if profile_name is not None:
        profile = _load_evaluation_profile(profile_name)
        model_config_stems = profile.config_stems
        profile_include_controls = profile.include_controls
        profile_package_limits = profile.package_limits
        if tier is not None and tier != profile.tier:
            raise SystemExit(
                f"HALT: --tier {tier} conflicts with --profile {profile_name} "
                f"(profile tier: {profile.tier})."
            )
        tier = profile.tier
    elif tier is None:
        profile_name = "budget"
        profile = _load_evaluation_profile(profile_name)
        tier = profile.tier
        model_config_stems = profile.config_stems
        profile_include_controls = profile.include_controls
        profile_package_limits = profile.package_limits

    gemini_enabled = args.gemini == "on"
    if not gemini_enabled:
        if model_config_stems is None:
            model_config_stems = _config_stems_for_tier(tier)
        model_config_stems = _apply_gemini_toggle(model_config_stems, gemini_enabled=False)

    if args.verbose:
        # Preserve configured sinks; just raise their level before first setup.
        cfg.setdefault("logging", {})["level"] = "DEBUG"
    setup_logger(cfg)
    active_log_path = get_active_log_path()
    if active_log_path is not None:
        log.info(f"Detailed log: {active_log_path}")
    progress_enabled = should_use_progress(
        args.progress,
        dry_run_resolution=args.dry_run_resolution,
    )
    EvaluationRunner(
        cfg,
        tier=tier,
        profile=profile_name,
        model_config_stems=model_config_stems,
        include_controls=args.include_controls or bool(profile_include_controls),
        package_limits=profile_package_limits,
        progress_enabled=progress_enabled,
        run_id_prefix=args.run_id_prefix,
        gemini_enabled=gemini_enabled,
        raw_experiment_log=args.raw_experiment_log == "on",
        identity_alias_probe=args.identity_alias_probe,
        cli_args=vars(args),
    ).run(
        skip_validation=args.skip_validation,
        sast_only=args.sast_only,
        skip_static=args.skip_static,
        skip_agentic=args.skip_agentic,
        only_agentic=args.only_agentic,
        dry_run_resolution=args.dry_run_resolution,
    )
