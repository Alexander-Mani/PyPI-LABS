#!/usr/bin/env python3
"""Source-free probe for model recognition of public PyPI incidents."""

from __future__ import annotations

import argparse
import json
import re
import socket
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CASES_FILE = _REPO_ROOT / "configs" / "model_memory_probe_cases.json"
_DEFAULT_LOG_DIR = _REPO_ROOT / "logs" / "model_memory_probe"
_ANALYZER_CONFIG = _REPO_ROOT / "src" / "analyzer" / "config.yaml"
_ANALYZER_DIR = _REPO_ROOT / "src" / "analyzer"
_MODELS_FILE = _REPO_ROOT / "configs" / "models.json"
PROBE_SCHEMA_VERSION = 2

# Reuse the profile/model parsing helpers used by the LiteLLM smoke test.
_SCRIPT_DIR = Path(__file__).resolve().parent
for _path in (_REPO_ROOT, _SCRIPT_DIR, _ANALYZER_DIR):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from litellm_smoke import _filter_gemini_models, _load_profile_config_stems, _truncate  # noqa: E402
from src.analyzer.progress_ui import provider_for_model  # noqa: E402
import src.analyzer.evaluate as analyzer_evaluate  # noqa: E402
from src.analyzer.simulator_resolver import normalize_project_name  # noqa: E402

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

with _MODELS_FILE.open(encoding="utf-8") as _f:
    _MODELS_CFG = json.load(_f)

_TOKEN_PRICES: dict[str, tuple[float, float]] = {
    key: (float(value[0]), float(value[1]))
    for key, value in _MODELS_CFG.get("token_prices", {}).items()
}

PROBE_RESPONSE_FORMAT = {
    "type": "json_schema",
    "json_schema": {
        "name": "model_memory_probe_v2",
        "schema": {
            "type": "object",
            "required": [
                "recognized_package",
                "recognized_exact_version",
                "version_scope",
                "related_versions",
                "confidence",
                "basis",
                "fact",
            ],
            "properties": {
                "recognized_package": {"type": "boolean"},
                "recognized_exact_version": {"type": "boolean"},
                "version_scope": {
                    "type": "string",
                    "enum": ["exact_version", "same_package_other_version", "package_only", "none"],
                },
                "related_versions": {"type": "string"},
                "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                "basis": {
                    "type": "string",
                    "enum": ["public_incident", "public_reporting", "guess", "none"],
                },
                "fact": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
}

MIN_REFRESH_INTERVAL_S = 0.75
TRANSPORT_RETRY_STATUSES = {"transport_rate_limit", "transport_provider_error", "transport_timeout"}
_VERSION_TOKEN_RE = re.compile(r"\b\d[0-9A-Za-z+._-]*(?:\.\d[0-9A-Za-z+._-]*)+\b")


@dataclass(frozen=True)
class ProbeCase:
    id: str
    package_name: str
    version: str
    expected_recognized: bool | None
    category: str
    sample_role: str = ""
    attack_vector: str | None = None
    baseline_target: str | None = None
    notes: str = ""
    source: str = "curated"


@dataclass(frozen=True)
class ModelSpec:
    config_stem: str | None
    model_name: str
    temperature: float = 0.0
    reasoning_effort: str | None = None
    extra_body: dict[str, Any] | None = None

    @property
    def label(self) -> str:
        return self.config_stem or self.model_name


@dataclass(frozen=True)
class ProbeOutcome:
    ok: bool
    status: str
    status_code: int | None = None
    raw_response: str | None = None
    response_json: dict[str, Any] | None = None
    error: str | None = None
    elapsed_s: float = 0.0
    parse_status: str = "ok_unparseable"
    parse_error: str | None = None
    recognized_package: bool | None = None
    recognized_exact_version: bool | None = None
    version_scope: str | None = None
    related_versions: str | None = None
    confidence: float | None = None
    basis: str | None = None
    fact: str | None = None
    suspicious_exact_claim: bool = False
    suspicious_exact_claim_reason: str | None = None
    finish_reason: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float | None = None
    litellm_model_group: str | None = None
    litellm_model_id: str | None = None
    response_model: str | None = None
    retries_used: int = 0


class ProbeProgress:
    def __init__(
        self,
        *,
        enabled: bool,
        run_id: str,
        scope: str,
        total_models: int,
        total_cases: int,
        total_calls: int,
        out_path: Path,
    ):
        self.enabled = bool(enabled and total_calls > 0 and Live is not None)
        self.run_id = run_id
        self.scope = scope
        self.total_models = total_models
        self.total_cases = total_cases
        self.total_calls = total_calls
        self.out_path = out_path
        self.completed_calls = 0
        self.current_model = ""
        self.current_case = ""
        self.current_role = ""
        self.parse_counts: Counter[str] = Counter()
        self.provider_costs: dict[str, float] = {
            "anthropic": 0.0,
            "openai": 0.0,
            "google": 0.0,
            "together": 0.0,
            "other": 0.0,
        }
        self.total_cost_usd = 0.0
        self.total_elapsed_s = 0.0
        self._last_refresh = 0.0
        self._console = Console(stderr=True) if self.enabled and Console is not None else None
        self._live = None

    def __enter__(self) -> "ProbeProgress":
        if self.enabled:
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

    @property
    def active(self) -> bool:
        return self.enabled and self._live is not None

    def start_call(self, spec: ModelSpec, case: ProbeCase) -> None:
        if not self.enabled:
            return
        self.current_model = spec.label
        self.current_case = f"{case.package_name}=={case.version}"
        self.current_role = case.sample_role or case.category
        self.refresh(force=True)

    def record(self, spec: ModelSpec, case: ProbeCase, outcome: ProbeOutcome) -> None:
        if not self.enabled:
            return
        self.completed_calls += 1
        self.total_elapsed_s += max(outcome.elapsed_s, 0.0)
        self.parse_counts[outcome.parse_status] += 1
        provider = provider_for_model(outcome.litellm_model_group or spec.model_name)
        cost = float(outcome.cost_usd or 0.0)
        self.provider_costs[provider] = self.provider_costs.get(provider, 0.0) + cost
        self.total_cost_usd += cost
        self.current_model = spec.label
        self.current_case = f"{case.package_name}=={case.version}"
        self.current_role = case.sample_role or case.category
        self.refresh()

    def refresh(self, *, force: bool = False) -> None:
        if not self.active:
            return
        now = time.monotonic()
        if not force and now - self._last_refresh < MIN_REFRESH_INTERVAL_S:
            return
        self._last_refresh = now
        self._live.refresh()

    def __rich_console__(self, console, options):
        yield self._render()

    def _render(self):
        header = Table.grid(expand=True)
        header.add_column(style="bold")
        header.add_column()
        header.add_row("Run", self.run_id)
        header.add_row("Scope", self.scope)
        header.add_row("Models", str(self.total_models))
        header.add_row("Cases", str(self.total_cases))
        header.add_row("Calls", f"{self.completed_calls}/{self.total_calls}")
        header.add_row("Current", self.current_case or "pending")
        header.add_row("Model", self.current_model or "pending")
        header.add_row("Role", self.current_role or "pending")
        header.add_row("Spent", f"${self.total_cost_usd:.4f}")
        if self.completed_calls > 0:
            avg_elapsed = self.total_elapsed_s / self.completed_calls
            remaining = max(self.total_calls - self.completed_calls, 0)
            header.add_row("Avg latency", f"{avg_elapsed:.1f}s")
            header.add_row("ETA", f"{avg_elapsed * remaining:.0f}s")
        panel = Panel(header, title="Model Memory Probe", border_style="cyan")

        counts = Table(title="Parse Status", expand=True)
        counts.add_column("Status")
        counts.add_column("Count", justify="right")
        for status in sorted(self.parse_counts) or ["pending"]:
            counts.add_row(status, str(self.parse_counts.get(status, 0)))

        cost = Table(title="Accumulated API Cost", expand=True)
        cost.add_column("anthropic", justify="right")
        cost.add_column("openai", justify="right")
        cost.add_column("google", justify="right")
        cost.add_column("together", justify="right")
        cost.add_column("other", justify="right")
        cost.add_column("total", justify="right")
        cost.add_row(
            f"${self.provider_costs['anthropic']:.4f}",
            f"${self.provider_costs['openai']:.4f}",
            f"${self.provider_costs['google']:.4f}",
            f"${self.provider_costs['together']:.4f}",
            f"${self.provider_costs['other']:.4f}",
            f"${self.total_cost_usd:.4f}",
        )
        return Group(panel, counts, cost)


def should_use_probe_progress(mode: str) -> bool:
    if mode == "never":
        return False
    if Live is None:
        return False
    if mode == "always":
        return True
    return sys.stderr.isatty()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _collapse_text(text: str | None, limit: int = 400) -> str | None:
    raw = (text or "").strip()
    if not raw:
        return None
    collapsed = " ".join(raw.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def _summary_json_path(out_path: Path) -> Path:
    return out_path.with_suffix(".summary.json")


def _summary_md_path(out_path: Path) -> Path:
    return out_path.with_suffix(".summary.md")


def _effective_runtime_options(args: argparse.Namespace) -> dict[str, Any]:
    if args.scope == "production":
        defaults = {
            "max_tokens": 8192,
            "timeout": 120.0,
            "retries": 2,
            "retry_delay": 20.0,
            "progress": "always",
        }
    else:
        defaults = {
            "max_tokens": 4096,
            "timeout": 60.0,
            "retries": 1,
            "retry_delay": 10.0,
            "progress": "auto",
        }
    return {
        "max_tokens": args.max_tokens if args.max_tokens is not None else defaults["max_tokens"],
        "timeout": args.timeout if args.timeout is not None else defaults["timeout"],
        "retries": args.retries if args.retries is not None else defaults["retries"],
        "retry_delay": args.retry_delay if args.retry_delay is not None else defaults["retry_delay"],
        "progress": args.progress if args.progress is not None else defaults["progress"],
    }


def load_cases(path: Path = _CASES_FILE) -> list[ProbeCase]:
    data = json.loads(path.read_text(encoding="utf-8"))
    raw_cases = data.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise SystemExit(f"HALT: {path} must contain a non-empty 'cases' list")

    cases: list[ProbeCase] = []
    seen: set[str] = set()
    for item in raw_cases:
        if not isinstance(item, dict):
            raise SystemExit(f"HALT: invalid case entry in {path}: {item!r}")
        missing = [
            key
            for key in ("id", "package_name", "version", "expected_recognized", "category")
            if key not in item
        ]
        if missing:
            raise SystemExit(f"HALT: case is missing required field(s) {missing}: {item!r}")
        case_id = str(item["id"])
        if case_id in seen:
            raise SystemExit(f"HALT: duplicate model memory probe case id: {case_id}")
        seen.add(case_id)
        cases.append(
            ProbeCase(
                id=case_id,
                package_name=str(item["package_name"]),
                version=str(item["version"]),
                expected_recognized=bool(item["expected_recognized"]),
                category=str(item["category"]),
                notes=str(item.get("notes") or ""),
                source="curated",
            )
        )
    return cases


def _sanitize_case_id(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "case"


def load_production_cases(profile_name: str, *, sample_set: str = "dataset") -> list[ProbeCase]:
    with _ANALYZER_CONFIG.open(encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    profile = analyzer_evaluate._load_evaluation_profile(profile_name)
    include_controls, package_limits = analyzer_evaluate._resolve_sample_selection(
        sample_set,
        include_controls=profile.include_controls,
        package_limits=profile.package_limits,
    )
    runner = analyzer_evaluate.EvaluationRunner(
        cfg,
        tier=profile.tier,
        profile=profile_name,
        model_config_stems=profile.config_stems,
        sample_set=sample_set,
        include_controls=include_controls,
        package_limits=package_limits,
        progress_enabled=False,
        raw_experiment_log=False,
        gemini_enabled=True,
        shadow_detector_stems=profile.shadow_detector_stems,
    )
    truth, _ = runner._build_ground_truth_index()
    samples = runner._resolve_simulator_samples(download=False)
    cases_by_key: dict[tuple[str, str], ProbeCase] = {}
    for sample in samples:
        key = (sample.package_name, sample.version)
        if key in cases_by_key:
            continue
        role = sample.sample_role or ("malware" if sample.ground_truth else "benign")
        case_id = _sanitize_case_id(f"{role}-{sample.package_name}-{sample.version}")
        truth_key = (normalize_project_name(sample.package_name), sample.version)
        label = truth.get(truth_key)
        cases_by_key[key] = ProbeCase(
            id=case_id,
            package_name=sample.package_name,
            version=sample.version,
            expected_recognized=None,
            category=role,
            sample_role=role,
            attack_vector=sample.attack_vector or (label.attack_vector if label else None),
            baseline_target=label.baseline_target if label else None,
            notes="",
            source="production",
        )
    if not cases_by_key:
        raise SystemExit(f"HALT: no production probe cases resolved for profile '{profile_name}'.")
    return sorted(
        cases_by_key.values(),
        key=lambda case: (case.sample_role, case.attack_vector or "", case.package_name, case.version),
    )


def _is_agentic_config(cfg: dict[str, Any]) -> bool:
    return bool(cfg.get("agentic_flow"))


def _load_model_spec_from_stem(stem: str) -> ModelSpec:
    cfg = analyzer_evaluate._load_model_config(stem)
    model_name = str(cfg.get("model_name") or "").strip()
    if not model_name:
        raise SystemExit(f"HALT: analyzer config '{stem}' has no model_name")
    return ModelSpec(
        config_stem=stem,
        model_name=model_name,
        temperature=float(cfg.get("temperature", 0.0) or 0.0),
        reasoning_effort=str(cfg.get("reasoning_effort") or "").strip() or None,
        extra_body=cfg.get("extra_body") if isinstance(cfg.get("extra_body"), dict) else None,
    )


def select_models(args: argparse.Namespace) -> tuple[list[ModelSpec], str]:
    if args.models is not None and args.all_models:
        raise SystemExit("HALT: use either --models or --all-models, not both")
    if args.models is not None:
        models = [ModelSpec(config_stem=None, model_name=model) for model in args.models]
        source = "explicit --models"
    else:
        profile_name = "all_models" if args.all_models else args.profile
        stems = _load_profile_config_stems(profile_name)
        specs: list[ModelSpec] = []
        for stem in stems:
            cfg = analyzer_evaluate._load_model_config(stem)
            if _is_agentic_config(cfg):
                continue
            spec = _load_model_spec_from_stem(stem)
            specs.append(spec)
        if not specs:
            raise SystemExit(f"HALT: profile '{profile_name}' has no non-agentic model configs")
        filtered_names = _filter_gemini_models(
            [spec.model_name for spec in specs],
            gemini_enabled=args.gemini == "on",
        )
        allowed = set(filtered_names)
        models = [spec for spec in specs if spec.model_name in allowed]
        source = f"profile:{profile_name}"
    if not models:
        raise SystemExit("HALT: Gemini filter removed every selected LiteLLM model")
    if args.gemini == "off":
        source = f"{source} (gemini off)"
    return models, source


def resolve_cases(args: argparse.Namespace) -> tuple[list[ProbeCase], str]:
    if args.scope == "curated":
        if args.sample_set != "dataset" or args.include_controls:
            raise SystemExit(
                "HALT: curated model-memory probes do not use resolver-derived sample sets. "
                "Use the default sample set or switch to --scope production."
            )
        return load_cases(args.cases), str(args.cases)
    resolver_profile = args.resolver_profile or ("all_models" if args.all_models and args.profile == "budget" else args.profile)
    sample_set = analyzer_evaluate._normalize_sample_set_arg(
        args.sample_set,
        include_controls_alias=args.include_controls,
    )
    args.sample_set = sample_set
    cases = load_production_cases(resolver_profile, sample_set=sample_set)
    source = f"profile:{resolver_profile}"
    if sample_set != "dataset":
        source = f"{source} (sample_set={sample_set})"
    return cases, source


def build_messages(case: ProbeCase) -> list[dict[str, str]]:
    system = (
        "You are evaluating possible prior public incident knowledge. "
        "You are not given source code, install logs, package contents, labels, "
        "or dataset membership. Answer only from generally known public security "
        "reporting, if any. Respond only through the provided JSON schema. "
        "Do not use markdown fences. Keep the fact short and concrete. "
        "Set recognized_package to true only if you recognize this package as linked to a publicly documented incident. "
        "Set recognized_exact_version to true only if you recognize this exact queried version as the affected or explicitly discussed version. "
        "Use version_scope='same_package_other_version' when you only know different versions from the same package incident history. "
        "Use version_scope='package_only' when you recognize the package family but not any concrete version. "
        "If you do not know a specific public incident for this package, set recognized_package=false, recognized_exact_version=false, "
        "version_scope='none', related_versions='', basis='none', and fact=''. "
        "If you claim exact-version recognition, related_versions should include the queried version."
    )
    user = (
        "Package name: {name}\n"
        "Version: {version}\n\n"
        "Question: Based only on public reporting you already know, is this exact Python/PyPI package and version "
        "associated with a publicly documented supply-chain or security incident?"
    ).format(name=case.package_name, version=case.version)
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def build_request_payload(spec: ModelSpec, messages: list[dict[str, str]], max_tokens: int) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": spec.model_name,
        "temperature": spec.temperature,
        "max_tokens": max_tokens,
        "messages": messages,
        "response_format": PROBE_RESPONSE_FORMAT,
    }
    if spec.reasoning_effort is not None:
        payload["reasoning_effort"] = spec.reasoning_effort
    if spec.extra_body is not None:
        payload["extra_body"] = spec.extra_body
    return payload


def _request(base_url: str, payload: dict[str, Any]) -> urllib.request.Request:
    return urllib.request.Request(
        base_url.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer no-key-needed",
            "Content-Type": "application/json",
        },
        method="POST",
    )


def _coerce_text_value(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "value", "content"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
    return None


def _extract_content(response_body: str) -> tuple[str, dict[str, Any]]:
    data = json.loads(response_body)
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("LiteLLM response has no choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if content is None:
        return "", data
    if isinstance(content, str):
        return content, data
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            text = _coerce_text_value(item)
            if text is not None:
                parts.append(text)
            else:
                parts.append(json.dumps(item, sort_keys=True))
        return "\n".join(parts), data
    return json.dumps(content, sort_keys=True), data


def parse_model_json(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", stripped, flags=re.DOTALL)
        if not match:
            match = re.search(r"(\{.*\})", stripped, flags=re.DOTALL)
        if not match:
            return None
        try:
            data = json.loads(match.group(1))
        except json.JSONDecodeError:
            return None
    return data if isinstance(data, dict) else None


def _int_value(value: object) -> int:
    try:
        return int(value) if value is not None else 0
    except (TypeError, ValueError):
        return 0


def _float_value(value: object) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _compute_fallback_cost(model_name: str | None, prompt_tokens: int, completion_tokens: int) -> float | None:
    if not model_name:
        return None
    prices = _TOKEN_PRICES.get(model_name)
    if not prices:
        return None
    prompt_price, completion_price = prices
    return ((prompt_tokens / 1_000_000.0) * prompt_price) + ((completion_tokens / 1_000_000.0) * completion_price)


def _classify_parse_status(raw_response: str, *, finish_reason: str | None) -> tuple[str, str | None]:
    text = raw_response.strip()
    if not text and finish_reason == "length":
        return "ok_empty_length", "empty_finish_reason_length"
    if not text:
        return "ok_blank_content", "empty_blank_content"
    return "ok_unparseable", None


def _classify_http_error(status_code: int) -> tuple[str, bool]:
    if status_code == 429:
        return "transport_rate_limit", True
    if status_code in {500, 502, 503, 504}:
        return "transport_provider_error", True
    return "transport_client_error", False


def _classify_url_error(reason: object) -> tuple[str, bool]:
    if isinstance(reason, (TimeoutError, socket.timeout)) or "timeout" in str(reason).lower():
        return "transport_timeout", True
    if isinstance(reason, socket.gaierror):
        return "transport_dns_error", False
    if isinstance(reason, ConnectionRefusedError):
        return "transport_connection_error", False
    if isinstance(reason, OSError):
        return "transport_connection_error", False
    return "transport_client_error", False


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _is_str(value: object) -> bool:
    return isinstance(value, str)


def _validate_probe_response(parsed: dict[str, Any], *, case: ProbeCase) -> tuple[dict[str, Any] | None, str | None]:
    errors: list[str] = []
    recognized_package = parsed.get("recognized_package")
    if not _is_bool(recognized_package):
        errors.append("recognized_package_not_bool")
    recognized_exact_version = parsed.get("recognized_exact_version")
    if not _is_bool(recognized_exact_version):
        errors.append("recognized_exact_version_not_bool")
    version_scope = parsed.get("version_scope")
    if not _is_str(version_scope) or version_scope not in {"exact_version", "same_package_other_version", "package_only", "none"}:
        errors.append("invalid_version_scope")
    related_versions = parsed.get("related_versions")
    if not _is_str(related_versions):
        errors.append("related_versions_not_string")
    confidence_raw = parsed.get("confidence")
    confidence = _float_value(confidence_raw)
    if confidence is None:
        errors.append("invalid_confidence")
    elif confidence < 0.0 or confidence > 1.0:
        errors.append("confidence_out_of_range")
    basis = parsed.get("basis")
    if not _is_str(basis) or basis not in {"public_incident", "public_reporting", "guess", "none"}:
        errors.append("invalid_basis")
    fact = parsed.get("fact")
    if not _is_str(fact):
        errors.append("fact_not_string")

    if errors:
        return None, ";".join(errors)

    recognized_package = bool(recognized_package)
    recognized_exact_version = bool(recognized_exact_version)
    version_scope = str(version_scope)
    related_versions = str(related_versions)
    basis = str(basis)
    fact = str(fact)

    if recognized_exact_version and not recognized_package:
        errors.append("exact_without_package")
    if recognized_exact_version and version_scope != "exact_version":
        errors.append("exact_requires_exact_version_scope")
    if not recognized_package:
        if recognized_exact_version:
            errors.append("package_false_but_exact_true")
        if version_scope != "none":
            errors.append("package_false_requires_none_scope")
        if basis != "none":
            errors.append("package_false_requires_none_basis")
        if related_versions != "":
            errors.append("package_false_requires_empty_related_versions")
        if fact != "":
            errors.append("package_false_requires_empty_fact")
    if version_scope == "same_package_other_version" and related_versions.strip() == "":
        errors.append("same_package_other_version_requires_related_versions")

    if errors:
        return None, ";".join(errors)

    return {
        "recognized_package": recognized_package,
        "recognized_exact_version": recognized_exact_version,
        "version_scope": version_scope,
        "related_versions": related_versions,
        "confidence": confidence,
        "basis": basis,
        "fact": fact,
        "queried_version": case.version,
    }, None


def _extract_versions(text: str) -> set[str]:
    if not text:
        return set()
    return set(_VERSION_TOKEN_RE.findall(text))


def _suspicious_exact_claim(normalized: dict[str, Any], case: ProbeCase) -> tuple[bool, str | None]:
    if not normalized.get("recognized_exact_version"):
        return False, None
    reasons: list[str] = []
    related_versions = str(normalized.get("related_versions") or "").strip()
    if related_versions and case.version not in related_versions:
        reasons.append("related_versions_mismatch")
    fact_versions = _extract_versions(str(normalized.get("fact") or ""))
    if fact_versions and case.version not in fact_versions:
        reasons.append("fact_mentions_other_versions_only")
    if reasons:
        return True, ";".join(reasons)
    return False, None


def _coerce_outcome_from_parsed(
    *,
    parsed: dict[str, Any] | None,
    case: ProbeCase,
    raw_response: str,
    finish_reason: str | None,
) -> tuple[str, str | None, dict[str, Any] | None, bool, str | None]:
    if parsed is None:
        parse_status, parse_error = _classify_parse_status(raw_response, finish_reason=finish_reason)
        return parse_status, parse_error, None, False, None
    normalized, validation_error = _validate_probe_response(parsed, case=case)
    if normalized is None:
        return "ok_schema_invalid", validation_error, parsed, False, None
    suspicious, suspicious_reason = _suspicious_exact_claim(normalized, case)
    return "ok_parsed", None, normalized, suspicious, suspicious_reason


def _probe_once_no_retry(base_url: str, spec: ModelSpec, case: ProbeCase, timeout: float, max_tokens: int) -> ProbeOutcome:
    messages = build_messages(case)
    payload = build_request_payload(spec, messages, max_tokens)
    req = _request(base_url, payload)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            raw_response, data = _extract_content(body)
            parsed = parse_model_json(raw_response)
            usage = data.get("usage") or {}
            prompt_tokens = _int_value(usage.get("prompt_tokens"))
            completion_tokens = _int_value(usage.get("completion_tokens"))
            total_tokens = _int_value(usage.get("total_tokens")) or (prompt_tokens + completion_tokens)
            headers = resp.headers
            finish_reason = None
            choices = data.get("choices") or []
            if choices:
                finish_reason = choices[0].get("finish_reason")
            cost = _float_value(headers.get("x-litellm-response-cost"))
            response_model = str(data.get("model") or "").strip() or None
            litellm_model_group = str(
                headers.get("x-litellm-model-group")
                or headers.get("x-litellm-model")
                or ""
            ).strip() or None
            if cost is None:
                cost = _compute_fallback_cost(
                    litellm_model_group or response_model or spec.model_name,
                    prompt_tokens,
                    completion_tokens,
                )
            parse_status, parse_error, normalized, suspicious, suspicious_reason = _coerce_outcome_from_parsed(
                parsed=parsed,
                case=case,
                raw_response=raw_response,
                finish_reason=str(finish_reason) if finish_reason is not None else None,
            )
            return ProbeOutcome(
                ok=True,
                status=f"HTTP {getattr(resp, 'status', 200)}",
                status_code=getattr(resp, "status", 200),
                raw_response=raw_response,
                response_json=normalized if normalized is not None else parsed,
                elapsed_s=time.monotonic() - t0,
                parse_status=parse_status,
                parse_error=parse_error,
                recognized_package=normalized.get("recognized_package") if normalized else None,
                recognized_exact_version=normalized.get("recognized_exact_version") if normalized else None,
                version_scope=normalized.get("version_scope") if normalized else None,
                related_versions=normalized.get("related_versions") if normalized else None,
                confidence=normalized.get("confidence") if normalized else None,
                basis=normalized.get("basis") if normalized else None,
                fact=normalized.get("fact") if normalized else None,
                suspicious_exact_claim=suspicious,
                suspicious_exact_claim_reason=suspicious_reason,
                finish_reason=str(finish_reason) if finish_reason is not None else None,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=total_tokens,
                cost_usd=cost,
                litellm_model_group=litellm_model_group,
                litellm_model_id=str(headers.get("x-litellm-model-id") or "").strip() or None,
                response_model=response_model,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        parse_status, retryable = _classify_http_error(exc.code)
        return ProbeOutcome(
            ok=False,
            status=f"HTTP {exc.code}",
            status_code=exc.code,
            error=_truncate(body),
            elapsed_s=time.monotonic() - t0,
            parse_status=parse_status,
            parse_error="retryable" if retryable else None,
        )
    except urllib.error.URLError as exc:
        parse_status, retryable = _classify_url_error(exc.reason)
        return ProbeOutcome(
            ok=False,
            status=type(exc.reason).__name__,
            error=str(exc.reason),
            elapsed_s=time.monotonic() - t0,
            parse_status=parse_status,
            parse_error="retryable" if retryable else None,
        )
    except TimeoutError as exc:
        return ProbeOutcome(
            ok=False,
            status=type(exc).__name__,
            error=str(exc),
            elapsed_s=time.monotonic() - t0,
            parse_status="transport_timeout",
            parse_error="retryable",
        )
    except Exception as exc:
        parse_status, retryable = _classify_url_error(exc)
        return ProbeOutcome(
            ok=False,
            status=type(exc).__name__,
            error=str(exc),
            elapsed_s=time.monotonic() - t0,
            parse_status=parse_status,
            parse_error="retryable" if retryable else None,
        )


def probe_once(
    base_url: str,
    spec: ModelSpec,
    case: ProbeCase,
    timeout: float,
    max_tokens: int,
    *,
    retries: int,
    retry_delay: float,
) -> ProbeOutcome:
    attempts = 0
    while True:
        outcome = _probe_once_no_retry(base_url, spec, case, timeout, max_tokens)
        if outcome.ok or attempts >= retries or outcome.parse_status not in TRANSPORT_RETRY_STATUSES:
            return ProbeOutcome(**{**asdict(outcome), "retries_used": attempts})
        attempts += 1
        time.sleep(retry_delay)


def _default_output_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return _DEFAULT_LOG_DIR / f"model-memory-probe-{stamp}.jsonl"


def _write_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def _case_public_view(case: ProbeCase) -> dict[str, Any]:
    return {
        "id": case.id,
        "package_name": case.package_name,
        "version": case.version,
        "category": case.category,
        "sample_role": case.sample_role,
        "attack_vector": case.attack_vector,
        "baseline_target": case.baseline_target,
        "source": case.source,
        "expected_recognized": case.expected_recognized,
    }


def _expected_package(case: ProbeCase) -> bool | None:
    return case.expected_recognized


def _expected_exact(case: ProbeCase) -> bool | None:
    return case.expected_recognized


def _new_bucket(label: str, *, model_name: str | None = None) -> dict[str, Any]:
    return {
        "label": label,
        "model_name": model_name,
        "calls": 0,
        "parsed": 0,
        "schema_invalid": 0,
        "length_empty": 0,
        "blank_content": 0,
        "package_true": 0,
        "package_only_true": 0,
        "exact_true": 0,
        "recognized_false": 0,
        "recognized_unknown": 0,
        "benign_package_false_positives": 0,
        "benign_exact_false_positives": 0,
        "suspicious_exact_claims": 0,
        "transport_failures": 0,
        "total_cost_usd": 0.0,
        "total_latency_s": 0.0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "parse_status_counts": {},
        "transport_status_counts": {},
        "package_matches": 0,
        "package_mismatches": 0,
        "exact_matches": 0,
        "exact_mismatches": 0,
    }


def _update_bucket(bucket: dict[str, Any], case: ProbeCase, outcome: ProbeOutcome) -> None:
    bucket["calls"] += 1
    bucket["total_latency_s"] += max(outcome.elapsed_s, 0.0)
    bucket["prompt_tokens"] += outcome.prompt_tokens
    bucket["completion_tokens"] += outcome.completion_tokens
    bucket["total_tokens"] += outcome.total_tokens
    bucket["total_cost_usd"] += float(outcome.cost_usd or 0.0)
    parse_counts = bucket["parse_status_counts"]
    parse_counts[outcome.parse_status] = parse_counts.get(outcome.parse_status, 0) + 1
    if outcome.ok and outcome.parse_status == "ok_parsed":
        bucket["parsed"] += 1
    if outcome.parse_status == "ok_schema_invalid":
        bucket["schema_invalid"] += 1
    if outcome.parse_status == "ok_empty_length":
        bucket["length_empty"] += 1
    if outcome.parse_status == "ok_blank_content":
        bucket["blank_content"] += 1
    if outcome.parse_status.startswith("transport_"):
        bucket["transport_failures"] += 1
        transport_counts = bucket["transport_status_counts"]
        transport_counts[outcome.parse_status] = transport_counts.get(outcome.parse_status, 0) + 1
    if outcome.recognized_package is True:
        bucket["package_true"] += 1
    if outcome.recognized_package is True and outcome.recognized_exact_version is False:
        bucket["package_only_true"] += 1
    if outcome.recognized_exact_version is True:
        bucket["exact_true"] += 1
    if outcome.ok and outcome.parse_status == "ok_parsed" and outcome.recognized_package is False:
        bucket["recognized_false"] += 1
    if outcome.parse_status != "ok_parsed":
        bucket["recognized_unknown"] += 1
    if case.sample_role == "benign" and outcome.recognized_package is True:
        bucket["benign_package_false_positives"] += 1
    if case.sample_role == "benign" and outcome.recognized_exact_version is True:
        bucket["benign_exact_false_positives"] += 1
    if outcome.suspicious_exact_claim:
        bucket["suspicious_exact_claims"] += 1
    expected_package = _expected_package(case)
    if expected_package is not None and outcome.recognized_package is not None:
        if outcome.recognized_package == expected_package:
            bucket["package_matches"] += 1
        else:
            bucket["package_mismatches"] += 1
    expected_exact = _expected_exact(case)
    if expected_exact is not None and outcome.recognized_exact_version is not None:
        if outcome.recognized_exact_version == expected_exact:
            bucket["exact_matches"] += 1
        else:
            bucket["exact_mismatches"] += 1


def _finalize_bucket(bucket: dict[str, Any]) -> dict[str, Any]:
    calls = bucket["calls"] or 1
    bucket["mean_latency_s"] = round(bucket["total_latency_s"] / calls, 3)
    bucket["mean_cost_usd"] = round(bucket["total_cost_usd"] / calls, 6)
    bucket["total_cost_usd"] = round(bucket["total_cost_usd"], 6)
    bucket["total_latency_s"] = round(bucket["total_latency_s"], 3)
    bucket["parse_status_counts"] = dict(sorted(bucket["parse_status_counts"].items()))
    bucket["transport_status_counts"] = dict(sorted(bucket["transport_status_counts"].items()))
    return bucket


def _result_case_view(record: dict[str, Any]) -> dict[str, Any]:
    case = record.get("case") or {}
    return {
        "case_id": case.get("id"),
        "package_name": case.get("package_name"),
        "version": case.get("version"),
        "sample_role": case.get("sample_role") or case.get("category"),
        "attack_vector": case.get("attack_vector"),
        "baseline_target": case.get("baseline_target"),
        "config_stem": record.get("config_stem"),
        "model": record.get("model"),
        "basis": record.get("basis"),
        "confidence": record.get("confidence"),
        "version_scope": record.get("version_scope"),
        "related_versions": record.get("related_versions"),
        "fact": record.get("fact"),
        "parse_status": record.get("parse_status"),
        "finish_reason": record.get("finish_reason"),
        "cost_usd": record.get("cost_usd"),
        "raw_preview": record.get("raw_preview"),
        "suspicious_exact_claim_reason": record.get("suspicious_exact_claim_reason"),
    }


def summarize_probe_records(
    *,
    run_id: str,
    scope: str,
    sample_set: str,
    model_source: str,
    case_source: str,
    models: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    result_records: list[dict[str, Any]],
    out_path: Path,
    schema_version: int,
) -> dict[str, Any]:
    transport_failures = 0
    parsed_results = 0
    schema_invalid_results = 0
    length_empty_results = 0
    blank_content_results = 0
    recognized_package_true = 0
    recognized_exact_version_true = 0
    package_only_true = 0
    recognized_false = 0
    recognized_unknown = 0
    package_matches = 0
    package_mismatches = 0
    exact_matches = 0
    exact_mismatches = 0
    benign_package_false_positives = 0
    benign_exact_false_positives = 0
    suspicious_exact_claims = 0
    provider_costs = defaultdict(float)
    parse_status_counts: Counter[str] = Counter()
    transport_status_counts: Counter[str] = Counter()
    by_model: dict[str, dict[str, Any]] = {}
    by_sample_role: dict[str, dict[str, Any]] = {}
    by_attack_vector: dict[str, dict[str, Any]] = {}
    exact_version_recognitions: list[dict[str, Any]] = []
    package_only_associations: list[dict[str, Any]] = []
    benign_false_associations: list[dict[str, Any]] = []
    suspicious_exact_claim_rows: list[dict[str, Any]] = []

    for model in models:
        label = model.get("config_stem") or model.get("model_name") or model.get("label")
        if label is None:
            continue
        model_name = model.get("model_name") or model.get("model")
        by_model.setdefault(str(label), _new_bucket(str(label), model_name=model_name))

    for record in result_records:
        parse_status = str(record.get("parse_status") or "ok_unparseable")
        parse_status_counts[parse_status] += 1
        if record.get("event") == "probe.error" or parse_status.startswith("transport_"):
            transport_failures += 1
        if parse_status.startswith("transport_"):
            transport_status_counts[parse_status] += 1
        if parse_status == "ok_parsed":
            parsed_results += 1
        if parse_status == "ok_schema_invalid":
            schema_invalid_results += 1
        if parse_status == "ok_empty_length":
            length_empty_results += 1
        if parse_status == "ok_blank_content":
            blank_content_results += 1

        recognized_package = record.get("recognized_package")
        recognized_exact = record.get("recognized_exact_version")
        if recognized_package is True:
            recognized_package_true += 1
        if recognized_exact is True:
            recognized_exact_version_true += 1
        if recognized_package is True and recognized_exact is False:
            package_only_true += 1
        if parse_status == "ok_parsed" and recognized_package is False:
            recognized_false += 1
        if parse_status != "ok_parsed":
            recognized_unknown += 1

        case = record.get("case") or {}
        sample_role = str(case.get("sample_role") or case.get("category") or "unknown")
        attack_vector = str(case.get("attack_vector") or "none")
        if sample_role == "benign" and recognized_package is True:
            benign_package_false_positives += 1
        if sample_role == "benign" and recognized_exact is True:
            benign_exact_false_positives += 1
        if record.get("suspicious_exact_claim"):
            suspicious_exact_claims += 1

        expected_package = record.get("expected_recognized_package")
        if expected_package is not None and recognized_package is not None:
            if bool(recognized_package) == bool(expected_package):
                package_matches += 1
            else:
                package_mismatches += 1
        expected_exact = record.get("expected_recognized_exact_version")
        if expected_exact is not None and recognized_exact is not None:
            if bool(recognized_exact) == bool(expected_exact):
                exact_matches += 1
            else:
                exact_mismatches += 1

        provider_name = provider_for_model(record.get("litellm_model_group") or record.get("model"))
        provider_costs[provider_name] += float(record.get("cost_usd") or 0.0)
        model_key = str(record.get("config_stem") or record.get("model") or "unknown")
        by_model.setdefault(model_key, _new_bucket(model_key, model_name=record.get("model")))
        by_sample_role.setdefault(sample_role, _new_bucket(sample_role))
        by_attack_vector.setdefault(attack_vector, _new_bucket(attack_vector))

        outcome = ProbeOutcome(
            ok=record.get("event") == "probe.result",
            status=str(record.get("status") or ""),
            status_code=record.get("status_code"),
            raw_response=record.get("raw_response"),
            response_json=record.get("response_json") if isinstance(record.get("response_json"), dict) else None,
            error=record.get("error"),
            elapsed_s=float(record.get("elapsed_s") or 0.0),
            parse_status=parse_status,
            parse_error=record.get("parse_error"),
            recognized_package=recognized_package,
            recognized_exact_version=recognized_exact,
            version_scope=record.get("version_scope"),
            related_versions=record.get("related_versions"),
            confidence=record.get("confidence"),
            basis=record.get("basis"),
            fact=record.get("fact"),
            suspicious_exact_claim=bool(record.get("suspicious_exact_claim")),
            suspicious_exact_claim_reason=record.get("suspicious_exact_claim_reason"),
            finish_reason=record.get("finish_reason"),
            prompt_tokens=int(record.get("prompt_tokens") or 0),
            completion_tokens=int(record.get("completion_tokens") or 0),
            total_tokens=int(record.get("total_tokens") or 0),
            cost_usd=record.get("cost_usd"),
            litellm_model_group=record.get("litellm_model_group"),
            litellm_model_id=record.get("litellm_model_id"),
            response_model=record.get("response_model"),
            retries_used=int(record.get("retries_used") or 0),
        )
        case_obj = ProbeCase(
            id=str(case.get("id") or ""),
            package_name=str(case.get("package_name") or ""),
            version=str(case.get("version") or ""),
            expected_recognized=record.get("expected_recognized_package"),
            category=str(case.get("category") or sample_role),
            sample_role=sample_role,
            attack_vector=case.get("attack_vector"),
            baseline_target=case.get("baseline_target"),
            source=str(case.get("source") or scope),
            notes=str(case.get("notes") or ""),
        )
        _update_bucket(by_model[model_key], case_obj, outcome)
        _update_bucket(by_sample_role[sample_role], case_obj, outcome)
        _update_bucket(by_attack_vector[attack_vector], case_obj, outcome)

        case_view = _result_case_view(record)
        if recognized_exact is True:
            exact_version_recognitions.append(case_view)
        if recognized_package is True and recognized_exact is False:
            package_only_associations.append(case_view)
        if sample_role == "benign" and (recognized_package is True or recognized_exact is True):
            benign_false_associations.append(case_view)
        if record.get("suspicious_exact_claim"):
            suspicious_exact_claim_rows.append(case_view)

    total_cost_usd = round(sum(provider_costs.values()), 6)
    return {
        "event": "run.summary",
        "probe_schema_version": schema_version,
        "run_id": run_id,
        "created_at": _utc_now(),
        "scope": scope,
        "sample_set": sample_set,
        "model_source": model_source,
        "case_source": case_source,
        "models": models,
        "cases": cases,
        "total_calls": len(result_records),
        "transport_failures": transport_failures,
        "parsed_results": parsed_results,
        "schema_invalid_results": schema_invalid_results,
        "length_empty_results": length_empty_results,
        "blank_content_results": blank_content_results,
        "recognized_package_true": recognized_package_true,
        "recognized_exact_version_true": recognized_exact_version_true,
        "package_only_true": package_only_true,
        "recognized_false": recognized_false,
        "recognized_unknown": recognized_unknown,
        "package_matches": package_matches,
        "package_mismatches": package_mismatches,
        "exact_matches": exact_matches,
        "exact_mismatches": exact_mismatches,
        "benign_package_false_positives": benign_package_false_positives,
        "benign_exact_false_positives": benign_exact_false_positives,
        "suspicious_exact_claims": suspicious_exact_claims,
        "parse_status_counts": dict(sorted(parse_status_counts.items())),
        "transport_status_counts": dict(sorted(transport_status_counts.items())),
        "provider_costs": {key: round(value, 6) for key, value in sorted(provider_costs.items())},
        "total_cost_usd": total_cost_usd,
        "output_path": str(out_path),
        "summary_json_path": str(_summary_json_path(out_path)),
        "summary_md_path": str(_summary_md_path(out_path)),
        "by_model": {key: _finalize_bucket(bucket) for key, bucket in sorted(by_model.items())},
        "by_sample_role": {key: _finalize_bucket(bucket) for key, bucket in sorted(by_sample_role.items())},
        "by_attack_vector": {key: _finalize_bucket(bucket) for key, bucket in sorted(by_attack_vector.items())},
        "exact_version_recognitions": exact_version_recognitions,
        "package_only_associations": package_only_associations,
        "benign_false_associations": benign_false_associations,
        "suspicious_exact_claim_rows": suspicious_exact_claim_rows,
    }


def _render_summary_markdown(summary: dict[str, Any]) -> str:
    lines = [
        "# Model Memory Probe Summary",
        "",
        f"- Run ID: `{summary['run_id']}`",
        f"- Schema version: `{summary['probe_schema_version']}`",
        f"- Scope: `{summary['scope']}`",
        f"- Sample set: `{summary['sample_set']}`",
        f"- Model source: `{summary['model_source']}`",
        f"- Case source: `{summary['case_source']}`",
        f"- Calls: `{summary['total_calls']}`",
        f"- Total cost: `${summary['total_cost_usd']:.6f}`",
        "",
        "## Overall",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Parsed OK | {summary['parsed_results']} |",
        f"| Schema invalid | {summary['schema_invalid_results']} |",
        f"| Length-empty results | {summary['length_empty_results']} |",
        f"| Blank-content results | {summary['blank_content_results']} |",
        f"| Transport failures | {summary['transport_failures']} |",
        f"| Package recognized true | {summary['recognized_package_true']} |",
        f"| Exact-version recognized true | {summary['recognized_exact_version_true']} |",
        f"| Package-only associations | {summary['package_only_true']} |",
        f"| Recognized false | {summary['recognized_false']} |",
        f"| Recognized unknown | {summary['recognized_unknown']} |",
        f"| Benign package false positives | {summary['benign_package_false_positives']} |",
        f"| Benign exact false positives | {summary['benign_exact_false_positives']} |",
        f"| Suspicious exact claims | {summary['suspicious_exact_claims']} |",
        "",
        "## Transport Status Counts",
        "",
    ]
    if summary["transport_status_counts"]:
        lines.extend([
            "| Status | Count |",
            "| --- | ---: |",
        ])
        for status, count in summary["transport_status_counts"].items():
            lines.append(f"| {status} | {count} |")
    else:
        lines.append("None")

    lines.extend([
        "",
        "## By Model",
        "",
        "| Config | Model | Calls | Parsed | Schema Invalid | Length Empty | Package True | Exact True | False | Unknown | Benign Pkg FP | Benign Exact FP | Transport | Cost USD | Mean Latency s |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for label, bucket in summary["by_model"].items():
        lines.append(
            f"| {label} | {bucket.get('model_name') or ''} | {bucket['calls']} | {bucket['parsed']} | "
            f"{bucket['schema_invalid']} | {bucket['length_empty']} | {bucket['package_true']} | {bucket['exact_true']} | "
            f"{bucket['recognized_false']} | {bucket['recognized_unknown']} | {bucket['benign_package_false_positives']} | "
            f"{bucket['benign_exact_false_positives']} | {bucket['transport_failures']} | {bucket['total_cost_usd']:.6f} | {bucket['mean_latency_s']:.3f} |"
        )
    lines.extend([
        "",
        "## By Sample Role",
        "",
        "| Role | Calls | Parsed | Length Empty | Package True | Exact True | False | Unknown | Transport | Cost USD |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for label, bucket in summary["by_sample_role"].items():
        lines.append(
            f"| {label} | {bucket['calls']} | {bucket['parsed']} | {bucket['length_empty']} | {bucket['package_true']} | {bucket['exact_true']} | "
            f"{bucket['recognized_false']} | {bucket['recognized_unknown']} | {bucket['transport_failures']} | {bucket['total_cost_usd']:.6f} |"
        )
    lines.extend([
        "",
        "## By Attack Vector",
        "",
        "| Attack Vector | Calls | Parsed | Length Empty | Package True | Exact True | False | Unknown | Transport | Cost USD |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ])
    for label, bucket in summary["by_attack_vector"].items():
        lines.append(
            f"| {label} | {bucket['calls']} | {bucket['parsed']} | {bucket['length_empty']} | {bucket['package_true']} | {bucket['exact_true']} | "
            f"{bucket['recognized_false']} | {bucket['recognized_unknown']} | {bucket['transport_failures']} | {bucket['total_cost_usd']:.6f} |"
        )

    def _append_case_table(title: str, rows: list[dict[str, Any]]) -> None:
        lines.extend([
            "",
            f"## {title}",
            "",
        ])
        if not rows:
            lines.append("None")
            return
        lines.extend([
            "| Package | Version | Role | Model | Basis | Scope | Related Versions | Confidence |",
            "| --- | --- | --- | --- | --- | --- | --- | ---: |",
        ])
        for row in rows:
            lines.append(
                f"| {row['package_name']} | {row['version']} | {row['sample_role']} | {row['config_stem'] or row['model']} | "
                f"{row['basis'] or ''} | {row['version_scope'] or ''} | {row['related_versions'] or ''} | {row['confidence'] if row['confidence'] is not None else ''} |"
            )

    _append_case_table("Exact-Version Recognitions", summary["exact_version_recognitions"])
    _append_case_table("Package-Only Associations", summary["package_only_associations"])
    _append_case_table("Benign False Associations", summary["benign_false_associations"])

    lines.extend([
        "",
        "## Suspicious Exact-Version Claims",
        "",
    ])
    if not summary["suspicious_exact_claim_rows"]:
        lines.append("None")
    else:
        lines.extend([
            "| Package | Version | Role | Model | Reason | Fact |",
            "| --- | --- | --- | --- | --- | --- |",
        ])
        for row in summary["suspicious_exact_claim_rows"]:
            lines.append(
                f"| {row['package_name']} | {row['version']} | {row['sample_role']} | {row['config_stem'] or row['model']} | "
                f"{row['suspicious_exact_claim_reason'] or ''} | {row['fact'] or ''} |"
            )
    return "\n".join(lines) + "\n"


def _write_summary_artifacts(out_path: Path, summary: dict[str, Any]) -> tuple[Path, Path]:
    summary_json_path = _summary_json_path(out_path)
    summary_md_path = _summary_md_path(out_path)
    summary_json_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    summary_md_path.write_text(_render_summary_markdown(summary), encoding="utf-8")
    return summary_json_path, summary_md_path


def summarize_probe_file(path: Path) -> dict[str, Any]:
    records = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    if not records:
        raise SystemExit(f"HALT: {path} contains no JSONL records")

    start_record = next((record for record in records if record.get("event") == "run.start"), None)
    if start_record is None:
        raise SystemExit(f"HALT: {path} is missing a run.start record")
    if int(start_record.get("probe_schema_version") or 0) != PROBE_SCHEMA_VERSION:
        raise SystemExit(
            f"HALT: {path} uses probe schema version "
            f"{start_record.get('probe_schema_version')!r}; only v{PROBE_SCHEMA_VERSION} is supported"
        )

    result_records = [
        record
        for record in records
        if record.get("event") in {"probe.result", "probe.error"}
    ]
    case_by_id: dict[str, dict[str, Any]] = {}
    for case in list(start_record.get("cases") or []):
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("id") or "")
        if not case_id:
            continue
        case_by_id[case_id] = case
    for record in result_records:
        case = record.get("case")
        if not isinstance(case, dict):
            continue
        case_id = str(case.get("id") or "")
        if not case_id or case_id in case_by_id:
            continue
        case_by_id[case_id] = {
            "id": case.get("id"),
            "package_name": case.get("package_name"),
            "version": case.get("version"),
            "category": case.get("category"),
            "sample_role": case.get("sample_role") or case.get("category"),
            "attack_vector": case.get("attack_vector"),
            "baseline_target": case.get("baseline_target"),
            "source": case.get("source"),
            "expected_recognized": record.get("expected_recognized_package"),
        }

    return summarize_probe_records(
        run_id=str(start_record.get("run_id") or path.stem),
        scope=str(start_record.get("scope") or "unknown"),
        sample_set=str(start_record.get("sample_set") or "dataset"),
        model_source=str(start_record.get("model_source") or "unknown"),
        case_source=str(start_record.get("case_source") or "unknown"),
        models=list(start_record.get("models") or []),
        cases=list(case_by_id.values()),
        result_records=result_records,
        out_path=path,
        schema_version=PROBE_SCHEMA_VERSION,
    )


def run_probe(args: argparse.Namespace) -> int:
    runtime = _effective_runtime_options(args)
    cases, case_source = resolve_cases(args)
    models, model_source = select_models(args)
    out_path = args.out or _default_output_path()
    summary_json_path = _summary_json_path(out_path)
    summary_md_path = _summary_md_path(out_path)
    run_id = args.run_id or f"memory-probe-{uuid.uuid4()}"
    total_calls = len(models) * len(cases)

    if args.dry_run:
        print(f"Model memory probe dry-run: {len(models)} model(s), {len(cases)} case(s)")
        print(f"scope={args.scope} base_url={args.base_url.rstrip('/')} model_source={model_source}")
        print(f"case_source={case_source}")
        print(f"sample_set={args.sample_set}")
        print(f"max_tokens={runtime['max_tokens']} timeout={runtime['timeout']} retries={runtime['retries']} retry_delay={runtime['retry_delay']} progress={runtime['progress']}")
        print(f"out={out_path}")
        print(f"summary_json={summary_json_path}")
        print(f"summary_md={summary_md_path}")
        for spec in models:
            print(f"MODEL {spec.label} -> {spec.model_name}")
        for case in cases:
            print(
                f"CASE {case.id}: {case.package_name}=={case.version} [{case.sample_role or case.category}]"
                + (f" attack_vector={case.attack_vector}" if case.attack_vector else "")
            )
        return 0

    start_record = {
        "event": "run.start",
        "probe_schema_version": PROBE_SCHEMA_VERSION,
        "run_id": run_id,
        "created_at": _utc_now(),
        "base_url": args.base_url.rstrip("/"),
        "scope": args.scope,
        "sample_set": args.sample_set,
        "model_source": model_source,
        "case_source": case_source,
        "models": [asdict(spec) for spec in models],
        "cases": [_case_public_view(case) for case in cases],
        "cases_file": str(args.cases),
        "case_count": len(cases),
        "max_tokens": runtime["max_tokens"],
        "timeout": runtime["timeout"],
        "retries": runtime["retries"],
        "retry_delay": runtime["retry_delay"],
        "progress": runtime["progress"],
        "summary_json_path": str(summary_json_path),
        "summary_md_path": str(summary_md_path),
    }
    _write_jsonl(out_path, start_record)

    result_records: list[dict[str, Any]] = []
    progress_enabled = should_use_probe_progress(runtime["progress"])
    with ProbeProgress(
        enabled=progress_enabled,
        run_id=run_id,
        scope=args.scope,
        total_models=len(models),
        total_cases=len(cases),
        total_calls=total_calls,
        out_path=out_path,
    ) as progress:
        for spec in models:
            for case in cases:
                progress.start_call(spec, case)
                outcome = probe_once(
                    args.base_url,
                    spec,
                    case,
                    runtime["timeout"],
                    runtime["max_tokens"],
                    retries=runtime["retries"],
                    retry_delay=runtime["retry_delay"],
                )
                expected_package = _expected_package(case)
                expected_exact = _expected_exact(case)
                record = {
                    "event": "probe.result" if outcome.ok else "probe.error",
                    "probe_schema_version": PROBE_SCHEMA_VERSION,
                    "run_id": run_id,
                    "created_at": _utc_now(),
                    "scope": args.scope,
                    "sample_set": args.sample_set,
                    "config_stem": spec.config_stem,
                    "model": spec.model_name,
                    "case": asdict(case),
                    "ok": outcome.ok,
                    "status": outcome.status,
                    "status_code": outcome.status_code,
                    "elapsed_s": round(outcome.elapsed_s, 3),
                    "parse_status": outcome.parse_status,
                    "parse_error": outcome.parse_error,
                    "recognized_package": outcome.recognized_package,
                    "recognized_exact_version": outcome.recognized_exact_version,
                    "version_scope": outcome.version_scope,
                    "related_versions": outcome.related_versions,
                    "confidence": outcome.confidence,
                    "basis": outcome.basis,
                    "fact": outcome.fact,
                    "expected_recognized_package": expected_package,
                    "expected_recognized_exact_version": expected_exact,
                    "package_match": (
                        outcome.recognized_package == expected_package
                        if expected_package is not None and outcome.recognized_package is not None
                        else None
                    ),
                    "exact_match": (
                        outcome.recognized_exact_version == expected_exact
                        if expected_exact is not None and outcome.recognized_exact_version is not None
                        else None
                    ),
                    "response_json": outcome.response_json,
                    "raw_preview": _collapse_text(outcome.raw_response),
                    "raw_response": outcome.raw_response if outcome.parse_status != "ok_parsed" else None,
                    "error": outcome.error,
                    "finish_reason": outcome.finish_reason,
                    "prompt_tokens": outcome.prompt_tokens,
                    "completion_tokens": outcome.completion_tokens,
                    "total_tokens": outcome.total_tokens,
                    "cost_usd": outcome.cost_usd,
                    "litellm_model_group": outcome.litellm_model_group,
                    "litellm_model_id": outcome.litellm_model_id,
                    "response_model": outcome.response_model,
                    "retries_used": outcome.retries_used,
                    "suspicious_exact_claim": outcome.suspicious_exact_claim,
                    "suspicious_exact_claim_reason": outcome.suspicious_exact_claim_reason,
                }
                result_records.append(record)
                _write_jsonl(out_path, record)
                progress.record(spec, case, outcome)
                status = "OK" if outcome.ok else "FAIL"
                print(
                    f"{status} {spec.label} {case.id}: parse_status={outcome.parse_status} "
                    f"pkg={outcome.recognized_package} exact={outcome.recognized_exact_version} "
                    f"cost=${float(outcome.cost_usd or 0.0):.6f} ({outcome.elapsed_s:.1f}s)"
                )

    summary = summarize_probe_records(
        run_id=run_id,
        scope=args.scope,
        sample_set=args.sample_set,
        model_source=model_source,
        case_source=case_source,
        models=[asdict(spec) for spec in models],
        cases=[_case_public_view(case) for case in cases],
        result_records=result_records,
        out_path=out_path,
        schema_version=PROBE_SCHEMA_VERSION,
    )
    _write_jsonl(out_path, summary)
    summary_json_path, summary_md_path = _write_summary_artifacts(out_path, summary)
    print(f"Wrote {out_path}")
    print(f"Wrote {summary_json_path}")
    print(f"Wrote {summary_md_path}")
    print(
        "Summary: "
        f"calls={summary['total_calls']} parsed={summary['parsed_results']} "
        f"schema_invalid={summary['schema_invalid_results']} transport_failures={summary['transport_failures']} "
        f"exact_true={summary['recognized_exact_version_true']} total_cost=${summary['total_cost_usd']:.6f}"
    )
    return 1 if summary["transport_failures"] else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:4000")
    parser.add_argument("--scope", choices=["curated", "production"], default="curated")
    parser.add_argument("--profile", default="budget")
    parser.add_argument("--resolver-profile", default=None)
    parser.add_argument("--include-controls", action="store_true")
    parser.add_argument("--sample-set", choices=analyzer_evaluate._VALID_SAMPLE_SETS, default="dataset")
    parser.add_argument("--gemini", choices=["on", "off"], default="on")
    parser.add_argument("--all-models", action="store_true")
    parser.add_argument("--models", nargs="+", default=None)
    parser.add_argument("--cases", type=Path, default=_CASES_FILE)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout", type=float, default=None)
    parser.add_argument("--max-tokens", type=int, default=None)
    parser.add_argument("--retries", type=int, default=None)
    parser.add_argument("--retry-delay", type=float, default=None)
    parser.add_argument("--progress", choices=["auto", "always", "never"], default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return run_probe(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
