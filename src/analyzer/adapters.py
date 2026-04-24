"""
adapters.py — Detector adapter hierarchy for the entry-point evaluation pipeline.

DetectorAdapter (ABC)
  StaticAdapter     — generic SAST tools (bandit, semgrep); ignores prompt params
  GuardDogAdapter   — PyPI-malware-specific static rules; source-only mode
  LLMAdapter        — Single-shot LLM call via YAML-configured model
  AgenticAdapter    — Plan-and-tool-use LiteLLM agent loop

EvalController imports from this module.
"""

from __future__ import annotations

import hashlib
import json as _json
import os as _os
import shutil
import subprocess
import sys
import tempfile
import time as _time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import yaml as _yaml

from src.utils.logger import get_logger
from entry_extractor import PackageInfo

log = get_logger()

GUARDDOG_VERSION = "2.9.0"
GUARDDOG_SOURCE_RULES = (
    "api-obfuscation",
    "shady-links",
    "obfuscation",
    "clipboard-access",
    "exfiltrate-sensitive-data",
    "download-executable",
    "exec-base64",
    "silent-process-execution",
    "dll-hijacking",
    "screenshot",
    "steganography",
    "code-execution",
    "unicode",
    "cmd-overwrite",
    "suspicious_passwd_access_linux",
)
SEMGREP_RULES_PATH = Path(__file__).resolve().parent / "static_rules" / "semgrep_python.yml"


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class EvalDetectionResult:
    detector: str
    experiment_mode: str    # "static" | "hybrid" | "agentic" | "llm_raw" | "error"
    verdict: bool           # True = malicious
    confidence: float | None
    heuristic_flags: list[str]
    exec_time_ms: int
    api_cost_usd: float     # 0.0 for SAST
    input_tokens: int = 0
    output_tokens: int = 0
    details: dict = field(default_factory=dict)


@dataclass
class ProxyCallResult:
    text: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    requested_model: str
    actual_model: str
    selected_model: str | None = None
    litellm_model_group: str | None = None
    litellm_model_id: str | None = None
    response_model: str | None = None
    pricing_model: str | None = None
    finish_reason: str | None = None
    content_shape: str | None = None
    has_tool_calls: bool = False
    protocol_details: dict | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def __iter__(self):
        yield self.text
        yield self.input_tokens
        yield self.output_tokens
        yield self.cost_usd


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

_TRANSIENT_EMPTY_PROTOCOL_CATEGORIES = {
    "empty_no_choices",
    "empty_missing_message",
    "empty_null_content",
    "empty_blank_content",
}
_GENERIC_EMPTY_PROTOCOL_RETRY_DELAY_SECONDS = 2.0

class DetectorAdapter(ABC):
    """
    Common interface for all entry-point detectors.

    EvalController calls run(pkg, prompt_strategy, system_prompt, template_override)
    uniformly across all adapter types. StaticAdapter ignores the prompt params;
    LLMAdapter and AgenticAdapter use them to select the active strategy.
    """

    @abstractmethod
    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        ...


def _write_pkg_files(pkg: PackageInfo, target: Path) -> None:
    for rel, content in pkg.files.items():
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def _static_error_result(
    detector: str,
    error: str,
    *,
    stdout: str | None = None,
    stderr: str | None = None,
    returncode: int | None = None,
) -> EvalDetectionResult:
    details: dict = {"error": error}
    if returncode is not None:
        details["returncode"] = returncode
    if stdout:
        details["stdout"] = stdout[-2000:]
    if stderr:
        details["stderr"] = stderr[-2000:]
    return EvalDetectionResult(
        detector=detector,
        experiment_mode="error",
        verdict=False,
        confidence=None,
        heuristic_flags=[],
        exec_time_ms=0,
        api_cost_usd=0.0,
        details=details,
    )


def _empty_protocol_failure_details(
    *,
    category: str,
    raw: str | None = None,
    finish_reason: str | None = None,
    content_shape: str | None = None,
    has_tool_calls: bool = False,
    parse_error: str | None = None,
    raw_content: object | None = None,
    refusal: object | None = None,
) -> dict:
    details: dict[str, object] = {
        "error": "empty_model_response",
        "protocol_category": category,
        "protocol_failure": True,
        "retryable": False,
        "raw": raw or "",
        "has_tool_calls": bool(has_tool_calls),
    }
    if finish_reason is not None:
        details["finish_reason"] = finish_reason
    if content_shape is not None:
        details["content_shape"] = content_shape
    if parse_error:
        details["parse_error"] = parse_error
    if raw_content is not None:
        details["raw_content"] = raw_content
    if refusal not in (None, ""):
        details["refusal"] = refusal
    return details


def _raw_preview(raw: str | None, limit: int = 400) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def _protocol_failure_details(raw: str | None, *, reason: str | None = None) -> dict:
    raw_text = raw or ""
    if not raw_text.strip():
        return _empty_protocol_failure_details(
            category="empty_blank_content",
            raw=raw_text,
            content_shape="str_blank",
            parse_error=reason,
        )

    details = {
        "error": "unparseable_model_response",
        "protocol_failure": True,
        "retryable": False,
        "raw": raw_text,
    }
    preview = _raw_preview(raw_text)
    if preview:
        details["raw_preview"] = preview
    if reason:
        details["parse_error"] = reason
    return details


def _is_protocol_failure(details: dict) -> bool:
    return bool(details.get("protocol_failure"))


def _parse_json_verdict_response(raw: str) -> tuple[bool, float | None, dict]:
    import re as _re

    m = _re.search(r"\{.*\}", raw, _re.DOTALL)
    if not m:
        return False, None, _protocol_failure_details(raw, reason="no_json_object")
    try:
        data = _json.loads(m.group())
    except _json.JSONDecodeError:
        return False, None, _protocol_failure_details(raw, reason="invalid_json")
    if not isinstance(data, dict):
        return False, None, _protocol_failure_details(raw, reason="json_not_object")

    verdict_raw = data.get("verdict")
    if not isinstance(verdict_raw, str):
        return False, None, _protocol_failure_details(raw, reason="missing_or_invalid_verdict")
    verdict_str = verdict_raw.strip().lower()
    if verdict_str not in {"malicious", "benign"}:
        return False, None, _protocol_failure_details(raw, reason="invalid_verdict")

    try:
        confidence = float(data["confidence"]) if "confidence" in data else None
    except (TypeError, ValueError):
        return False, None, _protocol_failure_details(raw, reason="invalid_confidence")
    return verdict_str == "malicious", confidence, data


def _context(trace_context: dict | None, pkg: PackageInfo | None = None) -> dict:
    ctx = dict(trace_context or {})
    if pkg is not None:
        ctx.setdefault("package", pkg.name)
        ctx.setdefault("version", pkg.version)
    return ctx


def _file_map(root: Path) -> list[dict]:
    files: list[dict] = []
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        data = path.read_bytes()
        files.append({
            "path": path.relative_to(root).as_posix(),
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return files


def _blob_text(raw_log, kind: str, text: str, suffix: str = ".txt"):
    if raw_log is None:
        return None
    return raw_log.blob_text(kind, text or "", suffix=suffix)


def _emit_protocol_error(raw_log, event: str, ctx: dict, *, model: str, details: dict) -> None:
    if raw_log is None:
        return
    payload = {
        "model": model,
        "error": details.get("error"),
        "protocol_category": details.get("protocol_category"),
        "retryable": details.get("retryable", False),
        "protocol_failure": True,
        "finish_reason": details.get("finish_reason"),
        "content_shape": details.get("content_shape"),
        "has_tool_calls": details.get("has_tool_calls", False),
        "litellm_model_group": details.get("litellm_model_group"),
        "litellm_model_id": details.get("litellm_model_id"),
        "raw_preview": details.get("raw_preview"),
    }
    raw = details.get("raw")
    if raw is not None:
        payload["raw_response_ref"] = raw_log.blob_text("model_protocol_failure_raw", str(raw), suffix=".txt")
    raw_log.emit(event, **ctx, payload=payload)


def _coerce_text_value(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "value", "content"):
            candidate = value.get(key)
            if isinstance(candidate, str):
                return candidate
    return None


def _extract_message_text(content: object) -> tuple[str, str, object | None]:
    if content is None:
        return "", "null", None
    if isinstance(content, str):
        return content, ("str_text" if content.strip() else "str_blank"), None
    if isinstance(content, dict):
        lowered_type = str(content.get("type", "")).lower()
        refusal = content if lowered_type in {"refusal", "content_filter"} else None
        text = _coerce_text_value(content)
        if text is not None:
            return text, ("dict_text" if text.strip() else "dict_blank"), refusal
        return "", ("dict_refusal" if refusal is not None else "dict_nontext"), refusal
    if isinstance(content, list):
        text_parts: list[str] = []
        saw_text = False
        saw_refusal = False
        refusal_items: list[object] = []
        for item in content:
            if isinstance(item, str):
                saw_text = True
                text_parts.append(item)
                continue
            if isinstance(item, dict):
                lowered_type = str(item.get("type", "")).lower()
                if lowered_type in {"refusal", "content_filter"}:
                    saw_refusal = True
                    refusal_items.append(item)
                text = _coerce_text_value(item)
                if text is not None:
                    saw_text = True
                    text_parts.append(text)
                continue
            text = _coerce_text_value(getattr(item, "text", None))
            if text is not None:
                saw_text = True
                text_parts.append(text)
        joined = "\n".join(part for part in text_parts if isinstance(part, str))
        if joined.strip():
            return joined, "list_text", refusal_items if saw_refusal else None
        if saw_text:
            return joined, "list_blank", refusal_items if saw_refusal else None
        if saw_refusal:
            return "", "list_refusal", refusal_items
        return "", "list_nontext", None
    return "", f"nonstandard_{type(content).__name__}", None


def _protocol_details_from_response(resp) -> tuple[str, dict | None, dict]:
    response_meta: dict[str, object] = {
        "finish_reason": None,
        "content_shape": None,
        "has_tool_calls": False,
    }
    choices = getattr(resp, "choices", None)
    if not choices:
        details = _empty_protocol_failure_details(
            category="empty_no_choices",
            content_shape="missing_choices",
        )
        response_meta.update({
            "content_shape": "missing_choices",
        })
        return "", details, response_meta

    choice = choices[0]
    finish_reason = getattr(choice, "finish_reason", None)
    response_meta["finish_reason"] = finish_reason
    message = getattr(choice, "message", None)
    if message is None:
        details = _empty_protocol_failure_details(
            category="empty_missing_message",
            finish_reason=finish_reason,
            content_shape="missing_message",
        )
        response_meta["content_shape"] = "missing_message"
        return "", details, response_meta

    tool_calls = getattr(message, "tool_calls", None)
    has_tool_calls = bool(tool_calls)
    response_meta["has_tool_calls"] = has_tool_calls
    refusal = getattr(message, "refusal", None)
    content = getattr(message, "content", None)
    text, content_shape, refusal_from_content = _extract_message_text(content)
    response_meta["content_shape"] = content_shape
    refusal_payload = refusal if refusal not in (None, "") else refusal_from_content

    if text.strip():
        return text, None, response_meta

    raw_content = None
    if hasattr(message, "model_dump"):
        raw_content = message.model_dump(mode="json")
    elif content is not None:
        raw_content = content

    if has_tool_calls:
        category = "empty_tool_calls_only"
    elif refusal_payload not in (None, "") or content_shape in {"list_refusal", "dict_refusal"}:
        category = "empty_refusal_only"
    elif finish_reason == "length":
        category = "empty_finish_reason_length"
    elif content is None:
        category = "empty_null_content"
    elif content_shape in {"str_blank", "dict_blank", "list_blank"}:
        category = "empty_blank_content"
    elif content_shape in {"list_nontext", "dict_nontext"} or content_shape.startswith("nonstandard_"):
        category = "empty_nontext_content"
    else:
        category = "empty_unknown_shape"

    details = _empty_protocol_failure_details(
        category=category,
        raw=text,
        finish_reason=finish_reason,
        content_shape=content_shape,
        has_tool_calls=has_tool_calls,
        raw_content=raw_content,
        refusal=refusal_payload,
    )
    return text, details, response_meta


def _provider_family(model_name: str) -> str:
    if model_name.startswith(("gemini-", "gemini/")):
        return "gemini"
    if model_name.startswith("together_ai/"):
        return "together"
    if model_name.startswith("claude-"):
        return "anthropic"
    if model_name.startswith(("gpt-", "o1-", "o3-")):
        return "openai"
    return "other"


def _exception_details(exc: Exception) -> tuple[str, str]:
    text = " ".join(str(exc).split())
    lower = text.lower()
    if any(token in lower for token in ("invalid api key", "unauthorized", "authentication", "401", "403")):
        return text or exc.__class__.__name__, "auth_error"
    if any(token in lower for token in ("429", "rate limit", "quota", "resource_exhausted", "too many requests")):
        return text or exc.__class__.__name__, "rate_limit"
    if any(token in lower for token in ("high demand", "overloaded", "unavailable", "resource exhausted")):
        return text or exc.__class__.__name__, "provider_overload"
    if any(token in lower for token in ("timeout", "timed out")):
        return text or exc.__class__.__name__, "client_timeout"
    if any(token in lower for token in ("500", "502", "503", "504")):
        return text or exc.__class__.__name__, "provider_or_proxy_transient"
    if any(token in lower for token in ("connection refused", "connection reset", "cannot connect", "connection error")):
        return text or exc.__class__.__name__, "provider_or_proxy_transient"
    if any(token in lower for token in ("404", "not found")):
        return text or exc.__class__.__name__, "http_error"
    return text or exc.__class__.__name__, "unknown_error"


def _resolve_tool_executable(tool: str) -> str:
    """Resolve a console script even when the venv was not shell-activated."""
    from_path = shutil.which(tool)
    if from_path:
        return from_path

    candidates = [Path(sys.executable).resolve().parent / tool]
    checked = [str(candidate) for candidate in candidates]
    for candidate in candidates:
        if candidate.exists() and _os.access(candidate, _os.X_OK):
            return str(candidate)

    raise FileNotFoundError(
        f"{tool!r} executable not found. Checked PATH and: {', '.join(checked)}. "
        "Install project requirements in the active venv or launch through deployment/TUI with the venv bin on PATH."
    )


# ---------------------------------------------------------------------------
# StaticAdapter — SAST tools
# ---------------------------------------------------------------------------

class StaticAdapter(DetectorAdapter):

    SUPPORTED = ("bandit", "semgrep")

    def __init__(self, tool: str):
        if tool not in self.SUPPORTED:
            raise ValueError(f"Unsupported static tool: {tool}")
        self._tool = tool

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        # Prompt params are unused — SAST is prompt-agnostic.
        if not pkg.files:
            return EvalDetectionResult(
                detector=self._tool, experiment_mode="static",
                verdict=False, confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=0, api_cost_usd=0.0,
                details={"note": "no files to scan"},
            )

        t0 = _time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            _write_pkg_files(pkg, tmp)
            result = self._invoke(tmp, raw_log=raw_log, trace_context=_context(trace_context, pkg))

        result.exec_time_ms = int((_time.monotonic() - t0) * 1000)
        result.heuristic_flags = list(pkg.heuristic_flags)
        return result

    def _invoke(self, target: Path, *, raw_log=None, trace_context: dict | None = None) -> EvalDetectionResult:
        if self._tool == "bandit":
            return self._run_bandit(target, raw_log=raw_log, trace_context=trace_context)
        return self._run_semgrep(target, raw_log=raw_log, trace_context=trace_context)

    def _run_bandit(self, target: Path, *, raw_log=None, trace_context: dict | None = None) -> EvalDetectionResult:
        cmd = [_resolve_tool_executable("bandit"), "-r", str(target), "-f", "json", "-q"]
        if raw_log is not None:
            raw_log.emit(
                "static.command.start",
                detector="bandit",
                mode="static",
                strategy=(trace_context or {}).get("strategy", "zero_shot"),
                package=(trace_context or {}).get("package"),
                version=(trace_context or {}).get("version"),
                artifact_filename=(trace_context or {}).get("artifact_filename"),
                payload={"argv": cmd, "timeout": 120, "temp_file_map": _file_map(target)},
            )
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120,
            )
            stdout_ref = _blob_text(raw_log, "static_stdout", proc.stdout, suffix=".json")
            stderr_ref = _blob_text(raw_log, "static_stderr", proc.stderr, suffix=".txt")
            if raw_log is not None:
                raw_log.emit(
                    "static.command.raw_exit",
                    detector="bandit",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "returncode": proc.returncode,
                        "stdout_ref": stdout_ref,
                        "stderr_ref": stderr_ref,
                    },
                )
            data = _json.loads(proc.stdout) if proc.stdout.strip() else {}
            issues = data.get("results", [])
            if raw_log is not None:
                raw_log.emit(
                    "static.command.exit",
                    detector="bandit",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "returncode": proc.returncode,
                        "stdout_ref": stdout_ref,
                        "stderr_ref": stderr_ref,
                        "parsed": {"issue_count": len(issues), "issues": issues[:10]},
                    },
                )
            if proc.returncode not in (0, 1) and not issues:
                return _static_error_result(
                    "bandit",
                    "bandit exited without parseable findings",
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    returncode=proc.returncode,
                )
            return EvalDetectionResult(
                detector="bandit", experiment_mode="static",
                verdict=bool(issues), confidence=None,
                heuristic_flags=[],
                exec_time_ms=0, api_cost_usd=0.0,
                details={"issue_count": len(issues), "issues": issues[:10]},
            )
        except Exception as exc:
            if raw_log is not None:
                raw_log.emit(
                    "static.command.error",
                    detector="bandit",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={"error": str(exc)},
                )
            return _static_error_result("bandit", str(exc))

    def _run_semgrep(self, target: Path, *, raw_log=None, trace_context: dict | None = None) -> EvalDetectionResult:
        try:
            semgrep_state = target / ".semgrep-state"
            semgrep_state.mkdir(exist_ok=True)
            semgrep_env = {
                **_os.environ,
                "SEMGREP_SETTINGS_FILE": str(semgrep_state / "settings.yml"),
                "SEMGREP_LOG_FILE": str(semgrep_state / "semgrep.log"),
                "SEMGREP_SEND_METRICS": "off",
            }
            cmd = [
                _resolve_tool_executable("semgrep"),
                "scan",
                "--config",
                str(SEMGREP_RULES_PATH),
                "--json",
                "--metrics",
                "off",
                "--disable-version-check",
                "--no-git-ignore",
                "--quiet",
                str(target),
            ]
            if raw_log is not None:
                raw_log.emit(
                    "static.command.start",
                    detector="semgrep",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "argv": cmd,
                        "timeout": 120,
                        "env_overrides": {
                            "SEMGREP_SETTINGS_FILE": semgrep_env["SEMGREP_SETTINGS_FILE"],
                            "SEMGREP_LOG_FILE": semgrep_env["SEMGREP_LOG_FILE"],
                            "SEMGREP_SEND_METRICS": semgrep_env["SEMGREP_SEND_METRICS"],
                        },
                        "temp_file_map": _file_map(target),
                    },
                )
            proc = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=120, env=semgrep_env,
            )
            stdout_ref = _blob_text(raw_log, "static_stdout", proc.stdout, suffix=".json")
            stderr_ref = _blob_text(raw_log, "static_stderr", proc.stderr, suffix=".txt")
            if raw_log is not None:
                raw_log.emit(
                    "static.command.raw_exit",
                    detector="semgrep",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "returncode": proc.returncode,
                        "stdout_ref": stdout_ref,
                        "stderr_ref": stderr_ref,
                    },
                )
            data = _json.loads(proc.stdout) if proc.stdout.strip() else {}
            findings = data.get("results", [])
            if raw_log is not None:
                raw_log.emit(
                    "static.command.exit",
                    detector="semgrep",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "returncode": proc.returncode,
                        "stdout_ref": stdout_ref,
                        "stderr_ref": stderr_ref,
                        "parsed": {"finding_count": len(findings), "findings": findings[:10]},
                    },
                )
            if proc.returncode not in (0, 1) and not findings:
                return _static_error_result(
                    "semgrep",
                    "semgrep exited without parseable findings",
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    returncode=proc.returncode,
                )
            return EvalDetectionResult(
                detector="semgrep", experiment_mode="static",
                verdict=bool(findings), confidence=None,
                heuristic_flags=[],
                exec_time_ms=0, api_cost_usd=0.0,
                details={"finding_count": len(findings), "findings": findings[:10]},
            )
        except Exception as exc:
            if raw_log is not None:
                raw_log.emit(
                    "static.command.error",
                    detector="semgrep",
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={"error": str(exc)},
                )
            return _static_error_result("semgrep", str(exc))


# ---------------------------------------------------------------------------
# GuardDogAdapter — PyPI-malware-specific static rules
# ---------------------------------------------------------------------------

class GuardDogAdapter(DetectorAdapter):
    """
    GuardDog source-only baseline.

    It scans the same PackageInfo.files evidence set as Bandit, Semgrep, and the
    LLM-hybrid prompt. Only explicit source-code rules are enabled; metadata
    heuristics are intentionally excluded because they can query live package
    registries and would give GuardDog evidence the other detectors do not see.
    """

    _detector_name = "guarddog"
    _experiment_mode = "static"

    def __init__(
        self,
        rules: tuple[str, ...] = GUARDDOG_SOURCE_RULES,
        timeout: int = 180,
    ):
        self._rules = tuple(rules)
        self._timeout = timeout

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        # Prompt params are unused — GuardDog is prompt-agnostic.
        if not pkg.files:
            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="static",
                verdict=False,
                confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=0,
                api_cost_usd=0.0,
                details={
                    "note": "no files to scan",
                    "guarddog_version": GUARDDOG_VERSION,
                    "rules": list(self._rules),
                },
            )

        t0 = _time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            _write_pkg_files(pkg, tmp)
            result = self._run_guarddog(tmp, raw_log=raw_log, trace_context=_context(trace_context, pkg))

        result.exec_time_ms = int((_time.monotonic() - t0) * 1000)
        result.heuristic_flags = list(pkg.heuristic_flags)
        return result

    def _command(self, target: Path) -> list[str]:
        cmd = [
            _resolve_tool_executable("guarddog"),
            "pypi",
            "scan",
            str(target),
            "--output-format=json",
        ]
        for rule in self._rules:
            cmd.extend(["--rules", rule])
        return cmd

    def _run_guarddog(self, target: Path, *, raw_log=None, trace_context: dict | None = None) -> EvalDetectionResult:
        cmd = self._command(target)
        if raw_log is not None:
            raw_log.emit(
                "static.command.start",
                detector=self._detector_name,
                mode="static",
                strategy=(trace_context or {}).get("strategy", "zero_shot"),
                package=(trace_context or {}).get("package"),
                version=(trace_context or {}).get("version"),
                artifact_filename=(trace_context or {}).get("artifact_filename"),
                payload={"argv": cmd, "timeout": self._timeout, "temp_file_map": _file_map(target)},
            )
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            stdout_ref = _blob_text(raw_log, "static_stdout", proc.stdout, suffix=".json")
            stderr_ref = _blob_text(raw_log, "static_stderr", proc.stderr, suffix=".txt")
            if raw_log is not None:
                raw_log.emit(
                    "static.command.raw_exit",
                    detector=self._detector_name,
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "returncode": proc.returncode,
                        "stdout_ref": stdout_ref,
                        "stderr_ref": stderr_ref,
                    },
                )
            data = None
            if not proc.stdout.strip():
                if proc.returncode == 0:
                    findings: list[dict] = []
                else:
                    return _static_error_result(
                        self._detector_name,
                        "guarddog exited without JSON output",
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        returncode=proc.returncode,
                    )
            else:
                data = _json.loads(proc.stdout)
                findings = self._extract_findings(data)
                errors = self._extract_errors(data)
                if errors and not findings:
                    return _static_error_result(
                        self._detector_name,
                        "guarddog reported rule execution errors",
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        returncode=proc.returncode,
                    )
                if proc.returncode != 0 and not findings:
                    return _static_error_result(
                        self._detector_name,
                        "guarddog exited non-zero without findings",
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        returncode=proc.returncode,
                    )

            if raw_log is not None:
                raw_log.emit(
                    "static.command.exit",
                    detector=self._detector_name,
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={
                        "returncode": proc.returncode,
                        "stdout_ref": stdout_ref,
                        "stderr_ref": stderr_ref,
                        "parsed": {"finding_count": len(findings), "findings": findings[:10]},
                    },
                )
            details = {
                "finding_count": len(findings),
                "findings": findings[:10],
                "guarddog_version": GUARDDOG_VERSION,
                "rules": list(self._rules),
            }
            if data is not None:
                errors = self._extract_errors(data)
                if errors:
                    details["errors"] = errors

            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="static",
                verdict=bool(findings),
                confidence=None,
                heuristic_flags=[],
                exec_time_ms=0,
                api_cost_usd=0.0,
                details=details,
            )
        except Exception as exc:
            if raw_log is not None:
                raw_log.emit(
                    "static.command.error",
                    detector=self._detector_name,
                    mode="static",
                    strategy=(trace_context or {}).get("strategy", "zero_shot"),
                    package=(trace_context or {}).get("package"),
                    version=(trace_context or {}).get("version"),
                    artifact_filename=(trace_context or {}).get("artifact_filename"),
                    payload={"error": str(exc)},
                )
            return _static_error_result(self._detector_name, str(exc))

    def _extract_errors(self, data) -> dict:
        if not isinstance(data, dict):
            return {}
        errors = data.get("errors")
        if isinstance(errors, dict):
            return {str(k): v for k, v in errors.items() if v}
        if isinstance(errors, list):
            return {str(i): item for i, item in enumerate(errors) if item}
        if errors:
            return {"error": errors}
        return {}

    def _extract_findings(self, data) -> list[dict]:
        if isinstance(data, list):
            return self._normalize_findings(data)

        if not isinstance(data, dict):
            return [{"value": data}] if data else []

        for key in ("results", "findings", "issues", "matches", "detections"):
            value = data.get(key)
            if isinstance(value, list):
                return self._normalize_findings(value)
            if isinstance(value, dict):
                return self._extract_findings(value)

        combined: list[dict] = []
        for value in data.values():
            if isinstance(value, list):
                combined.extend(self._normalize_findings(value))
            elif isinstance(value, dict):
                combined.extend(self._extract_findings(value))
        return combined

    def _normalize_findings(self, findings: list) -> list[dict]:
        normalized: list[dict] = []
        for item in findings:
            if isinstance(item, dict):
                normalized.append(item)
            else:
                normalized.append({"value": item})
        return normalized


# ---------------------------------------------------------------------------
# LLMAdapter - single-shot LLM call (YAML-configured model)
# ---------------------------------------------------------------------------

class LLMAdapter(DetectorAdapter):

    def __init__(self, config_path: str | Path):
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f)
        self._model_name: str      = cfg["model_name"]
        self._temperature: float   = float(cfg.get("temperature", 0.0))
        self._system_prompt: str   = cfg.get("system_prompt", "")
        self._user_template: str   = cfg.get("user_template", "{file_listing}")
        self._detector_name: str   = Path(config_path).stem   # e.g. "claude_opus"
        self._proxy_url: str | None = cfg.get("proxy_url") or None
        self._max_tokens: int = int(cfg.get("max_tokens", 512))
        self._response_format = cfg.get("response_format")
        self._extra_body = cfg.get("extra_body")
        self._reasoning_effort = cfg.get("reasoning_effort")
        legacy_request_params = dict(cfg.get("request_params") or {})
        if legacy_request_params:
            if self._response_format is None and "response_format" in legacy_request_params:
                self._response_format = legacy_request_params.pop("response_format")
            if self._extra_body is None and "extra_body" in legacy_request_params:
                self._extra_body = legacy_request_params.pop("extra_body")
            if self._reasoning_effort is None and "reasoning_effort" in legacy_request_params:
                self._reasoning_effort = legacy_request_params.pop("reasoning_effort")
            if legacy_request_params:
                raise ValueError(
                    f"Unsupported request_params keys in {config_path}: "
                    + ", ".join(sorted(legacy_request_params))
                )
        self._retry_attempts: int = int(cfg.get("retry_attempts", 0))
        self._retry_delay_seconds: float = float(cfg.get("retry_delay_seconds", 0.0))
        self._retry_unparseable: bool = bool(cfg.get("retry_unparseable", False))
        self._retry_transport_categories: set[str] = {
            str(item) for item in cfg.get("retry_transport_categories", [])
        }
        self._retry_protocol_errors: set[str] = {
            str(item) for item in cfg.get("retry_protocol_errors", [])
        }
        if self._retry_unparseable:
            self._retry_protocol_errors.add("unparseable_model_response")
        self._fallback_models: list[str] = [str(model) for model in cfg.get("fallback_models", [])]

    def _mode_name(self) -> str:
        return "hybrid"

    def _build_listing(self, pkg: PackageInfo) -> tuple[str, bool]:
        return self._build_file_listing(pkg)

    def _is_protocol_retryable(self, details: dict, requested_model: str) -> bool:
        if not _is_protocol_failure(details):
            return False
        error = str(details.get("error", ""))
        return error in set(getattr(self, "_retry_protocol_errors", set()) or [])

    @staticmethod
    def _is_generic_empty_retryable(details: dict) -> bool:
        return str(details.get("protocol_category") or "") in _TRANSIENT_EMPTY_PROTOCOL_CATEGORIES

    def _is_transport_retryable(self, category: str) -> bool:
        configured = set(getattr(self, "_retry_transport_categories", set()) or [])
        if configured:
            return category in configured
        return category in {
            "rate_limit",
            "provider_overload",
            "provider_or_proxy_transient",
            "client_timeout",
        }

    def _retry_sleep(self) -> None:
        delay = float(getattr(self, "_retry_delay_seconds", 0.0) or 0.0)
        if delay > 0:
            _time.sleep(delay)

    @staticmethod
    def _generic_protocol_retry_sleep() -> None:
        _time.sleep(_GENERIC_EMPTY_PROTOCOL_RETRY_DELAY_SECONDS)

    def _attempt_models(self) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for model in [self._model_name, *getattr(self, "_fallback_models", [])]:
            if model not in seen:
                ordered.append(model)
                seen.add(model)
        return ordered

    def _error_result(
        self,
        *,
        pkg: PackageInfo,
        mode: str,
        t0: float,
        details: dict,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
    ) -> EvalDetectionResult:
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode="error",
            verdict=False,
            confidence=None,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=cost_usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            details=details,
        )

    def _success_result(
        self,
        *,
        pkg: PackageInfo,
        mode: str,
        t0: float,
        verdict: bool,
        confidence: float | None,
        details: dict,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
    ) -> EvalDetectionResult:
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode=mode,
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=cost_usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            details=details,
        )

    def _run_mode(
        self,
        pkg: PackageInfo,
        *,
        mode: str,
        prompt_strategy: str,
        system: str,
        user: str,
        truncated: bool,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        ctx = _context(trace_context, pkg)
        ctx.update({"detector": self._detector_name, "mode": mode, "strategy": prompt_strategy})
        t0 = _time.monotonic()
        total_in = 0
        total_out = 0
        total_cost = 0.0
        attempts_summary: list[dict] = []
        pricing_breakdown: list[dict] = []
        last_protocol_details: dict | None = None
        last_exception: str | None = None
        last_requested_model = self._model_name
        last_actual_model = self._model_name
        last_selected_model = self._model_name
        attempt_models = self._attempt_models()

        for model_index, active_model in enumerate(attempt_models):
            transport_retries_used = 0
            generic_protocol_retries_used = 0
            configured_protocol_retries_used = 0
            advance_to_next_model = False
            while True:
                attempt_no = len(attempts_summary) + 1
                try:
                    call = self._call_api(
                        system,
                        user,
                        raw_log=raw_log,
                        trace_context=ctx,
                        model_name=active_model,
                        requested_model=self._model_name,
                        attempt=attempt_no,
                        mode=mode,
                    )
                    if not isinstance(call, ProxyCallResult):
                        raw_text, in_tok, out_tok, cost = call
                        call = ProxyCallResult(
                            text=raw_text,
                            input_tokens=in_tok,
                            output_tokens=out_tok,
                            cost_usd=cost,
                            requested_model=self._model_name,
                            actual_model=active_model,
                            selected_model=active_model,
                            pricing_model=active_model,
                        )
                except Exception as exc:
                    error_text, error_category = _exception_details(exc)
                    retryable = self._is_transport_retryable(error_category)
                    last_exception = error_text
                    attempts_summary.append({
                        "attempt": attempt_no,
                        "requested_model": self._model_name,
                        "selected_model": active_model,
                        "actual_model": active_model,
                        "error": error_text,
                        "error_category": error_category,
                        "retryable": retryable,
                        "phase": "transport",
                    })
                    if raw_log is not None:
                        raw_log.emit(
                            "llm.retry" if retryable else "llm.error",
                            **ctx,
                            payload={
                                "attempt": attempt_no,
                                "requested_model": self._model_name,
                                "selected_model": active_model,
                                "actual_model": active_model,
                                "error": error_text,
                                "error_category": error_category,
                                "retryable": retryable,
                                "phase": "transport",
                            },
                        )
                    has_same_model_retry = retryable and transport_retries_used < int(getattr(self, "_retry_attempts", 0))
                    has_fallback = retryable and model_index + 1 < len(attempt_models)
                    if has_same_model_retry:
                        transport_retries_used += 1
                        self._retry_sleep()
                        continue
                    if has_fallback:
                        self._retry_sleep()
                        advance_to_next_model = True
                        break
                    details = {
                        "error": error_text,
                        "error_category": error_category,
                        "model": active_model,
                        "requested_model": self._model_name,
                        "selected_model": active_model,
                        "actual_model": active_model,
                        "fallback_used": active_model != self._model_name,
                        "fallback_chain": attempt_models,
                        "attempt_count": attempt_no,
                        "attempts": attempts_summary,
                        "pricing_breakdown": pricing_breakdown,
                    }
                    return self._error_result(
                        pkg=pkg,
                        mode=mode,
                        t0=t0,
                        details=details,
                        input_tokens=total_in,
                        output_tokens=total_out,
                        cost_usd=total_cost,
                    )
                if advance_to_next_model:
                    break

                total_in += call.input_tokens
                total_out += call.output_tokens
                total_cost += call.cost_usd
                pricing_breakdown.append({
                    "model": call.pricing_model or call.actual_model or active_model,
                    "input_tokens": call.input_tokens,
                    "output_tokens": call.output_tokens,
                })
                last_requested_model = call.requested_model
                last_actual_model = call.actual_model
                last_selected_model = call.selected_model or active_model

                if call.protocol_details is not None:
                    verdict, confidence, details = False, None, dict(call.protocol_details)
                else:
                    verdict, confidence, details = self._parse_response(call.text)
                details["model"] = call.pricing_model or call.actual_model or active_model
                details["requested_model"] = self._model_name
                details["selected_model"] = call.selected_model or active_model
                details["actual_model"] = call.actual_model
                if call.response_model:
                    details["response_model"] = call.response_model
                if call.litellm_model_group:
                    details["litellm_model_group"] = call.litellm_model_group
                if call.litellm_model_id:
                    details["litellm_model_id"] = call.litellm_model_id
                if call.finish_reason is not None and "finish_reason" not in details:
                    details["finish_reason"] = call.finish_reason
                if call.content_shape is not None and "content_shape" not in details:
                    details["content_shape"] = call.content_shape
                details["has_tool_calls"] = bool(
                    details.get("has_tool_calls", False) or call.has_tool_calls
                )
                if truncated:
                    details["truncated"] = True
                details["fallback_used"] = (call.selected_model or active_model) != self._model_name
                details["fallback_chain"] = attempt_models
                details["attempt_count"] = attempt_no
                details["attempts"] = attempts_summary + [{
                    "attempt": attempt_no,
                    "requested_model": self._model_name,
                    "selected_model": call.selected_model or active_model,
                    "actual_model": call.actual_model,
                    "response_model": call.response_model,
                    "litellm_model_group": call.litellm_model_group,
                    "litellm_model_id": call.litellm_model_id,
                    "finish_reason": call.finish_reason,
                    "content_shape": call.content_shape,
                    "has_tool_calls": call.has_tool_calls,
                    "phase": "response",
                    "result": details.get("error", "ok"),
                    "retryable": details.get("retryable", False),
                }]
                details["pricing_breakdown"] = pricing_breakdown

                if not _is_protocol_failure(details):
                    return self._success_result(
                        pkg=pkg,
                        mode=mode,
                        t0=t0,
                        verdict=verdict,
                        confidence=confidence,
                        details=details,
                        input_tokens=total_in,
                        output_tokens=total_out,
                        cost_usd=total_cost,
                    )

                last_protocol_details = dict(details)
                details["error_category"] = "protocol_failure"
                generic_retryable = (
                    self._is_generic_empty_retryable(details)
                    and generic_protocol_retries_used < 1
                )
                configured_retryable = self._is_protocol_retryable(details, self._model_name)
                retryable = generic_retryable or configured_retryable
                details["retryable"] = retryable
                attempts_summary.append({
                    "attempt": attempt_no,
                    "requested_model": self._model_name,
                    "selected_model": call.selected_model or active_model,
                    "actual_model": call.actual_model,
                    "response_model": call.response_model,
                    "litellm_model_group": call.litellm_model_group,
                    "litellm_model_id": call.litellm_model_id,
                    "finish_reason": details.get("finish_reason"),
                    "content_shape": details.get("content_shape"),
                    "has_tool_calls": details.get("has_tool_calls", False),
                    "phase": "protocol",
                    "error": details.get("error"),
                    "error_category": "protocol_failure",
                    "protocol_category": details.get("protocol_category"),
                    "retryable": retryable,
                })
                if raw_log is not None:
                    raw_log.emit(
                        "llm.retry" if retryable else "llm.protocol_error",
                        **ctx,
                            payload={
                                "attempt": attempt_no,
                                "requested_model": self._model_name,
                                "selected_model": call.selected_model or active_model,
                                "actual_model": call.actual_model,
                                "error": details.get("error"),
                                "error_category": "protocol_failure",
                                "protocol_category": details.get("protocol_category"),
                                "retryable": retryable,
                                "phase": "protocol",
                                "finish_reason": details.get("finish_reason"),
                                "content_shape": details.get("content_shape"),
                                "has_tool_calls": details.get("has_tool_calls", False),
                                "litellm_model_group": call.litellm_model_group,
                                "litellm_model_id": call.litellm_model_id,
                            },
                        )
                configured_same_model_retry = (
                    configured_retryable
                    and configured_protocol_retries_used < int(getattr(self, "_retry_attempts", 0))
                )
                has_same_model_retry = generic_retryable or configured_same_model_retry
                has_fallback = retryable and model_index + 1 < len(attempt_models)
                if has_same_model_retry:
                    if generic_retryable:
                        generic_protocol_retries_used += 1
                        self._generic_protocol_retry_sleep()
                    else:
                        configured_protocol_retries_used += 1
                        self._retry_sleep()
                    continue
                if has_fallback:
                    self._retry_sleep()
                    advance_to_next_model = True
                    break

                details["intended_mode"] = mode
                _emit_protocol_error(
                    raw_log,
                    "llm.protocol_error",
                    ctx,
                    model=active_model,
                    details=details,
                )
                return self._error_result(
                    pkg=pkg,
                    mode=mode,
                    t0=t0,
                    details=details,
                    input_tokens=total_in,
                    output_tokens=total_out,
                    cost_usd=total_cost,
                )
            if advance_to_next_model:
                continue

        fallback_details = dict(last_protocol_details or {})
        fallback_details.setdefault("error", last_exception or "exhausted_retries")
        fallback_details.setdefault(
            "error_category",
            "protocol_failure" if last_protocol_details is not None else "unknown_error",
        )
        fallback_details.setdefault("model", last_actual_model)
        fallback_details["requested_model"] = self._model_name
        fallback_details["selected_model"] = last_selected_model
        fallback_details["actual_model"] = last_actual_model
        fallback_details["fallback_used"] = last_selected_model != self._model_name
        fallback_details["fallback_chain"] = attempt_models
        fallback_details["attempt_count"] = len(attempts_summary)
        fallback_details["attempts"] = attempts_summary
        fallback_details["pricing_breakdown"] = pricing_breakdown
        fallback_details["intended_mode"] = mode
        return self._error_result(
            pkg=pkg,
            mode=mode,
            t0=t0,
            details=fallback_details,
            input_tokens=total_in,
            output_tokens=total_out,
            cost_usd=total_cost,
        )

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        system = system_prompt    if system_prompt    is not None else self._system_prompt
        tmpl   = template_override if template_override is not None else self._user_template
        listing, truncated = self._build_listing(pkg)
        user   = tmpl.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=listing,
            heuristic_flags=", ".join(pkg.heuristic_flags) if pkg.heuristic_flags else "none",
        )
        log.debug(
            f"[{self._detector_name}] prompt ({len(user)} chars, truncated={truncated}):\n{user}"
        )
        return self._run_mode(
            pkg,
            mode=self._mode_name(),
            prompt_strategy=prompt_strategy,
            system=system,
            user=user,
            truncated=truncated,
            raw_log=raw_log,
            trace_context=trace_context,
        )

    def _build_file_listing(self, pkg: PackageInfo) -> tuple[str, bool]:
        """Returns (listing, truncated). truncated=True when the 8000-char cap was hit."""
        parts: list[str] = []
        total = 0
        for path, content in pkg.files.items():
            chunk = f"### {path} ###\n{content}\n\n"
            if total + len(chunk) > 8000:
                parts.append("[truncated]")
                return "".join(parts), True
            parts.append(chunk)
            total += len(chunk)
        return "".join(parts), False

    def _call_api(
        self,
        system: str,
        user: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        model_name: str | None = None,
        requested_model: str | None = None,
        attempt: int | None = None,
        mode: str | None = None,
    ) -> ProxyCallResult:
        m = model_name or self._model_name
        if m.startswith("claude-"):
            return self._call_anthropic(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=m,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        if m.startswith(("gpt-", "o1-", "o3-", "together_ai/")):
            return self._call_openai(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=m,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        if m.startswith(("gemini-", "gemini/")):
            return self._call_gemini(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=m,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise ValueError(f"Unknown model prefix for: {m}")

    def _call_via_proxy(
        self,
        system: str,
        user: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        model_name: str | None = None,
        requested_model: str | None = None,
        attempt: int | None = None,
        mode: str | None = None,
    ) -> ProxyCallResult:
        """Route through LiteLLM."""
        import openai as _openai
        active_model = model_name or self._model_name
        requested = requested_model or self._model_name
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]
        request_payload = {
            "model": active_model,
            "temperature": self._temperature,
            "max_tokens": int(getattr(self, "_max_tokens", 512) or 512),
            "messages": messages,
        }
        if getattr(self, "_response_format", None) is not None:
            request_payload["response_format"] = self._response_format
        if getattr(self, "_extra_body", None) is not None:
            request_payload["extra_body"] = self._extra_body
        if getattr(self, "_reasoning_effort", None) is not None:
            request_payload["reasoning_effort"] = self._reasoning_effort
        if raw_log is not None:
            raw_log.emit(
                "llm.request",
                **(trace_context or {}),
                payload={
                    "model": active_model,
                    "requested_model": requested,
                    "attempt": attempt,
                    "mode": mode,
                    "proxy_url": self._proxy_url,
                    "system_prompt_ref": raw_log.blob_text("llm_system_prompt", system, suffix=".txt"),
                    "user_prompt_ref": raw_log.blob_text("llm_user_prompt", user, suffix=".txt"),
                    "request_json_ref": raw_log.blob_json("llm_request", request_payload),
                },
            )
        client = _openai.OpenAI(
            base_url=self._proxy_url.rstrip("/") + "/v1",
            api_key="no-key-needed",
        )
        http_resp = client.with_raw_response.chat.completions.create(**request_payload)
        headers = dict(http_resp.headers)
        cost = float(headers.get("x-litellm-response-cost") or 0.0)
        resp = http_resp.parse()
        text, protocol_details, response_meta = _protocol_details_from_response(resp)
        in_tok  = resp.usage.prompt_tokens     if resp.usage else 0
        out_tok = resp.usage.completion_tokens if resp.usage else 0
        response_model = getattr(resp, "model", None)
        litellm_model_group = str(
            headers.get("x-litellm-model-group")
            or headers.get("x-litellm-model")
            or ""
        ).strip() or None
        litellm_model_id = str(headers.get("x-litellm-model-id") or "").strip() or None
        public_model = str(litellm_model_group or active_model)
        if raw_log is not None:
            if hasattr(resp, "model_dump"):
                response_payload = resp.model_dump(mode="json")
            else:  # pragma: no cover - SDK compatibility fallback
                response_payload = repr(resp)
            raw_log.emit(
                "llm.response",
                **(trace_context or {}),
                payload={
                    "model": active_model,
                    "requested_model": requested,
                    "selected_model": active_model,
                    "actual_model": public_model,
                    "litellm_model_group": litellm_model_group,
                    "litellm_model_id": litellm_model_id,
                    "response_model": response_model,
                    "attempt": attempt,
                    "mode": mode,
                    "headers": headers,
                    "finish_reason": response_meta.get("finish_reason"),
                    "content_shape": response_meta.get("content_shape"),
                    "has_tool_calls": response_meta.get("has_tool_calls", False),
                    "assistant_text_ref": raw_log.blob_text("llm_assistant_text", text, suffix=".txt"),
                    "response_json_ref": raw_log.blob_json("llm_response", response_payload),
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "cost_usd": cost,
                },
            )
        return ProxyCallResult(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost,
            requested_model=requested,
            actual_model=public_model,
            selected_model=active_model,
            litellm_model_group=litellm_model_group,
            litellm_model_id=litellm_model_id,
            response_model=str(response_model) if response_model is not None else None,
            pricing_model=public_model,
            finish_reason=str(response_meta.get("finish_reason")) if response_meta.get("finish_reason") is not None else None,
            content_shape=str(response_meta.get("content_shape")) if response_meta.get("content_shape") is not None else None,
            has_tool_calls=bool(response_meta.get("has_tool_calls", False)),
            protocol_details=protocol_details,
            headers=headers,
        )

    def _call_anthropic(
        self, system: str, user: str, *, raw_log=None, trace_context: dict | None = None, model_name: str | None = None, requested_model: str | None = None, attempt: int | None = None, mode: str | None = None
    ) -> ProxyCallResult:
        if self._proxy_url:
            return self._call_via_proxy(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=model_name,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config - direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _call_openai(
        self, system: str, user: str, *, raw_log=None, trace_context: dict | None = None, model_name: str | None = None, requested_model: str | None = None, attempt: int | None = None, mode: str | None = None
    ) -> ProxyCallResult:
        if self._proxy_url:
            return self._call_via_proxy(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=model_name,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config - direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _call_gemini(
        self, system: str, user: str, *, raw_log=None, trace_context: dict | None = None, model_name: str | None = None, requested_model: str | None = None, attempt: int | None = None, mode: str | None = None
    ) -> ProxyCallResult:
        if self._proxy_url:
            return self._call_via_proxy(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=model_name,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config - direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _parse_response(self, raw: str) -> tuple[bool, float | None, dict]:
        return _parse_json_verdict_response(raw)


# ---------------------------------------------------------------------------
# AgenticAdapter - multi-turn LiteLLM plan-and-tool-use loop
# ---------------------------------------------------------------------------

class AgenticAdapter(DetectorAdapter):

    def __init__(self, config_path: str | Path):
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f)
        self._model_name: str        = cfg["model_name"]
        self._system_prompt: str     = cfg.get("system_prompt", "")
        self._initial_template: str  = cfg.get(
            "initial_user_message",
            "Investigate package '{package_name}' v{version}.",
        )
        self._max_turns: int         = int(cfg.get("max_turns", 5))
        self._temperature: float     = float(cfg.get("temperature", 0.0))
        self._proxy_url: str | None  = cfg.get("proxy_url") or None
        self._agentic_flow: str      = str(cfg.get("agentic_flow", "legacy_tool_loop"))
        self._detector_name: str     = Path(config_path).stem   # e.g. "claude_haiku_agentic"
        self._current_pkg: PackageInfo | None = None
        self._last_plan: dict | None = None

    _TOOLS = [
        {
            "name": "list_files",
            "description": "List all file paths extracted from the package.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "read_file",
            "description": "Read the contents of a specific file from the package.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative file path to read."}
                },
                "required": ["path"],
            },
        },
        {
            "name": "search_files",
            "description": "Search extracted package files with a regular expression.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Python regular expression."},
                    "path_glob": {
                        "type": "string",
                        "description": "Optional shell-style glob limiting paths to search.",
                    },
                },
                "required": ["pattern"],
            },
        },
        {
            "name": "file_info",
            "description": "Return metadata for one extracted package file.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative file path to inspect."}
                },
                "required": ["path"],
            },
        },
    ]

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        # template_override maps to initial_user_message for the agentic adapter.
        self._current_pkg = pkg
        self._last_plan = None
        _sys  = system_prompt     if system_prompt     is not None else self._system_prompt
        _init = template_override if template_override is not None else self._initial_template
        ctx = _context(trace_context, pkg)
        ctx.update({"detector": self._detector_name, "mode": "agentic", "strategy": prompt_strategy})
        t0 = _time.monotonic()
        try:
            final_text, in_tok, out_tok, total_cost = self._agentic_loop(
                pkg, _sys, _init, raw_log=raw_log, trace_context=ctx
            )
            verdict, confidence, details = self._parse_response(final_text)
        except NotImplementedError:
            raise
        except Exception as exc:
            if raw_log is not None:
                raw_log.emit("agentic.error", **ctx, payload={"model": self._model_name, "error": str(exc)})
            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="error",
                verdict=False,
                confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=int((_time.monotonic() - t0) * 1000),
                api_cost_usd=0.0,
                input_tokens=0,
                output_tokens=0,
                details={"error": str(exc), "model": self._model_name},
            )
        finally:
            self._current_pkg = None

        details["model"] = self._model_name
        details["agentic_flow"] = self._agentic_flow
        if self._last_plan is not None:
            details["plan"] = self._last_plan
        if _is_protocol_failure(details):
            details["intended_mode"] = "agentic"
            _emit_protocol_error(
                raw_log,
                "agentic.protocol_error",
                ctx,
                model=self._model_name,
                details=details,
            )
            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="error",
                verdict=False,
                confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=int((_time.monotonic() - t0) * 1000),
                api_cost_usd=total_cost,
                input_tokens=in_tok,
                output_tokens=out_tok,
                details=details,
            )
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode="agentic",
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=total_cost,
            input_tokens=in_tok,
            output_tokens=out_tok,
            details=details,
        )

    def _make_api_call(
        self,
        messages: list[dict],
        system_prompt: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        turn: int = 0,
        tools_enabled: bool = True,
        phase: str = "turn",
    ) -> dict:
        """
        Single API call returning a normalised response dict:
          {content: list[dict], stop_reason: str, input_tokens: int, output_tokens: int}
        """
        _sys = system_prompt if system_prompt is not None else self._system_prompt
        if self._proxy_url:
            import openai as _openai, json as _j
            client = _openai.OpenAI(
                base_url=self._proxy_url.rstrip("/") + "/v1",
                api_key="no-key-needed",
            )
            oai_messages: list[dict] = [{"role": "system", "content": _sys}]
            for msg in messages:
                role = msg["role"]
                body = msg["content"]
                if role == "assistant" and isinstance(body, list):
                    text_parts = [b.get("text", "") for b in body if b.get("type") == "text"]
                    tool_calls = [
                        {
                            "id": b["id"],
                            "type": "function",
                            "function": {
                                "name": b["name"],
                                "arguments": _j.dumps(b.get("input", {})),
                            },
                        }
                        for b in body if b.get("type") == "tool_use"
                    ]
                    oai_msg: dict = {"role": "assistant", "content": " ".join(text_parts) or None}
                    if tool_calls:
                        oai_msg["tool_calls"] = tool_calls
                    oai_messages.append(oai_msg)
                elif (role == "user" and isinstance(body, list)
                        and body and body[0].get("type") == "tool_result"):
                    for block in body:
                        oai_messages.append({
                            "role": "tool",
                            "tool_call_id": block["tool_use_id"],
                            "content": str(block.get("content", "")),
                        })
                else:
                    oai_messages.append({"role": role, "content": body})

            oai_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    },
                }
                for t in self._TOOLS
            ] if tools_enabled else []
            request_payload = {
                "model": self._model_name,
                "temperature": self._temperature,
                "max_tokens": 1024,
                "messages": oai_messages,
            }
            if tools_enabled:
                request_payload["tools"] = oai_tools
            if raw_log is not None:
                payload = {
                    "turn": turn,
                    "phase": phase,
                    "model": self._model_name,
                    "proxy_url": self._proxy_url,
                    "messages_ref": raw_log.blob_json("agentic_messages", oai_messages),
                    "request_json_ref": raw_log.blob_json("agentic_request", request_payload),
                }
                if tools_enabled:
                    payload["tools_ref"] = raw_log.blob_json("agentic_tools", oai_tools)
                raw_log.emit(f"agentic.{phase}.request", **(trace_context or {}), payload=payload)
            http_resp = client.with_raw_response.chat.completions.create(**request_payload)
            call_cost = float(http_resp.headers.get("x-litellm-response-cost") or 0.0)
            resp = http_resp.parse()
            oai_msg_out = resp.choices[0].message
            finish = resp.choices[0].finish_reason
            content_blocks: list[dict] = []
            if oai_msg_out.content:
                content_blocks.append({"type": "text", "text": oai_msg_out.content})
            if oai_msg_out.tool_calls:
                for tc in oai_msg_out.tool_calls:
                    content_blocks.append({
                        "type":  "tool_use",
                        "id":    tc.id,
                        "name":  tc.function.name,
                        "input": _j.loads(tc.function.arguments or "{}"),
                    })
            if raw_log is not None:
                if hasattr(resp, "model_dump"):
                    response_payload = resp.model_dump(mode="json")
                else:  # pragma: no cover - SDK compatibility fallback
                    response_payload = repr(resp)
                raw_log.emit(
                    f"agentic.{phase}.response",
                    **(trace_context or {}),
                    payload={
                        "turn": turn,
                        "phase": phase,
                        "model": self._model_name,
                        "headers": dict(http_resp.headers),
                        "response_json_ref": raw_log.blob_json("agentic_response", response_payload),
                        "content_ref": raw_log.blob_json("agentic_content", content_blocks),
                        "tool_calls": [b for b in content_blocks if b.get("type") == "tool_use"],
                        "input_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                        "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
                        "cost_usd": call_cost,
                    },
                )
            return {
                "content":       content_blocks,
                "stop_reason":   "tool_use" if finish == "tool_calls" else "end_turn",
                "input_tokens":  resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
                "cost_usd":      call_cost,
            }

        raise RuntimeError(
            "proxy_url not set in AgenticAdapter config - direct API calls bypass "
            "key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the model YAML."
        )

    def _agentic_loop(
        self,
        pkg: PackageInfo,
        system_prompt: str,
        initial_template: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> tuple[str, int, int, float]:
        if self._agentic_flow == "plan_then_execute":
            return self._agentic_plan_then_execute_loop(
                pkg,
                system_prompt,
                initial_template,
                raw_log=raw_log,
                trace_context=trace_context,
            )
        if self._agentic_flow != "legacy_tool_loop":
            raise ValueError(f"unknown agentic_flow: {self._agentic_flow}")
        return self._tool_loop(
            pkg,
            system_prompt,
            initial_template,
            raw_log=raw_log,
            trace_context=trace_context,
            initial_turn=0,
        )

    def _agentic_plan_then_execute_loop(
        self,
        pkg: PackageInfo,
        system_prompt: str,
        initial_template: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> tuple[str, int, int, float]:
        initial_user = initial_template.format(
            package_name=pkg.name, version=pkg.version
        )
        plan_prompt = (
            f"{initial_user}\n\n"
            "Phase 1: produce an investigation plan only. Do not give a verdict yet.\n"
            "Use this file manifest to decide what to inspect in Phase 2:\n"
            f"{self._package_manifest(pkg)}\n\n"
            "Respond ONLY with valid JSON containing investigation planning fields, for example:\n"
            '{"suspicious_paths": [], "search_terms": [], '
            '"risk_hypotheses": [], "next_steps": []}'
        )
        plan_resp = self._make_api_call(
            [{"role": "user", "content": plan_prompt}],
            system_prompt=system_prompt,
            raw_log=raw_log,
            trace_context=trace_context,
            turn=0,
            tools_enabled=False,
            phase="plan",
        )
        plan_text = "".join(
            b["text"] for b in plan_resp["content"] if b.get("type") == "text"
        )
        plan = self._parse_plan(plan_text)
        self._last_plan = plan

        execute_template = (
            f"{initial_user}\n\n"
            "Phase 2: execute the investigation plan below using only the provided "
            "read-only tools. Do not install, import, or execute the package.\n\n"
            f"Investigation plan JSON:\n{_json.dumps(plan, sort_keys=True)}\n\n"
            "After using the tools, respond ONLY with valid JSON:\n"
            '{"verdict": "malicious" or "benign", "confidence": 0.0-1.0, '
            '"reasoning": "one sentence", "evidence": [], "files_reviewed": [], '
            '"limitations": []}'
        )
        final_text, in_tok, out_tok, total_cost = self._tool_loop(
            pkg,
            system_prompt,
            execute_template,
            raw_log=raw_log,
            trace_context=trace_context,
            initial_turn=1,
            preformatted=True,
        )
        return (
            final_text,
            plan_resp["input_tokens"] + in_tok,
            plan_resp["output_tokens"] + out_tok,
            plan_resp.get("cost_usd", 0.0) + total_cost,
        )

    @staticmethod
    def _parse_plan(raw: str) -> dict:
        import re as _re
        m = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not m:
            raise ValueError("agentic plan phase did not return JSON")
        try:
            data = _json.loads(m.group())
        except _json.JSONDecodeError as exc:
            raise ValueError(f"agentic plan phase returned invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("agentic plan phase JSON must be an object")
        if "verdict" in data:
            raise ValueError("agentic plan phase returned a verdict before investigation")
        for key in ("suspicious_paths", "search_terms", "risk_hypotheses", "next_steps"):
            data.setdefault(key, [])
        return data

    @staticmethod
    def _package_manifest(pkg: PackageInfo, limit: int = 200) -> str:
        lines = [
            f"- {path} ({len(content.encode('utf-8', errors='replace'))} bytes)"
            for path, content in sorted(pkg.files.items())[:limit]
        ]
        if len(pkg.files) > limit:
            lines.append(f"... {len(pkg.files) - limit} additional file(s) omitted")
        return "\n".join(lines) or "(no extracted files)"

    def _tool_loop(
        self,
        pkg: PackageInfo,
        system_prompt: str,
        initial_template: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        initial_turn: int = 0,
        preformatted: bool = False,
    ) -> tuple[str, int, int, float]:
        if preformatted:
            initial_user = initial_template
        else:
            initial_user = initial_template.format(
                package_name=pkg.name, version=pkg.version
            )
        messages: list[dict] = [{"role": "user", "content": initial_user}]
        total_input_tokens  = 0
        total_output_tokens = 0
        total_cost          = 0.0

        for offset in range(self._max_turns):
            _turn = initial_turn + offset
            resp = self._make_api_call(
                messages,
                system_prompt=system_prompt,
                raw_log=raw_log,
                trace_context=trace_context,
                turn=_turn,
                phase="turn",
            )
            total_input_tokens  += resp["input_tokens"]
            total_output_tokens += resp["output_tokens"]
            total_cost          += resp.get("cost_usd", 0.0)
            content: list[dict] = resp["content"]
            messages.append({"role": "assistant", "content": content})

            if resp["stop_reason"] == "end_turn":
                return "".join(
                    b["text"] for b in content if b.get("type") == "text"
                ), total_input_tokens, total_output_tokens, total_cost

            if resp["stop_reason"] == "tool_use":
                tool_results = []
                for block in content:
                    if block.get("type") == "tool_use":
                        result_content = self._handle_tool(block["name"], block.get("input", {}))
                        if raw_log is not None:
                            raw_log.emit(
                                "agentic.tool.call",
                                **(trace_context or {}),
                                payload={
                                    "turn": _turn,
                                    "tool_name": block["name"],
                                    "tool_use_id": block["id"],
                                    "tool_input": block.get("input", {}),
                                    "tool_output_ref": raw_log.blob_text(
                                        "agentic_tool_output", str(result_content), suffix=".txt"
                                    ),
                                },
                            )
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": block["id"],
                            "content":     str(result_content),
                        })
                messages.append({"role": "user", "content": tool_results})
            else:
                break

        # Max turns exhausted - return whatever the last assistant turn said.
        last_content = messages[-1].get("content", [])
        final_text = ""
        if isinstance(last_content, list):
            final_text = "".join(
                b["text"] for b in last_content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        return final_text, total_input_tokens, total_output_tokens, total_cost

    def _handle_tool(self, name: str, tool_input: dict) -> object:
        pkg = self._current_pkg
        if pkg is None:
            return "Error: no package loaded"
        if name == "list_files":
            return list(pkg.files.keys())
        if name == "read_file":
            path = tool_input.get("path", "")
            return pkg.files.get(path, f"File not found: {path}")
        if name == "search_files":
            return self._tool_search_files(pkg, tool_input)
        if name == "file_info":
            return self._tool_file_info(pkg, tool_input)
        return f"Unknown tool: {name}"

    @staticmethod
    def _tool_search_files(pkg: PackageInfo, tool_input: dict) -> object:
        import fnmatch as _fnmatch, re as _re
        pattern = str(tool_input.get("pattern", ""))
        path_glob = tool_input.get("path_glob")
        try:
            regex = _re.compile(pattern)
        except _re.error as exc:
            return {"error": f"invalid regex: {exc}"}
        matches = []
        for path, content in sorted(pkg.files.items()):
            if path_glob and not _fnmatch.fnmatch(path, str(path_glob)):
                continue
            for line_no, line in enumerate(content.splitlines(), start=1):
                if regex.search(line):
                    matches.append({
                        "path": path,
                        "line": line_no,
                        "text": line[:500],
                    })
                    if len(matches) >= 50:
                        return {"matches": matches, "truncated": True}
        return {"matches": matches, "truncated": False}

    @staticmethod
    def _tool_file_info(pkg: PackageInfo, tool_input: dict) -> object:
        path = str(tool_input.get("path", ""))
        if path not in pkg.files:
            return {"path": path, "exists": False}
        content = pkg.files[path]
        encoded = content.encode("utf-8", errors="replace")
        return {
            "path": path,
            "exists": True,
            "size_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "line_count": len(content.splitlines()),
            "in_raw_entrypoints": path in pkg.files_raw,
        }

    def _parse_response(self, raw: str) -> tuple[bool, float | None, dict]:
        return _parse_json_verdict_response(raw)


# ---------------------------------------------------------------------------
# LLMRawAdapter — LLM adapter using raw (unfiltered) entry-point source
# ---------------------------------------------------------------------------

class LLMRawAdapter(LLMAdapter):
    """
    Identical to LLMAdapter except it reads from pkg.files_raw (entry-point
    files only, no AST-resolved imports) instead of pkg.files.
    Produces experiment_mode="llm_raw" rows in the DB.
    """

    def _mode_name(self) -> str:
        return "llm_raw"

    def _build_listing(self, pkg: PackageInfo) -> tuple[str, bool]:
        return self._build_file_listing_raw(pkg)

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        system = system_prompt     if system_prompt     is not None else self._system_prompt
        tmpl   = template_override if template_override is not None else self._user_template
        listing, truncated = self._build_listing(pkg)
        user   = tmpl.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=listing,
            heuristic_flags=", ".join(pkg.heuristic_flags) if pkg.heuristic_flags else "none",
        )
        log.debug(
            f"[{self._detector_name}/raw] prompt ({len(user)} chars, truncated={truncated}):\n{user}"
        )
        return self._run_mode(
            pkg,
            mode=self._mode_name(),
            prompt_strategy=prompt_strategy,
            system=system,
            user=user,
            truncated=truncated,
            raw_log=raw_log,
            trace_context=trace_context,
        )

    def _build_file_listing_raw(self, pkg: PackageInfo) -> tuple[str, bool]:
        """Returns (listing, truncated). truncated=True when the 8000-char cap was hit."""
        parts: list[str] = []
        total = 0
        for path, content in pkg.files_raw.items():
            chunk = f"### {path} ###\n{content}\n\n"
            if total + len(chunk) > 8000:
                parts.append("[truncated]")
                return "".join(parts), True
            parts.append(chunk)
            total += len(chunk)
        return "".join(parts), False
