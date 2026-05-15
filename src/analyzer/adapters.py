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
# Compatibility exports for implementation modules
# ---------------------------------------------------------------------------

try:  # Package import path, used by scripts importing src.analyzer.adapters.
    from ._agentic_adapter import AgenticAdapter
    from ._llm_adapters import LLMAdapter, LLMRawAdapter
except ImportError:  # Top-level import path, used by tests and evaluate.py.
    from _agentic_adapter import AgenticAdapter
    from _llm_adapters import LLMAdapter, LLMRawAdapter

__all__ = [
    "AgenticAdapter",
    "DetectorAdapter",
    "EvalDetectionResult",
    "GUARDDOG_SOURCE_RULES",
    "GUARDDOG_VERSION",
    "GuardDogAdapter",
    "LLMAdapter",
    "LLMRawAdapter",
    "ProxyCallResult",
    "SEMGREP_RULES_PATH",
    "StaticAdapter",
]
