#!/usr/bin/env python3
"""Smoke-test LiteLLM proxy routing for PyPI-LABS model profiles."""

from __future__ import annotations

import argparse
import json
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROFILE_FILE = _REPO_ROOT / "configs" / "evaluation_profiles.yaml"
_LITELLM_CONFIG_FILE = _REPO_ROOT / "configs" / "litellm_config.yaml"
_ANALYZER_CONFIGS = _REPO_ROOT / "src" / "analyzer" / "configs"
TRANSIENT_HTTP_STATUS_CODES = {429, 500, 502, 503, 504}
AUTH_HTTP_STATUS_CODES = {401, 403}
RATE_LIMIT_HTTP_STATUS_CODES = {429}
PROVIDER_TRANSIENT_HTTP_STATUS_CODES = {500, 502, 503, 504}


@dataclass(frozen=True)
class SmokeOutcome:
    ok: bool
    message: str
    retryable: bool
    category: str
    status: str | None = None
    status_code: int | None = None
    diagnosis: str | None = None
    detail: str | None = None
    elapsed_s: float = 0.0


def _load_profile_config_stems(profile_name: str) -> list[str]:
    lines = _PROFILE_FILE.read_text(encoding="utf-8").splitlines()
    known: list[str] = []
    in_profile = False
    in_configs = False
    stems: list[str] = []

    for line in lines:
        if line.startswith("  ") and not line.startswith("    ") and line.rstrip().endswith(":"):
            current = line.strip()[:-1]
            known.append(current)
            if in_profile:
                break
            in_profile = current == profile_name
            in_configs = False
            continue
        if not in_profile:
            continue
        if line.strip() == "configs:":
            in_configs = True
            continue
        if in_configs and line.startswith("      - "):
            stems.append(line.split("-", 1)[1].strip())
            continue
        if in_configs and line.startswith("    ") and line.strip() and not line.startswith("      "):
            in_configs = False

    if not stems:
        known_text = ", ".join(sorted(set(known))) or "none"
        raise SystemExit(f"unknown LiteLLM smoke-test profile '{profile_name}'. Known: {known_text}")
    return stems


def _read_model_name(cfg_path: Path) -> str:
    for raw_line in cfg_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("model_name:"):
            continue
        return line.split(":", 1)[1].strip().strip("'\"")
    raise SystemExit(f"config '{cfg_path}' has no model_name")


def _load_profile_models(profile_name: str) -> list[str]:
    models: list[str] = []
    for stem in _load_profile_config_stems(profile_name):
        cfg_path = _ANALYZER_CONFIGS / f"{stem}.yaml"
        if not cfg_path.exists():
            raise SystemExit(f"profile '{profile_name}' references missing config: {stem}")
        model_name = _read_model_name(cfg_path)
        if model_name not in models:
            models.append(model_name)
    return models


def _is_gemini_model(model: str) -> bool:
    lowered = model.lower()
    return lowered.startswith(("gemini-", "gemini/"))


def _filter_gemini_models(models: list[str], *, gemini_enabled: bool) -> list[str]:
    if gemini_enabled:
        return list(models)
    return [model for model in models if not _is_gemini_model(model)]


def _load_proxy_route_models() -> list[str]:
    # Keep the raw proxy-route parser available even in minimal Python
    # environments where PyYAML is not installed.
    models: list[str] = []
    for raw_line in _LITELLM_CONFIG_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line.startswith("- model_name:"):
            continue
        model_name = line.split(":", 1)[1].strip().strip("'\"")
        if model_name and model_name not in models:
            models.append(model_name)
    if not models:
        raise SystemExit(f"no models found in {_LITELLM_CONFIG_FILE}")
    return models


def _load_all_litellm_models() -> list[str]:
    # "All models" should mean the canonical experiment lineup, not every
    # hidden proxy fallback alias. Fall back to the raw proxy model list only
    # if the profile-driven path is unavailable.
    try:
        return _load_profile_models("all_models")
    except SystemExit:
        return _load_proxy_route_models()


def _truncate(text: str, limit: int = 1000) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def _unique(parts: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for part in parts:
        if not part or part in seen:
            continue
        seen.add(part)
        result.append(part)
    return result


def _collect_error_parts(value, parts: list[str], *, prefix: str = "") -> None:
    if isinstance(value, dict):
        for key in ("type", "status", "code", "message", "param"):
            if key in value and value[key] not in (None, ""):
                label = f"{prefix}{key}" if prefix else key
                parts.append(f"{label}={value[key]}")
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                _collect_error_parts(item, parts, prefix=f"{key}.")
            elif key == "error" and isinstance(item, str):
                label = f"{prefix}{key}" if prefix else key
                parts.append(f"{label}={item}")
    elif isinstance(value, list):
        for item in value:
            _collect_error_parts(item, parts, prefix=prefix)
    elif isinstance(value, str):
        parts.append(value)


def _error_detail(body: str) -> str:
    if not body.strip():
        return "empty response body"
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return _truncate(body)
    parts: list[str] = []
    _collect_error_parts(data, parts)
    if parts:
        return _truncate("; ".join(_unique(parts)))
    return _truncate(body)


def _http_category(status_code: int, body: str) -> tuple[str, str, bool]:
    detail = _error_detail(body)
    lower = body.lower()
    if status_code in AUTH_HTTP_STATUS_CODES:
        return "auth_error", "API key, permission, or model access failure", False
    if status_code in RATE_LIMIT_HTTP_STATUS_CODES:
        return "rate_limit", "provider quota/rate limit; retry later or reduce concurrency", True
    if status_code in PROVIDER_TRANSIENT_HTTP_STATUS_CODES:
        if any(token in lower for token in ("overload", "high demand", "unavailable", "resource_exhausted")):
            return "provider_overload", "provider reported overload/high demand/unavailable", True
        return "provider_or_proxy_transient", "LiteLLM/provider returned a retryable server error", True
    return "http_error", "non-retryable HTTP error from LiteLLM/provider", False


def _is_timeout_reason(reason) -> bool:
    if isinstance(reason, (TimeoutError, socket.timeout)):
        return True
    text = str(reason).lower()
    return "timed out" in text or "timeout" in text


def _url_error_category(reason) -> tuple[str, str, bool]:
    if _is_timeout_reason(reason):
        return "client_timeout", "no HTTP response from LiteLLM before the smoke timeout", True
    if isinstance(reason, ConnectionRefusedError):
        return "proxy_connection_error", "LiteLLM proxy refused the connection or is not listening", False
    if isinstance(reason, socket.gaierror):
        return "dns_error", "could not resolve LiteLLM proxy host", False
    if isinstance(reason, OSError):
        return "proxy_connection_error", "client could not reach LiteLLM proxy", False
    return "url_error", "urllib/LiteLLM connection error", False


def _timeout_message(model: str, timeout: float, elapsed: float) -> str:
    return (
        f"FAIL {model}: client_timeout after {timeout:g}s "
        f"(elapsed={elapsed:.1f}s) waiting for LiteLLM; no HTTP response received. "
        "This does not prove whether the root cause is provider overload, rate limit, "
        "API key, or proxy hang; inspect /home/proxy-runner/litellm.log for the matching model."
    )


def _request(base_url: str, model: str, max_tokens: int) -> urllib.request.Request:
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": "Reply with OK."}],
    }
    return urllib.request.Request(
        base_url.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": "Bearer no-key-needed",
            "Content-Type": "application/json",
        },
        method="POST",
    )


def _smoke_once(base_url: str, model: str, timeout: float, max_tokens: int) -> SmokeOutcome:
    req = _request(base_url, model, max_tokens)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = time.monotonic() - t0
            status = f"HTTP {getattr(resp, 'status', 200)}"
            return SmokeOutcome(
                True,
                f"OK {model}: {status} {_truncate(body, 240)}",
                False,
                "ok",
                status=status,
                status_code=getattr(resp, "status", 200),
                detail=_truncate(body, 240),
                elapsed_s=elapsed,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        category, diagnosis, retryable = _http_category(exc.code, body)
        detail = _error_detail(body)
        elapsed = time.monotonic() - t0
        status = f"HTTP {exc.code}"
        return SmokeOutcome(
            False,
            (
                f"FAIL {model}: {category} HTTP {exc.code} retryable={str(retryable).lower()} "
                f"diagnosis={diagnosis}; detail={detail}"
            ),
            retryable,
            category,
            status=status,
            status_code=exc.code,
            diagnosis=diagnosis,
            detail=detail,
            elapsed_s=elapsed,
        )
    except urllib.error.URLError as exc:
        elapsed = time.monotonic() - t0
        if _is_timeout_reason(exc.reason):
            return SmokeOutcome(
                False,
                _timeout_message(model, timeout, elapsed),
                True,
                "client_timeout",
                status="timeout",
                diagnosis="no HTTP response from LiteLLM before the smoke timeout",
                detail=str(exc.reason),
                elapsed_s=elapsed,
            )
        category, diagnosis, retryable = _url_error_category(exc.reason)
        return SmokeOutcome(
            False,
            f"FAIL {model}: {category} retryable={str(retryable).lower()} diagnosis={diagnosis}; detail={exc.reason}",
            retryable,
            category,
            status=type(exc.reason).__name__ if exc.reason is not None else "URLError",
            diagnosis=diagnosis,
            detail=str(exc.reason),
            elapsed_s=elapsed,
        )
    except (TimeoutError, socket.timeout) as exc:
        elapsed = time.monotonic() - t0
        return SmokeOutcome(
            False,
            _timeout_message(model, timeout, elapsed),
            True,
            "client_timeout",
            status="timeout",
            diagnosis="no HTTP response from LiteLLM before the smoke timeout",
            detail=str(exc),
            elapsed_s=elapsed,
        )
    except Exception as exc:  # pragma: no cover - defensive fallback for urllib internals
        elapsed = time.monotonic() - t0
        return SmokeOutcome(
            False,
            f"FAIL {model}: unknown_error retryable=false detail={exc}",
            False,
            "unknown_error",
            status=type(exc).__name__,
            detail=str(exc),
            elapsed_s=elapsed,
        )


def smoke_model(
    base_url: str,
    model: str,
    timeout: float,
    max_tokens: int,
    retries: int = 2,
    retry_delay: float = 15.0,
) -> tuple[bool, str]:
    for attempt in range(retries + 1):
        outcome = _smoke_once(base_url, model, timeout, max_tokens)
        if outcome.ok or not outcome.retryable or attempt == retries:
            if outcome.ok:
                return True, outcome.message
            return False, f"{outcome.message} attempts={attempt + 1}/{retries + 1}"
        print(
            f"RETRY {model}: {outcome.category}; retrying in {retry_delay:g}s "
            f"(attempt {attempt + 1}/{retries + 1}) last={outcome.message}",
            file=sys.stderr,
        )
        time.sleep(retry_delay)
    raise AssertionError("unreachable")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:4000")
    parser.add_argument("--profile", default="budget")
    parser.add_argument(
        "--gemini",
        choices=["on", "off"],
        default="on",
        help="Include Gemini/Google models in profile or all-model smoke tests (default: on)",
    )
    parser.add_argument(
        "--all-models",
        action="store_true",
        help="Smoke-test every model listed in configs/litellm_config.yaml",
    )
    parser.add_argument("--models", nargs="+", default=None)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print selected models and request settings without calling LiteLLM",
    )
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--max-tokens", type=int, default=8)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=15.0)
    args = parser.parse_args(argv)

    if args.models is not None and args.all_models:
        raise SystemExit("HALT: use either --models or --all-models, not both")
    if args.models is not None:
        models = args.models
        source = "explicit --models"
    elif args.all_models:
        models = _load_all_litellm_models()
        source = str(_LITELLM_CONFIG_FILE.relative_to(_REPO_ROOT))
    else:
        models = _load_profile_models(args.profile)
        source = f"profile:{args.profile}"

    models = _filter_gemini_models(models, gemini_enabled=args.gemini == "on")
    if not models:
        raise SystemExit("HALT: Gemini filter removed every selected LiteLLM model")
    if args.gemini == "off":
        source = f"{source} (gemini off)"

    if args.dry_run:
        print(f"LiteLLM smoke dry-run: {len(models)} model(s) from {source}")
        print(f"base_url={args.base_url.rstrip('/')}")
        print(f"max_tokens={args.max_tokens} timeout={args.timeout:g}s retries={args.retries}")
        for model in models:
            print(f"DRY-RUN {model}")
        return 0

    failed = False
    for model in models:
        ok, message = smoke_model(
            args.base_url,
            model,
            args.timeout,
            args.max_tokens,
            retries=args.retries,
            retry_delay=args.retry_delay,
        )
        print(message, file=sys.stdout if ok else sys.stderr)
        failed = failed or not ok
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
