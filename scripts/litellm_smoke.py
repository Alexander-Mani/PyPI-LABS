#!/usr/bin/env python3
"""Smoke-test LiteLLM proxy routing for PyPI-SCADA model profiles."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parent.parent
_PROFILE_FILE = _REPO_ROOT / "configs" / "evaluation_profiles.yaml"
_LITELLM_CONFIG_FILE = _REPO_ROOT / "configs" / "litellm_config.yaml"
_ANALYZER_CONFIGS = _REPO_ROOT / "src" / "analyzer" / "configs"
TRANSIENT_HTTP_STATUS_CODES = {429, 500, 502, 503, 504}


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


def _load_all_litellm_models() -> list[str]:
    # Keep the all-model dry-run usable even in minimal Python environments
    # where PyYAML is not installed. The LiteLLM config shape we need is
    # deliberately simple: repeated "- model_name: <name>" lines.
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


def _truncate(text: str, limit: int = 1000) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


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


def _smoke_once(base_url: str, model: str, timeout: float, max_tokens: int) -> tuple[bool, str, bool]:
    req = _request(base_url, model, max_tokens)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return True, f"OK {model}: HTTP {getattr(resp, 'status', 200)} {_truncate(body, 240)}", False
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        retryable = exc.code in TRANSIENT_HTTP_STATUS_CODES
        return False, f"FAIL {model}: HTTP {exc.code} {_truncate(body)}", retryable
    except urllib.error.URLError as exc:
        return False, f"FAIL {model}: {exc.reason}", False
    except Exception as exc:  # pragma: no cover - defensive fallback for urllib internals
        return False, f"FAIL {model}: {exc}", False


def smoke_model(
    base_url: str,
    model: str,
    timeout: float,
    max_tokens: int,
    retries: int = 2,
    retry_delay: float = 15.0,
) -> tuple[bool, str]:
    for attempt in range(retries + 1):
        ok, message, retryable = _smoke_once(base_url, model, timeout, max_tokens)
        if ok or not retryable or attempt == retries:
            return ok, message
        print(
            f"RETRY {model}: transient failure; retrying in {retry_delay:g}s "
            f"(attempt {attempt + 1}/{retries + 1})",
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
