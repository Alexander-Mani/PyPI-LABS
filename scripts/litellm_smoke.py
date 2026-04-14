#!/usr/bin/env python3
"""Smoke-test LiteLLM proxy routing for the PyPI-SCADA budget tier."""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request


DEFAULT_MODELS = [
    "claude-haiku-4-5",
    "gpt-5.4-nano",
    "gemini-3.1-flash-lite-preview",
    "together_ai/Qwen/Qwen3.5-9B",
]
TRANSIENT_HTTP_STATUS_CODES = {429, 500, 502, 503, 504}


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
    parser.add_argument("--models", nargs="+", default=DEFAULT_MODELS)
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--max-tokens", type=int, default=8)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=15.0)
    args = parser.parse_args(argv)

    failed = False
    for model in args.models:
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
