"""Regression tests for the LiteLLM proxy smoke-test helper."""

from __future__ import annotations

import io
import json
import sys
import urllib.error
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import litellm_smoke  # noqa: E402


class _FakeResponse:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self) -> bytes:
        return b'{"choices":[{"message":{"content":"OK"}}]}'


def test_smoke_model_posts_openai_compatible_request(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout):
        captured["url"] = req.full_url
        captured["timeout"] = timeout
        captured["headers"] = dict(req.header_items())
        captured["payload"] = json.loads(req.data.decode("utf-8"))
        return _FakeResponse()

    monkeypatch.setattr(litellm_smoke.urllib.request, "urlopen", fake_urlopen)

    ok, message = litellm_smoke.smoke_model(
        base_url="http://127.0.0.1:4000/",
        model="gpt-5.4-nano",
        timeout=3.0,
        max_tokens=4,
    )

    assert ok is True
    assert "OK gpt-5.4-nano" in message
    assert captured["url"] == "http://127.0.0.1:4000/v1/chat/completions"
    assert captured["timeout"] == 3.0
    assert captured["headers"]["Authorization"] == "Bearer no-key-needed"
    assert captured["payload"]["model"] == "gpt-5.4-nano"
    assert captured["payload"]["max_tokens"] == 4


def test_smoke_main_returns_nonzero_for_failed_model(monkeypatch, capsys):
    def fake_urlopen(req, timeout):
        raise urllib.error.HTTPError(
            req.full_url,
            500,
            "Internal Server Error",
            {},
            io.BytesIO(b'{"error":"Cannot connect to host api.anthropic.com"}'),
        )

    monkeypatch.setattr(litellm_smoke.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(litellm_smoke.time, "sleep", lambda seconds: None)

    rc = litellm_smoke.main(
        ["--models", "claude-haiku-4-5", "--timeout", "1", "--retry-delay", "0"]
    )

    captured = capsys.readouterr()
    assert rc == 1
    assert "FAIL claude-haiku-4-5" in captured.err
    assert "api.anthropic.com" in captured.err


def test_smoke_model_retries_transient_http_failure(monkeypatch, capsys):
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        if len(calls) == 1:
            raise urllib.error.HTTPError(
                req.full_url,
                503,
                "Service Unavailable",
                {},
                io.BytesIO(b'{"error":"temporarily overloaded"}'),
            )
        return _FakeResponse()

    monkeypatch.setattr(litellm_smoke.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(litellm_smoke.time, "sleep", lambda seconds: None)

    ok, message = litellm_smoke.smoke_model(
        base_url="http://127.0.0.1:4000",
        model="gemini-2.5-flash-lite",
        timeout=1.0,
        max_tokens=4,
        retries=1,
        retry_delay=0,
    )

    captured = capsys.readouterr()
    assert ok is True
    assert "OK gemini-2.5-flash-lite" in message
    assert "RETRY gemini-2.5-flash-lite" in captured.err
    assert len(calls) == 2


def test_smoke_model_does_not_retry_auth_failure(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout):
        calls.append(req.full_url)
        raise urllib.error.HTTPError(
            req.full_url,
            401,
            "Unauthorized",
            {},
            io.BytesIO(b'{"error":"invalid api key"}'),
        )

    monkeypatch.setattr(litellm_smoke.urllib.request, "urlopen", fake_urlopen)

    ok, message = litellm_smoke.smoke_model(
        base_url="http://127.0.0.1:4000",
        model="together_ai/Qwen/Qwen3.5-9B",
        timeout=1.0,
        max_tokens=4,
        retries=3,
        retry_delay=0,
    )

    assert ok is False
    assert "HTTP 401" in message
    assert len(calls) == 1


def test_smoke_main_uses_profile_when_models_not_supplied(monkeypatch, capsys):
    captured_profile = {}

    def fake_load_profile_models(profile_name):
        captured_profile["name"] = profile_name
        return ["gpt-5.4-nano"]

    def fake_urlopen(req, timeout):
        return _FakeResponse()

    monkeypatch.setattr(litellm_smoke, "_load_profile_models", fake_load_profile_models)
    monkeypatch.setattr(litellm_smoke.urllib.request, "urlopen", fake_urlopen)

    rc = litellm_smoke.main(
        ["--profile", "budget_no_gemini", "--timeout", "1", "--retry-delay", "0"]
    )

    captured = capsys.readouterr()
    assert rc == 0
    assert captured_profile["name"] == "budget_no_gemini"
    assert "OK gpt-5.4-nano" in captured.out


def test_smoke_main_dry_run_all_models_reads_litellm_config(monkeypatch, capsys):
    def fail_urlopen(req, timeout):  # pragma: no cover - should never be called
        raise AssertionError("dry-run should not call LiteLLM")

    monkeypatch.setattr(litellm_smoke.urllib.request, "urlopen", fail_urlopen)

    rc = litellm_smoke.main(["--all-models", "--dry-run", "--timeout", "1"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "LiteLLM smoke dry-run" in captured.out
    assert "configs/litellm_config.yaml" in captured.out
    assert "DRY-RUN claude-haiku-4-5" in captured.out
    assert "DRY-RUN gpt-5.4-nano" in captured.out
    assert "DRY-RUN together_ai/Qwen/Qwen3.5-397B-A17B" in captured.out
    assert captured.err == ""


def test_smoke_main_rejects_all_models_with_explicit_models():
    try:
        litellm_smoke.main(["--all-models", "--models", "gpt-5.4-nano"])
    except SystemExit as exc:
        assert "either --models or --all-models" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("conflicting model selectors should halt")
