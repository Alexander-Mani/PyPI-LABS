"""Tests for the Gemini stability probe sidecar."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import gemini_stability_probe, litellm_smoke  # noqa: E402


def test_select_models_defaults_to_all_gemini_routes(monkeypatch):
    monkeypatch.setattr(
        gemini_stability_probe,
        "_load_all_litellm_models",
        lambda: ["gpt-5.4-mini", "gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.5-pro"],
    )

    models, source = gemini_stability_probe.select_models(SimpleNamespace(models=None))

    assert models == ["gemini-2.5-flash-lite", "gemini-2.5-flash", "gemini-2.5-pro"]
    assert "Gemini only" in source


def test_select_models_rejects_non_gemini_explicit_models():
    try:
        gemini_stability_probe.select_models(
            SimpleNamespace(models=["gemini-2.5-flash", "gpt-5.4-mini"])
        )
    except SystemExit as exc:
        assert "only accepts Gemini model names" in str(exc)
    else:  # pragma: no cover - defensive failure path
        raise AssertionError("non-Gemini explicit models should halt")


def test_dry_run_prints_models_without_writing(monkeypatch, tmp_path, capsys):
    out = tmp_path / "probe.jsonl"
    monkeypatch.setattr(
        gemini_stability_probe,
        "select_models",
        lambda args: (["gemini-2.5-flash-lite", "gemini-2.5-flash"], "test-source"),
    )

    rc = gemini_stability_probe.main(["--dry-run", "--out", str(out), "--iterations", "2"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "Gemini stability probe dry-run" in captured.out
    assert "MODEL gemini-2.5-flash-lite" in captured.out
    assert "MODEL gemini-2.5-flash" in captured.out
    assert not out.exists()


def test_run_probe_writes_jsonl_and_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(
        gemini_stability_probe,
        "select_models",
        lambda args: (["gemini-2.5-flash-lite"], "test-source"),
    )
    monkeypatch.setattr(
        gemini_stability_probe,
        "_smoke_once",
        lambda base_url, model, timeout, max_tokens: litellm_smoke.SmokeOutcome(
            ok=True,
            message=f"OK {model}: HTTP 200",
            retryable=False,
            category="ok",
            status="HTTP 200",
            status_code=200,
            detail="OK",
            elapsed_s=0.25,
        ),
    )

    out = tmp_path / "gemini.jsonl"
    args = SimpleNamespace(
        base_url="http://127.0.0.1:4000",
        models=None,
        out=out,
        run_id="gemini-probe-test",
        dry_run=False,
        timeout=1.0,
        max_tokens=8,
        interval_seconds=0.0,
        iterations=2,
        until_interrupt=False,
        summarize=None,
    )

    rc = gemini_stability_probe.run_probe(args)

    assert rc == 0
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert records[0]["event"] == "run.start"
    probe_records = [record for record in records if record["event"] == "probe.result"]
    assert len(probe_records) == 2
    assert all(record["category"] == "ok" for record in probe_records)
    assert records[-1]["event"] == "run.summary"
    assert records[-1]["attempts"] == 2
    assert records[-1]["ok"] == 2


def test_summarize_log_buckets_by_utc_hour(capsys, tmp_path):
    log_path = tmp_path / "probe.jsonl"
    log_path.write_text(
        "\n".join(
            [
                json.dumps(
                    {
                        "event": "probe.result",
                        "ts": "2026-04-21T03:00:00+00:00",
                        "run_id": "run-1",
                        "model": "gemini-2.5-flash",
                        "ok": True,
                        "category": "ok",
                        "elapsed_s": 1.0,
                    }
                ),
                json.dumps(
                    {
                        "event": "probe.error",
                        "ts": "2026-04-21T03:10:00+00:00",
                        "run_id": "run-1",
                        "model": "gemini-2.5-flash",
                        "ok": False,
                        "category": "provider_overload",
                        "elapsed_s": 2.0,
                    }
                ),
                json.dumps(
                    {
                        "event": "probe.error",
                        "ts": "2026-04-21T04:00:00+00:00",
                        "run_id": "run-1",
                        "model": "gemini-2.5-pro",
                        "ok": False,
                        "category": "rate_limit",
                        "elapsed_s": 3.0,
                    }
                ),
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    rc = gemini_stability_probe.summarize_log(log_path)

    captured = capsys.readouterr()
    assert rc == 0
    assert "Gemini stability summary" in captured.out
    assert "gemini-2.5-flash" in captured.out
    assert "gemini-2.5-pro" in captured.out
