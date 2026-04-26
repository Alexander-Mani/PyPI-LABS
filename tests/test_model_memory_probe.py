"""Tests for the source-free model memory probe helper."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import model_memory_probe  # noqa: E402


def test_load_cases_reads_known_and_control_cases():
    cases = model_memory_probe.load_cases()
    by_id = {case.id: case for case in cases}

    assert "known-colourama" in by_id
    assert by_id["known-colourama"].expected_recognized is True
    assert "control-colorama" in by_id
    assert by_id["control-colorama"].expected_recognized is False


def test_probe_prompt_does_not_leak_labels_or_dataset_terms():
    case = model_memory_probe.ProbeCase(
        id="known-colourama",
        package_name="colourama",
        version="0.1.6",
        expected_recognized=True,
        category="known_public_incident",
        notes="This note must not enter the prompt",
    )

    messages = model_memory_probe.build_messages(case)
    prompt_text = "\n".join(message["content"] for message in messages).lower()

    assert "colourama" in prompt_text
    assert "0.1.6" in prompt_text
    assert "malicious" not in prompt_text
    assert "ground_truth" not in prompt_text
    assert "backstabber" not in prompt_text
    assert "attack_vector" not in prompt_text
    assert "this note must not enter" not in prompt_text


def test_parse_model_json_accepts_plain_and_fenced_json():
    assert model_memory_probe.parse_model_json('{"recognized": true}') == {"recognized": True}
    assert model_memory_probe.parse_model_json('```json\n{"recognized": false}\n```') == {"recognized": False}
    assert model_memory_probe.parse_model_json("not json") is None


def test_select_models_uses_non_agentic_profile_configs():
    specs, source = model_memory_probe.select_models(
        SimpleNamespace(profile="all_models", all_models=False, models=None, gemini="on")
    )

    stems = {spec.config_stem for spec in specs}

    assert source == "profile:all_models"
    assert "claude_haiku_agentic" not in stems
    assert "claude_sonnet_agentic" not in stems
    assert "claude_agentic" not in stems
    assert "together_frontier_qwen" in stems
    assert "gemini_flash" in stems


def test_build_request_payload_includes_schema_and_reasoning_effort():
    spec = model_memory_probe.ModelSpec(
        config_stem="gemini_flash",
        model_name="gemini-2.5-flash",
        reasoning_effort="none",
    )

    payload = model_memory_probe.build_request_payload(spec, [{"role": "user", "content": "x"}], 4096)

    assert payload["model"] == "gemini-2.5-flash"
    assert payload["max_tokens"] == 4096
    assert payload["reasoning_effort"] == "none"
    assert payload["response_format"]["type"] == "json_schema"
    assert payload["response_format"]["json_schema"]["name"] == "model_memory_probe"


def test_dry_run_prints_models_and_cases_without_writing(monkeypatch, tmp_path, capsys):
    out = tmp_path / "probe.jsonl"
    monkeypatch.setattr(
        model_memory_probe,
        "select_models",
        lambda args: ([model_memory_probe.ModelSpec(config_stem="gpt_nano", model_name="gpt-5.4-nano")], "test-source"),
    )
    monkeypatch.setattr(
        model_memory_probe,
        "resolve_cases",
        lambda args: (
            [
                model_memory_probe.ProbeCase(
                    id="known-colourama",
                    package_name="colourama",
                    version="0.1.6",
                    expected_recognized=True,
                    category="known_public_incident",
                )
            ],
            "curated.json",
        ),
    )

    rc = model_memory_probe.main(["--dry-run", "--out", str(out), "--scope", "curated"])

    captured = capsys.readouterr()
    assert rc == 0
    assert "Model memory probe dry-run" in captured.out
    assert "MODEL gpt_nano -> gpt-5.4-nano" in captured.out
    assert "CASE known-colourama" in captured.out
    assert not out.exists()


def test_run_probe_writes_jsonl_with_summary_and_costs(monkeypatch, tmp_path):
    cases = [
        model_memory_probe.ProbeCase(
            id="known-colourama",
            package_name="colourama",
            version="0.1.6",
            expected_recognized=True,
            category="known_public_incident",
        ),
        model_memory_probe.ProbeCase(
            id="control-colorama",
            package_name="colorama",
            version="0.4.6",
            expected_recognized=False,
            category="benign_target_control",
        ),
    ]
    models = [model_memory_probe.ModelSpec(config_stem="gpt_nano", model_name="gpt-5.4-nano")]

    def fake_probe_once(base_url, spec, case, timeout, max_tokens, retries, retry_delay):
        recognized = case.expected_recognized
        return model_memory_probe.ProbeOutcome(
            ok=True,
            status="HTTP 200",
            raw_response=json.dumps({"recognized": recognized, "confidence": 0.9, "basis": "public_incident", "fact": ""}),
            response_json={"recognized": recognized, "confidence": 0.9, "basis": "public_incident", "fact": ""},
            elapsed_s=0.01,
            parse_status="ok_parsed",
            recognized=recognized,
            prompt_tokens=11,
            completion_tokens=7,
            total_tokens=18,
            cost_usd=0.000123,
            litellm_model_group="gpt-5.4-nano",
            response_model="gpt-5.4-nano",
        )

    out = tmp_path / "memory.jsonl"
    monkeypatch.setattr(model_memory_probe, "resolve_cases", lambda args: (cases, "curated.json"))
    monkeypatch.setattr(model_memory_probe, "select_models", lambda args: (models, "test-source"))
    monkeypatch.setattr(model_memory_probe, "probe_once", fake_probe_once)

    args = SimpleNamespace(
        scope="curated",
        cases=Path("unused.json"),
        profile="budget",
        resolver_profile=None,
        include_controls=False,
        models=None,
        all_models=False,
        gemini="on",
        base_url="http://127.0.0.1:4000",
        out=out,
        run_id="probe-test",
        dry_run=False,
        timeout=1.0,
        max_tokens=4096,
        retries=1,
        retry_delay=0.0,
        progress="never",
    )

    rc = model_memory_probe.run_probe(args)

    assert rc == 0
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert records[0]["event"] == "run.start"
    result_records = [record for record in records if record["event"] == "probe.result"]
    assert len(result_records) == 2
    assert all(record["parse_status"] == "ok_parsed" for record in result_records)
    assert all(record["recognition_match"] is True for record in result_records)
    assert records[-1]["event"] == "run.summary"
    assert records[-1]["recognition_matches"] == 2
    assert records[-1]["total_cost_usd"] > 0
    assert out.with_suffix(".summary.json").exists()
    assert out.with_suffix(".summary.md").exists()


def test_run_probe_keeps_parse_failures_as_telemetry(monkeypatch, tmp_path):
    cases = [
        model_memory_probe.ProbeCase(
            id="known-colourama",
            package_name="colourama",
            version="0.1.6",
            expected_recognized=True,
            category="known_public_incident",
        )
    ]
    models = [model_memory_probe.ModelSpec(config_stem="together_budget", model_name="together_ai/Qwen/Qwen3.5-9B")]

    def fake_probe_once(base_url, spec, case, timeout, max_tokens, retries, retry_delay):
        return model_memory_probe.ProbeOutcome(
            ok=True,
            status="HTTP 200",
            raw_response="",
            response_json=None,
            elapsed_s=0.25,
            parse_status="ok_empty_length",
            parse_error="empty_finish_reason_length",
            recognized=None,
            finish_reason="length",
            cost_usd=0.000321,
        )

    out = tmp_path / "memory.jsonl"
    monkeypatch.setattr(model_memory_probe, "resolve_cases", lambda args: (cases, "curated.json"))
    monkeypatch.setattr(model_memory_probe, "select_models", lambda args: (models, "test-source"))
    monkeypatch.setattr(model_memory_probe, "probe_once", fake_probe_once)

    args = SimpleNamespace(
        scope="curated",
        cases=Path("unused.json"),
        profile="budget",
        resolver_profile=None,
        include_controls=False,
        models=None,
        all_models=False,
        gemini="on",
        base_url="http://127.0.0.1:4000",
        out=out,
        run_id="probe-test",
        dry_run=False,
        timeout=1.0,
        max_tokens=4096,
        retries=1,
        retry_delay=0.0,
        progress="never",
    )

    rc = model_memory_probe.run_probe(args)

    assert rc == 0
    summary = json.loads(out.with_suffix(".summary.json").read_text(encoding="utf-8"))
    assert summary["transport_failures"] == 0
    assert summary["parse_status_counts"]["ok_empty_length"] == 1
    assert summary["recognized_unknown"] == 1


def test_run_probe_returns_nonzero_on_transport_failure(monkeypatch, tmp_path):
    cases = [
        model_memory_probe.ProbeCase(
            id="known-colourama",
            package_name="colourama",
            version="0.1.6",
            expected_recognized=True,
            category="known_public_incident",
        )
    ]
    models = [model_memory_probe.ModelSpec(config_stem="gemini_flash_lite", model_name="gemini-2.5-flash-lite")]

    def fake_probe_once(base_url, spec, case, timeout, max_tokens, retries, retry_delay):
        return model_memory_probe.ProbeOutcome(
            ok=False,
            status="HTTP 503",
            error="overloaded",
            elapsed_s=0.2,
            parse_status="transport_provider_error",
        )

    out = tmp_path / "memory.jsonl"
    monkeypatch.setattr(model_memory_probe, "resolve_cases", lambda args: (cases, "curated.json"))
    monkeypatch.setattr(model_memory_probe, "select_models", lambda args: (models, "test-source"))
    monkeypatch.setattr(model_memory_probe, "probe_once", fake_probe_once)

    args = SimpleNamespace(
        scope="curated",
        cases=Path("unused.json"),
        profile="budget",
        resolver_profile=None,
        include_controls=False,
        models=None,
        all_models=False,
        gemini="on",
        base_url="http://127.0.0.1:4000",
        out=out,
        run_id="probe-test",
        dry_run=False,
        timeout=1.0,
        max_tokens=4096,
        retries=1,
        retry_delay=0.0,
        progress="never",
    )

    rc = model_memory_probe.run_probe(args)

    assert rc == 1
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert any(record["event"] == "probe.error" for record in records)
    assert records[-1]["transport_failures"] == 1
