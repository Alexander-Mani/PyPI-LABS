"""Tests for the source-free model memory probe helper."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from scripts import model_memory_probe, summarize_model_memory_probe  # noqa: E402


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
    assert model_memory_probe.parse_model_json('{"recognized_package": true}') == {"recognized_package": True}
    assert model_memory_probe.parse_model_json(
        '```json\n{"recognized_exact_version": false}\n```'
    ) == {"recognized_exact_version": False}
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
    assert payload["response_format"]["json_schema"]["name"] == "model_memory_probe_v2"


def test_effective_runtime_options_use_scope_specific_defaults():
    curated = model_memory_probe._effective_runtime_options(
        SimpleNamespace(scope="curated", max_tokens=None, timeout=None, retries=None, retry_delay=None, progress=None)
    )
    production = model_memory_probe._effective_runtime_options(
        SimpleNamespace(scope="production", max_tokens=None, timeout=None, retries=None, retry_delay=None, progress=None)
    )

    assert curated == {
        "max_tokens": 4096,
        "timeout": 60.0,
        "retries": 1,
        "retry_delay": 10.0,
        "progress": "auto",
    }
    assert production == {
        "max_tokens": 8192,
        "timeout": 120.0,
        "retries": 2,
        "retry_delay": 20.0,
        "progress": "always",
    }


def test_validate_probe_response_rejects_out_of_range_confidence():
    case = model_memory_probe.ProbeCase(
        id="known-colourama",
        package_name="colourama",
        version="0.1.6",
        expected_recognized=True,
        category="known_public_incident",
    )

    normalized, error = model_memory_probe._validate_probe_response(
        {
            "recognized_package": True,
            "recognized_exact_version": True,
            "version_scope": "exact_version",
            "related_versions": "0.1.6",
            "confidence": 5,
            "basis": "public_incident",
            "fact": "public package compromise",
        },
        case=case,
    )

    assert normalized is None
    assert error == "confidence_out_of_range"


def test_validate_probe_response_rejects_inconsistent_exact_claim():
    case = model_memory_probe.ProbeCase(
        id="known-colourama",
        package_name="colourama",
        version="0.1.6",
        expected_recognized=True,
        category="known_public_incident",
    )

    normalized, error = model_memory_probe._validate_probe_response(
        {
            "recognized_package": False,
            "recognized_exact_version": True,
            "version_scope": "exact_version",
            "related_versions": "0.1.6",
            "confidence": 0.8,
            "basis": "public_incident",
            "fact": "public package compromise",
        },
        case=case,
    )

    assert normalized is None
    assert "exact_without_package" in error
    assert "package_false_but_exact_true" in error


def test_suspicious_exact_claim_flags_other_version_only_fact():
    case = model_memory_probe.ProbeCase(
        id="ultralytics-malware",
        package_name="ultralytics",
        version="8.3.46",
        expected_recognized=True,
        category="malware",
    )

    suspicious, reason = model_memory_probe._suspicious_exact_claim(
        {
            "recognized_exact_version": True,
            "related_versions": "8.3.41, 8.3.42",
            "fact": "Versions 8.3.41 and 8.3.42 were reported compromised.",
        },
        case,
    )

    assert suspicious is True
    assert "related_versions_mismatch" in reason
    assert "fact_mentions_other_versions_only" in reason


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
                    attack_vector="dependency_confusion",
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
    assert "attack_vector=dependency_confusion" in captured.out
    assert not out.exists()


def test_run_probe_writes_v2_jsonl_with_summary_and_costs(monkeypatch, tmp_path):
    cases = [
        model_memory_probe.ProbeCase(
            id="known-colourama",
            package_name="colourama",
            version="0.1.6",
            expected_recognized=True,
            category="known_public_incident",
            sample_role="malware",
            attack_vector="dependency_confusion",
            baseline_target="colorama",
        ),
        model_memory_probe.ProbeCase(
            id="control-colorama",
            package_name="colorama",
            version="0.4.6",
            expected_recognized=False,
            category="benign_target_control",
            sample_role="benign",
        ),
    ]
    models = [model_memory_probe.ModelSpec(config_stem="gpt_nano", model_name="gpt-5.4-nano")]

    def fake_probe_once(base_url, spec, case, timeout, max_tokens, retries, retry_delay):
        recognized = bool(case.expected_recognized)
        return model_memory_probe.ProbeOutcome(
            ok=True,
            status="HTTP 200",
            raw_response=json.dumps(
                {
                    "recognized_package": recognized,
                    "recognized_exact_version": recognized,
                    "version_scope": "exact_version" if recognized else "none",
                    "related_versions": case.version if recognized else "",
                    "confidence": 0.9 if recognized else 0.0,
                    "basis": "public_incident" if recognized else "none",
                    "fact": "known public incident" if recognized else "",
                }
            ),
            response_json={
                "recognized_package": recognized,
                "recognized_exact_version": recognized,
                "version_scope": "exact_version" if recognized else "none",
                "related_versions": case.version if recognized else "",
                "confidence": 0.9 if recognized else 0.0,
                "basis": "public_incident" if recognized else "none",
                "fact": "known public incident" if recognized else "",
            },
            elapsed_s=0.01,
            parse_status="ok_parsed",
            recognized_package=recognized,
            recognized_exact_version=recognized,
            version_scope="exact_version" if recognized else "none",
            related_versions=case.version if recognized else "",
            confidence=0.9 if recognized else 0.0,
            basis="public_incident" if recognized else "none",
            fact="known public incident" if recognized else "",
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
        timeout=60.0,
        max_tokens=4096,
        retries=1,
        retry_delay=0.0,
        progress="never",
    )

    rc = model_memory_probe.run_probe(args)

    assert rc == 0
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert records[0]["event"] == "run.start"
    assert records[0]["probe_schema_version"] == 2
    result_records = [record for record in records if record["event"] == "probe.result"]
    assert len(result_records) == 2
    assert all(record["parse_status"] == "ok_parsed" for record in result_records)
    assert all(record["package_match"] is True for record in result_records)
    assert all(record["exact_match"] is True for record in result_records)
    assert records[-1]["event"] == "run.summary"
    assert records[-1]["recognized_package_true"] == 1
    assert records[-1]["recognized_exact_version_true"] == 1
    assert records[-1]["by_attack_vector"]["dependency_confusion"]["exact_true"] == 1
    assert records[-1]["total_cost_usd"] > 0
    assert out.with_suffix(".summary.json").exists()
    assert out.with_suffix(".summary.md").exists()


def test_run_probe_keeps_schema_invalid_and_length_failures_as_telemetry(monkeypatch, tmp_path):
    cases = [
        model_memory_probe.ProbeCase(
            id="known-colourama",
            package_name="colourama",
            version="0.1.6",
            expected_recognized=True,
            category="known_public_incident",
            sample_role="malware",
        ),
        model_memory_probe.ProbeCase(
            id="control-colorama",
            package_name="colorama",
            version="0.4.6",
            expected_recognized=False,
            category="benign_target_control",
            sample_role="benign",
        ),
    ]
    models = [model_memory_probe.ModelSpec(config_stem="together_budget", model_name="together_ai/Qwen/Qwen3.5-9B")]

    outcomes = iter(
        [
            model_memory_probe.ProbeOutcome(
                ok=True,
                status="HTTP 200",
                raw_response='{"recognized_package": true, "recognized_exact_version": true, "version_scope": "exact_version", "related_versions": "0.1.6", "confidence": 5, "basis": "public_incident", "fact": "public compromise"}',
                response_json={
                    "recognized_package": True,
                    "recognized_exact_version": True,
                    "version_scope": "exact_version",
                    "related_versions": "0.1.6",
                    "confidence": 5,
                    "basis": "public_incident",
                    "fact": "public compromise",
                },
                elapsed_s=0.25,
                parse_status="ok_schema_invalid",
                parse_error="confidence_out_of_range",
                cost_usd=0.000321,
            ),
            model_memory_probe.ProbeOutcome(
                ok=True,
                status="HTTP 200",
                raw_response="",
                response_json=None,
                elapsed_s=0.25,
                parse_status="ok_empty_length",
                parse_error="empty_finish_reason_length",
                finish_reason="length",
                cost_usd=0.000321,
            ),
        ]
    )

    def fake_probe_once(base_url, spec, case, timeout, max_tokens, retries, retry_delay):
        return next(outcomes)

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
        timeout=60.0,
        max_tokens=4096,
        retries=1,
        retry_delay=0.0,
        progress="never",
    )

    rc = model_memory_probe.run_probe(args)

    assert rc == 0
    summary = json.loads(out.with_suffix(".summary.json").read_text(encoding="utf-8"))
    assert summary["schema_invalid_results"] == 1
    assert summary["length_empty_results"] == 1
    assert summary["recognized_unknown"] == 2
    assert summary["by_model"]["together_budget"]["schema_invalid"] == 1
    assert summary["by_model"]["together_budget"]["length_empty"] == 1


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
        timeout=60.0,
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
    assert records[-1]["transport_status_counts"]["transport_provider_error"] == 1


def test_summarize_probe_file_rebuilds_v2_summary(tmp_path):
    out = tmp_path / "memory.jsonl"
    records = [
        {
            "event": "run.start",
            "probe_schema_version": 2,
            "run_id": "probe-test",
            "scope": "production",
            "model_source": "profile:all_models",
            "case_source": "profile:all_models",
            "models": [{"config_stem": "claude_opus", "model_name": "claude-opus-4-6"}],
        },
        {
            "event": "probe.result",
            "probe_schema_version": 2,
            "run_id": "probe-test",
            "config_stem": "claude_opus",
            "model": "claude-opus-4-6",
            "case": {
                "id": "malware-ultralytics",
                "package_name": "ultralytics",
                "version": "8.3.46",
                "category": "malware",
                "sample_role": "malware",
                "attack_vector": "typosquat",
                "baseline_target": None,
                "source": "production",
            },
            "parse_status": "ok_parsed",
            "elapsed_s": 1.2,
            "recognized_package": True,
            "recognized_exact_version": False,
            "version_scope": "same_package_other_version",
            "related_versions": "8.3.41, 8.3.42",
            "confidence": 0.8,
            "basis": "public_reporting",
            "fact": "Compromised versions 8.3.41 and 8.3.42 were reported.",
            "cost_usd": 0.0012,
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150,
            "litellm_model_group": "claude-opus-4-6",
            "expected_recognized_package": None,
            "expected_recognized_exact_version": None,
            "suspicious_exact_claim": False,
            "suspicious_exact_claim_reason": None,
        },
        {
            "event": "probe.error",
            "probe_schema_version": 2,
            "run_id": "probe-test",
            "config_stem": "claude_opus",
            "model": "claude-opus-4-6",
            "case": {
                "id": "benign-termcolor",
                "package_name": "termcolor",
                "version": "3.3.0",
                "category": "benign",
                "sample_role": "benign",
                "attack_vector": "none",
                "baseline_target": None,
                "source": "production",
            },
            "parse_status": "transport_timeout",
            "elapsed_s": 120.0,
            "recognized_package": None,
            "recognized_exact_version": None,
            "version_scope": None,
            "related_versions": None,
            "confidence": None,
            "basis": None,
            "fact": None,
            "cost_usd": 0.0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "litellm_model_group": "claude-opus-4-6",
            "expected_recognized_package": None,
            "expected_recognized_exact_version": None,
            "suspicious_exact_claim": False,
            "suspicious_exact_claim_reason": None,
        },
    ]
    out.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

    summary = model_memory_probe.summarize_probe_file(out)

    assert summary["probe_schema_version"] == 2
    assert summary["package_only_true"] == 1
    assert summary["recognized_exact_version_true"] == 0
    assert summary["transport_status_counts"]["transport_timeout"] == 1
    assert summary["by_attack_vector"]["typosquat"]["package_only_true"] == 1
    assert len(summary["package_only_associations"]) == 1


def test_summarize_model_memory_probe_script_rewrites_summary_artifacts(tmp_path, capsys):
    out = tmp_path / "memory.jsonl"
    records = [
        {
            "event": "run.start",
            "probe_schema_version": 2,
            "run_id": "probe-test",
            "scope": "curated",
            "model_source": "profile:budget",
            "case_source": "curated.json",
            "models": [{"config_stem": "gpt_nano", "model_name": "gpt-5.4-nano"}],
        },
        {
            "event": "probe.result",
            "probe_schema_version": 2,
            "run_id": "probe-test",
            "config_stem": "gpt_nano",
            "model": "gpt-5.4-nano",
            "case": {
                "id": "known-colourama",
                "package_name": "colourama",
                "version": "0.1.6",
                "category": "known_public_incident",
                "sample_role": "malware",
                "attack_vector": "dependency_confusion",
                "baseline_target": "colorama",
                "source": "curated",
            },
            "parse_status": "ok_parsed",
            "elapsed_s": 1.0,
            "recognized_package": True,
            "recognized_exact_version": True,
            "version_scope": "exact_version",
            "related_versions": "0.1.6",
            "confidence": 0.9,
            "basis": "public_incident",
            "fact": "Public compromise was reported.",
            "cost_usd": 0.0002,
            "prompt_tokens": 10,
            "completion_tokens": 8,
            "total_tokens": 18,
            "litellm_model_group": "gpt-5.4-nano",
            "expected_recognized_package": True,
            "expected_recognized_exact_version": True,
            "suspicious_exact_claim": False,
            "suspicious_exact_claim_reason": None,
        },
    ]
    out.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")

    rc = summarize_model_memory_probe.main([str(out)])

    captured = capsys.readouterr()
    assert rc == 0
    assert "Wrote" in captured.out
    assert out.with_suffix(".summary.json").exists()
    assert out.with_suffix(".summary.md").exists()


def test_summarize_probe_file_rejects_legacy_schema(tmp_path):
    out = tmp_path / "legacy.jsonl"
    out.write_text(
        json.dumps({"event": "run.start", "probe_schema_version": 1, "run_id": "old"}) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="only v2 is supported"):
        model_memory_probe.summarize_probe_file(out)
