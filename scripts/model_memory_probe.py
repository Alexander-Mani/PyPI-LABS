#!/usr/bin/env python3
"""Source-free probe for model recognition of public PyPI incidents."""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_CASES_FILE = _REPO_ROOT / "configs" / "model_memory_probe_cases.json"
_DEFAULT_LOG_DIR = _REPO_ROOT / "logs" / "model_memory_probe"

# Reuse the profile/model parsing helpers used by the LiteLLM smoke test.
_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))
from litellm_smoke import (  # noqa: E402
    _filter_gemini_models,
    _load_all_litellm_models,
    _load_profile_models,
    _truncate,
)


@dataclass(frozen=True)
class ProbeCase:
    id: str
    package_name: str
    version: str
    expected_recognized: bool
    category: str
    notes: str = ""


@dataclass(frozen=True)
class ProbeOutcome:
    ok: bool
    status: str
    raw_response: str | None = None
    response_json: dict[str, Any] | None = None
    error: str | None = None
    elapsed_s: float = 0.0


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


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
        missing = [key for key in ("id", "package_name", "version", "expected_recognized", "category") if key not in item]
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
            )
        )
    return cases


def select_models(args: argparse.Namespace) -> tuple[list[str], str]:
    if args.models is not None and args.all_models:
        raise SystemExit("HALT: use either --models or --all-models, not both")
    if args.models is not None:
        models = list(args.models)
        source = "explicit --models"
    elif args.all_models:
        models = _load_all_litellm_models()
        source = "configs/litellm_config.yaml"
    else:
        models = _load_profile_models(args.profile)
        source = f"profile:{args.profile}"

    models = _filter_gemini_models(models, gemini_enabled=args.gemini == "on")
    if not models:
        raise SystemExit("HALT: Gemini filter removed every selected LiteLLM model")
    if args.gemini == "off":
        source = f"{source} (gemini off)"
    return models, source


def build_messages(case: ProbeCase) -> list[dict[str, str]]:
    system = (
        "You are evaluating possible prior public incident knowledge. "
        "You are not given source code, install logs, package contents, labels, "
        "or dataset membership. Answer only from generally known public security "
        "reporting, if any. Respond only as JSON with keys: recognized, confidence, "
        "summary, specific_facts, basis. If you do not know a specific public "
        "incident for this exact package/version, set recognized to false."
    )
    user = (
        "Package name: {name}\n"
        "Version: {version}\n\n"
        "Question: Is this exact Python/PyPI package and version associated with "
        "a publicly documented supply-chain or security incident? If yes, summarize "
        "the public facts you recognize. If no, say that you do not recognize a "
        "specific public incident."
    ).format(name=case.package_name, version=case.version)
    return [{"role": "system", "content": system}, {"role": "user", "content": user}]


def _request(base_url: str, model: str, messages: list[dict[str, str]], max_tokens: int) -> urllib.request.Request:
    payload = {
        "model": model,
        "temperature": 0,
        "max_tokens": max_tokens,
        "messages": messages,
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


def _extract_content(response_body: str) -> str:
    data = json.loads(response_body)
    choices = data.get("choices") or []
    if not choices:
        raise ValueError("LiteLLM response has no choices")
    message = choices[0].get("message") or {}
    content = message.get("content")
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    return json.dumps(content, sort_keys=True)


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


def probe_once(base_url: str, model: str, case: ProbeCase, timeout: float, max_tokens: int) -> ProbeOutcome:
    messages = build_messages(case)
    req = _request(base_url, model, messages, max_tokens)
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            content = _extract_content(body)
            return ProbeOutcome(
                ok=True,
                status=f"HTTP {getattr(resp, 'status', 200)}",
                raw_response=content,
                response_json=parse_model_json(content),
                elapsed_s=time.monotonic() - t0,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return ProbeOutcome(
            ok=False,
            status=f"HTTP {exc.code}",
            error=_truncate(body),
            elapsed_s=time.monotonic() - t0,
        )
    except Exception as exc:
        return ProbeOutcome(
            ok=False,
            status=type(exc).__name__,
            error=str(exc),
            elapsed_s=time.monotonic() - t0,
        )


def _recognized(parsed: dict[str, Any] | None) -> bool | None:
    if not parsed or "recognized" not in parsed:
        return None
    value = parsed["recognized"]
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "recognized"}:
            return True
        if lowered in {"false", "no", "not recognized", "unknown"}:
            return False
    return None


def _default_output_path() -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return _DEFAULT_LOG_DIR / f"model-memory-probe-{stamp}.jsonl"


def _write_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, sort_keys=True) + "\n")


def _case_public_view(case: ProbeCase) -> dict[str, str]:
    return {"id": case.id, "package_name": case.package_name, "version": case.version}


def run_probe(args: argparse.Namespace) -> int:
    cases = load_cases(args.cases)
    models, model_source = select_models(args)
    out_path = args.out or _default_output_path()
    run_id = args.run_id or f"memory-probe-{uuid.uuid4()}"

    if args.dry_run:
        print(f"Model memory probe dry-run: {len(models)} model(s), {len(cases)} case(s)")
        print(f"base_url={args.base_url.rstrip('/')} model_source={model_source}")
        print(f"cases={args.cases}")
        print(f"out={out_path}")
        for model in models:
            print(f"MODEL {model}")
        for case in cases:
            print(f"CASE {case.id}: {case.package_name}=={case.version}")
        return 0

    _write_jsonl(out_path, {
        "event": "run.start",
        "run_id": run_id,
        "created_at": _utc_now(),
        "base_url": args.base_url.rstrip("/"),
        "model_source": model_source,
        "models": models,
        "cases_file": str(args.cases),
        "case_count": len(cases),
        "max_tokens": args.max_tokens,
        "timeout": args.timeout,
    })

    failures = 0
    parse_failures = 0
    recognized_matches = 0
    scored = 0
    for model in models:
        for case in cases:
            messages = build_messages(case)
            outcome = probe_once(args.base_url, model, case, args.timeout, args.max_tokens)
            parsed_recognized = _recognized(outcome.response_json)
            match = parsed_recognized == case.expected_recognized if parsed_recognized is not None else None
            if match is True:
                recognized_matches += 1
            if parsed_recognized is not None:
                scored += 1
            if outcome.ok and outcome.response_json is None:
                parse_failures += 1
            if not outcome.ok:
                failures += 1

            record = {
                "event": "probe.result" if outcome.ok else "probe.error",
                "run_id": run_id,
                "created_at": _utc_now(),
                "model": model,
                "case": asdict(case),
                "prompt_messages": messages,
                "ok": outcome.ok,
                "status": outcome.status,
                "elapsed_s": round(outcome.elapsed_s, 3),
                "raw_response": outcome.raw_response,
                "response_json": outcome.response_json,
                "parsed_recognized": parsed_recognized,
                "expected_recognized": case.expected_recognized,
                "recognition_match": match,
                "error": outcome.error,
            }
            _write_jsonl(out_path, record)
            status = "OK" if outcome.ok else "FAIL"
            print(
                f"{status} {model} {case.id}: recognized={parsed_recognized} "
                f"expected={case.expected_recognized} match={match} ({outcome.elapsed_s:.1f}s)"
            )

    summary = {
        "event": "run.summary",
        "run_id": run_id,
        "created_at": _utc_now(),
        "models": models,
        "cases": [_case_public_view(case) for case in cases],
        "total_calls": len(models) * len(cases),
        "transport_failures": failures,
        "parse_failures": parse_failures,
        "scored_results": scored,
        "recognition_matches": recognized_matches,
        "output_path": str(out_path),
    }
    _write_jsonl(out_path, summary)
    print(f"Wrote {out_path}")
    print(
        "Summary: "
        f"calls={summary['total_calls']} transport_failures={failures} "
        f"parse_failures={parse_failures} scored={scored} matches={recognized_matches}"
    )
    return 1 if failures else 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:4000")
    parser.add_argument("--profile", default="budget")
    parser.add_argument("--gemini", choices=["on", "off"], default="on")
    parser.add_argument("--all-models", action="store_true")
    parser.add_argument("--models", nargs="+", default=None)
    parser.add_argument("--cases", type=Path, default=_CASES_FILE)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--run-id", default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--max-tokens", type=int, default=220)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return run_probe(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
