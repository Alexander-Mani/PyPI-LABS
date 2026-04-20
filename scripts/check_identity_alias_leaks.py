#!/usr/bin/env python3
"""Check identity-alias runs for original package identity in model requests."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_LOG_DIR = _REPO_ROOT / "logs" / "experiments"


def _load_events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _blob_refs(payload: dict[str, Any]) -> list[Path]:
    refs: list[Path] = []
    for key, value in payload.items():
        if key.endswith("_ref") and isinstance(value, dict) and value.get("path"):
            refs.append(Path(str(value["path"])))
    return refs


def _contains_term(text: str, term: str) -> bool:
    return bool(re.search(re.escape(term), text, flags=re.IGNORECASE))


def check_run(run_id: str, log_dir: Path) -> int:
    log_path = log_dir / f"{run_id}.jsonl"
    if not log_path.exists():
        raise SystemExit(f"HALT: raw experiment log not found: {log_path}")

    events = _load_events(log_path)
    masks: dict[tuple[str, str, str], set[str]] = {}
    for event in events:
        if event.get("event") != "identity_alias.mask":
            continue
        key = (
            str(event.get("package") or ""),
            str(event.get("version") or ""),
            str(event.get("artifact_filename") or ""),
        )
        terms = {
            str(term)
            for term in (event.get("payload") or {}).get("original_terms", [])
            if str(term)
        }
        if event.get("package"):
            terms.add(str(event["package"]))
        if event.get("version"):
            terms.add(str(event["version"]))
        masks[key] = terms

    if not masks:
        raise SystemExit(f"HALT: no identity_alias.mask events found in {log_path}")

    leaks: list[str] = []
    checked = 0
    for event in events:
        if event.get("event") != "llm.request":
            continue
        key = (
            str(event.get("package") or ""),
            str(event.get("version") or ""),
            str(event.get("artifact_filename") or ""),
        )
        terms = masks.get(key)
        if not terms:
            continue
        for ref in _blob_refs(event.get("payload") or {}):
            checked += 1
            try:
                text = ref.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                leaks.append(f"{ref}: could not read blob ({exc})")
                continue
            for term in sorted(terms, key=len, reverse=True):
                if _contains_term(text, term):
                    leaks.append(f"{ref}: leaked original identity term {term!r}")

    if checked == 0:
        raise SystemExit(f"HALT: no LLM request blobs found for alias-masked events in {log_path}")

    if leaks:
        print("FAIL: identity alias leak check found model-facing leaks", file=sys.stderr)
        for leak in leaks:
            print(f"  {leak}", file=sys.stderr)
        return 1

    print(f"OK: checked {checked} model-facing request blob(s); no original identity terms found")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id", required=True, help="Alias-probe run_id to inspect")
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=_DEFAULT_LOG_DIR,
        help="Raw experiment log directory (default: logs/experiments)",
    )
    args = parser.parse_args(argv)
    return check_run(args.run_id, args.log_dir)


if __name__ == "__main__":
    raise SystemExit(main())
