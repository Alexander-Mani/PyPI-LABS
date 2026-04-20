#!/usr/bin/env python3
"""Print and validate the Review TUI execution context.

This is a small diagnostic helper for catching the class of failure where the
TUI targets the deployed checkout but accidentally generates commands with
system Python instead of the project virtualenv.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from scripts import review_tui  # noqa: E402


def _check_python_import(python: str, module: str) -> tuple[bool, str]:
    cmd = [python, "-c", f"import {module}; print('{module} ok')"]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
    except Exception as exc:  # pragma: no cover - defensive diagnostics
        return False, f"{type(exc).__name__}: {exc}"
    output = (completed.stdout + completed.stderr).strip()
    return completed.returncode == 0, output


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", choices=("auto", "deployed", "local"), default="deployed")
    parser.add_argument("--config", type=Path, default=review_tui._DEFAULT_CONFIG)
    parser.add_argument("--action", default="experiment-static-baseline")
    parser.add_argument("--module", default="loguru", help="Module to import with the selected context Python")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    parsed = review_tui._parse_review_tui_config(args.config)
    raw_context = (parsed.get("contexts") or {}).get(args.context) if args.context != "auto" else None

    print("Review TUI context check")
    print(f"config     : {args.config}")
    if raw_context is not None:
        print(f"raw context: {raw_context}")

    try:
        context = review_tui.resolve_review_context(args.context, config_path=args.config)
    except SystemExit as exc:
        print(f"resolve    : FAIL {exc}")
        return 1

    actions = {action.id: action for action in review_tui.build_actions(context=context)}
    action = actions.get(args.action)

    print(f"context    : {review_tui.context_summary(context)}")
    print(f"runner_user: {context.runner_user or 'current user'}")
    print(f"configured : {context.configured_python or 'not set'}")
    print(f"python     : {context.python_executable}")
    print(f"python ok  : {Path(context.python_executable).exists()}")
    if context.warnings:
        print("warnings   :")
        for warning in context.warnings:
            print(f"  - {warning}")

    import_ok, import_output = _check_python_import(context.python_executable, args.module)
    print(f"import     : {args.module} -> {'ok' if import_ok else 'FAIL'}")
    if import_output:
        print(f"import out : {import_output}")

    if action is None:
        print(f"action     : FAIL unknown action id {args.action!r}")
        print("known ids  :")
        for action_id in sorted(actions):
            print(f"  {action_id}")
        return 1

    preview = review_tui.command_preview(action.command)
    print(f"action     : {action.id} ({action.title})")
    print("command    :")
    print(preview)

    expected_python = context.python_executable
    command_uses_context_python = expected_python in preview
    print(f"uses python: {'ok' if command_uses_context_python else 'FAIL'}")

    if not import_ok or not command_uses_context_python:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
