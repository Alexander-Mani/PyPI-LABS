"""Agentic detector adapter.

This module keeps the non-primary multi-step LLM workflow out of the main
adapter facade while preserving the original public import surface.
"""

from __future__ import annotations

import hashlib
import json as _json
from pathlib import Path
import time as _time

import yaml as _yaml

try:  # Package import path, used by scripts importing src.analyzer.adapters.
    from .adapters import (
        DetectorAdapter,
        EvalDetectionResult,
        _context,
        _emit_protocol_error,
        _is_protocol_failure,
        _parse_json_verdict_response,
    )
    from .entry_extractor import PackageInfo
except ImportError:  # Top-level import path, used by tests and evaluate.py.
    from adapters import (
        DetectorAdapter,
        EvalDetectionResult,
        _context,
        _emit_protocol_error,
        _is_protocol_failure,
        _parse_json_verdict_response,
    )
    from entry_extractor import PackageInfo

# ---------------------------------------------------------------------------
# AgenticAdapter - multi-turn LiteLLM plan-and-tool-use loop
# ---------------------------------------------------------------------------

class AgenticAdapter(DetectorAdapter):

    def __init__(self, config_path: str | Path):
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f)
        self._model_name: str        = cfg["model_name"]
        self._system_prompt: str     = cfg.get("system_prompt", "")
        self._initial_template: str  = cfg.get(
            "initial_user_message",
            "Investigate package '{package_name}' v{version}.",
        )
        self._max_turns: int         = int(cfg.get("max_turns", 5))
        self._max_tokens: int        = int(cfg.get("max_tokens", 1024))
        self._temperature: float     = float(cfg.get("temperature", 0.0))
        self._proxy_url: str | None  = cfg.get("proxy_url") or None
        self._agentic_flow: str      = str(cfg.get("agentic_flow", "legacy_tool_loop"))
        self._detector_name: str     = Path(config_path).stem   # e.g. "claude_haiku_agentic"
        self._current_pkg: PackageInfo | None = None
        self._last_plan: dict | None = None

    _TOOLS = [
        {
            "name": "list_files",
            "description": "List all file paths extracted from the package.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "read_file",
            "description": "Read the contents of a specific file from the package.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative file path to read."}
                },
                "required": ["path"],
            },
        },
        {
            "name": "search_files",
            "description": "Search extracted package files with a regular expression.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Python regular expression."},
                    "path_glob": {
                        "type": "string",
                        "description": "Optional shell-style glob limiting paths to search.",
                    },
                },
                "required": ["pattern"],
            },
        },
        {
            "name": "file_info",
            "description": "Return metadata for one extracted package file.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Relative file path to inspect."}
                },
                "required": ["path"],
            },
        },
    ]

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        # template_override maps to initial_user_message for the agentic adapter.
        self._current_pkg = pkg
        self._last_plan = None
        _sys  = system_prompt     if system_prompt     is not None else self._system_prompt
        _init = template_override if template_override is not None else self._initial_template
        ctx = _context(trace_context, pkg)
        ctx.update({"detector": self._detector_name, "mode": "agentic", "strategy": prompt_strategy})
        t0 = _time.monotonic()
        try:
            final_text, in_tok, out_tok, total_cost = self._agentic_loop(
                pkg, _sys, _init, raw_log=raw_log, trace_context=ctx
            )
            verdict, confidence, details = self._parse_response(final_text)
        except NotImplementedError:
            raise
        except Exception as exc:
            if raw_log is not None:
                raw_log.emit("agentic.error", **ctx, payload={"model": self._model_name, "error": str(exc)})
            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="error",
                verdict=False,
                confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=int((_time.monotonic() - t0) * 1000),
                api_cost_usd=0.0,
                input_tokens=0,
                output_tokens=0,
                details={"error": str(exc), "model": self._model_name},
            )
        finally:
            self._current_pkg = None

        details["model"] = self._model_name
        details["agentic_flow"] = self._agentic_flow
        if self._last_plan is not None:
            details["plan"] = self._last_plan
        if _is_protocol_failure(details):
            details["intended_mode"] = "agentic"
            _emit_protocol_error(
                raw_log,
                "agentic.protocol_error",
                ctx,
                model=self._model_name,
                details=details,
            )
            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="error",
                verdict=False,
                confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=int((_time.monotonic() - t0) * 1000),
                api_cost_usd=total_cost,
                input_tokens=in_tok,
                output_tokens=out_tok,
                details=details,
            )
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode="agentic",
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=total_cost,
            input_tokens=in_tok,
            output_tokens=out_tok,
            details=details,
        )

    def _make_api_call(
        self,
        messages: list[dict],
        system_prompt: str | None = None,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        turn: int = 0,
        tools_enabled: bool = True,
        phase: str = "turn",
    ) -> dict:
        """
        Single API call returning a normalised response dict:
          {content: list[dict], stop_reason: str, input_tokens: int, output_tokens: int}
        """
        _sys = system_prompt if system_prompt is not None else self._system_prompt
        if self._proxy_url:
            import openai as _openai, json as _j
            client = _openai.OpenAI(
                base_url=self._proxy_url.rstrip("/") + "/v1",
                api_key="no-key-needed",
            )
            oai_messages: list[dict] = [{"role": "system", "content": _sys}]
            for msg in messages:
                role = msg["role"]
                body = msg["content"]
                if role == "assistant" and isinstance(body, list):
                    text_parts = [b.get("text", "") for b in body if b.get("type") == "text"]
                    tool_calls = [
                        {
                            "id": b["id"],
                            "type": "function",
                            "function": {
                                "name": b["name"],
                                "arguments": _j.dumps(b.get("input", {})),
                            },
                        }
                        for b in body if b.get("type") == "tool_use"
                    ]
                    oai_msg: dict = {"role": "assistant", "content": " ".join(text_parts) or None}
                    if tool_calls:
                        oai_msg["tool_calls"] = tool_calls
                    oai_messages.append(oai_msg)
                elif (role == "user" and isinstance(body, list)
                        and body and body[0].get("type") == "tool_result"):
                    for block in body:
                        oai_messages.append({
                            "role": "tool",
                            "tool_call_id": block["tool_use_id"],
                            "content": str(block.get("content", "")),
                        })
                else:
                    oai_messages.append({"role": role, "content": body})

            oai_tools = [
                {
                    "type": "function",
                    "function": {
                        "name": t["name"],
                        "description": t["description"],
                        "parameters": t["input_schema"],
                    },
                }
                for t in self._TOOLS
            ] if tools_enabled else []
            request_payload = {
                "model": self._model_name,
                "temperature": self._temperature,
                "max_tokens": int(getattr(self, "_max_tokens", 1024) or 1024),
                "messages": oai_messages,
            }
            if tools_enabled:
                request_payload["tools"] = oai_tools
            if raw_log is not None:
                payload = {
                    "turn": turn,
                    "phase": phase,
                    "model": self._model_name,
                    "proxy_url": self._proxy_url,
                    "messages_ref": raw_log.blob_json("agentic_messages", oai_messages),
                    "request_json_ref": raw_log.blob_json("agentic_request", request_payload),
                }
                if tools_enabled:
                    payload["tools_ref"] = raw_log.blob_json("agentic_tools", oai_tools)
                raw_log.emit(f"agentic.{phase}.request", **(trace_context or {}), payload=payload)
            http_resp = client.with_raw_response.chat.completions.create(**request_payload)
            call_cost = float(http_resp.headers.get("x-litellm-response-cost") or 0.0)
            resp = http_resp.parse()
            oai_msg_out = resp.choices[0].message
            finish = resp.choices[0].finish_reason
            content_blocks: list[dict] = []
            if oai_msg_out.content:
                content_blocks.append({"type": "text", "text": oai_msg_out.content})
            if oai_msg_out.tool_calls:
                for tc in oai_msg_out.tool_calls:
                    content_blocks.append({
                        "type":  "tool_use",
                        "id":    tc.id,
                        "name":  tc.function.name,
                        "input": _j.loads(tc.function.arguments or "{}"),
                    })
            if raw_log is not None:
                if hasattr(resp, "model_dump"):
                    response_payload = resp.model_dump(mode="json")
                else:  # pragma: no cover - SDK compatibility fallback
                    response_payload = repr(resp)
                raw_log.emit(
                    f"agentic.{phase}.response",
                    **(trace_context or {}),
                    payload={
                        "turn": turn,
                        "phase": phase,
                        "model": self._model_name,
                        "headers": dict(http_resp.headers),
                        "response_json_ref": raw_log.blob_json("agentic_response", response_payload),
                        "content_ref": raw_log.blob_json("agentic_content", content_blocks),
                        "tool_calls": [b for b in content_blocks if b.get("type") == "tool_use"],
                        "input_tokens": resp.usage.prompt_tokens if resp.usage else 0,
                        "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
                        "cost_usd": call_cost,
                    },
                )
            return {
                "content":       content_blocks,
                "stop_reason":   "tool_use" if finish == "tool_calls" else "end_turn",
                "input_tokens":  resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
                "cost_usd":      call_cost,
            }

        raise RuntimeError(
            "proxy_url not set in AgenticAdapter config - direct API calls bypass "
            "key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the model YAML."
        )

    def _agentic_loop(
        self,
        pkg: PackageInfo,
        system_prompt: str,
        initial_template: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> tuple[str, int, int, float]:
        if self._agentic_flow == "plan_then_execute":
            return self._agentic_plan_then_execute_loop(
                pkg,
                system_prompt,
                initial_template,
                raw_log=raw_log,
                trace_context=trace_context,
            )
        if self._agentic_flow != "legacy_tool_loop":
            raise ValueError(f"unknown agentic_flow: {self._agentic_flow}")
        return self._tool_loop(
            pkg,
            system_prompt,
            initial_template,
            raw_log=raw_log,
            trace_context=trace_context,
            initial_turn=0,
        )

    def _agentic_plan_then_execute_loop(
        self,
        pkg: PackageInfo,
        system_prompt: str,
        initial_template: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> tuple[str, int, int, float]:
        initial_user = initial_template.format(
            package_name=pkg.name, version=pkg.version
        )
        plan_prompt = (
            f"{initial_user}\n\n"
            "Phase 1: produce an investigation plan only. Do not give a verdict yet.\n"
            "Use this file manifest to decide what to inspect in Phase 2:\n"
            f"{self._package_manifest(pkg)}\n\n"
            "Respond ONLY with valid JSON containing investigation planning fields, for example:\n"
            '{"suspicious_paths": [], "search_terms": [], '
            '"risk_hypotheses": [], "next_steps": []}'
        )
        plan_resp = self._make_api_call(
            [{"role": "user", "content": plan_prompt}],
            system_prompt=system_prompt,
            raw_log=raw_log,
            trace_context=trace_context,
            turn=0,
            tools_enabled=False,
            phase="plan",
        )
        plan_text = "".join(
            b["text"] for b in plan_resp["content"] if b.get("type") == "text"
        )
        plan = self._parse_plan(plan_text)
        self._last_plan = plan

        execute_template = (
            f"{initial_user}\n\n"
            "Phase 2: execute the investigation plan below using only the provided "
            "read-only tools. Do not install, import, or execute the package.\n\n"
            f"Investigation plan JSON:\n{_json.dumps(plan, sort_keys=True)}\n\n"
            "After using the tools, respond ONLY with valid JSON:\n"
            '{"verdict": "malicious" or "benign", "confidence": 0.0-1.0, '
            '"reasoning": "one sentence", "evidence": [], "files_reviewed": [], '
            '"limitations": []}'
        )
        final_text, in_tok, out_tok, total_cost = self._tool_loop(
            pkg,
            system_prompt,
            execute_template,
            raw_log=raw_log,
            trace_context=trace_context,
            initial_turn=1,
            preformatted=True,
        )
        return (
            final_text,
            plan_resp["input_tokens"] + in_tok,
            plan_resp["output_tokens"] + out_tok,
            plan_resp.get("cost_usd", 0.0) + total_cost,
        )

    @staticmethod
    def _parse_plan(raw: str) -> dict:
        import re as _re
        m = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not m:
            raise ValueError("agentic plan phase did not return JSON")
        try:
            data = _json.loads(m.group())
        except _json.JSONDecodeError as exc:
            raise ValueError(f"agentic plan phase returned invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError("agentic plan phase JSON must be an object")
        if "verdict" in data:
            raise ValueError("agentic plan phase returned a verdict before investigation")
        for key in ("suspicious_paths", "search_terms", "risk_hypotheses", "next_steps"):
            data.setdefault(key, [])
        return data

    @staticmethod
    def _package_manifest(pkg: PackageInfo, limit: int = 200) -> str:
        lines = [
            f"- {path} ({len(content.encode('utf-8', errors='replace'))} bytes)"
            for path, content in sorted(pkg.files.items())[:limit]
        ]
        if len(pkg.files) > limit:
            lines.append(f"... {len(pkg.files) - limit} additional file(s) omitted")
        return "\n".join(lines) or "(no extracted files)"

    def _tool_loop(
        self,
        pkg: PackageInfo,
        system_prompt: str,
        initial_template: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        initial_turn: int = 0,
        preformatted: bool = False,
    ) -> tuple[str, int, int, float]:
        if preformatted:
            initial_user = initial_template
        else:
            initial_user = initial_template.format(
                package_name=pkg.name, version=pkg.version
            )
        messages: list[dict] = [{"role": "user", "content": initial_user}]
        total_input_tokens  = 0
        total_output_tokens = 0
        total_cost          = 0.0

        for offset in range(self._max_turns):
            _turn = initial_turn + offset
            resp = self._make_api_call(
                messages,
                system_prompt=system_prompt,
                raw_log=raw_log,
                trace_context=trace_context,
                turn=_turn,
                phase="turn",
            )
            total_input_tokens  += resp["input_tokens"]
            total_output_tokens += resp["output_tokens"]
            total_cost          += resp.get("cost_usd", 0.0)
            content: list[dict] = resp["content"]
            messages.append({"role": "assistant", "content": content})

            if resp["stop_reason"] == "end_turn":
                return "".join(
                    b["text"] for b in content if b.get("type") == "text"
                ), total_input_tokens, total_output_tokens, total_cost

            if resp["stop_reason"] == "tool_use":
                tool_results = []
                for block in content:
                    if block.get("type") == "tool_use":
                        result_content = self._handle_tool(block["name"], block.get("input", {}))
                        if raw_log is not None:
                            raw_log.emit(
                                "agentic.tool.call",
                                **(trace_context or {}),
                                payload={
                                    "turn": _turn,
                                    "tool_name": block["name"],
                                    "tool_use_id": block["id"],
                                    "tool_input": block.get("input", {}),
                                    "tool_output_ref": raw_log.blob_text(
                                        "agentic_tool_output", str(result_content), suffix=".txt"
                                    ),
                                },
                            )
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": block["id"],
                            "content":     str(result_content),
                        })
                messages.append({"role": "user", "content": tool_results})
            else:
                break

        # Max turns exhausted - return whatever the last assistant turn said.
        last_content = messages[-1].get("content", [])
        final_text = ""
        if isinstance(last_content, list):
            final_text = "".join(
                b["text"] for b in last_content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        return final_text, total_input_tokens, total_output_tokens, total_cost

    def _handle_tool(self, name: str, tool_input: dict) -> object:
        pkg = self._current_pkg
        if pkg is None:
            return "Error: no package loaded"
        if name == "list_files":
            return list(pkg.files.keys())
        if name == "read_file":
            path = tool_input.get("path", "")
            return pkg.files.get(path, f"File not found: {path}")
        if name == "search_files":
            return self._tool_search_files(pkg, tool_input)
        if name == "file_info":
            return self._tool_file_info(pkg, tool_input)
        return f"Unknown tool: {name}"

    @staticmethod
    def _tool_search_files(pkg: PackageInfo, tool_input: dict) -> object:
        import fnmatch as _fnmatch, re as _re
        pattern = str(tool_input.get("pattern", ""))
        path_glob = tool_input.get("path_glob")
        try:
            regex = _re.compile(pattern)
        except _re.error as exc:
            return {"error": f"invalid regex: {exc}"}
        matches = []
        for path, content in sorted(pkg.files.items()):
            if path_glob and not _fnmatch.fnmatch(path, str(path_glob)):
                continue
            for line_no, line in enumerate(content.splitlines(), start=1):
                if regex.search(line):
                    matches.append({
                        "path": path,
                        "line": line_no,
                        "text": line[:500],
                    })
                    if len(matches) >= 50:
                        return {"matches": matches, "truncated": True}
        return {"matches": matches, "truncated": False}

    @staticmethod
    def _tool_file_info(pkg: PackageInfo, tool_input: dict) -> object:
        path = str(tool_input.get("path", ""))
        if path not in pkg.files:
            return {"path": path, "exists": False}
        content = pkg.files[path]
        encoded = content.encode("utf-8", errors="replace")
        return {
            "path": path,
            "exists": True,
            "size_bytes": len(encoded),
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "line_count": len(content.splitlines()),
            "in_raw_entrypoints": path in pkg.files_raw,
        }

    def _parse_response(self, raw: str) -> tuple[bool, float | None, dict]:
        return _parse_json_verdict_response(raw)
