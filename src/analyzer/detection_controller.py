"""
detection_controller.py — Detection orchestration layer.

Takes a PackageDiff as input, invokes configured detection schemes
(static SAST tools and/or LLM APIs), gathers results to the DB,
and enforces the YAML configuration.
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from diff import PackageDiff, FileDiff
from sql import SQL


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field


@dataclass
class DetectionResult:
    detector: str
    verdict: str          # "malicious" | "benign" | "error"
    confidence: float | None = None
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# StaticDetectorAdapter
# ---------------------------------------------------------------------------

class StaticDetectorAdapter:
    """
    Wraps industry-standard SAST tools (Bandit, Semgrep).
    Writes changed source to a temp directory and runs the tool against it.
    """

    SUPPORTED = ("bandit", "semgrep")

    def __init__(self, tool: str, config: dict):
        if tool not in self.SUPPORTED:
            raise ValueError(f"Unsupported static tool: {tool}")
        self._tool = tool
        self._cfg = config

    def run(self, diff: PackageDiff) -> DetectionResult:
        added_code = self._collect_added_code(diff)
        if not added_code.strip():
            return DetectionResult(
                detector=self._tool,
                verdict="benign",
                details={"note": "no added Python code to scan"},
            )

        with tempfile.TemporaryDirectory() as tmpdir:
            src = Path(tmpdir) / "scan_target.py"
            src.write_text(added_code, encoding="utf-8")
            return self._invoke(src, tmpdir)

    def _collect_added_code(self, diff: PackageDiff) -> str:
        lines: list[str] = []
        for fd in diff.file_diffs:
            if fd.path.endswith(".py"):
                lines.extend(fd.added_lines)
        return "\n".join(lines)

    def _invoke(self, src: Path, workdir: str) -> DetectionResult:
        if self._tool == "bandit":
            return self._run_bandit(src)
        if self._tool == "semgrep":
            return self._run_semgrep(src)
        raise RuntimeError("unreachable")

    def _run_bandit(self, src: Path) -> DetectionResult:
        try:
            proc = subprocess.run(
                ["bandit", "-r", str(src), "-f", "json", "-q"],
                capture_output=True, text=True, timeout=60,
            )
            import json
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
            issues = data.get("results", [])
            verdict = "malicious" if issues else "benign"
            return DetectionResult(
                detector="bandit",
                verdict=verdict,
                details={"issue_count": len(issues), "issues": issues[:10]},
            )
        except Exception as exc:
            return DetectionResult(detector="bandit", verdict="error", details={"error": str(exc)})

    def _run_semgrep(self, src: Path) -> DetectionResult:
        try:
            proc = subprocess.run(
                ["semgrep", "--config", "p/python", "--json", str(src)],
                capture_output=True, text=True, timeout=60,
            )
            import json
            data = json.loads(proc.stdout) if proc.stdout.strip() else {}
            findings = data.get("results", [])
            verdict = "malicious" if findings else "benign"
            return DetectionResult(
                detector="semgrep",
                verdict=verdict,
                details={"finding_count": len(findings), "findings": findings[:10]},
            )
        except Exception as exc:
            return DetectionResult(detector="semgrep", verdict="error", details={"error": str(exc)})


# ---------------------------------------------------------------------------
# LLMDetectorAdapter
# ---------------------------------------------------------------------------

class LLMDetectorAdapter:
    """
    Wraps LLM API providers (Anthropic, OpenAI, Gemini, Deepseek, Mistral, Meta).
    Sends a structured prompt containing the diff and returns a verdict.
    """

    SUPPORTED = ("anthropic", "openai", "gemini", "deepseek", "mistral", "meta")

    def __init__(self, provider: str, config: dict, prompt_store: str | Path):
        if provider not in self.SUPPORTED:
            raise ValueError(f"Unsupported LLM provider: {provider}")
        self._provider = provider
        self._cfg = config
        self._prompt_store = Path(prompt_store)
        self._proxy_url: str | None = config.get("proxy_url") or None

    def run(self, diff: PackageDiff) -> DetectionResult:
        system_prompt = self._load_system_prompt()
        user_message = self._build_user_message(diff)

        try:
            raw = self._call_api(system_prompt, user_message)
            verdict, confidence, details = self._parse_response(raw)
            return DetectionResult(
                detector=self._provider,
                verdict=verdict,
                confidence=confidence,
                details=details,
            )
        except Exception as exc:
            return DetectionResult(
                detector=self._provider,
                verdict="error",
                details={"error": str(exc)},
            )

    def _load_system_prompt(self) -> str:
        prompt_file = self._prompt_store / f"{self._provider}_system.txt"
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        return self._default_system_prompt()

    def _default_system_prompt(self) -> str:
        return (
            "You are a security researcher analysing Python package diffs "
            "for supply chain attack indicators. "
            "Respond with JSON: {\"verdict\": \"malicious\"|\"benign\", "
            "\"confidence\": 0.0-1.0, \"reasoning\": \"...\"}."
        )

    def _build_user_message(self, diff: PackageDiff) -> str:
        parts = [
            f"Project: {diff.project}",
            f"Version before: {diff.version_before}",
            f"Version after:  {diff.version_after}",
            "",
            "Changed files:",
        ]
        for fd in diff.file_diffs[:20]:  # cap to avoid token overflow
            parts.append(f"\n### {fd.path} ({fd.status}) ###")
            if fd.unified_diff:
                parts.append(fd.unified_diff[:4000])
        return "\n".join(parts)

    def _call_api(self, system: str, user: str) -> str:
        """Dispatch to the correct provider SDK. Stub — implement per provider."""
        if self._provider == "anthropic":
            return self._call_anthropic(system, user)
        raise NotImplementedError(f"Provider not yet implemented: {self._provider}")

    def _call_anthropic(self, system: str, user: str) -> str:
        messages = [{"role": "user", "content": user}]
        if self._proxy_url:
            resp = self._call_via_proxy("anthropic", "claude-opus-4-6", system, messages, 512)
            return resp["content"][0]["text"]
        import anthropic, os
        client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        msg = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=512,
            system=system,
            messages=messages,
        )
        return msg.content[0].text

    def _call_via_proxy(
        self,
        provider: str,
        model: str,
        system: str,
        messages: list,
        max_tokens: int = 512,
        temperature: float = 0.0,
        tools: list | None = None,
    ) -> dict:
        import requests as _req
        payload: dict = {
            "provider":    provider,
            "model":       model,
            "system":      system,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": temperature,
        }
        if tools:
            payload["tools"] = tools
        r = _req.post(
            self._proxy_url.rstrip("/") + "/proxy/analyze",
            json=payload,
            timeout=120,
        )
        r.raise_for_status()
        return r.json()

    def _parse_response(self, raw: str) -> tuple[str, float | None, dict]:
        import json, re
        m = re.search(r"\{.*\}", raw, re.DOTALL)
        if not m:
            return "error", None, {"raw": raw}
        try:
            data = json.loads(m.group())
            verdict = data.get("verdict", "error")
            confidence = float(data.get("confidence", 0))
            return verdict, confidence, data
        except json.JSONDecodeError:
            return "error", None, {"raw": raw}


# ---------------------------------------------------------------------------
# DetectionController
# ---------------------------------------------------------------------------

class DetectionController:
    """
    Reads configuration, instantiates the appropriate adapters,
    runs them against a PackageDiff, and writes results to the DB.
    """

    def __init__(self, config: dict, db: SQL):
        self._cfg = config
        self._db = db
        det_cfg = config.get("detection", {})
        prompt_store = config.get("detection", {}).get("prompt_store", "prompts/")

        # Propagate proxy URL from top-level credential_proxy section into
        # det_cfg so LLMDetectorAdapter constructors can read it uniformly.
        proxy_url = config.get("credential_proxy", {}).get("url")
        if proxy_url:
            det_cfg = {**det_cfg, "proxy_url": proxy_url}

        self._static: list[StaticDetectorAdapter] = [
            StaticDetectorAdapter(tool, det_cfg)
            for tool in det_cfg.get("static_tools", [])
        ]
        self._llm: list[LLMDetectorAdapter] = [
            LLMDetectorAdapter(provider, det_cfg, prompt_store)
            for provider in det_cfg.get("llm_providers", [])
        ]

    def run(self, run_id: str, diff: PackageDiff) -> list[DetectionResult]:
        results: list[DetectionResult] = []

        for adapter in self._static + self._llm:  # type: ignore[operator]
            res = adapter.run(diff)
            results.append(res)
            self._db.insert_result(
                run_id=run_id,
                project=diff.project,
                version_before=diff.version_before,
                version_after=diff.version_after,
                detector=res.detector,
                verdict=res.verdict,
                confidence=res.confidence,
                details=res.details,
            )

        return results


# ===========================================================================
# Entry-point scanning evaluation pipeline
# (appended — existing classes above are unchanged)
# ===========================================================================

import json as _json
import os as _os
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed

import yaml as _yaml

from entry_extractor import PackageInfo


# ---------------------------------------------------------------------------
# Result type for the evaluation pipeline
# ---------------------------------------------------------------------------

@dataclass
class EvalDetectionResult:
    detector: str
    pipeline: str           # "sast_baseline" | "single_llm" | "agentic"
    verdict: bool           # True = malicious
    confidence: float | None
    heuristic_flags: list[str]
    exec_time_ms: int
    api_cost_usd: float     # 0.0 for SAST
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SAST adapter (entry-point files → temp dir → bandit / semgrep)
# ---------------------------------------------------------------------------

class EntryPointStaticAdapter:

    SUPPORTED = ("bandit", "semgrep")

    def __init__(self, tool: str):
        if tool not in self.SUPPORTED:
            raise ValueError(f"Unsupported static tool: {tool}")
        self._tool = tool

    def run(self, pkg: PackageInfo) -> EvalDetectionResult:
        import tempfile

        if not pkg.files:
            return EvalDetectionResult(
                detector=self._tool, pipeline="sast_baseline",
                verdict=False, confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=0, api_cost_usd=0.0,
                details={"note": "no files to scan"},
            )

        t0 = _time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            for rel, content in pkg.files.items():
                dest = tmp / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(content, encoding="utf-8")
            result = self._invoke(tmp)

        result.exec_time_ms = int((_time.monotonic() - t0) * 1000)
        result.heuristic_flags = list(pkg.heuristic_flags)
        return result

    def _invoke(self, target: Path) -> EvalDetectionResult:
        if self._tool == "bandit":
            return self._run_bandit(target)
        return self._run_semgrep(target)

    def _run_bandit(self, target: Path) -> EvalDetectionResult:
        try:
            proc = subprocess.run(
                ["bandit", "-r", str(target), "-f", "json", "-q"],
                capture_output=True, text=True, timeout=120,
            )
            data = _json.loads(proc.stdout) if proc.stdout.strip() else {}
            issues = data.get("results", [])
            return EvalDetectionResult(
                detector="bandit", pipeline="sast_baseline",
                verdict=bool(issues), confidence=None,
                heuristic_flags=[],  # filled by caller
                exec_time_ms=0, api_cost_usd=0.0,
                details={"issue_count": len(issues), "issues": issues[:10]},
            )
        except Exception as exc:
            return EvalDetectionResult(
                detector="bandit", pipeline="sast_baseline",
                verdict=False, confidence=None,
                heuristic_flags=[], exec_time_ms=0, api_cost_usd=0.0,
                details={"error": str(exc)},
            )

    def _run_semgrep(self, target: Path) -> EvalDetectionResult:
        try:
            proc = subprocess.run(
                ["semgrep", "--config", "p/python", "--json", str(target)],
                capture_output=True, text=True, timeout=120,
            )
            data = _json.loads(proc.stdout) if proc.stdout.strip() else {}
            findings = data.get("results", [])
            return EvalDetectionResult(
                detector="semgrep", pipeline="sast_baseline",
                verdict=bool(findings), confidence=None,
                heuristic_flags=[],
                exec_time_ms=0, api_cost_usd=0.0,
                details={"finding_count": len(findings), "findings": findings[:10]},
            )
        except Exception as exc:
            return EvalDetectionResult(
                detector="semgrep", pipeline="sast_baseline",
                verdict=False, confidence=None,
                heuristic_flags=[], exec_time_ms=0, api_cost_usd=0.0,
                details={"error": str(exc)},
            )


# ---------------------------------------------------------------------------
# Single-shot LLM adapter (YAML-configured)
# ---------------------------------------------------------------------------

class EntryPointLLMAdapter:

    def __init__(self, config_path: str | Path):
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f)
        self._model_name: str = cfg["model_name"]
        self._temperature: float = float(cfg.get("temperature", 0.0))
        self._system_prompt: str = cfg["system_prompt"]
        self._user_template: str = cfg["user_template"]
        self._detector_name = Path(config_path).stem  # e.g. "claude_opus"
        self._proxy_url: str | None = cfg.get("proxy_url") or None

    def run(self, pkg: PackageInfo) -> EvalDetectionResult:
        system = self._system_prompt
        user   = self._user_template.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=self._build_file_listing(pkg),
        )
        t0 = _time.monotonic()
        try:
            raw, tokens = self._call_api(system, user)
            verdict, confidence, details = self._parse_response(raw)
        except Exception as exc:
            verdict, confidence, details, tokens = False, None, {"error": str(exc)}, 0

        return EvalDetectionResult(
            detector=self._detector_name,
            pipeline="single_llm",
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=0.0,   # extend: tokens * rate_per_token
            details=details,
        )

    def _build_file_listing(self, pkg: PackageInfo) -> str:
        parts: list[str] = []
        total = 0
        for path, content in pkg.files.items():
            chunk = f"### {path} ###\n{content}\n\n"
            if total + len(chunk) > 8000:
                parts.append("[truncated]")
                break
            parts.append(chunk)
            total += len(chunk)
        return "".join(parts)

    def _call_api(self, system: str, user: str) -> tuple[str, int]:
        m = self._model_name
        if m.startswith("claude-"):
            return self._call_anthropic(system, user)
        if m.startswith(("gpt-", "o1-", "o3-", "together_ai/")):
            return self._call_openai(system, user)
        if m.startswith(("gemini-", "gemini/")):
            return self._call_gemini(system, user)
        raise ValueError(f"Unknown model prefix for: {m}")

    def _call_via_proxy(self, system: str, user: str) -> tuple[str, int]:
        """Route through LiteLLM using its OpenAI-compatible endpoint."""
        import openai as _openai
        client = _openai.OpenAI(
            base_url=self._proxy_url.rstrip("/") + "/v1",
            api_key="no-key-needed",
        )
        resp = client.chat.completions.create(
            model=self._model_name,
            temperature=self._temperature,
            max_tokens=512,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        text = resp.choices[0].message.content or ""
        tokens = (resp.usage.prompt_tokens + resp.usage.completion_tokens) if resp.usage else 0
        return text, tokens

    def _call_anthropic(self, system: str, user: str) -> tuple[str, int]:
        if self._proxy_url:
            return self._call_via_proxy(system, user)
        import anthropic
        client = anthropic.Anthropic(api_key=_os.environ["ANTHROPIC_API_KEY"])
        resp = client.messages.create(
            model=self._model_name,
            max_tokens=512,
            temperature=self._temperature,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        tokens = resp.usage.input_tokens + resp.usage.output_tokens
        return resp.content[0].text, tokens

    def _call_openai(self, system: str, user: str) -> tuple[str, int]:
        if self._proxy_url:
            return self._call_via_proxy(system, user)
        try:
            import openai
        except ImportError as exc:
            raise ImportError("openai package not installed") from exc
        client = openai.OpenAI(api_key=_os.environ["OPENAI_API_KEY"])
        resp = client.chat.completions.create(
            model=self._model_name,
            temperature=self._temperature,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        tokens = resp.usage.total_tokens if resp.usage else 0
        return resp.choices[0].message.content, tokens

    def _call_gemini(self, system: str, user: str) -> tuple[str, int]:
        if self._proxy_url:
            return self._call_via_proxy(system, user)
        try:
            import google.generativeai as genai
        except ImportError as exc:
            raise ImportError("google-generativeai package not installed") from exc
        genai.configure(api_key=_os.environ["GEMINI_API_KEY"])
        model = genai.GenerativeModel(self._model_name, system_instruction=system)
        resp = model.generate_content(user)
        tokens = getattr(getattr(resp, "usage_metadata", None), "total_token_count", 0)
        return resp.text, tokens

    def _parse_response(self, raw: str) -> tuple[bool, float | None, dict]:
        import re as _re, json as _j
        m = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not m:
            return False, None, {"raw": raw}
        try:
            data = _j.loads(m.group())
            verdict_str = data.get("verdict", "benign")
            verdict = verdict_str.strip().lower() == "malicious"
            confidence = float(data["confidence"]) if "confidence" in data else None
            return verdict, confidence, data
        except (_j.JSONDecodeError, ValueError):
            return False, None, {"raw": raw}


# ---------------------------------------------------------------------------
# Agentic adapter (Anthropic tool_use, multi-turn)
# ---------------------------------------------------------------------------

class AgenticAdapter:

    def __init__(self, config_path: str | Path):
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f)
        self._model_name: str        = cfg["model_name"]
        self._system_prompt: str     = cfg["system_prompt"]
        self._initial_template: str  = cfg.get("initial_user_message", "Investigate package '{package_name}' v{version}.")
        self._max_turns: int         = int(cfg.get("max_turns", 5))
        self._temperature: float     = float(cfg.get("temperature", 0.0))
        self._proxy_url: str | None  = cfg.get("proxy_url") or None
        # pkg reference held for duration of one run() call (see CONCERNS.md §C note)
        self._current_pkg: PackageInfo | None = None

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
    ]

    def run(self, pkg: PackageInfo) -> EvalDetectionResult:
        self._current_pkg = pkg
        t0 = _time.monotonic()
        try:
            final_text, total_tokens = self._agentic_loop(pkg)
            verdict, confidence, details = self._parse_response(final_text)
        except NotImplementedError:
            raise
        except Exception as exc:
            verdict, confidence, details, total_tokens = False, None, {"error": str(exc)}, 0
        finally:
            self._current_pkg = None

        return EvalDetectionResult(
            detector="agentic_claude",
            pipeline="agentic",
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=0.0,   # extend: total_tokens * rate_per_token
            details=details,
        )

    def _make_api_call(self, messages: list[dict]) -> dict:
        """
        Single API call returning a normalised response dict:
          {content: list[dict], stop_reason: str, input_tokens: int, output_tokens: int}

        Proxy path (LiteLLM): translates Anthropic-format messages → OpenAI format,
        calls LiteLLM's /v1/chat/completions, then normalises the OpenAI response back
        to the Anthropic-like dict shape so _agentic_loop() stays unchanged.

        Direct path (dev/no proxy): calls Anthropic SDK and converts to the same dict.
        """
        if self._proxy_url:
            import openai as _openai, json as _j
            client = _openai.OpenAI(
                base_url=self._proxy_url.rstrip("/") + "/v1",
                api_key="no-key-needed",
            )
            # --- translate Anthropic-format message history → OpenAI format ---
            oai_messages: list[dict] = [
                {"role": "system", "content": self._system_prompt}
            ]
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
                    oai_msg: dict = {
                        "role": "assistant",
                        "content": " ".join(text_parts) or None,
                    }
                    if tool_calls:
                        oai_msg["tool_calls"] = tool_calls
                    oai_messages.append(oai_msg)
                elif role == "user" and isinstance(body, list) and body and body[0].get("type") == "tool_result":
                    # Anthropic tool_result blocks → individual OpenAI tool messages
                    for block in body:
                        oai_messages.append({
                            "role": "tool",
                            "tool_call_id": block["tool_use_id"],
                            "content": str(block.get("content", "")),
                        })
                else:
                    oai_messages.append({"role": role, "content": body})
            # --- convert _TOOLS (Anthropic schema) → OpenAI function format ---
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
            ]
            resp = client.chat.completions.create(
                model=self._model_name,
                temperature=self._temperature,
                max_tokens=1024,
                messages=oai_messages,
                tools=oai_tools,
            )
            # --- normalise OpenAI response → Anthropic-like dict ---
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
            return {
                "content":       content_blocks,
                "stop_reason":   "tool_use" if finish == "tool_calls" else "end_turn",
                "input_tokens":  resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
            }

        import anthropic
        client = anthropic.Anthropic(api_key=_os.environ["ANTHROPIC_API_KEY"])
        resp = client.messages.create(
            model=self._model_name,
            max_tokens=1024,
            temperature=self._temperature,
            system=self._system_prompt,
            tools=self._TOOLS,
            messages=messages,
        )
        return {
            "content":       [b.model_dump() for b in resp.content],
            "stop_reason":   resp.stop_reason,
            "input_tokens":  resp.usage.input_tokens,
            "output_tokens": resp.usage.output_tokens,
        }

    def _agentic_loop(self, pkg: PackageInfo) -> tuple[str, int]:
        initial_user = self._initial_template.format(
            package_name=pkg.name, version=pkg.version
        )
        messages: list[dict] = [{"role": "user", "content": initial_user}]
        total_tokens = 0

        for _turn in range(self._max_turns):
            resp = self._make_api_call(messages)
            total_tokens += resp["input_tokens"] + resp["output_tokens"]
            content: list[dict] = resp["content"]
            messages.append({"role": "assistant", "content": content})

            if resp["stop_reason"] == "end_turn":
                final_text = "".join(
                    b["text"] for b in content if b.get("type") == "text"
                )
                return final_text, total_tokens

            if resp["stop_reason"] == "tool_use":
                tool_results = []
                for block in content:
                    if block.get("type") == "tool_use":
                        result_content = self._handle_tool(
                            block["name"], block.get("input", {})
                        )
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": block["id"],
                            "content":     str(result_content),
                        })
                messages.append({"role": "user", "content": tool_results})
            else:
                break  # unexpected stop reason

        # Max turns exhausted — collect whatever the last assistant message said.
        last = messages[-1]
        raw_content = last.get("content", [])
        final_text = ""
        if isinstance(raw_content, list):
            final_text = "".join(
                b["text"] for b in raw_content if isinstance(b, dict) and b.get("type") == "text"
            )
        return final_text, total_tokens

    def _handle_tool(self, name: str, tool_input: dict) -> object:
        pkg = self._current_pkg
        if pkg is None:
            return "Error: no package loaded"
        if name == "list_files":
            return list(pkg.files.keys())
        if name == "read_file":
            path = tool_input.get("path", "")
            return pkg.files.get(path, f"File not found: {path}")
        return f"Unknown tool: {name}"

    def _parse_response(self, raw: str) -> tuple[bool, float | None, dict]:
        import re as _re, json as _j
        m = _re.search(r"\{.*\}", raw, _re.DOTALL)
        if not m:
            return False, None, {"raw": raw}
        try:
            data = _j.loads(m.group())
            verdict = data.get("verdict", "benign").strip().lower() == "malicious"
            confidence = float(data["confidence"]) if "confidence" in data else None
            return verdict, confidence, data
        except (_j.JSONDecodeError, ValueError):
            return False, None, {"raw": raw}


# ---------------------------------------------------------------------------
# EvalController — orchestrates all three tracks in parallel
# ---------------------------------------------------------------------------

class EvalController:

    def __init__(self, configs_dir: str | Path, db):
        # Lazy import to avoid cross-package issues at module load time.
        from src.data.db_manager import DBManager  # noqa: F401 (type reference)
        self._db = db
        configs_dir = Path(configs_dir)

        self._static: list[EntryPointStaticAdapter] = [
            EntryPointStaticAdapter("bandit"),
            EntryPointStaticAdapter("semgrep"),
        ]

        self._llm: list[EntryPointLLMAdapter] = []
        self._agentic: list[AgenticAdapter] = []

        for yaml_path in sorted(configs_dir.glob("*.yaml")):
            if "agentic" in yaml_path.stem:
                self._agentic.append(AgenticAdapter(yaml_path))
            else:
                self._llm.append(EntryPointLLMAdapter(yaml_path))

    def run(self, run_id: str, pkg: PackageInfo) -> list[EvalDetectionResult]:
        adapters = (
            self._static
            + self._llm       # type: ignore[operator]
            + self._agentic   # type: ignore[operator]
        )
        results: list[EvalDetectionResult] = []

        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {pool.submit(a.run, pkg): a for a in adapters}
            for future in as_completed(futures):
                adapter = futures[future]
                try:
                    res = future.result()
                except Exception as exc:
                    name = getattr(adapter, "_tool", None) or getattr(adapter, "_detector_name", "unknown")
                    res = EvalDetectionResult(
                        detector=name, pipeline="error",
                        verdict=False, confidence=None,
                        heuristic_flags=list(pkg.heuristic_flags),
                        exec_time_ms=0, api_cost_usd=0.0,
                        details={"error": str(exc)},
                    )

                results.append(res)
                self._db.insert_eval_result(
                    run_id=run_id,
                    package_name=pkg.name,
                    version=pkg.version,
                    pipeline=res.pipeline,
                    detector=res.detector,
                    verdict=res.verdict,
                    heuristic_flags=res.heuristic_flags,
                    exec_time_ms=res.exec_time_ms,
                    api_cost_usd=res.api_cost_usd,
                    details=res.details,
                )

        return results
