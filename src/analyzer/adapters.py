"""
adapters.py — Detector adapter hierarchy for the entry-point evaluation pipeline.

DetectorAdapter (ABC)
  StaticAdapter     — generic SAST tools (bandit, semgrep); ignores prompt params
  GuardDogAdapter   — PyPI-malware-specific static rules; source-only mode
  LLMAdapter        — Single-shot LLM call via YAML-configured model
  AgenticAdapter    — Multi-turn Anthropic tool_use loop

EvalController imports from this module.
"""

from __future__ import annotations

import json as _json
import os as _os
import subprocess
import tempfile
import time as _time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import yaml as _yaml

from src.utils.logger import get_logger
from entry_extractor import PackageInfo

log = get_logger()

GUARDDOG_VERSION = "2.9.0"
GUARDDOG_SOURCE_RULES = (
    "api-obfuscation",
    "shady-links",
    "obfuscation",
    "clipboard-access",
    "exfiltrate-sensitive-data",
    "download-executable",
    "exec-base64",
    "silent-process-execution",
    "dll-hijacking",
    "screenshot",
    "steganography",
    "code-execution",
    "unicode",
    "cmd-overwrite",
    "suspicious_passwd_access_linux",
)


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class EvalDetectionResult:
    detector: str
    experiment_mode: str    # "static" | "hybrid" | "agentic" | "llm_raw" | "error"
    verdict: bool           # True = malicious
    confidence: float | None
    heuristic_flags: list[str]
    exec_time_ms: int
    api_cost_usd: float     # 0.0 for SAST
    input_tokens: int = 0
    output_tokens: int = 0
    details: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------

class DetectorAdapter(ABC):
    """
    Common interface for all entry-point detectors.

    EvalController calls run(pkg, prompt_strategy, system_prompt, template_override)
    uniformly across all adapter types. StaticAdapter ignores the prompt params;
    LLMAdapter and AgenticAdapter use them to select the active strategy.
    """

    @abstractmethod
    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
    ) -> EvalDetectionResult:
        ...


def _write_pkg_files(pkg: PackageInfo, target: Path) -> None:
    for rel, content in pkg.files.items():
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")


def _static_error_result(
    detector: str,
    error: str,
    *,
    stdout: str | None = None,
    stderr: str | None = None,
    returncode: int | None = None,
) -> EvalDetectionResult:
    details: dict = {"error": error}
    if returncode is not None:
        details["returncode"] = returncode
    if stdout:
        details["stdout"] = stdout[-2000:]
    if stderr:
        details["stderr"] = stderr[-2000:]
    return EvalDetectionResult(
        detector=detector,
        experiment_mode="error",
        verdict=False,
        confidence=None,
        heuristic_flags=[],
        exec_time_ms=0,
        api_cost_usd=0.0,
        details=details,
    )


# ---------------------------------------------------------------------------
# StaticAdapter — SAST tools
# ---------------------------------------------------------------------------

class StaticAdapter(DetectorAdapter):

    SUPPORTED = ("bandit", "semgrep")

    def __init__(self, tool: str):
        if tool not in self.SUPPORTED:
            raise ValueError(f"Unsupported static tool: {tool}")
        self._tool = tool

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
    ) -> EvalDetectionResult:
        # Prompt params are unused — SAST is prompt-agnostic.
        if not pkg.files:
            return EvalDetectionResult(
                detector=self._tool, experiment_mode="static",
                verdict=False, confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=0, api_cost_usd=0.0,
                details={"note": "no files to scan"},
            )

        t0 = _time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            _write_pkg_files(pkg, tmp)
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
            if proc.returncode not in (0, 1) and not issues:
                return _static_error_result(
                    "bandit",
                    "bandit exited without parseable findings",
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    returncode=proc.returncode,
                )
            return EvalDetectionResult(
                detector="bandit", experiment_mode="static",
                verdict=bool(issues), confidence=None,
                heuristic_flags=[],
                exec_time_ms=0, api_cost_usd=0.0,
                details={"issue_count": len(issues), "issues": issues[:10]},
            )
        except Exception as exc:
            return _static_error_result("bandit", str(exc))

    def _run_semgrep(self, target: Path) -> EvalDetectionResult:
        try:
            proc = subprocess.run(
                ["semgrep", "--config", "p/python", "--json", str(target)],
                capture_output=True, text=True, timeout=120,
            )
            data = _json.loads(proc.stdout) if proc.stdout.strip() else {}
            findings = data.get("results", [])
            if proc.returncode not in (0, 1) and not findings:
                return _static_error_result(
                    "semgrep",
                    "semgrep exited without parseable findings",
                    stdout=proc.stdout,
                    stderr=proc.stderr,
                    returncode=proc.returncode,
                )
            return EvalDetectionResult(
                detector="semgrep", experiment_mode="static",
                verdict=bool(findings), confidence=None,
                heuristic_flags=[],
                exec_time_ms=0, api_cost_usd=0.0,
                details={"finding_count": len(findings), "findings": findings[:10]},
            )
        except Exception as exc:
            return _static_error_result("semgrep", str(exc))


# ---------------------------------------------------------------------------
# GuardDogAdapter — PyPI-malware-specific static rules
# ---------------------------------------------------------------------------

class GuardDogAdapter(DetectorAdapter):
    """
    GuardDog source-only baseline.

    It scans the same PackageInfo.files evidence set as Bandit, Semgrep, and the
    LLM-hybrid prompt. Only explicit source-code rules are enabled; metadata
    heuristics are intentionally excluded because they can query live package
    registries and would give GuardDog evidence the other detectors do not see.
    """

    _detector_name = "guarddog"
    _experiment_mode = "static"

    def __init__(
        self,
        rules: tuple[str, ...] = GUARDDOG_SOURCE_RULES,
        timeout: int = 180,
    ):
        self._rules = tuple(rules)
        self._timeout = timeout

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
    ) -> EvalDetectionResult:
        # Prompt params are unused — GuardDog is prompt-agnostic.
        if not pkg.files:
            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="static",
                verdict=False,
                confidence=None,
                heuristic_flags=list(pkg.heuristic_flags),
                exec_time_ms=0,
                api_cost_usd=0.0,
                details={
                    "note": "no files to scan",
                    "guarddog_version": GUARDDOG_VERSION,
                    "rules": list(self._rules),
                },
            )

        t0 = _time.monotonic()
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            _write_pkg_files(pkg, tmp)
            result = self._run_guarddog(tmp)

        result.exec_time_ms = int((_time.monotonic() - t0) * 1000)
        result.heuristic_flags = list(pkg.heuristic_flags)
        return result

    def _command(self, target: Path) -> list[str]:
        cmd = [
            "guarddog",
            "pypi",
            "scan",
            str(target),
            "--output-format=json",
        ]
        for rule in self._rules:
            cmd.extend(["--rules", rule])
        return cmd

    def _run_guarddog(self, target: Path) -> EvalDetectionResult:
        try:
            proc = subprocess.run(
                self._command(target),
                capture_output=True,
                text=True,
                timeout=self._timeout,
            )
            data = None
            if not proc.stdout.strip():
                if proc.returncode == 0:
                    findings: list[dict] = []
                else:
                    return _static_error_result(
                        self._detector_name,
                        "guarddog exited without JSON output",
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        returncode=proc.returncode,
                    )
            else:
                data = _json.loads(proc.stdout)
                findings = self._extract_findings(data)
                errors = self._extract_errors(data)
                if errors and not findings:
                    return _static_error_result(
                        self._detector_name,
                        "guarddog reported rule execution errors",
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        returncode=proc.returncode,
                    )
                if proc.returncode != 0 and not findings:
                    return _static_error_result(
                        self._detector_name,
                        "guarddog exited non-zero without findings",
                        stdout=proc.stdout,
                        stderr=proc.stderr,
                        returncode=proc.returncode,
                    )

            details = {
                "finding_count": len(findings),
                "findings": findings[:10],
                "guarddog_version": GUARDDOG_VERSION,
                "rules": list(self._rules),
            }
            if data is not None:
                errors = self._extract_errors(data)
                if errors:
                    details["errors"] = errors

            return EvalDetectionResult(
                detector=self._detector_name,
                experiment_mode="static",
                verdict=bool(findings),
                confidence=None,
                heuristic_flags=[],
                exec_time_ms=0,
                api_cost_usd=0.0,
                details=details,
            )
        except Exception as exc:
            return _static_error_result(self._detector_name, str(exc))

    def _extract_errors(self, data) -> dict:
        if not isinstance(data, dict):
            return {}
        errors = data.get("errors")
        if isinstance(errors, dict):
            return {str(k): v for k, v in errors.items() if v}
        if isinstance(errors, list):
            return {str(i): item for i, item in enumerate(errors) if item}
        if errors:
            return {"error": errors}
        return {}

    def _extract_findings(self, data) -> list[dict]:
        if isinstance(data, list):
            return self._normalize_findings(data)

        if not isinstance(data, dict):
            return [{"value": data}] if data else []

        for key in ("results", "findings", "issues", "matches", "detections"):
            value = data.get(key)
            if isinstance(value, list):
                return self._normalize_findings(value)
            if isinstance(value, dict):
                return self._extract_findings(value)

        combined: list[dict] = []
        for value in data.values():
            if isinstance(value, list):
                combined.extend(self._normalize_findings(value))
            elif isinstance(value, dict):
                combined.extend(self._extract_findings(value))
        return combined

    def _normalize_findings(self, findings: list) -> list[dict]:
        normalized: list[dict] = []
        for item in findings:
            if isinstance(item, dict):
                normalized.append(item)
            else:
                normalized.append({"value": item})
        return normalized


# ---------------------------------------------------------------------------
# LLMAdapter — single-shot LLM call (YAML-configured model)
# ---------------------------------------------------------------------------

class LLMAdapter(DetectorAdapter):

    def __init__(self, config_path: str | Path):
        with open(config_path, encoding="utf-8") as f:
            cfg = _yaml.safe_load(f)
        self._model_name: str      = cfg["model_name"]
        self._temperature: float   = float(cfg.get("temperature", 0.0))
        self._system_prompt: str   = cfg.get("system_prompt", "")
        self._user_template: str   = cfg.get("user_template", "{file_listing}")
        self._detector_name: str   = Path(config_path).stem   # e.g. "claude_opus"
        self._proxy_url: str | None = cfg.get("proxy_url") or None

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
    ) -> EvalDetectionResult:
        system = system_prompt    if system_prompt    is not None else self._system_prompt
        tmpl   = template_override if template_override is not None else self._user_template
        listing, truncated = self._build_file_listing(pkg)
        user   = tmpl.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=listing,
            heuristic_flags=", ".join(pkg.heuristic_flags) if pkg.heuristic_flags else "none",
        )
        log.debug(
            f"[{self._detector_name}] prompt ({len(user)} chars, truncated={truncated}):\n{user}"
        )
        t0 = _time.monotonic()
        try:
            raw_text, in_tok, out_tok, cost = self._call_api(system, user)
            log.debug(
                f"[{self._detector_name}] response "
                f"(in={in_tok} out={out_tok} cost=${cost:.6f}):\n{raw_text}"
            )
            verdict, confidence, details = self._parse_response(raw_text)
        except Exception as exc:
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

        details["model"] = self._model_name
        if truncated:
            details["truncated"] = True
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode="hybrid",
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=cost,
            input_tokens=in_tok,
            output_tokens=out_tok,
            details=details,
        )

    def _build_file_listing(self, pkg: PackageInfo) -> tuple[str, bool]:
        """Returns (listing, truncated). truncated=True when the 8000-char cap was hit."""
        parts: list[str] = []
        total = 0
        for path, content in pkg.files.items():
            chunk = f"### {path} ###\n{content}\n\n"
            if total + len(chunk) > 8000:
                parts.append("[truncated]")
                return "".join(parts), True
            parts.append(chunk)
            total += len(chunk)
        return "".join(parts), False

    def _call_api(self, system: str, user: str) -> tuple[str, int, int, float]:
        m = self._model_name
        if m.startswith("claude-"):
            return self._call_anthropic(system, user)
        if m.startswith(("gpt-", "o1-", "o3-", "together_ai/")):
            return self._call_openai(system, user)
        if m.startswith(("gemini-", "gemini/")):
            return self._call_gemini(system, user)
        raise ValueError(f"Unknown model prefix for: {m}")

    def _call_via_proxy(self, system: str, user: str) -> tuple[str, int, int, float]:
        """Route through LiteLLM; returns (text, input_tokens, output_tokens, cost_usd)."""
        import openai as _openai
        client = _openai.OpenAI(
            base_url=self._proxy_url.rstrip("/") + "/v1",
            api_key="no-key-needed",
        )
        http_resp = client.with_raw_response.chat.completions.create(
            model=self._model_name,
            temperature=self._temperature,
            max_tokens=512,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user},
            ],
        )
        cost = float(http_resp.headers.get("x-litellm-response-cost") or 0.0)
        resp = http_resp.parse()
        text = resp.choices[0].message.content or ""
        in_tok  = resp.usage.prompt_tokens     if resp.usage else 0
        out_tok = resp.usage.completion_tokens if resp.usage else 0
        return text, in_tok, out_tok, cost

    def _call_anthropic(self, system: str, user: str) -> tuple[str, int, int, float]:
        if self._proxy_url:
            return self._call_via_proxy(system, user)
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config — direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _call_openai(self, system: str, user: str) -> tuple[str, int, int, float]:
        if self._proxy_url:
            return self._call_via_proxy(system, user)
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config — direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _call_gemini(self, system: str, user: str) -> tuple[str, int, int, float]:
        if self._proxy_url:
            return self._call_via_proxy(system, user)
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config — direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

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
# AgenticAdapter — multi-turn Anthropic tool_use loop
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
        self._temperature: float     = float(cfg.get("temperature", 0.0))
        self._proxy_url: str | None  = cfg.get("proxy_url") or None
        self._detector_name: str     = Path(config_path).stem   # e.g. "claude_haiku_agentic"
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

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
    ) -> EvalDetectionResult:
        # template_override maps to initial_user_message for the agentic adapter.
        self._current_pkg = pkg
        _sys  = system_prompt     if system_prompt     is not None else self._system_prompt
        _init = template_override if template_override is not None else self._initial_template
        t0 = _time.monotonic()
        try:
            final_text, in_tok, out_tok, total_cost = self._agentic_loop(pkg, _sys, _init)
            verdict, confidence, details = self._parse_response(final_text)
        except NotImplementedError:
            raise
        except Exception as exc:
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

    def _make_api_call(self, messages: list[dict], system_prompt: str | None = None) -> dict:
        """
        Single API call returning a normalised response dict:
          {content: list[dict], stop_reason: str, input_tokens: int, output_tokens: int}

        Proxy path (LiteLLM): translates Anthropic-format messages → OpenAI format,
        calls /v1/chat/completions, normalises response back to Anthropic-like dict.
        Direct path: calls Anthropic SDK directly.
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
            ]
            http_resp = client.with_raw_response.chat.completions.create(
                model=self._model_name,
                temperature=self._temperature,
                max_tokens=1024,
                messages=oai_messages,
                tools=oai_tools,
            )
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
            return {
                "content":       content_blocks,
                "stop_reason":   "tool_use" if finish == "tool_calls" else "end_turn",
                "input_tokens":  resp.usage.prompt_tokens if resp.usage else 0,
                "output_tokens": resp.usage.completion_tokens if resp.usage else 0,
                "cost_usd":      call_cost,
            }

        raise RuntimeError(
            "proxy_url not set in AgenticAdapter config — direct API calls bypass "
            "key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the model YAML."
        )

    def _agentic_loop(
        self, pkg: PackageInfo, system_prompt: str, initial_template: str
    ) -> tuple[str, int, int, float]:
        initial_user = initial_template.format(
            package_name=pkg.name, version=pkg.version
        )
        messages: list[dict] = [{"role": "user", "content": initial_user}]
        total_input_tokens  = 0
        total_output_tokens = 0
        total_cost          = 0.0

        for _turn in range(self._max_turns):
            resp = self._make_api_call(messages, system_prompt=system_prompt)
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
                        tool_results.append({
                            "type":        "tool_result",
                            "tool_use_id": block["id"],
                            "content":     str(result_content),
                        })
                messages.append({"role": "user", "content": tool_results})
            else:
                break

        # Max turns exhausted — return whatever the last assistant turn said.
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
# LLMRawAdapter — LLM adapter using raw (unfiltered) entry-point source
# ---------------------------------------------------------------------------

class LLMRawAdapter(LLMAdapter):
    """
    Identical to LLMAdapter except it reads from pkg.files_raw (entry-point
    files only, no AST-resolved imports) instead of pkg.files.
    Produces experiment_mode="llm_raw" rows in the DB.
    """

    def run(
        self,
        pkg: PackageInfo,
        prompt_strategy: str = "zero_shot",
        system_prompt: str | None = None,
        template_override: str | None = None,
    ) -> EvalDetectionResult:
        system = system_prompt     if system_prompt     is not None else self._system_prompt
        tmpl   = template_override if template_override is not None else self._user_template
        listing, truncated = self._build_file_listing_raw(pkg)
        user   = tmpl.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=listing,
            heuristic_flags=", ".join(pkg.heuristic_flags) if pkg.heuristic_flags else "none",
        )
        log.debug(
            f"[{self._detector_name}/raw] prompt ({len(user)} chars, truncated={truncated}):\n{user}"
        )
        t0 = _time.monotonic()
        try:
            raw_text, in_tok, out_tok, cost = self._call_api(system, user)
            log.debug(
                f"[{self._detector_name}/raw] response "
                f"(in={in_tok} out={out_tok} cost=${cost:.6f}):\n{raw_text}"
            )
            verdict, confidence, details = self._parse_response(raw_text)
        except Exception as exc:
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

        details["model"] = self._model_name
        if truncated:
            details["truncated"] = True
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode="llm_raw",
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=cost,
            input_tokens=in_tok,
            output_tokens=out_tok,
            details=details,
        )

    def _build_file_listing_raw(self, pkg: PackageInfo) -> tuple[str, bool]:
        """Returns (listing, truncated). truncated=True when the 8000-char cap was hit."""
        parts: list[str] = []
        total = 0
        for path, content in pkg.files_raw.items():
            chunk = f"### {path} ###\n{content}\n\n"
            if total + len(chunk) > 8000:
                parts.append("[truncated]")
                return "".join(parts), True
            parts.append(chunk)
            total += len(chunk)
        return "".join(parts), False
