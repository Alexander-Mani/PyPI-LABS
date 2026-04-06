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
# ===========================================================================

import os as _os
from concurrent.futures import ThreadPoolExecutor, as_completed

from entry_extractor import PackageInfo
from adapters import (
    EvalDetectionResult,
    DetectorAdapter,
    StaticAdapter,
    LLMAdapter,
    LLMRawAdapter,
    AgenticAdapter,
)

# Backward-compat aliases for any code that still references the old names.
EntryPointStaticAdapter = StaticAdapter
EntryPointLLMAdapter    = LLMAdapter



# ---------------------------------------------------------------------------
# EvalController — orchestrates all adapter tracks in parallel
# ---------------------------------------------------------------------------

class EvalController:

    def __init__(self, configs_dir: str | Path, db, tier: str = "budget"):
        # Lazy import to avoid cross-package issues at module load time.
        from src.data.db_manager import DBManager  # noqa: F401 (type reference)
        import yaml as _yaml
        self._db = db
        configs_dir = Path(configs_dir)

        self._static: list[StaticAdapter] = [
            StaticAdapter("bandit"),
            StaticAdapter("semgrep"),
        ]

        self._llm: list[LLMAdapter] = []
        self._llm_raw: list[LLMRawAdapter] = []
        self._agentic: list[AgenticAdapter] = []

        for yaml_path in sorted(configs_dir.glob("*.yaml")):
            if yaml_path.stem == "prompts":
                continue  # strategy registry, not a model config
            with open(yaml_path, encoding="utf-8") as f:
                cfg = _yaml.safe_load(f)
            cfg_tier = cfg.get("tier", "frontier")
            if cfg_tier != tier:
                continue
            if "agentic" in yaml_path.stem:
                self._agentic.append(AgenticAdapter(yaml_path))
            else:
                self._llm.append(LLMAdapter(yaml_path))
                self._llm_raw.append(LLMRawAdapter(yaml_path))

    def run(
        self,
        run_id: str,
        pkg: PackageInfo,
        ground_truth: dict[str, bool] | None = None,
    ) -> list[EvalDetectionResult]:
        from prompt_manager import PromptManager
        pm = PromptManager.instance()

        # Build a uniform task list: (adapter, strategy, sys_override, tpl_override).
        # All adapters share the DetectorAdapter.run() signature so they can be
        # dispatched identically. Static adapters ignore the prompt params.
        tasks: list[tuple] = []
        for a in self._static:
            tasks.append((a, "zero_shot", None, None))
        for a in self._llm:
            for s in pm.llm_strategy_names():
                sp, ut = pm.get_llm_strategy(s)
                tasks.append((a, s, sp, ut))
        for a in self._llm_raw:
            for s in pm.llm_strategy_names():
                sp, ut = pm.get_llm_strategy(s)
                tasks.append((a, s, sp, ut))
        for a in self._agentic:
            for s in pm.agentic_strategy_names():
                sp, im = pm.get_agentic_strategy(s)
                tasks.append((a, s, sp, im))

        results: list[EvalDetectionResult] = []
        gt_label = ground_truth.get(pkg.name) if ground_truth else None

        with ThreadPoolExecutor(max_workers=4) as pool:
            futures: dict = {
                pool.submit(a.run, pkg, strategy, sys_p, tpl): (a, strategy)
                for a, strategy, sys_p, tpl in tasks
            }

            for future in as_completed(futures):
                adapter, strategy = futures[future]
                try:
                    res = future.result()
                except Exception as exc:
                    name = getattr(adapter, "_tool", None) or getattr(adapter, "_detector_name", None) or "unknown"
                    res = EvalDetectionResult(
                        detector=name, experiment_mode="error",
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
                    experiment_mode=res.experiment_mode,
                    prompt_strategy=strategy,
                    detector=res.detector,
                    verdict=res.verdict,
                    ground_truth=gt_label,
                    heuristic_flags=res.heuristic_flags,
                    input_tokens=res.input_tokens,
                    output_tokens=res.output_tokens,
                    exec_time_ms=res.exec_time_ms,
                    api_cost_usd=res.api_cost_usd,
                    details=res.details,
                )

        return results
