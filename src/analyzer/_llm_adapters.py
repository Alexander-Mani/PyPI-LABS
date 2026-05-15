"""Single-shot LLM detector adapters.

This module holds the hybrid and raw LLM adapters that used to live in
``adapters.py``. The public import path remains ``adapters.LLMAdapter`` and
``adapters.LLMRawAdapter`` through the compatibility facade.
"""

from __future__ import annotations

from pathlib import Path
import time as _time

import yaml as _yaml

try:  # Package import path, used by scripts importing src.analyzer.adapters.
    from .adapters import (
        _GENERIC_EMPTY_PROTOCOL_RETRY_DELAY_SECONDS,
        _TRANSIENT_EMPTY_PROTOCOL_CATEGORIES,
        DetectorAdapter,
        EvalDetectionResult,
        ProxyCallResult,
        _context,
        _emit_protocol_error,
        _exception_details,
        _is_protocol_failure,
        _parse_json_verdict_response,
        _protocol_details_from_response,
        log,
    )
    from .entry_extractor import PackageInfo
except ImportError:  # Top-level import path, used by tests and evaluate.py.
    from adapters import (
        _GENERIC_EMPTY_PROTOCOL_RETRY_DELAY_SECONDS,
        _TRANSIENT_EMPTY_PROTOCOL_CATEGORIES,
        DetectorAdapter,
        EvalDetectionResult,
        ProxyCallResult,
        _context,
        _emit_protocol_error,
        _exception_details,
        _is_protocol_failure,
        _parse_json_verdict_response,
        _protocol_details_from_response,
        log,
    )
    from entry_extractor import PackageInfo

# ---------------------------------------------------------------------------
# LLMAdapter - single-shot LLM call (YAML-configured model)
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
        self._max_tokens: int = int(cfg.get("max_tokens", 512))
        self._response_format = cfg.get("response_format")
        self._extra_body = cfg.get("extra_body")
        self._reasoning_effort = cfg.get("reasoning_effort")
        legacy_request_params = dict(cfg.get("request_params") or {})
        if legacy_request_params:
            if self._response_format is None and "response_format" in legacy_request_params:
                self._response_format = legacy_request_params.pop("response_format")
            if self._extra_body is None and "extra_body" in legacy_request_params:
                self._extra_body = legacy_request_params.pop("extra_body")
            if self._reasoning_effort is None and "reasoning_effort" in legacy_request_params:
                self._reasoning_effort = legacy_request_params.pop("reasoning_effort")
            if legacy_request_params:
                raise ValueError(
                    f"Unsupported request_params keys in {config_path}: "
                    + ", ".join(sorted(legacy_request_params))
                )
        self._retry_attempts: int = int(cfg.get("retry_attempts", 0))
        self._retry_delay_seconds: float = float(cfg.get("retry_delay_seconds", 0.0))
        self._retry_unparseable: bool = bool(cfg.get("retry_unparseable", False))
        self._retry_transport_categories: set[str] = {
            str(item) for item in cfg.get("retry_transport_categories", [])
        }
        self._retry_protocol_errors: set[str] = {
            str(item) for item in cfg.get("retry_protocol_errors", [])
        }
        if self._retry_unparseable:
            self._retry_protocol_errors.add("unparseable_model_response")
        self._fallback_models: list[str] = [str(model) for model in cfg.get("fallback_models", [])]

    def _mode_name(self) -> str:
        return "hybrid"

    def _build_listing(self, pkg: PackageInfo) -> tuple[str, bool]:
        return self._build_file_listing(pkg)

    def _is_protocol_retryable(self, details: dict, requested_model: str) -> bool:
        if not _is_protocol_failure(details):
            return False
        error = str(details.get("error", ""))
        return error in set(getattr(self, "_retry_protocol_errors", set()) or [])

    @staticmethod
    def _is_generic_empty_retryable(details: dict) -> bool:
        return str(details.get("protocol_category") or "") in _TRANSIENT_EMPTY_PROTOCOL_CATEGORIES

    def _is_transport_retryable(self, category: str) -> bool:
        configured = set(getattr(self, "_retry_transport_categories", set()) or [])
        if configured:
            return category in configured
        return category in {
            "rate_limit",
            "provider_overload",
            "provider_or_proxy_transient",
            "client_timeout",
        }

    def _retry_sleep(self) -> None:
        delay = float(getattr(self, "_retry_delay_seconds", 0.0) or 0.0)
        if delay > 0:
            _time.sleep(delay)

    @staticmethod
    def _generic_protocol_retry_sleep() -> None:
        _time.sleep(_GENERIC_EMPTY_PROTOCOL_RETRY_DELAY_SECONDS)

    def _attempt_models(self) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for model in [self._model_name, *getattr(self, "_fallback_models", [])]:
            if model not in seen:
                ordered.append(model)
                seen.add(model)
        return ordered

    def _error_result(
        self,
        *,
        pkg: PackageInfo,
        mode: str,
        t0: float,
        details: dict,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
    ) -> EvalDetectionResult:
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode="error",
            verdict=False,
            confidence=None,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=cost_usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            details=details,
        )

    def _success_result(
        self,
        *,
        pkg: PackageInfo,
        mode: str,
        t0: float,
        verdict: bool,
        confidence: float | None,
        details: dict,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
    ) -> EvalDetectionResult:
        return EvalDetectionResult(
            detector=self._detector_name,
            experiment_mode=mode,
            verdict=verdict,
            confidence=confidence,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=int((_time.monotonic() - t0) * 1000),
            api_cost_usd=cost_usd,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            details=details,
        )

    def _run_mode(
        self,
        pkg: PackageInfo,
        *,
        mode: str,
        prompt_strategy: str,
        system: str,
        user: str,
        truncated: bool,
        raw_log=None,
        trace_context: dict | None = None,
    ) -> EvalDetectionResult:
        ctx = _context(trace_context, pkg)
        ctx.update({"detector": self._detector_name, "mode": mode, "strategy": prompt_strategy})
        t0 = _time.monotonic()
        total_in = 0
        total_out = 0
        total_cost = 0.0
        attempts_summary: list[dict] = []
        pricing_breakdown: list[dict] = []
        last_protocol_details: dict | None = None
        last_exception: str | None = None
        last_requested_model = self._model_name
        last_actual_model = self._model_name
        last_selected_model = self._model_name
        attempt_models = self._attempt_models()

        for model_index, active_model in enumerate(attempt_models):
            transport_retries_used = 0
            generic_protocol_retries_used = 0
            configured_protocol_retries_used = 0
            advance_to_next_model = False
            while True:
                attempt_no = len(attempts_summary) + 1
                try:
                    call = self._call_api(
                        system,
                        user,
                        raw_log=raw_log,
                        trace_context=ctx,
                        model_name=active_model,
                        requested_model=self._model_name,
                        attempt=attempt_no,
                        mode=mode,
                    )
                    if not isinstance(call, ProxyCallResult):
                        raw_text, in_tok, out_tok, cost = call
                        call = ProxyCallResult(
                            text=raw_text,
                            input_tokens=in_tok,
                            output_tokens=out_tok,
                            cost_usd=cost,
                            requested_model=self._model_name,
                            actual_model=active_model,
                            selected_model=active_model,
                            pricing_model=active_model,
                        )
                except Exception as exc:
                    error_text, error_category = _exception_details(exc)
                    retryable = self._is_transport_retryable(error_category)
                    last_exception = error_text
                    attempts_summary.append({
                        "attempt": attempt_no,
                        "requested_model": self._model_name,
                        "selected_model": active_model,
                        "actual_model": active_model,
                        "error": error_text,
                        "error_category": error_category,
                        "retryable": retryable,
                        "phase": "transport",
                    })
                    if raw_log is not None:
                        raw_log.emit(
                            "llm.retry" if retryable else "llm.error",
                            **ctx,
                            payload={
                                "attempt": attempt_no,
                                "requested_model": self._model_name,
                                "selected_model": active_model,
                                "actual_model": active_model,
                                "error": error_text,
                                "error_category": error_category,
                                "retryable": retryable,
                                "phase": "transport",
                            },
                        )
                    has_same_model_retry = retryable and transport_retries_used < int(getattr(self, "_retry_attempts", 0))
                    has_fallback = retryable and model_index + 1 < len(attempt_models)
                    if has_same_model_retry:
                        transport_retries_used += 1
                        self._retry_sleep()
                        continue
                    if has_fallback:
                        self._retry_sleep()
                        advance_to_next_model = True
                        break
                    details = {
                        "error": error_text,
                        "error_category": error_category,
                        "model": active_model,
                        "requested_model": self._model_name,
                        "selected_model": active_model,
                        "actual_model": active_model,
                        "fallback_used": active_model != self._model_name,
                        "fallback_chain": attempt_models,
                        "attempt_count": attempt_no,
                        "attempts": attempts_summary,
                        "pricing_breakdown": pricing_breakdown,
                    }
                    return self._error_result(
                        pkg=pkg,
                        mode=mode,
                        t0=t0,
                        details=details,
                        input_tokens=total_in,
                        output_tokens=total_out,
                        cost_usd=total_cost,
                    )
                if advance_to_next_model:
                    break

                total_in += call.input_tokens
                total_out += call.output_tokens
                total_cost += call.cost_usd
                pricing_breakdown.append({
                    "model": call.pricing_model or call.actual_model or active_model,
                    "input_tokens": call.input_tokens,
                    "output_tokens": call.output_tokens,
                })
                last_requested_model = call.requested_model
                last_actual_model = call.actual_model
                last_selected_model = call.selected_model or active_model

                if call.protocol_details is not None:
                    verdict, confidence, details = False, None, dict(call.protocol_details)
                else:
                    verdict, confidence, details = self._parse_response(call.text)
                details["model"] = call.pricing_model or call.actual_model or active_model
                details["requested_model"] = self._model_name
                details["selected_model"] = call.selected_model or active_model
                details["actual_model"] = call.actual_model
                if call.response_model:
                    details["response_model"] = call.response_model
                if call.litellm_model_group:
                    details["litellm_model_group"] = call.litellm_model_group
                if call.litellm_model_id:
                    details["litellm_model_id"] = call.litellm_model_id
                if call.finish_reason is not None and "finish_reason" not in details:
                    details["finish_reason"] = call.finish_reason
                if call.content_shape is not None and "content_shape" not in details:
                    details["content_shape"] = call.content_shape
                details["has_tool_calls"] = bool(
                    details.get("has_tool_calls", False) or call.has_tool_calls
                )
                if truncated:
                    details["truncated"] = True
                details["fallback_used"] = (call.selected_model or active_model) != self._model_name
                details["fallback_chain"] = attempt_models
                details["attempt_count"] = attempt_no
                details["attempts"] = attempts_summary + [{
                    "attempt": attempt_no,
                    "requested_model": self._model_name,
                    "selected_model": call.selected_model or active_model,
                    "actual_model": call.actual_model,
                    "response_model": call.response_model,
                    "litellm_model_group": call.litellm_model_group,
                    "litellm_model_id": call.litellm_model_id,
                    "finish_reason": call.finish_reason,
                    "content_shape": call.content_shape,
                    "has_tool_calls": call.has_tool_calls,
                    "phase": "response",
                    "result": details.get("error", "ok"),
                    "retryable": details.get("retryable", False),
                }]
                details["pricing_breakdown"] = pricing_breakdown

                if not _is_protocol_failure(details):
                    return self._success_result(
                        pkg=pkg,
                        mode=mode,
                        t0=t0,
                        verdict=verdict,
                        confidence=confidence,
                        details=details,
                        input_tokens=total_in,
                        output_tokens=total_out,
                        cost_usd=total_cost,
                    )

                last_protocol_details = dict(details)
                details["error_category"] = "protocol_failure"
                generic_retryable = (
                    self._is_generic_empty_retryable(details)
                    and generic_protocol_retries_used < 1
                )
                configured_retryable = self._is_protocol_retryable(details, self._model_name)
                retryable = generic_retryable or configured_retryable
                details["retryable"] = retryable
                attempts_summary.append({
                    "attempt": attempt_no,
                    "requested_model": self._model_name,
                    "selected_model": call.selected_model or active_model,
                    "actual_model": call.actual_model,
                    "response_model": call.response_model,
                    "litellm_model_group": call.litellm_model_group,
                    "litellm_model_id": call.litellm_model_id,
                    "finish_reason": details.get("finish_reason"),
                    "content_shape": details.get("content_shape"),
                    "has_tool_calls": details.get("has_tool_calls", False),
                    "phase": "protocol",
                    "error": details.get("error"),
                    "error_category": "protocol_failure",
                    "protocol_category": details.get("protocol_category"),
                    "retryable": retryable,
                })
                if raw_log is not None:
                    raw_log.emit(
                        "llm.retry" if retryable else "llm.protocol_error",
                        **ctx,
                            payload={
                                "attempt": attempt_no,
                                "requested_model": self._model_name,
                                "selected_model": call.selected_model or active_model,
                                "actual_model": call.actual_model,
                                "error": details.get("error"),
                                "error_category": "protocol_failure",
                                "protocol_category": details.get("protocol_category"),
                                "retryable": retryable,
                                "phase": "protocol",
                                "finish_reason": details.get("finish_reason"),
                                "content_shape": details.get("content_shape"),
                                "has_tool_calls": details.get("has_tool_calls", False),
                                "litellm_model_group": call.litellm_model_group,
                                "litellm_model_id": call.litellm_model_id,
                            },
                        )
                configured_same_model_retry = (
                    configured_retryable
                    and configured_protocol_retries_used < int(getattr(self, "_retry_attempts", 0))
                )
                has_same_model_retry = generic_retryable or configured_same_model_retry
                has_fallback = retryable and model_index + 1 < len(attempt_models)
                if has_same_model_retry:
                    if generic_retryable:
                        generic_protocol_retries_used += 1
                        self._generic_protocol_retry_sleep()
                    else:
                        configured_protocol_retries_used += 1
                        self._retry_sleep()
                    continue
                if has_fallback:
                    self._retry_sleep()
                    advance_to_next_model = True
                    break

                details["intended_mode"] = mode
                _emit_protocol_error(
                    raw_log,
                    "llm.protocol_error",
                    ctx,
                    model=active_model,
                    details=details,
                )
                return self._error_result(
                    pkg=pkg,
                    mode=mode,
                    t0=t0,
                    details=details,
                    input_tokens=total_in,
                    output_tokens=total_out,
                    cost_usd=total_cost,
                )
            if advance_to_next_model:
                continue

        fallback_details = dict(last_protocol_details or {})
        fallback_details.setdefault("error", last_exception or "exhausted_retries")
        fallback_details.setdefault(
            "error_category",
            "protocol_failure" if last_protocol_details is not None else "unknown_error",
        )
        fallback_details.setdefault("model", last_actual_model)
        fallback_details["requested_model"] = self._model_name
        fallback_details["selected_model"] = last_selected_model
        fallback_details["actual_model"] = last_actual_model
        fallback_details["fallback_used"] = last_selected_model != self._model_name
        fallback_details["fallback_chain"] = attempt_models
        fallback_details["attempt_count"] = len(attempts_summary)
        fallback_details["attempts"] = attempts_summary
        fallback_details["pricing_breakdown"] = pricing_breakdown
        fallback_details["intended_mode"] = mode
        return self._error_result(
            pkg=pkg,
            mode=mode,
            t0=t0,
            details=fallback_details,
            input_tokens=total_in,
            output_tokens=total_out,
            cost_usd=total_cost,
        )

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
        system = system_prompt    if system_prompt    is not None else self._system_prompt
        tmpl   = template_override if template_override is not None else self._user_template
        listing, truncated = self._build_listing(pkg)
        user   = tmpl.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=listing,
            heuristic_flags=", ".join(pkg.heuristic_flags) if pkg.heuristic_flags else "none",
        )
        log.debug(
            f"[{self._detector_name}] prompt ({len(user)} chars, truncated={truncated}):\n{user}"
        )
        return self._run_mode(
            pkg,
            mode=self._mode_name(),
            prompt_strategy=prompt_strategy,
            system=system,
            user=user,
            truncated=truncated,
            raw_log=raw_log,
            trace_context=trace_context,
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

    def _call_api(
        self,
        system: str,
        user: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        model_name: str | None = None,
        requested_model: str | None = None,
        attempt: int | None = None,
        mode: str | None = None,
    ) -> ProxyCallResult:
        m = model_name or self._model_name
        if m.startswith("claude-"):
            return self._call_anthropic(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=m,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        if m.startswith(("gpt-", "o1-", "o3-", "together_ai/")):
            return self._call_openai(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=m,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        if m.startswith(("gemini-", "gemini/")):
            return self._call_gemini(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=m,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise ValueError(f"Unknown model prefix for: {m}")

    def _call_via_proxy(
        self,
        system: str,
        user: str,
        *,
        raw_log=None,
        trace_context: dict | None = None,
        model_name: str | None = None,
        requested_model: str | None = None,
        attempt: int | None = None,
        mode: str | None = None,
    ) -> ProxyCallResult:
        """Route through LiteLLM."""
        import openai as _openai
        active_model = model_name or self._model_name
        requested = requested_model or self._model_name
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]
        request_payload = {
            "model": active_model,
            "temperature": self._temperature,
            "max_tokens": int(getattr(self, "_max_tokens", 512) or 512),
            "messages": messages,
        }
        if getattr(self, "_response_format", None) is not None:
            request_payload["response_format"] = self._response_format
        if getattr(self, "_extra_body", None) is not None:
            request_payload["extra_body"] = self._extra_body
        if getattr(self, "_reasoning_effort", None) is not None:
            request_payload["reasoning_effort"] = self._reasoning_effort
        if raw_log is not None:
            raw_log.emit(
                "llm.request",
                **(trace_context or {}),
                payload={
                    "model": active_model,
                    "requested_model": requested,
                    "attempt": attempt,
                    "mode": mode,
                    "proxy_url": self._proxy_url,
                    "system_prompt_ref": raw_log.blob_text("llm_system_prompt", system, suffix=".txt"),
                    "user_prompt_ref": raw_log.blob_text("llm_user_prompt", user, suffix=".txt"),
                    "request_json_ref": raw_log.blob_json("llm_request", request_payload),
                },
            )
        client = _openai.OpenAI(
            base_url=self._proxy_url.rstrip("/") + "/v1",
            api_key="no-key-needed",
        )
        http_resp = client.with_raw_response.chat.completions.create(**request_payload)
        headers = dict(http_resp.headers)
        cost = float(headers.get("x-litellm-response-cost") or 0.0)
        resp = http_resp.parse()
        text, protocol_details, response_meta = _protocol_details_from_response(resp)
        in_tok  = resp.usage.prompt_tokens     if resp.usage else 0
        out_tok = resp.usage.completion_tokens if resp.usage else 0
        response_model = getattr(resp, "model", None)
        litellm_model_group = str(
            headers.get("x-litellm-model-group")
            or headers.get("x-litellm-model")
            or ""
        ).strip() or None
        litellm_model_id = str(headers.get("x-litellm-model-id") or "").strip() or None
        public_model = str(litellm_model_group or active_model)
        if raw_log is not None:
            if hasattr(resp, "model_dump"):
                response_payload = resp.model_dump(mode="json")
            else:  # pragma: no cover - SDK compatibility fallback
                response_payload = repr(resp)
            raw_log.emit(
                "llm.response",
                **(trace_context or {}),
                payload={
                    "model": active_model,
                    "requested_model": requested,
                    "selected_model": active_model,
                    "actual_model": public_model,
                    "litellm_model_group": litellm_model_group,
                    "litellm_model_id": litellm_model_id,
                    "response_model": response_model,
                    "attempt": attempt,
                    "mode": mode,
                    "headers": headers,
                    "finish_reason": response_meta.get("finish_reason"),
                    "content_shape": response_meta.get("content_shape"),
                    "has_tool_calls": response_meta.get("has_tool_calls", False),
                    "assistant_text_ref": raw_log.blob_text("llm_assistant_text", text, suffix=".txt"),
                    "response_json_ref": raw_log.blob_json("llm_response", response_payload),
                    "input_tokens": in_tok,
                    "output_tokens": out_tok,
                    "cost_usd": cost,
                },
            )
        return ProxyCallResult(
            text=text,
            input_tokens=in_tok,
            output_tokens=out_tok,
            cost_usd=cost,
            requested_model=requested,
            actual_model=public_model,
            selected_model=active_model,
            litellm_model_group=litellm_model_group,
            litellm_model_id=litellm_model_id,
            response_model=str(response_model) if response_model is not None else None,
            pricing_model=public_model,
            finish_reason=str(response_meta.get("finish_reason")) if response_meta.get("finish_reason") is not None else None,
            content_shape=str(response_meta.get("content_shape")) if response_meta.get("content_shape") is not None else None,
            has_tool_calls=bool(response_meta.get("has_tool_calls", False)),
            protocol_details=protocol_details,
            headers=headers,
        )

    def _call_anthropic(
        self, system: str, user: str, *, raw_log=None, trace_context: dict | None = None, model_name: str | None = None, requested_model: str | None = None, attempt: int | None = None, mode: str | None = None
    ) -> ProxyCallResult:
        if self._proxy_url:
            return self._call_via_proxy(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=model_name,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config - direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _call_openai(
        self, system: str, user: str, *, raw_log=None, trace_context: dict | None = None, model_name: str | None = None, requested_model: str | None = None, attempt: int | None = None, mode: str | None = None
    ) -> ProxyCallResult:
        if self._proxy_url:
            return self._call_via_proxy(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=model_name,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config - direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _call_gemini(
        self, system: str, user: str, *, raw_log=None, trace_context: dict | None = None, model_name: str | None = None, requested_model: str | None = None, attempt: int | None = None, mode: str | None = None
    ) -> ProxyCallResult:
        if self._proxy_url:
            return self._call_via_proxy(
                system,
                user,
                raw_log=raw_log,
                trace_context=trace_context,
                model_name=model_name,
                requested_model=requested_model,
                attempt=attempt,
                mode=mode,
            )
        raise RuntimeError(
            f"proxy_url not set in '{self._detector_name}' config - direct API calls "
            "bypass key isolation (RISK_DIARY.md Decision 5). Add proxy_url to the "
            "model YAML."
        )

    def _parse_response(self, raw: str) -> tuple[bool, float | None, dict]:
        return _parse_json_verdict_response(raw)

# ---------------------------------------------------------------------------
# LLMRawAdapter — LLM adapter using raw (unfiltered) entry-point source
# ---------------------------------------------------------------------------

class LLMRawAdapter(LLMAdapter):
    """
    Identical to LLMAdapter except it reads from pkg.files_raw (entry-point
    files only, no AST-resolved imports) instead of pkg.files.
    Produces experiment_mode="llm_raw" rows in the DB.
    """

    def _mode_name(self) -> str:
        return "llm_raw"

    def _build_listing(self, pkg: PackageInfo) -> tuple[str, bool]:
        return self._build_file_listing_raw(pkg)

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
        system = system_prompt     if system_prompt     is not None else self._system_prompt
        tmpl   = template_override if template_override is not None else self._user_template
        listing, truncated = self._build_listing(pkg)
        user   = tmpl.format(
            package_name=pkg.name,
            version=pkg.version,
            file_listing=listing,
            heuristic_flags=", ".join(pkg.heuristic_flags) if pkg.heuristic_flags else "none",
        )
        log.debug(
            f"[{self._detector_name}/raw] prompt ({len(user)} chars, truncated={truncated}):\n{user}"
        )
        return self._run_mode(
            pkg,
            mode=self._mode_name(),
            prompt_strategy=prompt_strategy,
            system=system,
            user=user,
            truncated=truncated,
            raw_log=raw_log,
            trace_context=trace_context,
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
