"""
server.py — Credential Proxy for the PyPi-SCADA pipeline.

Holds LLM API keys in its own process environment. The analyzer sends
structured analysis requests here; this service makes the actual outbound
API calls and returns a normalised response. The analyzer process itself
never holds any API key.

Normalised response shape (all providers):
{
  "content":      [{"type": "text", "text": "..."}, ...],
  "stop_reason":  "end_turn" | "tool_use" | "stop" | null,
  "input_tokens":  <int>,
  "output_tokens": <int>
}

For tool_use responses (Anthropic agentic mode) the content list may include
tool_use blocks:
  {"type": "tool_use", "id": "...", "name": "...", "input": {...}}

Start:
    cd src/credential_proxy
    python server.py [config.yaml]
"""

import os
import sys
from pathlib import Path

import yaml
from flask import Flask, request, jsonify, abort

# ---------------------------------------------------------------------------
# Logging — shared loguru logger
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
from src.utils.logger import setup_logger, get_logger  # noqa: E402

# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------

def _load_config(path: str = "config.yaml") -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------------------------------------------------------------------------
# Provider normalisers
# ---------------------------------------------------------------------------

def _call_anthropic(payload: dict) -> dict:
    """Forward to Anthropic Messages API and return normalised response."""
    import anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        abort(503, description="ANTHROPIC_API_KEY not configured in proxy environment")

    client = anthropic.Anthropic(api_key=api_key)

    kwargs: dict = {
        "model":       payload["model"],
        "max_tokens":  int(payload.get("max_tokens", 512)),
        "temperature": float(payload.get("temperature", 0.0)),
        "system":      payload.get("system", ""),
        "messages":    payload["messages"],
    }
    if payload.get("tools"):
        kwargs["tools"] = payload["tools"]

    resp = client.messages.create(**kwargs)

    content = [b.model_dump() for b in resp.content]
    return {
        "content":       content,
        "stop_reason":   resp.stop_reason,
        "input_tokens":  resp.usage.input_tokens,
        "output_tokens": resp.usage.output_tokens,
    }


def _call_openai(payload: dict) -> dict:
    """Forward to OpenAI Chat Completions API and return normalised response."""
    try:
        import openai
    except ImportError:
        abort(503, description="openai package not installed in proxy environment")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        abort(503, description="OPENAI_API_KEY not configured in proxy environment")

    client = openai.OpenAI(api_key=api_key)

    # Convert Anthropic-style messages to OpenAI format if needed.
    # Caller is expected to send OpenAI-format messages for OpenAI requests.
    messages = payload["messages"]

    # Prepend system message if provided separately (Anthropic-style split).
    system = payload.get("system", "")
    if system:
        messages = [{"role": "system", "content": system}] + list(messages)

    resp = client.chat.completions.create(
        model=payload["model"],
        temperature=float(payload.get("temperature", 0.0)),
        messages=messages,
    )

    text = resp.choices[0].message.content or ""
    tokens_in  = resp.usage.prompt_tokens if resp.usage else 0
    tokens_out = resp.usage.completion_tokens if resp.usage else 0

    return {
        "content":       [{"type": "text", "text": text}],
        "stop_reason":   resp.choices[0].finish_reason,
        "input_tokens":  tokens_in,
        "output_tokens": tokens_out,
    }


def _call_gemini(payload: dict) -> dict:
    """Forward to Google Generative AI and return normalised response."""
    try:
        import google.generativeai as genai
    except ImportError:
        abort(503, description="google-generativeai package not installed in proxy environment")

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        abort(503, description="GEMINI_API_KEY not configured in proxy environment")

    genai.configure(api_key=api_key)

    system = payload.get("system", "")
    # Gemini takes the user content as a single string from the last user message.
    messages = payload.get("messages", [])
    user_text = ""
    for msg in reversed(messages):
        if msg.get("role") == "user":
            content = msg.get("content", "")
            user_text = content if isinstance(content, str) else str(content)
            break

    model = genai.GenerativeModel(payload["model"], system_instruction=system or None)
    resp = model.generate_content(user_text)

    text = resp.text or ""
    tokens = getattr(getattr(resp, "usage_metadata", None), "total_token_count", 0)

    return {
        "content":       [{"type": "text", "text": text}],
        "stop_reason":   "end_turn",
        "input_tokens":  tokens,
        "output_tokens": 0,   # Gemini API doesn't split in/out in all SDK versions
    }


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

_DISPATCHERS = {
    "anthropic": _call_anthropic,
    "openai":    _call_openai,
    "gemini":    _call_gemini,
}


def create_app(cfg: dict) -> Flask:
    app = Flask(__name__)
    allowed = set(cfg.get("allowed_providers", list(_DISPATCHERS)))
    max_bytes = int(cfg.get("max_payload_bytes", 65536))
    log = get_logger()

    @app.route("/health", methods=["GET"])
    def health():
        return jsonify({"status": "ok"})

    @app.route("/proxy/analyze", methods=["POST"])
    def proxy_analyze():
        # Payload size guard — prevent use as large-content relay.
        content_length = request.content_length or 0
        if content_length > max_bytes:
            log.warning(f"Payload too large: {content_length} bytes (limit {max_bytes})")
            abort(413, description=f"Payload exceeds {max_bytes} byte limit")

        payload = request.get_json(force=True, silent=True)
        if not payload:
            abort(400, description="Request body must be JSON")

        provider = payload.get("provider", "")
        if provider not in allowed:
            log.warning(f"Rejected request for disallowed provider: {provider!r}")
            abort(400, description=f"Provider not allowed: {provider!r}")

        if "model" not in payload or "messages" not in payload:
            abort(400, description="Request must include 'model' and 'messages'")

        log.info(f"Proxying: provider={provider} model={payload['model']} "
                 f"messages={len(payload['messages'])}")

        try:
            result = _DISPATCHERS[provider](payload)
        except Exception as exc:
            log.error(f"Proxy error for {provider}: {exc}")
            abort(502, description=f"Upstream API error: {exc}")

        log.info(f"Completed: in={result['input_tokens']} out={result['output_tokens']} "
                 f"stop={result['stop_reason']}")
        return jsonify(result)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"
    cfg = _load_config(config_path)

    log_cfg = {"logging": cfg["logging"]}
    log_cfg["logging"]["file"] = str(
        Path(config_path).parent / cfg["logging"]["file"]
    )
    setup_logger(log_cfg)
    log = get_logger()

    srv = cfg["server"]
    log.info(f"Starting Credential Proxy on {srv['host']}:{srv['port']}")
    log.info(f"Allowed providers: {cfg.get('allowed_providers')}")

    app = create_app(cfg)
    app.run(host=srv["host"], port=int(srv["port"]), debug=srv.get("debug", False))


if __name__ == "__main__":
    main()
