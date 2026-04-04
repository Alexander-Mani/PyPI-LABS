# PyPi-SCADA — Project Instructions for Claude

## LLM Routing

All LLM calls route through LiteLLM running as `proxy-runner` on `http://127.0.0.1:4000`.
The `pypi-runner` analyzer process holds no API keys. See `RISK_DIARY.md` Decision 5.

* **Model Configuration:** The pipeline dynamically loads the testing grid from `configs/models.json`, which categorizes models into `frontier`, `medium`, and `budget` tiers.
* **Execution Rule:** Default to `budget` or `medium` tiers for all development and standard execution. `frontier` models are strictly reserved for final data-gathering runs to preserve API budgets.
