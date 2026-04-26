# CODEX.md

Project-local notes for future Codex work in this repository.

## What This Repo Is

PyPi-SCADA is a Spring 2026 BSc thesis project for studying PyPI supply-chain attacks in an isolated lab.

Main subsystems:
- `src/simulator/`: local PEP 503-compatible package index
- `src/injector/`: uploads benign, control, and malicious samples into the simulator
- `src/analyzer/`: static + LLM detection pipeline over simulator-resolved artifacts
- `samples/`: curated benign and malicious package corpus
- `overleaf_thesis/`: separate git repo for the report; do not mix its commits with the main repo

## Current Experiment Shape

Canonical profiles live in `configs/evaluation_profiles.yaml`.

Important profiles:
- `budget`
- `medium`
- `frontier`
- `all_models`
- `test`
- `gemini_only`
- `frontier_together_bakeoff`

Canonical frontier Together is currently split into:
- `together_frontier`: required Kimi detector
- `together_frontier_qwen`: shadow Qwen detector

Gemini hardening now exists in canonical mixed-provider configs:
- `src/analyzer/configs/gemini_flash.yaml`
- `src/analyzer/configs/gemini.yaml`

That means:
- explicit `response_format` JSON schema
- explicit `max_tokens`
- explicit `reasoning_effort` where supported

Canonical experiment sample-set behavior:
- default is `--sample-set dataset`
- `--sample-set controls` is the controls-only false-positive lane
- `--sample-set both` adds controls to the canonical dataset
- legacy `--include-controls` now means `--sample-set both`
- the experiment TUI carries this through a `Sample Set` toggle for canonical runs, static, alias probe, and production memory probe

## Memory Probe

The source-free package-recognition probe is:
- `scripts/model_memory_probe.py`

It now has two scopes:
- `--scope curated`: small known-incident / control / decoy set from `configs/model_memory_probe_cases.json`
- `--scope production`: full production package/version set resolved from the evaluator’s simulator logic

Key behavior:
- uses canonical non-agentic model configs, not raw model-name-only routing
- defaults to `--max-tokens 4096` for curated runs and `8192` for production runs
- treats exact-version recognition as the primary metric and package-only association as a secondary signal
- treats schema-invalid outputs as failures, not negatives
- writes JSONL plus `.summary.json` and `.summary.md`
- does **not** write `eval_results.db` rows

Related validity probe:
- `src/analyzer/evaluate.py --identity-alias-probe`

## Operational Gotchas

- Many experiment actions assume a clean `src/data/eval_results.db`. Check the TUI warning before expensive runs.
- Thesis analysis and production repair use the repo-root `./eval_results.db`, not `src/data/eval_results.db`.
- Production package resolution depends on the local simulator being available at the configured base URL.
- LiteLLM/provider behavior is often the real failure mode. Prefer explicit telemetry over guessing from final verdicts.
- The production memory probe is intentionally expensive: `8192` output tokens, `120s` timeout, `2` retries, `20s` retry delay.
- The analyzer’s live progress UI and cost bucketing are already good sources of implementation patterns for new tooling.
- `overleaf_thesis/` is intentionally separate work. Do not stage it into main-repo commits unless the user explicitly wants the gitlink updated.
- Untracked JSONL logs from probes or experiments should usually stay out of commits.

## Production Eval DB Tooling

The production-study DB helpers are:
- `scripts/error_correct_production_data.py`
- `scripts/summarize_thesis_eval_db.py`
- `scripts/production_eval_db_common.py`

Selection policy:
- latest complete run per canonical family by package/version coverage, then recency
- default DB-analysis sample set is `dataset`; controls/both runs must be selected explicitly
- primary families:
  - `sast-only`
  - `profile:budget:llm-no-agentic`
  - `profile:medium:llm-no-agentic`
  - `profile:frontier:llm-no-agentic`
  - `profile:frontier:agentic-only`
  - `profile:all_models:identity-alias-probe`

Repair behavior:
- only targets `experiment_mode="error"` rows in the selected runs
- re-downloads only the affected artifact, not the full simulator sample set
- reuses stored alias names for alias-probe rows
- creates a new `:repair` run per selected source run
- keeps the original source rows untouched and links correction rows back with `repair_source_row_id`

Summarizer behavior:
- primary detector metrics exclude error-only package/version units from TP/TN/FP/FN
- alias probe is reported as a validity sidecar, not folded into primary detector scoring
- emits both raw and cleaned overlays; cleaned views only replace source error rows when a correction row exists

## Useful Commands

Common test targets:
```bash
./.venv/bin/pytest tests/test_model_memory_probe.py tests/test_review_tui.py -q
./.venv/bin/pytest tests/test_litellm_config.py -q
```

Curated memory probe dry-run:
```bash
./.venv/bin/python scripts/model_memory_probe.py --scope curated --profile all_models --dry-run
```

Production memory probe:
```bash
./.venv/bin/python scripts/model_memory_probe.py --scope production --profile all_models --resolver-profile all_models --max-tokens 8192 --timeout 120 --retries 2 --retry-delay 20 --progress always
```

Recompute a probe summary from JSONL:
```bash
./.venv/bin/python scripts/summarize_model_memory_probe.py logs/model_memory_probe/<file>.jsonl
```

Canonical non-agentic evaluation:
```bash
./.venv/bin/python src/analyzer/evaluate.py --profile medium --skip-static --skip-agentic --progress always
```

Production eval DB repair preview:
```bash
./.venv/bin/python scripts/error_correct_production_data.py --db ./eval_results.db --dry-run
```

Production eval DB repair apply:
```bash
./.venv/bin/python scripts/error_correct_production_data.py --db ./eval_results.db --apply
```

Thesis summary from production DB:
```bash
./.venv/bin/python scripts/summarize_thesis_eval_db.py --db ./eval_results.db --out-dir analysis/eval_db/latest
```

## Editing Guidance

- Prefer config-driven changes over hidden defaults.
- When fixing protocol instability, preserve the exact failure evidence:
  - `finish_reason`
  - raw preview
  - parse-status / protocol category
  - token usage
  - cost
- If the user asks for a commit script, write `commits.sh` in the repo root and omit unrelated dirty state.
- If you touch TUI actions, update `tests/test_review_tui.py`.
- If you touch probe behavior, update `tests/test_model_memory_probe.py`.
