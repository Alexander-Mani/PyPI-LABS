# PyPi-SCADA — Course Correction Checklist

Architecture pivot: single-pipeline → multi-modal scientific benchmark.
Each phase must be approved before execution. Check off when complete.

---

- [x] **Phase 1: SQLite Schema Migration**
  Migrate `eval_results.db` to support the 4-mode experiment matrix.
  New columns: `experiment_mode`, `prompt_strategy`, `input_tokens`,
  `output_tokens`, `ground_truth`. New unique constraint and index.

- [x] **Phase 2: Prompt Configuration (`configs/prompts.yaml`)**
  YAML-based prompt template registry. `PromptManager` singleton for
  Zero-shot, Few-shot, and Role-based strategies.

- [x] **Phase 3: Adapter Pattern (`src/analyzer/adapters.py`)**
  Decouple `DetectionController`. Base class + Static, LLM, Agentic
  subclasses. Main loop sequences all active adapters per sample.

- [x] **Phase 4: Extraction Bypass (Mode B — LLM Raw)**
  Add bypass in `entry_extractor.py` that returns raw unparsed source
  strings for `setup.py`, `__init__.py` without AST filtering.

- [x] **Phase 5: Financial Air-Gap Validation**
  Enforce `--tier` argument. Startup validation: one benign package across
  all modes on budget tier. HALT if actual LiteLLM cost ≠ expected token math.
