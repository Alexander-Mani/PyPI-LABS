# Analyzer Evaluation — Task Breakdown

Update status markers as work completes: [ ] not started · [~] in progress · [x] done

## A — entry_extractor.py
- [x] A-1  PackageInfo dataclass (name, version, files, heuristic_flags)
- [x] A-2  EntryPointExtractor.extract() dispatch (.tar.gz / .whl / .zip)
- [x] A-3  _extract_tar: .py files + pyproject.toml, strip top-level prefix, errors="replace"
- [x] A-4  _extract_wheel: .py files + pyproject.toml, skip .dist-info
- [x] A-5  _extract_zip: setpassword(b"infected"), per-file RuntimeError guard
- [x] A-6  _resolve_imports: ast.parse, 3-level BFS within-package import resolution
- [x] A-7  Total-failure guard: return empty PackageInfo, log, never raise

## B — heuristic_filter.py
- [x] B-1  HeuristicFilter.scan() framework (4 try/except checks, no duplicates)
- [x] B-2  Check: base64_or_hex (string patterns + regex)
- [x] B-3  Check: network_in_install_hook (setup.py + pyproject.toml only)
- [x] B-4  Check: shell_execution (all files)
- [x] B-5  Check: bundled_binary (\x00 in decoded string)

## C — detection_controller.py (append only)
- [x] C-1  EvalDetectionResult dataclass
- [x] C-2  EntryPointStaticAdapter — REMOVED in Phase 3 cleanup (was legacy diff pipeline)
- [x] C-3  EntryPointLLMAdapter — REMOVED in Phase 3 cleanup (was legacy diff pipeline)
- [x] C-4  AgenticAdapter (tool_use loop, max_turns, token accumulation)
- [x] C-5  EvalController (ThreadPoolExecutor, per-future error catch, DB write)

**Phase 3 note:** The legacy diff pipeline section (~300 lines) was deleted from
detection_controller.py in Phase 3. StaticDetectorAdapter, LLMDetectorAdapter,
DetectionController, and the EntryPointStaticAdapter/EntryPointLLMAdapter
backward-compat aliases no longer exist. EvalController is the sole active class.

## D — db_manager.py (append only)
- [x] D-1  _EVAL_SCHEMA constant (eval_result + eval_run + indexes)
- [x] D-2  DBManager.__init__ + _init_eval_schema()
- [x] D-3  create_eval_run()
- [x] D-4  insert_eval_result() (JSON serialise list + dict fields)
- [x] D-5  get_eval_results_for_run() (deserialise JSON fields)
- [x] D-6  get_eval_summary() (GROUP BY detector+pipeline)

## E — configs/
- [x] E-1  configs/claude_opus.yaml
- [x] E-2  configs/gpt.yaml  (NOTE: model_name is placeholder — verify before running)
- [x] E-3  configs/gemini.yaml  (NOTE: model_name is placeholder — verify before running)
- [x] E-4  configs/claude_agentic.yaml (adds max_turns)

## F — evaluate.py
- [x] F-1  EvaluationRunner.__init__
- [x] F-2  _discover_benign() — latest version per package, skip controls/
- [x] F-3  _discover_malware() — graceful if dir missing
- [x] F-4  Folder-based ground truth: is_malicious bool from _discover_*() folder
           membership, stored per-row at insert time. _build_ground_truth() removed.
- [x] F-5  run() main loop with per-archive exception guard
- [x] F-6  _print_metrics() — rich.table TP/TN/FP/FN/F1 per detector

## G — Integration
- [x] G-1  Smoke test: single benign tar.gz through extract → filter → SAST only (no API)
           Prereq: install dependencies via hashed lockfile (`pip install --require-hashes --no-deps -r requirements.txt`)
- [x] G-2  Verify evaluate.py runs from repo root: python src/analyzer/evaluate.py
           Prereq: LiteLLM running on http://127.0.0.1:4000 as proxy-runner for any LLM detector test
