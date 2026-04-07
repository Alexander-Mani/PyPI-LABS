# Claude Code Session Diary — PyPi-SCADA

---

## 2026-04-07  (UTC block 2, 06–11)

### Summary
Full four-phase remediation of the PyPi-SCADA codebase, driven by a cross-report synthesis of three independent audit reports (Claude, Gemini, Codex). Phases 1–3 were completed in a prior session; Phase 3 Step 6 (stale documentation) and the complete Phase 4 were executed in this session. The codebase is now clean, correctly implemented, and has a minimum-viable test suite.

### What Was Done

**Phase 3 completion (Step 6 — stale documentation):**
- `src/analyzer/CONCERNS.md §1`: Replaced old meta.json-based ground truth description with folder-based refactor status. Re-framed as "ATO detection completeness" rather than a bug.
- `src/analyzer/TODO.md`: Updated F-4 entry from `_build_ground_truth()` to folder-based labelling description. Added Phase 3 cleanup note for removed legacy classes (C-2, C-3).
- `audit_todo.md`: Marked all Phase 3 items `[x]`.

**Phase 4 — Efficiency, Edge Cases & QA:**
- `entry_extractor.py`: Expanded `_resolve_imports` from 1-level to 3-level BFS with a visited set for cycle safety.
- `entry_extractor.py`: Replaced O(N×M) linear scan with `{basename: [paths]}` and `{dir: [__init__.py paths]}` indexes built once per extraction call.
- `entry_extractor.py`: Added `bad_password_files: list[str]` to `PackageInfo`; `_extract_zip` now distinguishes "bad password" from other `RuntimeError`s and records skipped filenames.
- `detection_controller.py`: `EvalController.run()` now propagates `pkg.bad_password_files` into `res.details["skipped_bad_password"]` before DB insert.
- `adapters.py`: `_build_file_listing()` and `_build_file_listing_raw()` now return `tuple[str, bool]` (listing, truncated). Both `LLMAdapter.run()` and `LLMRawAdapter.run()` unpack the flag and add `{"truncated": True}` to `details` when hit.
- `evaluate.py`: `_discover_benign()` and `_discover_malware()` results cached as instance attributes after first call; `_validate_financial_airgap` no longer causes a double filesystem scan.
- `src/injector/upload_samples.py`: `ARCHIVE_SUFFIXES` restricted to `{".whl", ".gz"}`, removing `.zip` which caused noisy twine failures.
- `evaluate.py`: Fixed incorrect path `_ANALYZER_DIR / "configs" / "models.json"` → `_REPO_ROOT / "configs" / "models.json"` (models.json lives at repo root, not inside src/analyzer/configs/).
- `tests/test_extraction.py`: 5 tests covering pyproject.toml extraction, 2-level import chain, cycle safety, and bad-password tracking.
- `tests/test_ground_truth.py`: 5 tests covering benign/malware folder labelling, controls/ exclusion, and discovery caching.

### What Worked
- BFS import resolution with a visited set was the cleanest solution for both the depth increase and cycle prevention in one change.
- Using `_build_file_listing` returning a `(str, bool)` tuple was cleaner than an instance variable approach for truncation tracking.
- `EvaluationRunner.__new__()` in ground truth tests avoids the heavy `__init__` (DBManager, EvalController) while still testing the discovery methods directly.

### Issues / Notes
- The `evaluate.py` module-level `open(_ANALYZER_DIR / "configs" / "models.json")` was a latent bug: the YAML configs live in `src/analyzer/configs/` but `models.json` is in the repo-root `configs/`. This only surfaced when the test imported `evaluate.py` and the CWD wasn't `src/analyzer/`. Fixed to use `_REPO_ROOT`.
- `pytest` was not installed in either venv; had to `pip install pytest` into `.venv` before tests could run.
- All 10 tests pass: `pytest tests/ -v` — 10 passed in 0.14s.
