# PyPI-SCADA Audit Remediation Tracker

Source reports: `claude-code-audit-report-pypi-scada-20260406_1400.md`,
`gemini-code-audit-report-phase-3-benchmarking-260407-1030.md`,
`codex-code-audit-report-pypi-scada-repo-audit-070426-1200.md`

Status key: `[ ]` pending · `[~]` in progress · `[x]` complete

---

## Phase 1 — Critical Security, Budget & Scientific Blockers

- [x] **Fix `pyproject.toml` extraction** — `entry_extractor.py:107,124,153`
  Expand `.endswith(".py")` filter in `_extract_tar`, `_extract_wheel`, `_extract_zip`
  to also pass through files where `Path(name).name == "pyproject.toml"`.

- [x] **Enforce hashed lockfiles** — `requirements.txt`, new `requirements.in`,
  new `proxy-requirements.in`, new `proxy-requirements.txt`
  Add missing runtime deps (`openai`, `google-generativeai`) to requirements.in.
  Run `pip-compile --generate-hashes requirements.in -o requirements.txt` and same
  for proxy. Deployment script already uses `--require-hashes --no-deps`.

- [x] **Secure git clone** — `deployment.sh:22`
  Replace `https://Alexander-Mani:"$PULL_TOKEN"@github.com/...` with ephemeral
  `.netrc` approach: write → clone → `rm /home/pypi-runner/.netrc`.
  Mirror in `docs/ops/DEPLOYMENT_MANIFEST.md` Step 2.

- [x] **Lock down DNS egress** — `deployment.sh:78-79`
  Replace global port-53 ACCEPT rules with destination-locked rules for
  8.8.8.8, 8.8.4.4, 1.1.1.1 only. Mirror in DEPLOYMENT_MANIFEST.md Step 6.

- [x] **Fix API key shell expansion guards** — `deployment.sh` before Step 5 heredoc
  Add `: "${VAR:?ERROR: VAR is not set}"` guards for all four API key variables
  before the heredoc that writes proxy-runner's `.env`.

- [x] **Fix agentic token split** — `adapters.py:503-508,510-554,379-401`
  (a) Add `"cost_usd": 0.0` to direct-SDK return dict in `_make_api_call()`.
  (b) Change `_agentic_loop()` return type to `tuple[str, int, int, float]`
      with separate `total_input_tokens` / `total_output_tokens` accumulators.
  (c) Update `AgenticAdapter.run()` to unpack 4-tuple into
      `input_tokens=in_tok, output_tokens=out_tok`.

- [x] **Enforce proxy isolation** — `adapters.py:264-311,493-508`
  Remove direct-SDK bodies from `LLMAdapter._call_anthropic`, `_call_openai`,
  `_call_gemini` and replace with `RuntimeError("proxy_url not set...")`.
  Same for `AgenticAdapter._make_api_call()` direct path.

- [x] **Add malware sample gate** — `evaluate.py` after `_discover_malware()` call
  If `not malware_archives and not sast_only` → `raise SystemExit("HALT: ...")`.
  Remove the warning-only behavior from `_discover_malware()` (gate handles it).

---

## Phase 2 — High-Priority Bugs & Methodology Fixes

- [x] **Fix malware archive discovery** — `evaluate.py:132`
  Change `malware_dir.rglob("*.zip")` to include `*.tar.gz` and `*.whl`.

- [x] **Fail-secure proxy errors** — `adapters.py:199-203` (LLMAdapter.run except block)
  On API exception, return `verdict=None` / `experiment_mode="error"` row instead
  of `verdict=False`. DB `verdict INTEGER NOT NULL` — consider adding an `is_error`
  flag to `EvalDetectionResult` or storing a sentinel value.
  **Note:** Gemini ranked this High; it's deferred because it requires a schema
  discussion before committing to a representation.

- [x] **Fix proxy config drift** — `src/analyzer/config.yaml`
  If `credential_proxy.url` references port 9090, update to 4000 (LiteLLM port).
  Mark the `credential_proxy` section as legacy-only or remove it if unused.

- [x] **Fix runtime dependencies** — ensure `requirements.in` includes all needed packages
  (handled in Phase 1 for `openai`, `google-generativeai`; check `twine`, `packaging`
  for injector).

- [x] **Fix agentic detector naming** — `adapters.py:392`
  Change `detector="agentic_claude"` to `detector=self._detector_name` where
  `self._detector_name = Path(config_path).stem` set in `__init__`. One-line fix.

- [x] **Fix malware stem parsing** — `evaluate.py:135-138`
  `_STEM_RE` in `entry_extractor.py` handles standard naming. The partition-on-hyphen
  in `_discover_malware()` gives `version="unknown"` for stems without hyphens.
  Apply `_STEM_RE` regex from the extractor instead, or at minimum log a warning
  when stem is unparseable.

---

## Phase 3 — Codebase Cleanup & Deprecation

- [x] **Purge legacy pipeline files** — delete `src/analyzer/diff.py`, `sql.py`, `main.py`
  Remove backward-compat aliases in `detection_controller.py:317-319`
  (`EntryPointStaticAdapter`, `EntryPointLLMAdapter`).
  Check for and remove the top ~300 lines of `detection_controller.py` that implement
  the old `StaticDetectorAdapter`, `LLMDetectorAdapter`, `DetectionController` classes.

- [x] **Purge `src/credential_proxy/`** — confirmed obsolete by Codex.

- [x] **Consolidate `_TOKEN_PRICES`** — `evaluate.py:48-61`
  Add `input_price_per_1m` / `output_price_per_1m` fields to each model entry in
  `configs/models.json`. Load from there in `_validate_financial_airgap()` instead
  of the hardcoded dict.

- [x] **Remove dead DB code** — `db_manager.py:153-254`
  Delete the ~100 lines of commented-out URL-crawler methods from a prior project.

- [x] **Update stale docs** — `evaluate.py` module docstring, `CONCERNS.md §1`,
  `TODO.md` — reflect folder-based ground truth (not meta.json).

- [x] **Remove `EntryPointStaticAdapter` alias** — already covered in legacy purge above.

---

## Phase 4 — Efficiency, Edge Cases & QA

- [x] **Expand import resolution depth** — `entry_extractor.py:209-237`
  Increase `_resolve_imports` from 1-level to 2-3 levels recursively to catch
  multi-stage stager chains (e.g. `setup.py → payload.py → exfil.py`).

- [x] **Optimize `_resolve_imports`** — `entry_extractor.py:227-236`
  Build `{filename: [full_path, ...]}` index once before the module loop.
  Reduces O(N×M) to O(N) dict lookups.

- [x] **Prevent twine noise** — `src/injector/upload_samples.py:127`
  Restrict `ARCHIVE_SUFFIXES` for benign/control uploads to `.tar.gz` and `.whl`.
  `.zip` attempts cause noisy twine failures.

- [x] **Handle non-standard malware passwords** — `entry_extractor.py:_extract_zip`
  Distinguish "bad password" from "corrupt archive" in the RuntimeError handler.
  Log skipped archives to `EvalDetectionResult.details` as `{"skipped": "bad_password"}`.

- [x] **Log truncation warnings** — `adapters.py:_build_file_listing` (~line 219)
  When the 8000-char limit is hit, append `{"truncated": True}` to the result's
  `details` dict so truncation can be correlated with False Negatives post-hoc.

- [x] **Cache sample discovery** — `evaluate.py:_validate_financial_airgap`
  Store `_discover_benign()` and `_discover_malware()` results as instance attributes
  after first call to avoid double filesystem scan in validation + run.

- [x] **Add basic automated tests** — new `tests/` directory
  Minimum viable: test pyproject.toml extraction from a synthetic tarball,
  and test that folder-based ground truth labels propagate to DB correctly.

---

## Cross-Report Notes

| Finding | Claude | Gemini | Codex | Resolution |
|---|---|---|---|---|
| `pyproject.toml` not extracted | Yes | Yes | Critical | Phase 1 |
| Legacy pipeline cleanup | Yes | Yes | Yes (Low) | Phase 3 |
| Hashed lockfile | No | No | Critical | Phase 1 |
| DNS tunneling via port 53 | Yes (Security) | Yes (Critical) | No | Phase 1 |
| `verdict=False` on proxy fail | Partial | Yes (High) | No | Phase 2 |
| `detector="agentic_claude"` hardcoded | Yes | No | No | Phase 2 |
| Agentic token split (output=0) | Yes | No | No | Phase 1 |
| Proxy isolation / direct SDK fallback | Yes (Security) | No | No | Phase 1 |
| Malware dir missing = FP-only run | Yes | No | High | Phase 1 |
| config.yaml port 9090 vs 4000 | Partial | No | High | Phase 2 |
| Missing runtime deps (openai, etc.) | No | No | High | Phase 1 (requirements.in) |
| No test suite | No | No | Medium | Phase 4 |
| `_TOKEN_PRICES` dual source of truth | Yes | No | No | Phase 3 |
| Stale docs post ground-truth refactor | No | No | Medium | Phase 3 |
