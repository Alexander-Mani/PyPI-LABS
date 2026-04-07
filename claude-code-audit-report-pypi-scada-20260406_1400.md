# Claude Code Audit Report — PyPI-SCADA

**Date:** 2026-04-06  
**Scope:** Full codebase — all Python source files in `src/analyzer/`, `src/data/`, deployment scripts  
**Files examined:** `adapters.py`, `detection_controller.py`, `evaluate.py`, `entry_extractor.py`,
`heuristic_filter.py`, `prompt_manager.py`, `db_manager.py`, `deployment.sh`,
`docs/ops/DEPLOYMENT_MANIFEST.md`, `configs/*.yaml`

---

## Security

1. **`deployment.sh:54-61` — API keys written with unvalidated shell expansion**  
   The heredoc that writes `proxy-runner/.env` uses `$ANTHROPIC_API_KEY` etc. directly from the operator shell. If any key variable is unset, an empty value is written to the file silently — no `${VAR:?}` guard. The proxy starts and fails on the first real API call with an opaque authentication error rather than an early, clear "key is missing" message. Add `${ANTHROPIC_API_KEY:?ANTHROPIC_API_KEY must be set}` guards before the heredoc.

2. **`deployment.sh:22` — PULL_TOKEN embedded in git clone URL**  
   `git clone https://Alexander-Mani:"$PULL_TOKEN"@github.com/...` embeds the token in the remote URL. Git stores this URL in `.git/config` of the cloned repo, which is owned by `pypi-runner` and readable by `root`. The token also appears in the bash process list during the clone. Use a `.netrc` or `GIT_ASKPASS` credential helper instead, or clone anonymously and configure the token via `git remote set-url`.

3. **`adapters.py:493-508` — Direct (non-proxy) Anthropic SDK path reads `ANTHROPIC_API_KEY` from environment inside `pypi-runner` process**  
   The architectural intent is that `pypi-runner` holds no API keys (CLAUDE.md, docs/ops/RISK_DIARY.md Decision 5). The fallback path in `AgenticAdapter._make_api_call()` (and `LLMAdapter._call_anthropic/openai/gemini`) directly reads `os.environ["ANTHROPIC_API_KEY"]`. If `proxy_url` is misconfigured or absent from a YAML, the process silently falls through to the direct path and reads a key it shouldn't have. No warning is logged. Consider raising `RuntimeError("proxy_url not configured — direct API calls violate key isolation policy")` on the non-proxy branch for production configs.

---

## Bugs / Errors / QA

1. **`adapters.py:391-401` — AgenticAdapter stores combined token count in `input_tokens`, `output_tokens=0`**  
   `_agentic_loop()` accumulates `total_tokens = sum(input + output per turn)` and returns a single integer. `run()` assigns it to `input_tokens=total_tokens, output_tokens=0`. The DB column `output_tokens INTEGER NOT NULL DEFAULT 0` accepts this but the split is permanently lost. `_validate_financial_airgap()` in `evaluate.py:213-215` uses `r.input_tokens` and `r.output_tokens` separately to compute expected cost; for agentic rows, `expected_total` will be calculated using only the input price for the full token budget, understating expected cost. Fix: change `_agentic_loop()` return type to `tuple[str, int, int, float]` (input_tokens, output_tokens accumulated separately) and unpack in `run()`.

2. **`adapters.py:503-508` — Direct SDK path in `AgenticAdapter._make_api_call()` omits `cost_usd` from return dict**  
   The proxy path returns `{"cost_usd": call_cost, ...}`. The direct Anthropic SDK path at lines 503-508 returns a dict without `"cost_usd"`. `_agentic_loop()` does `total_cost += resp.get("cost_usd", 0.0)` — silently 0.0 for every direct-SDK call. Financial validation will see zero cost for any agentic run not routed through the proxy. The direct path should either raise (see Security finding 3) or compute token-math cost consistently.

3. **`db_manager.py:153-254` — Large block of commented-out URL-crawler code**  
   ~100 lines of commented methods (`upsert_urls`, `print_recent_urls`, `add_url`, `get_next_target`, `mark_visited`) reference `url`, `UrlModel`, `url_metadata.db` — clearly from a prior unrelated project. They will never be uncommented. Dead code adds confusion for anyone reading `DBManager` and inflates the file size.

4. **`evaluate.py:232-233` — `_validate_financial_airgap()` rediscovers all archives to count packages**  
   After running validation on one package, the method calls `_discover_benign()` and `_discover_malware()` again solely to compute `n_packages` for the cost projection. Both lists are already computed in `run()` — 4 filesystem scans happen where 2 would suffice. Minor but unnecessary I/O on every non-`--skip-validation` run.

5. **`entry_extractor.py:72-85` — `_parse_name_version()` applied to archive stems before manifest override**  
   `evaluate.py:169-171` overrides `pkg.name` and `pkg.version` with manifest values after extraction. But malware archives have no manifest — they rely entirely on stem parsing via `_STEM_RE`. The regex partitions on the first hyphen in the stem (`stem.partition("-")`), so `malware_a-b-c-1.0.zip` would give `name="malware_a"` and `version="b-c-1.0"`, and a stem like `exploit1.0.zip` (no hyphen) falls to the `(stem, "unknown")` fallback. Malware DB rows will have `version="unknown"` in ambiguous cases.

---

## Logical Errors — Methodology

1. **`evaluate.py:89-116` — Only the latest benign version is evaluated per package**  
   `_discover_benign()` takes `entries[-1]` — the last entry in `manifest.json`. Packages with many versions (e.g. `requests`, `numpy`) contribute only one sample point to the benign set. The benign distribution is therefore biased towards recent code. This is documented as R-04 in `CONCERNS.md` but no mitigation has been implemented.

2. **`evaluate.py:118-140` — Malware discovery uses `rglob("*.zip")` only**  
   `_discover_malware()` does `malware_dir.rglob("*.zip")`. Malware samples distributed as `.tar.gz` or `.whl` are silently ignored. The Backstabbers Knife Collection ships some samples as tarballs. No warning is emitted when non-zip archives are skipped.

3. **`entry_extractor.py:169-193` — Import resolution is one level deep by design but not enforced for pyproject.toml**  
   `_filter_entry_points()` resolves imports from `.py` candidates but explicitly skips `pyproject.toml` because it's TOML. A malicious `pyproject.toml` that installs a build backend or defines `[tool.setuptools]` entry points would not have its referenced modules included in `pkg.files`. The LLM and hybrid adapters would see only the TOML header but not the actual malicious code it references.

---

## Logical Errors — Project Context

1. **`detection_controller.py:1-114` + `diff.py`, `main.py`, `sql.py` — Legacy diff pipeline coexists with no deprecation signal**  
   The first ~300 lines of `detection_controller.py` implement `StaticDetectorAdapter`, `LLMDetectorAdapter`, and `DetectionController` — the old diff-based pipeline. `diff.py`, `sql.py`, and `main.py` remain at `src/analyzer/`. These are never called by `evaluate.py` or any active code path. There is no deprecation comment, README note, or `DeprecationWarning`. A new contributor reading the module sees two complete pipelines and cannot determine which is active.

2. **`adapters.py:392` — `AgenticAdapter.run()` hardcodes `detector="agentic_claude"` regardless of configured model**  
   `LLMAdapter` correctly uses `Path(config_path).stem` for its `_detector_name` (line 179), so the DB shows `claude_haiku`, `claude_opus`, etc. `AgenticAdapter` does not: line 392 always writes `detector="agentic_claude"`. Running `claude_haiku_agentic.yaml` and `claude_agentic.yaml` through the pipeline produces identical `detector` values in the DB, making the two agentic configs indistinguishable in metrics. Fix: `self._detector_name = Path(config_path).stem` in `AgenticAdapter.__init__()` and use it in `run()`.

3. **`src/analyzer/config.yaml` `storage.results_db` path does not match `DBManager.DB_PATH`**  
   `DBManager.DB_PATH` is computed as `DBCore.BASE_DIR / "data" / "eval_results.db"` (a hardcoded class attribute). If `config.yaml` specifies a `storage.results_db` path (e.g., `src/data/eval_results.db`), it is never read by `DBManager` — `evaluate.py` instantiates `DBManager()` with no config. This creates a false impression that the DB path is configurable. Either remove `storage.results_db` from `config.yaml` or wire it through `DBManager.__init__()`.

4. **`detection_controller.py:317-319` — Backward-compat aliases reference no live callers**  
   `EntryPointStaticAdapter = StaticAdapter` and `EntryPointLLMAdapter = LLMAdapter` are declared "for any code that still references the old names." No such code exists in the repo. These aliases add noise without benefit.

---

## Code Cleanliness

1. **`evaluate.py:48-61` — `_TOKEN_PRICES` is a second source of truth for model pricing**  
   `configs/models.json` already exists as the model registry (used by `EvalController` to filter tiers). Pricing data is maintained separately in the `_TOKEN_PRICES` dict inside `evaluate.py`. When a new model is added to `configs/models.json`, its price must also be manually added to `_TOKEN_PRICES` or financial validation will silently compute `expected_total=0`. Consolidate: add `input_price_per_1m` / `output_price_per_1m` fields to each model entry in `models.json` and load from there.

2. **`adapters.py:231-239` — `_call_api()` dispatches `together_ai/` prefix to `_call_openai()`**  
   The method name `_call_openai` handles OpenAI, Together AI, and any `o1-`/`o3-` prefixed model. A reader unfamiliar with Together AI's OpenAI-compatible API will not understand why a Together model routes here. Rename to `_call_openai_compat()` or add an inline comment explaining the dispatch.

3. **`evaluate.py:258-268` — `_print_metrics()` computes metrics in a single loop but builds the display key inline**  
   `key = f"{r['detector']}:{r['experiment_mode']}:{r['prompt_strategy']}"` is assembled inside the loop and used as a dict key, then later iterated in sorted order. The same compound key construction is used again in `get_eval_summary()` in `db_manager.py:149`. Extract the key format to a shared constant or helper.

4. **`entry_extractor.py:103-118` — `_extract_tar()` silently drops non-`.py` files**  
   `pyproject.toml` is included in `_ENTRY_POINTS` (line 29) and is relevant for detecting malicious build backends, but `_extract_tar()` filters `if not member.name.endswith(".py"): continue` at line 107 — it never reads `pyproject.toml` from tarballs. `_extract_wheel()` and `_extract_zip()` have the same filter. `pyproject.toml` is therefore always empty in `pkg.files` for tarball and wheel packages, even though `_filter_entry_points()` tries to include it.

---

## Efficiency

1. **`entry_extractor.py:91-163` — Full archive read into memory before filtering**  
   `_read_archive()` returns a `dict[str, bytes]` containing every `.py` file in the archive. For a large package this can be several MB of in-memory bytes before `_filter_entry_points()` selects the handful of entry-point files. The tar/wheel/zip readers could accept a predicate and skip extraction for non-entry-point files in a first pass, then do a targeted second pass for imports.

2. **`entry_extractor.py:209-237` — `_resolve_imports()` is O(N × M)**  
   For each of N distinct module names from the AST, the method iterates over all M files in `all_files` checking `Path(candidate).name == f"{mod}.py"`. For a package with 50 imports and 200 files this is 10,000 string comparisons. Building an index `{filename: [path, ...]}` once before the loop drops this to O(N) dict lookups.

3. **`detection_controller.py:393` — `ThreadPoolExecutor(max_workers=4)` hardcoded**  
   With 5 budget LLM configs × 3 prompt strategies × 2 (LLM + LLMRaw) + 2 SAST + 1 agentic × 3 strategies = ~40 tasks per package, a pool of 4 creates a deep queue. The limit is not documented or configurable. For I/O-bound API calls 4 workers is conservative; for SAST-heavy runs on a single CPU it may be too many. Expose as a config field or derive from the number of adapters.

4. **`evaluate.py:193-243` — `_validate_financial_airgap()` re-scans the samples directory**  
   `_discover_benign()` and `_discover_malware()` glob the filesystem and parse manifest JSONs. `_validate_financial_airgap()` calls them a second time (lines 193, 232) purely for the projection count. Cache the results as instance attributes after the first `run()` call, or accept them as parameters.

---

## Summary

| Category | Findings |
|---|---|
| Security | 3 |
| Bugs / Errors / QA | 5 |
| Logical errors — methodology | 3 |
| Logical errors — project context | 4 |
| Code cleanliness | 4 |
| Efficiency | 4 |
| **Total** | **23** |

### Top 5 Priority Actions

1. **(Security / Bug)** `adapters.py:392` + Security finding 3 — Fix `AgenticAdapter` to use config stem as `detector` name AND raise on the non-proxy API path to enforce key isolation. Both are one-line fixes with high correctness impact.

2. **(Bug — data integrity)** `adapters.py:391-401` — Split `total_tokens` into `input_tokens` + `output_tokens` in `_agentic_loop()`. Financial validation currently uses these fields to compute expected cost; the current collapse to `(total, 0)` silently underestimates agentic cost.

3. **(Project context — reproducibility)** `entry_extractor.py:103-163` — `pyproject.toml` is never extracted from tarballs or wheels because the file-extension filter `endswith(".py")` excludes it. TOML entry points and build backends are invisible to every detector mode. This is a silent gap in malware coverage.

4. **(Code cleanliness — maintainability)** `evaluate.py:48-61` — Consolidate `_TOKEN_PRICES` into `configs/models.json`. The current two-source-of-truth arrangement means any new model added to the experiment grid requires a manual price update in a Python file that is easy to overlook.

5. **(Project context — legibility)** `detection_controller.py` + `diff.py` + `main.py` + `sql.py` — Mark the legacy diff pipeline as deprecated with a docstring note and a planned removal milestone, or remove it now if it is dead. The coexistence of two complete pipelines with no signal about which is active is the most confusing aspect of the codebase for a new reader.
