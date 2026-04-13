# Docs Sync Audit Report — PyPi-SCADA
**Generated:** 2026-04-07 14:30 UTC  
**Auditor:** Claude Sonnet 4.6 via `/docs-sync-audit`

---

## 1. Executive Summary

9 documentation drift findings across 6 files. Three are **High** severity because they describe
system behaviour that is factually incorrect today — an examiner or operator following them
would be misled. The remaining six are Medium or Low and represent incomplete coverage, stale
task checklists, or missing documentation for recently added components.

| Severity | Count |
|---|---|
| High | 3 |
| Medium | 5 |
| Low | 1 |
| **Total** | **9** |

Most drift originates from the Phase 1–4 remediation work completed this session, which touched
`entry_extractor.py`, `evaluate.py`, `detection_controller.py`, `adapters.py`, and the lockfile
infrastructure. Most source files were updated; several docs were not.

---

## 2. Scope and Inputs

### Implementation baseline
| File | Relevance |
|---|---|
| `src/analyzer/evaluate.py` | Main runner — malware gate, discovery, tier flag |
| `src/analyzer/entry_extractor.py` | Archive extraction — 3-level BFS |
| `src/analyzer/adapters.py` | Four adapter modes including `LLMRawAdapter` |
| `src/analyzer/detection_controller.py` | EvalController only (legacy classes deleted) |
| `requirements.in` | Canonical dependency list (includes pytest) |
| `deployment.sh` | No `pip-audit` call present |
| `src/injector/config.yaml` | Stale dataset paths |
| `tests/` | 11 tests added; no docs mention them |
| `configs/models.json` | Token prices consolidated here |
| `git diff README.md` | Partially updated, not yet committed |

### Documentation baseline
| File | Status |
|---|---|
| `README.md` | Modified (uncommitted) — partially updated |
| `docs/USAGE.md` | Not updated this session |
| `docs/ops/DEPLOYMENT_MANIFEST.md` | Updated in Phase 1 |
| `docs/ops/DEPENDENCY_SECURITY_SOP.md` | Not updated — contains phantom feature |
| `docs/ops/THESIS_TODO.md` | Not updated — stale task checklist |
| `src/analyzer/CONCERNS.md` | §1 updated; §2 and R-05 still stale |

---

## 3. Findings by Severity

---

### HIGH-1 — `DEPENDENCY_SECURITY_SOP.md §2`: `pip-audit` claimed as implemented but does not exist

**File:** `docs/ops/DEPENDENCY_SECURITY_SOP.md:9`  
**Status:** Confirmed

**Stale claim:**
> "The project uses `pip-audit` for continuous Software Composition Analysis. The execution
> pipeline runs this audit against the active lockfile **before initiating any evaluation batch**.
> The system aborts execution immediately if the audit returns known CVEs or malicious package flags."

**Reality:**
- `pip-audit` is absent from `requirements.in` (verified).
- `evaluate.py` calls no pre-flight audit before `EvaluationRunner.run()`.
- `deployment.sh` contains no `pip-audit` step.
- The claim is aspirational text written as present fact. An operator following this doc would
  expect an automatic safety check that does not exist.

**Required fix:** Replace §2 body with accurate text stating this is a planned control that is
not yet implemented, or implement it. If describing a future goal, label it explicitly as such.

---

### HIGH-2 — `CONCERNS.md §2`: Stale behavior description after Phase 1 malware gate fix

**File:** `src/analyzer/CONCERNS.md:40–41`  
**Status:** Confirmed

**Stale claim:**
> "When the evaluation runner starts, it logs a warning and returns an empty malware list, so the
> entire run executes as a false-positive-only benchmark."

**Reality (after Phase 1):**
`evaluate.py:170–176` — if `malware_archives` is empty and `--sast-only` is not set, the runner
raises `SystemExit("HALT: ...")`. It does not silently continue. The "warning-only" behavior was
the bug that Phase 1 fixed. The fix is documented in `audit_todo.md` but not reflected in
CONCERNS.md §2.

**Required fix:** Update §2 to say the runner halts with a `SystemExit` and refers the operator
to `--sast-only` for the intentional FP-only mode.

---

### HIGH-3 — `CONCERNS.md R-05`: References deleted pipeline files as still present

**File:** `src/analyzer/CONCERNS.md:233–251` (Risk R-05)  
**Status:** Confirmed

**Stale claims:**
- Line 233: "Repository contains both legacy diff pipeline and active entry-point pipeline"
- Line 240: "Questions about why `main.py` (diff) and `evaluate.py` (entry-point) coexist."

**Reality (after Phase 3):**
`diff.py`, `sql.py`, and `src/analyzer/main.py` were deleted. `src/credential_proxy/` was
deleted. `detection_controller.py` was rewritten to contain only `EvalController`. The risk
R-05 described is now resolved and should be retired or re-framed.

**Required fix:** Mark R-05 as **Resolved** and update its description to note the legacy
pipeline was removed in the Phase 3 cleanup. Remove the two bullet points that name deleted files.

---

### MEDIUM-1 — `USAGE.md §2`: Injector prerequisites reference non-existent sample paths

**File:** `docs/USAGE.md:91–92`  
**Status:** Confirmed

**Stale claim:**
```
- data/samples/malicious/
- data/samples/benign/
```

**Reality:**
The actual sample directories used by `evaluate.py` and the VM deployment are:
- `samples/benign/` (repo root level)
- `samples/malware_backstabbers_knife/` (repo root level)

The `data/samples/` path does not exist in the repository. The same stale paths appear verbatim
in the injector `config.yaml` example block at `USAGE.md:131–132`, which reflects the actual
`src/injector/config.yaml` on disk — meaning that file is also stale for the VM workflow.

**Required fix:** Update USAGE.md §2 Prerequisites to show the correct paths. Add a note
distinguishing the local dev injector workflow (simulator upload) from the evaluate.py evaluation
workflow (which reads directly from `samples/`).

---

### MEDIUM-2 — `THESIS_TODO.md §2 & §3`: Completed engineering tasks remain unchecked

**File:** `docs/ops/THESIS_TODO.md:15–26`  
**Status:** Confirmed

The following items are marked `[ ]` but are fully implemented:

| THESIS_TODO item | Implementation location |
|---|---|
| "Implement model loading from `configs/models.json`" | `evaluate.py:49–56` — JSON load into `_TOKEN_PRICES` |
| "Update `evaluate.py` to parse `models.json` and accept `--tier` argument" | `evaluate.py:349,363` — `--tier` CLI arg, `EvaluationRunner(tier=args.tier)` |
| "Transition from floating dependencies to a cryptographic lockfile" | `requirements.in`, `requirements.txt` (hashed), `proxy-requirements.*`, `injector-requirements.*` |
| "Use `pip-tools` to compile `requirements.in` into a hashed `requirements.txt`" | Done |
| "Update `deployment.sh` to install via `--require-hashes --no-deps`" | `deployment.sh:56-58` |

**Required fix:** Mark these items `[x]` in THESIS_TODO.md.

---

### MEDIUM-3 — `THESIS_TODO.md` four-mode architecture section: items not marked done

**File:** `docs/ops/THESIS_TODO.md:40–62`  
**Status:** Confirmed

The "New mode pipeline" section describes architecture changes (four modes, `DetectorAdapter`
interface, `experiment_mode` + `prompt_strategy` schema columns, YAML prompt config system)
that are fully implemented. Specifically:

- `adapters.py`: `StaticAdapter`, `LLMAdapter`, `LLMRawAdapter`, `AgenticAdapter` (four modes)
- `db_manager.py`: `eval_result` schema has `experiment_mode TEXT` and `prompt_strategy TEXT`
- `src/analyzer/configs/prompts.yaml`: YAML prompt strategy registry
- `detection_controller.py`: `EvalController` dispatches all four adapter types

These items have no `[ ]` / `[x]` markers (they are prose), but the thesis writing tasks they
reference ("update §3 Methodology to describe four modes", "update §3.3.1 Prompt Strategies", etc.)
reflect work that should now be done given the implementation is stable.

**Required fix:** Add a completion note to this section, or mark specific sub-items done where
applicable. The thesis writing tasks (updating report sections) remain open and valid.

---

### MEDIUM-4 — No test suite documentation exists anywhere

**File:** None — absence finding  
**Status:** Confirmed

`tests/test_extraction.py` (6 tests) and `tests/test_ground_truth.py` (5 tests) were added in
Phase 4. No documentation references them:
- README.md Quickstart has no test step
- USAGE.md has no testing section
- DEPLOYMENT_MANIFEST.md has no test run step
- `docs/ops/DEPENDENCY_SECURITY_SOP.md §2` references `pip-audit` as a CI gate but says nothing
  about the test suite

**Required fix:** Add a testing step to README.md Quickstart:
```bash
# Run the test suite (requires pytest, already in requirements.in)
pytest tests/
```
Optionally add a brief note to USAGE.md Prerequisites.

---

### MEDIUM-5 — `README.md`: `adapters.py` description omits `LLMRawAdapter`

**File:** `README.md:61`  
**Status:** Confirmed

**Current text:**
```
- `adapters.py` -- `StaticAdapter` (SAST), `LLMAdapter` (Single-shot), `AgenticAdapter` (Multi-turn)
```

**Reality:**
`adapters.py` also exports `LLMRawAdapter` — the fourth experiment mode (`llm_raw`) that feeds
raw entry-point files without AST import resolution, and is central to the four-mode comparison.
Omitting it misrepresents the experiment design to readers of the README.

**Required fix:** Add `LLMRawAdapter` to the adapters.py description line:
```
- `adapters.py` -- `StaticAdapter` (SAST), `LLMAdapter` (hybrid), `LLMRawAdapter` (raw),
  `AgenticAdapter` (multi-turn); all LLM calls route through LiteLLM on `http://127.0.0.1:4000`
```

---

### LOW-1 — `CONCERNS.md §3`: Config table lists only frontier-tier configs; 5 budget/medium files undocumented

**File:** `src/analyzer/CONCERNS.md:58–72`  
**Status:** Confirmed

The table lists 5 files (`claude_opus.yaml`, `claude_agentic.yaml`, `gpt.yaml`, `gemini.yaml`,
`together_frontier.yaml`) but `src/analyzer/configs/` currently contains 11 files including
budget/medium tier configs: `claude_haiku.yaml`, `claude_haiku_agentic.yaml`, `gemini_flash_lite.yaml`,
`gpt_nano.yaml`, `together_budget.yaml`.

**Required fix:** Either expand the table to include all tiers, or add a note: "Budget and medium
tier configs follow the same structure; see `configs/models.json` for the complete tier registry."

---

## 4. File-by-File Update Checklist

| File | Action | Finding(s) |
|---|---|---|
| `docs/ops/DEPENDENCY_SECURITY_SOP.md` | Rewrite §2 to reflect that pip-audit is **not yet implemented** | HIGH-1 |
| `src/analyzer/CONCERNS.md` | Update §2 behavior description (HALT, not warning) | HIGH-2 |
| `src/analyzer/CONCERNS.md` | Retire / resolve R-05 (legacy files deleted) | HIGH-3 |
| `docs/USAGE.md` | Fix §2 prerequisite paths (`data/samples/` → `samples/`) | MEDIUM-1 |
| `docs/ops/THESIS_TODO.md` | Mark completed engineering items `[x]` | MEDIUM-2 |
| `docs/ops/THESIS_TODO.md` | Add completion note to four-mode section | MEDIUM-3 |
| `README.md` | Add `pytest tests/` step to Quickstart | MEDIUM-4 |
| `README.md` | Add `LLMRawAdapter` to adapters.py description | MEDIUM-5 |
| `src/analyzer/CONCERNS.md` | Expand §3 config table or add budget/medium note | LOW-1 |

---

## 5. Contradictions Matrix

| Claim in Doc A | Claim in Doc B / Code | Verdict |
|---|---|---|
| `DEPENDENCY_SECURITY_SOP.md §2`: "pipeline runs pip-audit before each batch" | `evaluate.py`: no pip-audit call | **Contradiction — code wins** |
| `CONCERNS.md §2`: "logs a warning and returns empty malware list" | `evaluate.py:170`: raises `SystemExit("HALT:...")` | **Contradiction — code wins** |
| `CONCERNS.md R-05`: "main.py (diff) and evaluate.py coexist" | `src/analyzer/main.py`: deleted | **Contradiction — code wins** |
| `USAGE.md §2`: injector prereqs `data/samples/malicious/` | `evaluate.py` / VM workflow: `samples/malware_backstabbers_knife/` | **Contradiction — code wins** |
| `README.md:61`: adapters = StaticAdapter, LLMAdapter, AgenticAdapter | `adapters.py:564`: class `LLMRawAdapter(LLMAdapter)` | **Omission — code wins** |
| `THESIS_TODO.md §2`: "[ ] Implement model loading from models.json" | `evaluate.py:49–56`: implemented | **Stale checklist — code wins** |

---

## 6. Recommended Edit Order (fastest risk reduction first)

1. **`src/analyzer/CONCERNS.md §2`** (10 min) — Single paragraph rewrite. Direct factual error
   that will confuse operators running the evaluation pipeline.

2. **`src/analyzer/CONCERNS.md R-05`** (5 min) — Add "Resolved in Phase 3 cleanup" header and
   remove deleted-file references. Prevents examiner confusion about codebase state.

3. **`docs/ops/DEPENDENCY_SECURITY_SOP.md §2`** (10 min) — Rewrite to accurately describe what
   IS implemented (hashed lockfiles) vs what IS NOT (pip-audit integration). High examiner-facing
   risk if read as a security claim.

4. **`README.md`** (5 min) — Two targeted edits: add `pytest tests/` to Quickstart; add
   `LLMRawAdapter` to the adapters.py bullet. README is examiner-first document.

5. **`docs/USAGE.md §2`** (10 min) — Fix stale `data/samples/` paths. Operator-facing.

6. **`docs/ops/THESIS_TODO.md`** (5 min) — Mark completed items `[x]`. Prevents treating done
   work as pending in thesis planning.

7. **`src/analyzer/CONCERNS.md §3`** (5 min) — Add budget/medium tier note to config table.

---

## 7. Open Questions / Missing Evidence

1. **`pip-audit` intent** — Was `DEPENDENCY_SECURITY_SOP.md §2` describing a planned feature or
   a misremembered claim? If planned, where should the integration point be (`evaluate.py` startup
   or `deployment.sh` pre-run step)? This determines whether the fix is "delete the claim" or
   "implement and document it."

2. **Injector local dev paths** — `src/injector/config.yaml` still references `../data/samples/`
   paths. Do these paths need to work for local `controller.sh` usage, or is `controller.sh` only
   a legacy dev tool that no longer needs to match the sample layout? If the latter, a note in
   USAGE.md §2 clarifying that `controller.sh` requires manual path setup would suffice.

3. **THESIS_TODO.md four-mode section** — The writing tasks (update §3 Methodology, §3.3.1
   Prompt Strategies, etc.) are open and valid. Are these already reflected in the current thesis
   draft, or are they still pending? Cannot determine from repository alone.
