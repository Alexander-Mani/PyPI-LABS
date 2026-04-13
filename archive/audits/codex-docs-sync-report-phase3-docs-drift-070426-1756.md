# Codex Docs Sync Report — Phase 3 Docs Drift

Generated (UTC): 2026-04-07 17:56

## 1. Executive Summary

The documentation is substantially improved and mostly aligned with the current entry-point architecture, but there are still several material drifts.

Most important: VM deployment docs/scripts stage malicious archives under `samples/malware_backstabbers_knife/`, while `upload_samples.py --only malicious` reads from `samples/<samples-dir>/malicious/`. This makes the documented upload step incomplete for malicious samples and can silently produce a benign-only simulator index.

Additional high/medium drift remains in analyzer internal docs (`src/analyzer/CONCERNS.md`, `src/analyzer/TODO.md`) and minor reference drift (Step numbering, stale notes).

## 2. Scope and Inputs

### Git/Input Baseline

- `git status --short`: only `README.md` modified in current worktree.
- `git diff --name-only`: `README.md`.

### Files Reviewed

- `README.md`
- `docs/USAGE.md`
- `docs/ops/DEPLOYMENT_MANIFEST.md`
- `docs/ops/RISK_DIARY.md`
- `deployment.sh`
- `src/analyzer/evaluate.py`
- `src/analyzer/entry_extractor.py`
- `src/analyzer/detection_controller.py`
- `src/analyzer/adapters.py`
- `src/analyzer/TODO.md`
- `src/analyzer/CONCERNS.md`
- `src/injector/upload_samples.py`
- `src/injector/config.yaml`
- `src/injector/controller.sh`

## 3. Findings by Severity

### Critical

1. VM malicious upload path mismatch breaks operability (Confirmed)
- Evidence (docs/scripts):
  - `docs/ops/DEPLOYMENT_MANIFEST.md:58` stages to `samples/malware_backstabbers_knife/`.
  - `docs/ops/DEPLOYMENT_MANIFEST.md:176-179` runs `upload_samples.py --only malicious` with `--samples-dir samples`.
  - `deployment.sh:37-39`, `deployment.sh:44-48`, `deployment.sh:149` use same pattern.
- Evidence (code):
  - `src/injector/upload_samples.py:220-233` scans `malicious_dir = samples_dir / "malicious"`.
- Impact:
  - `--only malicious` finds 0 files unless a `samples/malicious/` directory exists.
  - Simulator dataset can end up benign/controls-only despite operator following docs exactly.

### High

1. `src/analyzer/CONCERNS.md` Section 2 is outdated against current evaluate behavior (Confirmed)
- Evidence (doc): `src/analyzer/CONCERNS.md:38-47` says warning-only benign/FP-only behavior.
- Evidence (code): `src/analyzer/evaluate.py:170-176` now hard-fails (SystemExit) on missing malware unless `--sast-only`.
- Impact:
  - Misstates evaluation semantics and expected metrics behavior.

2. `src/analyzer/CONCERNS.md` still states `.zip`-only malware expectation (Confirmed)
- Evidence (doc): `src/analyzer/CONCERNS.md:49-52` says restore password-protected `.zip` archives.
- Evidence (code): `src/analyzer/evaluate.py:133-136` discovers `.zip`, `.tar.gz`, `.whl` for malware corpus.
- Impact:
  - Documentation understates accepted malware archive formats and can constrain dataset prep unnecessarily.

3. Internal analyzer TODO has stale extractor behavior claims (Confirmed)
- Evidence (doc):
  - `src/analyzer/TODO.md:8` says `_extract_tar` is ".py files only".
  - `src/analyzer/TODO.md:11` says import resolution is "1-level".
- Evidence (code):
  - `src/analyzer/entry_extractor.py:113` includes `pyproject.toml` in tar extraction.
  - `src/analyzer/entry_extractor.py:209` resolves imports up to 3 levels via BFS.
- Impact:
  - Maintainer-facing status file no longer reflects implemented design.

### Medium

1. Step-number references are stale after deployment manifest restructuring (Confirmed)
- Evidence:
  - `README.md:124` says LiteLLM in Step 8.
  - `docs/USAGE.md:223`, `docs/USAGE.md:255` also point to Step 8.
  - `docs/ops/DEPLOYMENT_MANIFEST.md:138` shows LiteLLM starts in Step 7.
- Impact:
  - Operator friction and confusion during runbook execution.

2. Historical note references deleted custom proxy path without explicit "deleted" state (Confirmed)
- Evidence:
  - `docs/ops/RISK_DIARY.md:122-127` references `src/credential_proxy/server.py` as implementation history.
  - `src/credential_proxy/` is deleted in current tree.
- Impact:
  - Not wrong historically, but should clearly indicate module removal to avoid readers searching for non-existent code.

3. Authorship line in concern register is process-noisy for thesis docs (Inference)
- Evidence: `src/analyzer/CONCERNS.md:278-280` contains "written by Codex" note.
- Impact:
  - Can look non-academic in final thesis appendix/documentation set.

### Low

1. Minor architecture wording drift in `adapters.py` module docstring (Confirmed)
- Evidence: `src/analyzer/adapters.py:9-10` says `detection_controller.py` retains legacy diff classes; current `detection_controller.py` is EvalController-focused.
- Impact:
  - Small reader confusion, low operational risk.

## 4. File-by-File Update Checklist

- `docs/ops/DEPLOYMENT_MANIFEST.md`
  - Fix malicious sample staging/upload path mismatch.
  - Either stage to `samples/malicious/` for injector flow, or update `upload_samples.py` usage/docs to read from `malware_backstabbers_knife/` consistently.
  - Re-validate all step numbers referenced by other docs.

- `deployment.sh`
  - Align staged malware folder with `upload_samples.py --only malicious` expectations.
  - Keep script and manifest in lockstep (same folder names and sequence).

- `README.md`
  - Update LiteLLM step reference from Step 8 to Step 7.
  - Recheck quickstart comments for consistency with manifest order.

- `docs/USAGE.md`
  - Update Step 8 references for LiteLLM to Step 7.
  - Reconcile local/dev sample folder guidance with VM/deployment naming where relevant.

- `src/analyzer/CONCERNS.md`
  - Rewrite Section 2 to reflect current hard-gate behavior in `evaluate.py`.
  - Update accepted malware formats (`.zip/.tar.gz/.whl`).
  - Consider removing AI authorship note for formal thesis-facing docs.

- `src/analyzer/TODO.md`
  - Replace stale extractor bullets with implemented behavior (includes `pyproject.toml`, 3-level BFS import resolution).

- `docs/ops/RISK_DIARY.md`
  - Keep historical proxy note but explicitly state files were removed and LiteLLM is the only active implementation path.

- `src/analyzer/adapters.py`
  - Adjust top docstring to match current module responsibilities.

## 5. Contradictions Matrix (Doc A vs Doc B vs Code)

| Topic | Doc A | Doc B | Code | Status |
|---|---|---|---|---|
| VM malicious upload folder | `DEPLOYMENT_MANIFEST.md:58` uses `samples/malware_backstabbers_knife/` | `deployment.sh:37-39,44-48` same | `upload_samples.py:220-233` expects `samples/malicious/` | Confirmed contradiction (Critical) |
| LiteLLM manifest step number | `README.md:124` says Step 8 | `docs/USAGE.md:223,255` says Step 8 | `DEPLOYMENT_MANIFEST.md:138` shows LiteLLM at Step 7 | Confirmed contradiction (Medium) |
| Missing malware behavior | `CONCERNS.md:38-47` says warning-only FP benchmark | — | `evaluate.py:170-176` hard HALT unless `--sast-only` | Confirmed contradiction (High) |
| Malware archive formats | `CONCERNS.md:49-52` implies `.zip` restore path | — | `evaluate.py:133-136` accepts `.zip/.tar.gz/.whl` | Confirmed contradiction (High) |
| Extractor depth/file scope | `TODO.md:8,11` says `.py-only`, `1-level` imports | — | `entry_extractor.py:113,209` includes `pyproject.toml`, 3-level BFS | Confirmed contradiction (High) |

## 6. Recommended Edit Order (fastest risk reduction first)

1. Fix deployment path mismatch (`DEPLOYMENT_MANIFEST.md` + `deployment.sh`) so malicious uploads work reliably.
2. Correct `CONCERNS.md` Section 2 and archive-format expectations to prevent methodological misinterpretation.
3. Update `README.md` and `docs/USAGE.md` step-number links to match manifest.
4. Refresh `src/analyzer/TODO.md` to current extractor design.
5. Clean low-risk wording and historical notes (`RISK_DIARY.md`, `adapters.py` docstring, optional authorship cleanup).

## 7. Open Questions / Missing Evidence

1. Should VM staging standardize on one malware folder name across both injector and analyzer paths (`malicious/` vs `malware_backstabbers_knife/`), or intentionally keep two views with a documented synchronization step?
2. Is `src/analyzer/CONCERNS.md` intended as thesis-facing artifact or internal engineering note? (affects tone, authorship line, and level of implementation detail).
3. Are `docs/ops/TODO.md` and `docs/ops/THESIS_TODO.md` considered archival logs or active docs? If active, they need consistency passes for removed modules and finalized dependency workflow.
