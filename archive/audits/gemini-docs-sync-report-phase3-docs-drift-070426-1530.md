# Docs Sync Audit Report — Phase III Hardening Update
**Date:** 2026-04-07 15:30 UTC
**Auditor:** Gemini CLI (Docs Sync Skill)

## 1. Executive Summary
The project has undergone a significant "Phase III Hardening Sprint" which refactored the core extraction logic, purged legacy modules, and hardened the VM security posture. While `README.md` and `DEPLOYMENT_MANIFEST.md` have been updated recently, minor drift remains in `docs/USAGE.md` regarding sample directory paths and legacy port references. The scientific documentation (`CONCERNS.md`) is now fully synchronized with the Folder-based Truth implementation.

---

## 2. Scope and Inputs
- **Codebase Baseline:** `src/analyzer/` (3-level BFS, TOML support), `deployment.sh` (DNS hardening, ephemeral .netrc), `configs/models.json` (pricing authority).
- **Documentation Baseline:** `README.md`, `docs/USAGE.md`, `docs/ops/DEPLOYMENT_MANIFEST.md`, `docs/ops/RISK_DIARY.md`, `src/analyzer/CONCERNS.md`.

---

## 3. Findings by Severity

### Critical
*None.* (The most critical architectural shifts were patched in the previous turn).

### High
*   **[Operability] `docs/USAGE.md` Sample Path Contradiction (Confirmed):**
    *   *Finding:* Section 2 specifies sample paths as `data/samples/`.
    *   *Implementation:* `evaluate.py` and `deployment.sh` now exclusively use `samples/` at the repo root.
    *   *Impact:* A user following the USAGE guide will place files in the wrong directory, and `evaluate.py` will find zero archives.

### Medium
*   **[Accuracy] `docs/USAGE.md` Entry-Point Depth (Confirmed):**
    *   *Finding:* Still claims "1-level imports" in the Analyzer section.
    *   *Implementation:* Upgraded to 3-level BFS in `entry_extractor.py`.
    *   *Impact:* Documentation understates the power of the detection pipeline.
*   **[Consistency] `docs/USAGE.md` Legacy Port reference (Confirmed):**
    *   *Finding:* Mentions "port 9090" in troubleshooting or troubleshooting context related to `credential_proxy`.
    *   *Implementation:* `src/credential_proxy/` was deleted; LiteLLM on 4000 is the only active proxy.

### Low
*   **[Completeness] `TODO.md` stale entries (Confirmed):**
    *   *Finding:* Section F-4 still references `_build_ground_truth()` logic.
    *   *Implementation:* This function was removed in favor of direct tuple-based truth in discovery.

---

## 4. File-by-File Update Checklist

| File | Section | Required Change |
|---|---|---|
| `docs/USAGE.md` | 2. Injector | Update `data/samples/` -> `samples/` in prerequisites. |
| `docs/USAGE.md` | Typical Workflow | Update `1-level imports` -> `3-level BFS imports`. |
| `docs/USAGE.md` | Logs | Remove mentions of `src/analyzer/config.yaml` for log level if it's now authoritative in `evaluate.py`. |
| `src/analyzer/TODO.md` | Section F | Update F-4 description to "Folder-based labelling". |

---

## 5. Contradictions Matrix

| Topic | README | USAGE.md | Actual Code |
|---|---|---|---|
| **Sample Root** | `samples/` | `data/samples/` | `samples/` (root) |
| **Import Depth** | 3-level BFS | 1-level | 3-level BFS |
| **Proxy Port** | 4000 | 4000 (correct) | 4000 |
| **Truth Logic** | Folder-based | meta.json | Folder-based |

---

## 6. Recommended Edit Order
1.  **USAGE.md (High):** Fix the sample paths to prevent user setup failure.
2.  **USAGE.md (Medium):** Correct the import depth and remove legacy proxy port references.
3.  **TODO.md (Low):** Clean up the stale F-4 entry to reflect reality.

---

## 7. Open Questions / Missing Evidence
*   *Question:* Is the `samples/download_benign.py` script also updated to use the new `samples/` root, or does it still target `data/samples/`? (Inferred: needs verification).

---
*End of Report*
