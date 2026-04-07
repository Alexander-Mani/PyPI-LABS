# Code Audit Report: PyPI-SCADA

## 1. Executive Summary
This repository has a strong capstone structure and clear research intent, but the current state contains several material risks that can invalidate runs or weaken thesis defensibility if not addressed before final evaluation. The most serious issues are: dependency security policy drift (lockfile/hashes not actually present), extractor behavior not matching stated entry-point methodology (`pyproject.toml` is not extracted), and proxy/config drift (`9090` vs `4000`) that can silently break LLM execution assumptions.

Overall judgment: solid architecture and direction, but final-phase hardening is required for scientific and operational integrity.

## 2. Audit Scope and Method
- Audited primary runtime modules in `src/analyzer`, `src/simulator`, `src/injector`, `src/data`, and supporting docs/config.
- Prioritized evidence-backed findings from executable paths and config/doc consistency.
- Checked for test coverage presence, dependency/security controls, and methodology-to-code alignment.
- Classified findings by severity and by requested categories A-F.

## 3. Findings by Severity

### Critical

1. Dependency-security policy is declared but not implemented in repository artifacts (A: Security, B: QA, D: Project-context)
- Evidence:
  - [`README.md:110`](/home/lexman/ru_spring_2026/PyPi-SCADA/README.md:110) requires hashed lockfile installation with `--require-hashes`.
  - [`README.md:140`](/home/lexman/ru_spring_2026/PyPi-SCADA/README.md:140) states hashed lockfiles are mandatory.
  - [`docs/USAGE.md:10`](/home/lexman/ru_spring_2026/PyPi-SCADA/docs/USAGE.md:10) repeats same requirement.
  - [`requirements.txt:1`](/home/lexman/ru_spring_2026/PyPi-SCADA/requirements.txt:1) is not hash-pinned (plain package list).
- Impact:
  - `pip install --require-hashes` fails or policy is bypassed, defeating stated supply-chain control.
  - Reproducibility and security claims in report become non-verifiable.
- Mitigation:
  - Generate and commit a true hashed lockfile (`pip-compile --generate-hashes` or equivalent).
  - Add CI/preflight check that fails if hashes are missing.

2. Entry-point methodology is partially broken: extractor never ingests `pyproject.toml` from archives (C: Methodology, D: Project-context)
- Evidence:
  - Method claims include scanning `pyproject.toml` as core entry point: [`README.md:7`](/home/lexman/ru_spring_2026/PyPi-SCADA/README.md:7).
  - Extractors only collect `.py` files in tar/whl/zip: [`src/analyzer/entry_extractor.py:107`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/entry_extractor.py:107), [`src/analyzer/entry_extractor.py:124`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/entry_extractor.py:124), [`src/analyzer/entry_extractor.py:152`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/entry_extractor.py:152).
  - Filtering expects `pyproject.toml`, but it cannot appear because it was never read.
- Impact:
  - Blind spot in install-time behavior analysis.
  - Methodology-to-implementation mismatch weakens thesis claims.
- Mitigation:
  - Include `.toml` extraction for `pyproject.toml` explicitly in all archive readers.
  - Add regression test fixture proving pyproject extraction and downstream heuristics.

### High

3. Proxy routing drift can silently break LLM execution path assumptions (A, B, D)
- Evidence:
  - Analyzer config points to `9090`: [`src/analyzer/config.yaml:8`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/config.yaml:8).
  - Model configs and docs target LiteLLM on `4000`: [`src/analyzer/configs/gpt.yaml:4`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/configs/gpt.yaml:4), [`docs/USAGE.md:244`](/home/lexman/ru_spring_2026/PyPi-SCADA/docs/USAGE.md:244).
- Impact:
  - Operators can run the wrong proxy stack or misinterpret failures.
  - Cost/latency/results can differ from documented threat model.
- Mitigation:
  - Unify to one canonical endpoint path (LiteLLM `4000`) and mark `credential_proxy` as legacy-only in active configs.
  - Add preflight endpoint check and fail-fast startup.

4. Missing malware archive directory invalidates full benchmark outcomes (B, C, D)
- Evidence:
  - `samples/malware_backstabbers_knife` is currently missing in workspace (command check).
  - Runner explicitly degrades to FP-only benchmark when missing: [`src/analyzer/evaluate.py:124`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/evaluate.py:124).
- Impact:
  - No valid recall/F1 inference for malicious detection.
  - Final conclusions can be misread as complete when they are not.
- Mitigation:
  - Add hard gate for final runs: fail if malware count < expected threshold.
  - Include sample inventory and run manifest in thesis appendix.

5. Runtime dependencies are incomplete relative to actual execution paths (A, B, F)
- Evidence:
  - `requirements.txt` lacks several runtime-used packages (`openai`, `google-generativeai`, `twine`, `packaging`): [`requirements.txt:1`](/home/lexman/ru_spring_2026/PyPi-SCADA/requirements.txt:1).
  - Adapters import `openai` and `google.generativeai`: [`src/analyzer/adapters.py:243`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/adapters.py:243), [`src/analyzer/adapters.py:302`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/adapters.py:302).
  - Injector uploader calls `python -m twine`: [`src/injector/upload_samples.py:91`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/injector/upload_samples.py:91).
  - Version sort optionally imports `packaging.version`: [`src/injector/upload_samples.py:61`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/injector/upload_samples.py:61).
- Impact:
  - Environment setup may pass policy checks but fail operationally.
  - Reproducibility and deployment reliability are reduced.
- Mitigation:
  - Rebuild dependency spec from actual imports and CLI tool usage.
  - Add smoke scripts for SAST-only and LLM-enabled setups.

### Medium

6. Documentation and code comments are stale after ground-truth refactor (B, C, E)
- Evidence:
  - `evaluate.py` top docstring still states ground truth from `meta.json`: [`src/analyzer/evaluate.py:5`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/evaluate.py:5).
  - `TODO.md` still marks `_build_ground_truth()` task despite current source-aware labeling: [`src/analyzer/TODO.md:46`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/TODO.md:46).
  - `CONCERNS.md` section 1 still describes old name-keyed behavior: [`src/analyzer/CONCERNS.md:19`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/analyzer/CONCERNS.md:19).
- Impact:
  - Methodology narrative diverges from implementation.
  - Examiner trust can drop when document and code disagree.
- Mitigation:
  - Update docs to reflect per-archive folder-based ground truth.
  - Maintain a changelog subsection for methodology pivots.

7. No automated test suite found for critical paths (B, E)
- Evidence:
  - Repository scan shows no test files (`tests/`, `test_*.py`, etc.).
- Impact:
  - Refactors can silently regress extraction, labeling, and DB writes.
- Mitigation:
  - Add minimal deterministic tests:
    - extractor includes setup/init/pyproject
    - ground-truth propagation to `eval_result.ground_truth`
    - SAST-only execution path

8. Benign/control archive selection accepts `.zip` in flat uploader (B, F)
- Evidence:
  - `ARCHIVE_SUFFIXES` includes `.zip` for benign/control paths: [`src/injector/upload_samples.py:127`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/injector/upload_samples.py:127).
- Impact:
  - Twine attempts on non-distribution zips can generate noisy failures and wasted runtime.
- Mitigation:
  - Restrict benign/control uploads to `.tar.gz` and `.whl` only.

### Low

9. Legacy vs active analyzer paths remain co-located and can confuse operation (D, E)
- Evidence:
  - Active pipeline in `evaluate.py`; legacy diff pipeline still present in `main.py/diff.py/sql.py`.
- Impact:
  - Operational ambiguity and reporting inconsistency.
- Mitigation:
  - Mark legacy entry points as deprecated in code headers and README architecture section.

10. Minor script/doc hygiene drift (E)
- Evidence:
  - `controller.sh` header says `yq` required, but parser uses inline Python: [`src/injector/controller.sh:9`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/injector/controller.sh:9), [`src/injector/controller.sh:17`](/home/lexman/ru_spring_2026/PyPi-SCADA/src/injector/controller.sh:17).
- Impact:
  - Setup confusion for contributors.
- Mitigation:
  - Correct script header comments and prerequisites.

## 4. Findings by Category (A-F)

### A. Security
- Critical: dependency lock/hash policy not materially enforced in committed artifacts.
- High: proxy endpoint drift can bypass intended key-isolation architecture.
- High: missing explicit dependency declaration for security-critical runtime tools.

### B. Bugs, Errors, and Quality Assurance
- High: runtime dependency incompleteness can break common execution flows.
- Medium: stale docs/comments create QA blind spots and incorrect operator assumptions.
- Medium: no automated tests for critical dataflow and labeling logic.

### C. Logical Errors in Methodology / Expected Outcome
- Critical: `pyproject.toml` advertised as analyzed but not actually extracted.
- High: malware-missing condition can produce FP-only runs and invalidate recall claims.
- Medium: historical concern docs still describe superseded ground-truth model.

### D. Logical Errors in Project Context
- Critical/High cluster: security/reproducibility claims in thesis docs are stronger than current repository state.
- High: configuration split between 9090/4000 undermines deployment narrative consistency.
- Low: legacy/active pipeline ambiguity weakens final presentation clarity.

### E. Code Cleanliness, Readability, Simplification
- Medium: stale TODO/CONCERNS/evaluate docstring after methodology pivot.
- Low: legacy and active paths should be cleaner separated or explicitly deprecated.
- Low: minor script prerequisite comment drift.

### F. Efficiency
- Medium: benign/control `.zip` acceptance creates avoidable failed twine calls.
- Inference: repeated discovery calls in validation and run paths add small avoidable I/O overhead.

## 5. Remediation Roadmap

### Immediate (before next benchmark run)
1. Generate and commit a real hashed lockfile; enforce via CI/preflight.
2. Fix extractor to include `pyproject.toml` from all archive formats and validate with tests.
3. Unify proxy endpoint configuration (`4000` LiteLLM) across active config/docs.
4. Add run gate that refuses "final" run when malware sample set is missing.

### Near-term (before final report freeze)
1. Add focused tests for extractor, ground-truth persistence, and SAST-only mode.
2. Update `CONCERNS.md`, `TODO.md`, and evaluate docstrings to match current source-aware ground truth behavior.
3. Restrict uploader benign/control file types to valid distributions only.

### Later (cleanup and maintainability)
1. Isolate/deprecate legacy analyzer path explicitly.
2. Add lightweight benchmarking hooks for performance/cost regression visibility.

## 6. Open Questions / Missing Evidence
1. Is there a private/ignored hashed lockfile not present in this workspace? If yes, where is it generated and validated?
2. Is `src/analyzer/config.yaml` still used operationally, or are per-model configs now authoritative only?
3. What is the canonical expected malware archive count for a "complete" evaluation run?
4. Is the custom `credential_proxy` intentionally maintained for fallback, or should it be removed from active docs and config references?

## 7. Appendix

### Commands Run
- `git status --short`
- `date -u +%d%m%y-%H%M`
- `rg --files`
- `find . -maxdepth 3 -type d`
- `sed -n ...` / `nl -ba ...` on audited files
- `rg --files | rg -n "test|tests|pytest|unittest"`
- `if [ -d samples/malware_backstabbers_knife ]; then ...`

### Assumptions
- Audit based on current workspace contents on April 7, 2026 (UTC).
- Findings prioritize active entry-point pipeline used by `src/analyzer/evaluate.py`.

### Limitations
- No runtime integration test was executed during this audit (static code + config/doc consistency review).
- Some deployment behaviors may depend on private VM setup not represented in this repository snapshot.
