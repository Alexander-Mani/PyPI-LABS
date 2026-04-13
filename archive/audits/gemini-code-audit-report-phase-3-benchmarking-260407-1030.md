# Repo Audit Report — PyPI-SCADA Phase III Benchmarking
**Date:** 2026-04-07 10:30
**Auditor:** Gemini CLI (Audit Skill)

## 1. Executive Summary
The PyPI-SCADA project is architecturally sound and successfully implements the pivot to **Entry-Point Scanning**. The hardening decisions in the `RISK_DIARY.md` are robust, and the "Folder-based Truth" fix has secured the scientific integrity of the benchmarking data. However, legacy code removal and minor security hardening of the egress policy are recommended before live malware execution.

---

## 2. Audit Findings by Category

### a. Security
*   **[Critical] Egress Filtering (DNS Leak):** The `iptables` rules in `deployment.sh` allow UDP/TCP Port 53 for DNS resolution to any destination. A sophisticated malware payload could use DNS tunneling (similar to the real-world `torchtriton` attack) to exfiltrate data (e.g., system metadata or harvested tokens) via DNS queries to an attacker-controlled nameserver.
    *   *Recommendation:* Restrict Port 53 to a known-safe upstream DNS provider (e.g., Google or Cloudflare) rather than allowing global outbound Port 53.
*   **[High] Privilege Escalation:** While `pypi-runner` is unprivileged, it still runs in a shell with `~/.bashrc` access. 
    *   *Recommendation:* Use `rbash` (restricted bash) or a more restrictive profile if possible, though current isolation is acceptable for a lab environment.

### b. Bugs, Errors, and Quality Assurance
*   **[Medium] Archive Extraction Fault Tolerance:** `entry_extractor.py` uses a hardcoded password `b"infected"`. While standard for Backstabber's Collection, any malware sample with a different password will trigger a `RuntimeError` and be skipped.
    *   *Recommendation:* Log specific "Password Mismatch" vs "Corrupt Archive" errors to the `eval_result` table to differentiate between "Skipped" and "Failed" samples.
*   **[Low] SQLite Concurrency:** `DBManager` does not explicitly handle `SQLITE_BUSY` errors. In high-concurrency scenarios (multiple `EvalController` workers), writes might fail if the WAL mode isn't perfectly configured.

### c. Logical Errors in Methodology or Expected Outcome
*   **[Medium] Import Resolution Depth:** `_resolve_imports` in `entry_extractor.py` only resolves **one level deep**. Modern malware like `termncolor` might use multi-stage imports across three or four modules.
    *   *Recommendation:* Consider recursive import resolution up to a depth of 3 to capture more sophisticated stager chains.
*   **[Low] Heuristic Overlap:** The `base64_or_hex` check in `heuristic_filter.py` has a high overlap with standard API keys. This is documented in `CONCERNS.md` but should be highlighted in the thesis as a source of "Heuristic Noise."

### d. Logical Error in the Context of the Project
*   **[High] Detector Blindness Verification:** I have verified that `is_malicious` is **never** passed to the `DetectorAdapter.run()` method. The scientific "air-gap" is intact.
*   **[Medium] Ambiguous Proxy Config:** The LiteLLM configuration in `gpt.yaml` and `gemini.yaml` uses `proxy_url: "http://127.0.0.1:4000"`. If the proxy is not running during a remote VM run, the analyzer will record "benign" verdicts (default on exception) instead of "error."
    *   *Recommendation:* Change the default exception behavior in `adapters.py` to return `verdict="error"` rather than `False`.

### e. Code Cleanliness, Readability, and Simplification
*   **[Actionable] Legacy Code Removal:** The directory `src/credential_proxy/` and the file `src/analyzer/sql.py` (old diff-engine logic) are obsolete.
    *   *Recommendation:* **DELETE** `src/credential_proxy/` and `src/analyzer/diff.py` to prevent developer confusion.
*   **[Actionable] Adapter Naming:** `StaticAdapter` in `adapters.py` is aliased as `EntryPointStaticAdapter` in `detection_controller.py`. 
    *   *Recommendation:* Standardize on one name to simplify the codebase.

### f. Efficiency
*   **[Medium] Token Budget Truncation:** The `_build_file_listing` method truncates at 8000 characters. For large `setup.py` files or deeply nested packages, the most malicious code might be at the end of the file.
    *   *Recommendation:* Log a warning to the DB `details` field when truncation occurs so you can track if truncation correlates with False Negatives.
*   **[Low] Concurrency Bottleneck:** `EvalController` is capped at `max_workers=4`. Given the I/O-bound nature of API calls, this can be safely increased to 10-15 to speed up large benchmark runs.

---

## 3. Recommended Task List (Priority Order)
1.  **Refactor:** Delete `src/credential_proxy/` and legacy `diff.py` logic.
2.  **Harden:** Tighten iptables DNS rules in `deployment.sh`.
3.  **Fix:** Update `adapters.py` to return `verdict="error"` on API failure.
4.  **Improve:** Extend `_resolve_imports` to 2-3 levels of depth.
5.  **Log:** Add truncation warnings to the `EvalDetectionResult`.

---
*End of Report*
