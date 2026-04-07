# Evaluation Module — Known Concerns

This document records design decisions and data interpretation issues that affect
how evaluation results should be read. These are not bugs — they are intentional
trade-offs or inherent properties of the dataset that must be understood before
drawing conclusions from the metrics output.

---

## 1. Ground Truth Labelling for Account-Takeover Packages

**Affected packages:** `num2words`, `ultralytics`

The benign download script collects all versions of these packages up to and
including the Last Known Good Release (LKGR). In `meta.json`, both packages
have `malicious_package == target_package` because the attacker did not register
a separate name — they took over the real package and pushed a poisoned update.

As a result, the evaluation runner's ground truth builder labels these packages
as `True` (malicious), even though every archive in `benign/num2words/` and
`benign/ultralytics/` is a clean, pre-compromise release.

**Consequence:** Every detector will produce a False Negative on these packages.
This is expected and correct behaviour — the clean archives genuinely do not
contain the injected payload, so a well-functioning detector *should* return
benign. The FN count for account-takeover packages therefore measures how much
of the poisoned version's signal "leaked" into pre-compromise releases (ideally
none). Do not interpret these FNs as detector failures.

**Mitigation path:** If you want to measure true account-takeover detection
performance, the malicious versions (0.5.15 for num2words, 8.3.41 for
ultralytics) must be added to the malware archive set and evaluated separately.

---

## 2. Malware Archives Not Present on Disk

**Affected component:** `_discover_malware()` in `evaluate.py`

The directory `samples/malware_backstabbers_knife/` is excluded from version
control (`.gitignore`) and does not currently exist on disk. When the evaluation
runner starts, it logs a warning and returns an empty malware list, so the entire
run executes as a **false-positive-only benchmark** — no malicious samples are
processed, all ground truth labels are `False` (benign), and no True Positives or
False Negatives are possible.

**Consequence:** Precision, Recall, and F1 are undefined (division by zero
guarded against) until at least one malware archive is present. The TP/FP/TN/FN
table will show only TN and FP columns populated.

**What to do:** Download or restore the password-protected `.zip` archives to
`samples/malware_backstabbers_knife/{category}/{package}.zip` using the password
`"infected"`. The directory structure expected is described in `SAMPLES.md`.
Once present, re-run `evaluate.py` to get a complete confusion matrix.

---

## 3. LLM Model Names and LiteLLM Routing

**Affected files:** `configs/gpt.yaml`, `configs/gemini.yaml`, `configs/claude_opus.yaml`, `configs/claude_agentic.yaml`, `configs/together_frontier.yaml`

All LLM calls route through LiteLLM on `http://127.0.0.1:4000`. Model names in the
YAML configs use bare model IDs; LiteLLM infers the provider from the prefix.
The full model grid is in `configs/models.json` (repo root).

Current confirmed model IDs per config:

| Config file | model_name | Tier |
|---|---|---|
| `claude_opus.yaml` | `claude-opus-4-6` | frontier |
| `claude_agentic.yaml` | `claude-opus-4-6` | frontier |
| `gpt.yaml` | `gpt-5.4` | frontier |
| `gemini.yaml` | `gemini-3.1-pro-preview` | frontier |
| `together_frontier.yaml` | `together_ai/Qwen/Qwen3.5-397B-A17B` | frontier |

**LiteLLM routing prefixes used by the adapter dispatch (`_call_api`):**
- `claude-` → Anthropic
- `gpt-`, `o1-`, `o3-`, `together_ai/` → OpenAI-compatible
- `gemini-`, `gemini/` → Google

**Consequence if model ID is wrong:** LiteLLM returns 404 or routing error.
`EvalController` catches this and records `verdict=False, confidence=None`,
silently inflating the FP count for that detector.

**What to do:** Verify model IDs are active API identifiers before a run. Budget
and medium tier alternatives are listed in `configs/models.json`.

---

## 4. Benign Version Selection (Latest Only)

**Affected component:** `_discover_benign()` in `evaluate.py`

Each package in `samples/benign/` has many historical versions (e.g., colorama
has 46, ultralytics has 465). The evaluation runner takes only the **last entry**
from each `manifest.json` (the most recent version) rather than processing every
version. This avoids hundreds of redundant API calls for the LLM and agentic
pipelines, but it means the false-positive measurement is based on a single
snapshot per package, not a distribution across the package's full history.

**Consequence:** A package version that happens to contain a suspicious-looking
but entirely benign pattern (e.g., a legitimate base64-encoded resource embedded
in a wheel) could inflate the FP rate in a way that would average out across
multiple versions. The SAST pipeline is particularly susceptible to this since
Bandit flags patterns without semantic understanding.

**Mitigation path:** Add a `--all-versions` flag to `evaluate.py` that iterates
every manifest entry rather than just the last. Use this for deep false-positive
characterisation runs; use the default (latest only) for rapid iteration.

---

## 5. Heuristic Filter False-Positive Sensitivity

**Affected component:** `heuristic_filter.py`, `"base64_or_hex"` check

The base64 detection regex `[A-Za-z0-9+/]{40,}={0,2}` matches any alphanumeric
string longer than 40 characters. This includes SHA hashes, long URLs, JWT
tokens, certificate fingerprints, and lengthy variable names — all of which
appear routinely in legitimate packages. The flag is a low-signal triage hint,
not a verdict signal.

**Consequence:** Nearly every large, real-world package (boto3, requests, etc.)
will receive the `base64_or_hex` heuristic flag. This is intentional — the
heuristic layer is designed to be high-recall and low-precision, leaving the
actual verdict to the SAST and LLM pipelines. Do not use heuristic flag counts
as a proxy for malice.

---

## 6. Capstone Delivery Risk Register (Ordered)

This section reframes the technical concerns above as capstone-grade delivery
risks: what can hurt the final project evaluation, how to detect it early, and
how to mitigate it with concrete, verifiable actions.

### R-01 (Critical): Incomplete Malware Coverage During Final Evaluation

**Risk statement:** Final runs are executed without the malware archive set
present on disk, producing only benign/FP metrics.

**Why it matters for grading:** Examiners may conclude the project failed to
demonstrate detection efficacy on malicious inputs, undermining the core thesis.

**Early warning signals:**
- Startup warning about missing `samples/malware_backstabbers_knife/`.
- Metrics table shows only TN/FP, with TP/FN always zero or undefined.

**Detailed mitigations:**
1. Add a pre-run gate in the execution checklist: fail the run if malicious
   archive count is below the expected dataset minimum.
2. Keep a signed sample inventory file (package, hash, source, retrieval date)
   in the thesis appendix and repository docs.
3. Run one mandatory "smoke confusion matrix" before final benchmarking and
   archive the output table as evidence.

**Acceptance criteria before final presentation:**
- Malware directory exists and contains the expected zip set.
- At least one run produces non-zero TP or FN counts.
- Run log and table are attached to final report artifacts.

### R-02 (High): Ground-Truth Labelling Ambiguity for Account-Takeover Cases

**Risk statement:** Clean pre-compromise versions of `num2words` and
`ultralytics` are labeled malicious in ground truth logic, generating expected
FNs that can be misread as detector failure.

**Why it matters for grading:** If not explicitly explained, metric readers can
interpret systematic FNs as poor engineering quality.

**Early warning signals:**
- FN counts are consistently present for these packages even when code is benign.
- Reviewer questions about "why detectors miss obvious malicious cases."

**Detailed mitigations:**
1. Split account-takeover evaluation into two explicit cohorts:
   `pre_compromise_benign` and `compromised_release_malicious`.
2. Add compromised versions as separate malware entries and report them in a
   dedicated table.
3. Include an interpretation note directly under confusion matrices in the
   report and presentation slides.

**Acceptance criteria before final presentation:**
- Report contains a subsection defining account-takeover label semantics.
- Confusion matrix includes or references compromised-release evaluation rows.

### R-03 (High): Reproducibility Drift from Model Routing/Configuration

**Risk statement:** Wrong model identifiers, changed provider aliases, or proxy
routing issues silently degrade results and inflate error-like verdicts.

**Why it matters for grading:** Weakens scientific reproducibility and can make
cross-model comparisons invalid.

**Early warning signals:**
- Sudden spikes in low-confidence benign/error-like outputs for one detector.
- Proxy/adapter logs show 404, routing, or provider mismatch responses.

**Detailed mitigations:**
1. Freeze a run manifest: git commit, config checksums, model IDs, proxy
   endpoint, and execution timestamp.
2. Add a preflight "model reachability" script that calls each configured model
   with a tiny known prompt and fails on routing errors.
3. Record LiteLLM request/response metadata and attach it as evidence for the
   final benchmark run.

**Acceptance criteria before final presentation:**
- Preflight model validation passes for all enabled detectors.
- Final report includes exact model IDs and config snapshot references.

### R-04 (Medium): Evaluation Bias from "Latest-Only" Benign Sampling

**Risk statement:** Using only the newest benign version per package may distort
false-positive behavior versus full historical distribution.

**Why it matters for grading:** Limits validity claims and can overstate or
understate detector quality.

**Early warning signals:**
- High variance between packages with similar risk profiles.
- Reviewer asks whether results hold across version history.

**Detailed mitigations:**
1. Keep the default fast mode for iteration, but run a secondary historical mode
   (`all versions`) for a subset of representative packages.
2. Report both results: "rapid benchmark" and "history-sensitive benchmark."
3. Treat differences as an explicit finding, not as noise.

**Acceptance criteria before final presentation:**
- At least one historical-version sensitivity run is documented.
- Final report discusses external-validity limits of latest-only sampling.

### R-05 (Medium): Legacy vs Active Pipeline Confusion

**Risk statement:** Repository contains both legacy diff pipeline and active
entry-point pipeline; evaluators may not know which outputs are authoritative.

**Why it matters for grading:** Can create perceived inconsistency in design,
implementation maturity, and reported outcomes.

**Early warning signals:**
- Questions about why `main.py` (diff) and `evaluate.py` (entry-point) coexist.
- Conflicting logs/databases from separate execution paths.

**Detailed mitigations:**
1. Add one canonical "authoritative pipeline" note in `README.md` and thesis:
   entry-point evaluation is primary, diff pipeline is legacy/reference.
2. Name output databases and report tables with pipeline prefixes.
3. Include a one-page architecture delta ("design pivot rationale") in report.

**Acceptance criteria before final presentation:**
- All final metric tables are explicitly tagged with pipeline name.
- Presentation includes one slide clarifying legacy vs active status.

### R-06 (Medium): Evidence Gaps in Verification and Testing

**Risk statement:** Core claims are not backed by clear verification artifacts
(smoke tests, run logs, environment manifest, reproducible commands).

**Why it matters for grading:** Reduces confidence that results are reproducible
and engineering process is disciplined.

**Early warning signals:**
- "Works on my machine" style claims without attached logs.
- Missing end-to-end command transcript for final run.

**Detailed mitigations:**
1. Maintain a release-candidate checklist for final evaluation week:
   environment setup, dataset verification, preflight checks, full run, archive.
2. Store immutable artifacts (stdout/stderr logs, DB export, config snapshot,
   git commit hash) under a dated `artifacts/` directory.
3. Add a concise verification appendix in thesis with exact commands.

**Acceptance criteria before final presentation:**
- One complete reproducible run package is available end-to-end.
- Supervisor/examiner can replay the workflow from documented steps.

---

### Author Note

Risk register section (Section 6) written by Codex (GPT-5) on April 7, 2026.
