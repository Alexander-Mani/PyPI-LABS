# Evaluation Module — Known Concerns

This document records design decisions and data interpretation issues that affect
how evaluation results should be read. These are not bugs — they are intentional
trade-offs or inherent properties of the dataset that must be understood before
drawing conclusions from the metrics output.

---

## 1. Account-Takeover Packages: Clean Pre-Compromise Releases

**Status: Ground truth labelling is correct as of the folder-based refactor.**

**Affected packages:** `num2words`, `ultralytics`

The benign download script collected all versions up to and including the Last
Known Good Release (LKGR). These clean pre-compromise versions live in
`samples/benign/{package}/` and are correctly labelled `is_malicious=False` by
the folder-based ground truth logic (folder membership, not `meta.json`).

**The remaining open item:** The compromised versions (e.g., num2words 0.5.15,
ultralytics 8.3.41) are the actual malicious releases. They must be present in
`samples/malware_backstabbers_knife/` for the evaluation to measure ATO
detection recall. If only clean versions are present, FN counts for these
packages will be zero — which is correct (they are benign) but does not
demonstrate ATO detection capability.

**What to do:** Source the compromised archive for each ATO package and add it
to `samples/malware_backstabbers_knife/`. Then re-run to see the ATO detection
confusion matrix.

---

## 2. Simulator-Resolved Input Is Required

**Affected component:** simulator resolver and `run()` in `evaluate.py`

The staged dataset is now used for candidate metadata and ground-truth labels,
but the analyzer scans artifacts downloaded from the local simulator. This keeps
the simulator central to the experiment while avoiding `pip install` and package
execution.

**Consequence:** If packages are staged on disk but not uploaded to the simulator,
the analyzer will not evaluate them. If malicious versions cannot be resolved
from the simulator, non-`--sast-only` runs halt because recall/F1 would be invalid.

**What to do:** Run the simulator, upload the staged dataset with
`upload_samples.py`, then run `python src/analyzer/evaluate.py --dry-run-resolution
--skip-validation` to verify the exact package/version/artifact set before a
budget or frontier evaluation.

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
| `gemini.yaml` | `gemini-2.5-pro` | frontier |
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

## 4. Latest-Version Package Selection

**Affected component:** simulator resolver in `evaluate.py`

Each package can have many versions and multiple artifacts per version. The
canonical evaluation runner resolves the latest stable labelled version of each
package from the simulator and scans all artifacts for that selected version.
This keeps the package selection rule consistent between full runs and test
profiles while preserving wheel-vs-sdist evidence.

**Consequence:** Metrics describe latest labelled package versions, not the
entire historical package universe. Packages with many wheels can produce many
artifact-level DB rows, so thesis metrics are aggregated at package-version
level to prevent artifact-heavy packages from dominating results.

**Mitigation path:** Use `--dry-run-resolution --skip-validation` before any paid
run. Report both artifact counts and package-version counts, and document that
test profiles cap package selection rather than artifact rows. LKGR samples
remain dataset/provenance context, but canonical scoring uses the latest
labelled stable package version. Regenerate canonical metrics after this change;
old DB rows may record the previous `sample_limits` resolver policy.

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

### R-05 (Resolved): Legacy vs Active Pipeline Confusion

**Status: Resolved in Phase 3 cleanup.**

The legacy diff pipeline (`diff.py`, `sql.py`, `main.py`) was entirely purged from the repository. The active entry-point scanning architecture in `evaluate.py` is now the only detection path, eliminating any operational or architectural ambiguity for examiners.

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

## 7. Hybrid vs Raw Divergence on Typosquat Samples

**Status: Observed in test-profile validation run `43fae0ba-411f-47d4-b961-def9f3b17822`. Investigate before canonical-v2 budget burn.**

**Affected package:** `nmap-python` (Typosquatting, confirmed malicious)

**Observation:** In the 4-package test-profile run (2 control + 2 malicious), `nmap-python` was flagged malicious by every static detector (Bandit, Semgrep, GuardDog) and by most `llm_raw` calls across all budget LLMs, but produced inconsistent false-negative outcomes under `hybrid` mode — multiple budget providers returned `verdict=False` on the hybrid prompt while returning `verdict=True` on the same sample under `llm_raw`. The sibling typosquat sample `colourama` did not exhibit the same gap; it was flagged consistently across hybrid and raw.

**Why it matters:** If the gap is a prompt-template or entry-point-extraction artefact (e.g., the hybrid path dropping a file the LLM needs for the verdict that `llm_raw` preserves), canonical-v2 `hybrid` numbers will systematically under-detect a class of typosquats across every tier — not just budget. The finding then becomes a measurement artefact rather than a real RQ signal on prompt-strategy sensitivity.

**What to do before canonical-v2:**
1. Read the rendered `hybrid` prompt blob for `nmap-python` in the validation run and compare to the `llm_raw` payload. Identify which code content differs between the two modes.
2. Inspect the LLM's returned `reasoning` text on the hybrid FN rows — does the model explicitly reason "insufficient evidence" or does it confidently declare benign on the trimmed content?
3. If the gap is an extraction/template bug, fix it and re-run the test profile before spending frontier-tier API budget.
4. If the gap reflects genuine prompt-sensitivity behaviour, leave it in canonical-v2 and document it as an RQ2/RQ-prompt-strategy finding rather than silently averaging it away.

---

## 8. Frontier-Model Recognition of Named Incident Packages

**Status: Pre-existing limitation; acknowledged in thesis validity section as
Decision 6 residual. Controlled with a source-free sidecar probe, not with
benchmark metrics.**

**Affected packages:** `colourama`, `num2words`, `ultralytics` — any malicious sample whose compromise is a public incident with published writeups.

**Observation:** Frontier-tier LLMs are trained on public security writeups. When the package name alone signals a known incident (`colourama` as the classic `colorama` typosquat, `ultralytics 8.3.41` as a GitHub Actions supply-chain compromise, `num2words 0.5.15` as a known ATO case), the model may be recalling the published incident rather than reasoning from the supplied source code.

**Why it matters:** A frontier-LLM "correct" verdict on `colourama` does not prove the LLM can detect unseen typosquats — it may prove only that the LLM read about `colourama` during pre-training. This is the residual risk of Decision 6 (folder-based ground truth, `docs/ops/RISK_DIARY.md`). It weakens external-validity claims under RQ1 unless explicitly controlled for.

**Implemented controls:**
`scripts/model_memory_probe.py` runs a name/version-only recognition probe
through LiteLLM. It sends no source code, no extracted evidence, no ground-truth
label, no Backstabber's Knife reference, and no dataset membership. Cases live
in `configs/model_memory_probe_cases.json` and include known public incident
names plus benign/decoy controls. Results are written as JSONL under
`logs/model_memory_probe/`.

`src/analyzer/evaluate.py --identity-alias-probe` runs a cheap source-based
identity-sensitivity probe. It masks package names and versions as neutral
aliases such as `X001` / `V001`, then runs only `hybrid:zero_shot` across the
selected non-agentic models. It skips static tools, raw LLM mode, prompt
strategy sweeps, agentic mode, and financial validation. Rows are written to
`eval_results.db` under the original package/version but include
`identity_mask="alias"` and `alias_probe=true` in result details. Use
`scripts/check_identity_alias_leaks.py --run-id <run_id>` to verify that
model-facing request blobs did not contain original identity terms.

Example:

```bash
python scripts/model_memory_probe.py --profile budget --dry-run
python scripts/model_memory_probe.py --profile frontier
python src/analyzer/evaluate.py --profile all_models --identity-alias-probe
```

**Interpretation rule:**
Neither probe is a contamination detector and neither can prove that a model was
or was not trained on a specific package artifact. The realistic risk is public
incident prior knowledge from advisories, news, forums, package lists, and
writeups. If a model recognizes `colourama==0.1.6` or `ultralytics==8.3.41` in
the source-free setting, final thesis interpretation should treat code-based
success on those packages as potentially aided by prior public knowledge. If a
canonical source run detects a package but the alias run misses it, interpret
that as identity sensitivity. If the alias run still detects it, source evidence
appears sufficient even without package identity. If the model does not recognize
a case, that still does not prove the benchmark verdict was source-derived.

**What to do in the thesis:**
- Continue to name this as a Decision 6 residual in the Validity section.
- Report source-free and identity-alias probe results in an appendix or validity subsection,
  separate from the detector metrics table.
- Use the probe as a sanity check when interpreting unusually strong results on
  famous public incidents, not as a row-level correction factor.

---

## 9. Empty or Malformed Model Responses Must Not Become Benign Rows

**Status: Fixed in adapters; historical DBs may need normalization.**

**Observation:** Some LiteLLM calls can return an empty assistant body or a
non-JSON/prose response while still producing tokens and cost metadata. The old
parser path preserved that text in `details.raw` but returned `verdict=False`,
which made the row look like a benign classification.

**Why it matters:** This is a false-negative accounting bug. A model that failed
the required response protocol did not classify the package as benign. Counting
these rows in metrics penalizes or rewards detectors for provider/protocol
failures instead of detection behavior.

**Implemented control:** Hybrid, raw-LLM, and agentic adapters now store these
cases as `experiment_mode="error"` with `details.protocol_failure=true`.
Empty responses are marked `details.retryable=true`; malformed non-empty outputs
are marked `details.retryable=false` unless a later retry policy explicitly
decides otherwise. Token counts and LiteLLM-reported costs are preserved so
provider reliability and spend can still be audited.

**Historical cleanup:** Run `scripts/normalize_llm_protocol_failures.py` against
older databases before interpreting them. The script dry-runs by default, checks
for unique-key collisions, and creates a timestamped backup before applying.
