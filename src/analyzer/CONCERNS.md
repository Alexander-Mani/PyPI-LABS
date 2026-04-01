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

## 3. LLM Model Name Placeholders

**Affected files:** `configs/gpt.yaml`, `configs/gemini.yaml`

The evaluation spec referenced "Gemini 3.1 Pro" and "GPT-5.4". Neither is a real
API model identifier as of the time this code was written. The YAML configs
default to `gemini-1.5-pro` and `gpt-4o` respectively, which are real model IDs
but may not be the intended targets.

**Consequence:** If the intended models become available under different IDs, the
adapters will call the wrong (or a non-existent) model, producing API errors that
the `EvalController` will catch and record as error verdicts (`verdict=False`,
`confidence=None`). These errors will silently inflate the FP count for those
detectors.

**What to do:** Before running LLM evaluation, open `configs/gpt.yaml` and
`configs/gemini.yaml` and update the `model_name` field to the correct API
identifier. No Python code changes are required — the adapters dispatch entirely
on the YAML value.

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
