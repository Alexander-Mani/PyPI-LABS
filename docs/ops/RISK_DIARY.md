# Risk Diary — PyPi-SCADA Experiment

Records security decisions made for the VM deployment phase.
Each entry states the decision, the threat it addresses, and any residual risk.

---

## Decision 1 — Unprivileged execution account (`pypi-runner`)

**Decision:**
All pipeline components (simulator, injector, analyzer) run under a dedicated
`pypi-runner` system account with no sudo privileges. The existing `lexi` sudoer
account and `root` are not used for any experiment activity.

**Threat addressed:**
During the evaluation pipeline, `bandit` and `semgrep` are invoked as subprocesses
on extracted package source code. A malicious sample that achieves code execution
at extraction time (e.g. a weaponised `setup.py` or import-time payload) would
execute with the same privileges as the scanner process. Under `root` or a sudoer,
such a payload could escalate to full system compromise — modifying the OS, exfiltrating
secrets stored elsewhere on the host, or pivoting to other machines on the network.

**Controls applied:**
- `pypi-runner` has no entry in `/etc/sudoers`.
- No SUID binaries are owned by or writable by `pypi-runner`.
- Home directory and experiment dirs are owned exclusively by `pypi-runner`; other
  accounts (including `lexi`) have no write access to those paths.

**Residual risk:**
Local privilege escalation via unpatched kernel or SUID binary. Accepted — the VM
is a dedicated lab host with no production workloads, and the kernel is kept patched
via automated security updates.

---

## Decision 2 — API keys via environment variables, not YAML config files

**Decision:**
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, and `TOGETHER_API_KEY` are
stored in `~proxy-runner/.env` (permissions `0600`, owned by `proxy-runner`) and
exported into the LiteLLM proxy process only. The `pypi-runner` account that runs the
analyzer holds **no API keys** in its environment. Keys are never written into any YAML
config file checked into the repository.

**Threat addressed:**
Config files are committed to git. Keys embedded in YAML would appear in repository
history and be accessible to anyone with read access to the repo — including any
future public mirror. A leaked API key allows an adversary to consume paid API quota
and potentially access models with the experiment's identity.

**Controls applied:**
- `.env` is in `.gitignore`.
- YAML config files contain only structural parameters (model names, prompt paths,
  database paths, proxy URL). They contain no secret values.
- LiteLLM reads the provider keys from `proxy-runner`'s environment and proxies
  requests from `pypi-runner` at `http://127.0.0.1:4000`. No vendor SDK imports
  are required in the analyzer process.

**Residual risk:**
Process environment inspection of the `proxy-runner` process by a co-resident
process with ptrace capability. Accepted — the VM hosts only the experiment.

---

## Decision 3 — Per-process egress filtering via iptables owner module

**Decision:**
Egress filtering is applied per-user account rather than blanket NIC isolation. This
allows the `proxy-runner` process (LiteLLM) to reach vendor API endpoints while
preventing the `pypi-runner` analyzer process from making any outbound connection.
Dependency and repository pulls happen before isolation is applied.

**Threat addressed:**
Malicious packages routinely beacon to command-and-control servers on import or during
`setup.py` execution. Without network isolation:
- C2 infrastructure could receive confirmation that the package was analysed, alerting
  threat actors.
- The sample could exfiltrate environment variables (API keys) or VM metadata.
- Traffic logs become ambiguous — it is unclear whether observed connections are from
  the experiment harness or from the malware payload itself.

**Controls applied:**

```bash
sudo modprobe xt_owner

# pypi-runner: all non-loopback outbound traffic dropped
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner ! -o lo -j DROP

# proxy-runner: loopback always allowed
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT

# proxy-runner: LLM vendor endpoints only, resolved at deployment time
for host in api.anthropic.com api.openai.com generativelanguage.googleapis.com api.together.xyz; do
  for ip in $(getent ahostsv4 "$host" | awk '{print $1}' | sort -u); do
    sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d "$ip" -p tcp --dport 443 -j ACCEPT
  done
done
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP
```

**Residual risk:**
DNS-over-HTTPS payloads tunnelling over localhost-forwarded ports; unlikely in the
lab network topology. Also, if the malware payload targets the local simulator's
HTTP port (8080), it could interact with the simulated index — logged but not blocked.
LLM vendor CDN IPs can rotate after deployment, so long-running VMs may need the
egress rules refreshed by rerunning the firewall step or redeploying.

---

## Decision 5 — Isolated credential proxy for LLM API keys (implemented via LiteLLM)

**Decision:**
LLM API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`,
`TOGETHER_API_KEY`) are held exclusively by the `proxy-runner` account, which runs
**LiteLLM** on `http://127.0.0.1:4000`. The analyzer process (`pypi-runner`) carries
no API keys in its environment. All LLM calls go through `http://127.0.0.1:4000`
using the OpenAI-compatible API; no vendor SDKs are imported in the analyzer.

**Note on implementation history:** A custom Flask proxy (`src/credential_proxy/server.py`)
was built to implement this threat model and wired into `detection_controller.py`
(proxy dispatch at port 9090). This was subsequently replaced by LiteLLM, which
provides a production-grade implementation of the same isolation. The legacy custom
proxy code has been deleted from the repository.

**Threat addressed:**
Decision 2 moved API keys from config files into environment variables. A
sufficiently capable malicious package can still harvest environment variables
at import time or via `setup.py` execution within the analyzer process. It can
then encode the keys in a request payload (e.g. as part of the JSON it expects
from an LLM) and exfiltrate them through the single outbound channel that
existing iptables rules permit. The attacker gets a paid-API credential without
triggering any process-level anomaly.

**Controls applied:**
- `pypi-runner` environment: no `*_API_KEY` variables set. Any attempt to read
  them from `os.environ` in the analyzer raises `KeyError`.
- `proxy-runner` account: separate unprivileged user, separate login shell,
  separate `~proxy-runner/.env` (chmod 600). Only this account's processes can
  read the keys.
- Egress policy enforced per Decision 3 iptables owner rules.
- LiteLLM binds to `127.0.0.1:4000` only — no external exposure.

**Residual risk:**
A malicious package that discovers `127.0.0.1:4000` and crafts a valid LiteLLM
request could use the proxy as an unwitting relay to exfiltrate content to the
LLM provider (e.g. embedding secrets in a user message). Accepted: the payload
would be package source code already held on the execution VM, not new secrets,
and the provider's logging would record the request under the experiment's API
key identity.

---

## Decision 4 — Malicious archive staging

**Decision:**
Deployment extracts the single password-protected malicious bundle
(`malware_backstabbers_knife.zip`, password `infected`) into the ignored VM-local
repo staging directory `samples/malware_backstabbers_knife/`. The uploader then
uploads the staged distribution artifacts into the simulator. The analyzer does
not scan this staging directory directly; it resolves and downloads selected
artifacts from the simulator before static analysis.

**Threat addressed:**
Extracted malicious distribution archives could persist on disk after the
experiment, representing an ongoing risk if the VM is repurposed or audited.

**Controls applied:**
- Deployment clears and recreates
  `samples/malware_backstabbers_knife/` before extracting the encrypted bundle,
  preventing stale package archives from previous runs.
- `samples/` is git-ignored and VM-local; it must not be committed or copied to
  non-experiment systems.
- Legacy extraction target: `/tmp/pypi-scada-staging/<uuid>/` — unique per zip,
  removed with `shutil.rmtree` after upload.
- If `upload_samples.py` is interrupted mid-run, `/tmp/pypi-scada-staging/` may
  retain partial content. Operator cleans with `rm -rf /tmp/pypi-scada-staging/`
  before rerunning.

**Residual risk:**
A sufficiently large malicious archive could consume VM disk or tmpfs space during
staging. Mitigated by the relatively small size of the known malicious samples
(all under 10 MB extracted) and by clearing the staging directory on each deployment.

---

## Decision 6 — Source-Aware Ground Truth Assignment (Folder-based Truth)

**Decision:**
Ground truth labels are assigned based on the source directory and version in
the staged dataset, rather than via a name-based lookup table. Benign versions
(e.g., 0.5.14) and poisoned versions (e.g., 0.5.15) of the same package name are
labeled `False` and `True` respectively, based on their presence in the `benign/`
or `malware_backstabbers_knife/` directories. The artifact bytes used for scanning
are then fetched from the simulator so the benchmark exercises the controlled
package-index path.

**Threat addressed (Methodological Flaw):**
In Account Takeover (ATO) scenarios, the same package name exists in both benign
and malicious states. A name-keyed ground truth dictionary (e.g., `truth["num2words"] = True`)
causes "Ground Truth Collision," where a clean version of a targeted package is
incorrectly labeled as malicious. This leads to:
- **Inflation of False Negatives:** Accurate detectors that correctly identify
  clean code are penalized.
- **Flattery of Hallucination:** Inaccurate detectors that over-flag clean code
  as malicious are incorrectly rewarded with True Positives.
- **Skewed Metrics:** Precision and Recall become scientifically invalid,
  undermining the core objective of the benchmarking study.

**Controls applied:**
- **Simulator-Resolved Discovery:** `EvaluationRunner` builds version-aware labels
  from the staged dataset, queries the simulator index, and downloads selected
  package artifacts for scanning.
- **Detector Blindness:** The `ground_truth` label is passed to the database
  layer only *after* the detection adapters have completed their work. The
  detectors (SAST and LLMs) never receive the label.
- **Version/Artifact Isolation:** The evaluation database key includes package,
  version, artifact filename, detector, mode, and prompt strategy so multiple
  versions of the same project cannot overwrite each other.

**Residual risk:**
"Pre-existing Knowledge Bias" in Frontier LLMs. If a model has seen security
reports for `num2words 0.5.15` during its training, it may flag the package
based on memory rather than code analysis. This is documented as a limitation
in the final thesis and addressed via the "Reasoning" analysis in the rubric.
The source-free `scripts/model_memory_probe.py` sidecar records whether models
recognize selected package names/versions without source evidence; those JSONL
results are validity evidence only and are not included in detector metrics.

The identity-alias probe adds a second, cheap validity control for the same
risk. `src/analyzer/evaluate.py --profile all_models --identity-alias-probe`
masks model-visible package names and versions as neutral aliases such as
`X001` / `V001`, then runs only one source-based lane:
`hybrid:zero_shot` across non-agentic models. It skips static tools, raw LLM
mode, prompt-strategy sweeps, agentic mode, and financial validation so it stays
timely late in the semester. The probe is not a corrected score and does not
prove training-set membership. It tests whether model verdicts are sensitive to
recognizable public identity cues while preserving source-code behavior evidence.
Because package identity can itself be part of the attack signal, especially for
typosquatting, alias misses are interpreted as identity sensitivity rather than
proof of memorization. Use `scripts/check_identity_alias_leaks.py` on alias run
IDs to verify that model-facing request blobs do not contain original package
identity.

---

## Decision 7 — GuardDog source-only baseline

**Decision:**
GuardDog is added as a third static baseline detector alongside Bandit and Semgrep.
The pinned version is `guarddog==2.9.0` (pinned on 2026-04-14). GuardDog scans only
the local extracted source files in `PackageInfo.files`, matching the evidence set
seen by Bandit, Semgrep, and the LLM-hybrid prompt.

**Rules enabled:**
Only source-code rules are passed via an explicit `--rules` allowlist:
`api-obfuscation`, `shady-links`, `obfuscation`, `clipboard-access`,
`exfiltrate-sensitive-data`, `download-executable`, `exec-base64`,
`silent-process-execution`, `dll-hijacking`, `screenshot`, `steganography`,
`code-execution`, `unicode`, `cmd-overwrite`, and
`suspicious_passwd_access_linux`.

**Rules excluded:**
All GuardDog package-metadata heuristics are excluded, including typosquatting,
release-recency, repository-integrity, maintainer/email-domain, bundled-binary,
single-file, deceptive-author, and empty-information metadata checks.

**Threat addressed (methodological fairness):**
GuardDog is purpose-built for malicious package detection, so it is a stronger
rule-based baseline than generic Bandit/Semgrep alone. However, GuardDog's metadata
heuristics can query live package registry metadata. Allowing those heuristics would:
- Violate the `pypi-runner` egress firewall model.
- Give GuardDog live PyPI evidence that the LLMs and generic SAST baselines do not
  receive.
- Undermine the simulator-resolved methodology by mixing local simulator evidence
  with real registry evidence.

**Controls applied:**
- GuardDog is invoked against a temporary local directory populated from
  `PackageInfo.files`; package names are never passed as remote scan targets.
- The command uses an explicit source-rule allowlist rather than `--exclude-rules`,
  so future GuardDog metadata rules cannot silently enter the benchmark.
- Deployment runs `guarddog --version` after dependency installation and a
  source-only local smoke test after `pypi-runner` outbound egress is blocked.
- Static scanner runtime failures are recorded as `experiment_mode="error"` rather
  than benign `static` verdicts, preventing broken tools from improving false-negative
  metrics.

**Residual risk:**
Dataset contamination. GuardDog rules may have been tuned on historical PyPI malware
families overlapping with Backstabber's Knife samples. GuardDog outperformance on
known patterns should be interpreted as "malware-specific rule baseline performance,"
not as an unbiased oracle. This caveat must be carried into the thesis discussion.

**Metric compatibility note:**
The GuardDog integration also changes Bandit/Semgrep failure semantics: scanner
runtime failures that previously appeared as benign `static` rows are now stored as
`experiment_mode="error"`. Historical evaluation databases from before this change
must not be mixed with canonical post-GuardDog metrics; rerun the static baselines
before final thesis comparisons.

---

## Decision 8 — Offline Semgrep ruleset

**Decision:**
Semgrep is invoked with the checked-in local ruleset
`src/analyzer/static_rules/semgrep_python.yml`, plus `--metrics off` and
`--disable-version-check`. Registry configs such as `p/python` are not used.
The checked-in rules are custom, Semgrep CE-compatible rules focused on
package-install abuse, encoded execution, shell execution, dynamic imports,
native library loading, persistence writes, and credential exfiltration.

**Threat addressed:**
The deployment firewall intentionally blocks `pypi-runner` outbound egress during
evaluation. Semgrep Registry configs require network access, causing static
baseline rows to fail and be excluded from package-version metrics.

**Residual risk:**
The local ruleset is smaller than Semgrep's hosted Python registry pack, and
custom rule selection can bias Semgrep results. Semgrep results should therefore
be interpreted as a curated offline syntax-pattern baseline, while GuardDog
remains the malware-specific rule baseline. Download-and-execute and
credential-exfiltration rules use same-function co-occurrence approximations
because Semgrep CE does not provide the Semgrep Pro data-flow engine. The
credential-exfiltration rule uses a closed vocabulary of high-value environment
variable names and direct HTTP sink patterns, so it may miss broader environment
enumeration or `.env` file theft. The persistence rule is syntax-based and
primarily catches literal path arguments; paths assembled through helper
functions may be missed. The install-command-network rule intentionally flags
all network access inside install/develop/build command classes, including
benign-looking metadata fetches, because install-time network access is itself
the suspicious behavior for this threat model.

**Metric compatibility note:**
Prior Semgrep rows from Registry-based runs are invalid under the VM firewall and
must be excluded from final thesis metrics. Canonical post-custom-ruleset runs
should use `--run-id-prefix canonical-v2` so final queries can select
`run_id LIKE 'canonical-v2-%'` rather than relying on memory.

---

## Decision 9 — Replace `gemini-3.1-flash-lite-preview` with `gemini-2.5-flash-lite`

**Decision:**
The budget-tier Google model is changed from `gemini-3.1-flash-lite-preview` to
`gemini-2.5-flash-lite` across all config files, the LiteLLM proxy routing, the
analyzer detector config, and test fixtures.

**Threat addressed (availability):**
`gemini-3.1-flash-lite-preview` returned HTTP 503 ("This model is currently
experiencing high demand") repeatedly during evaluation runs on 2026-04-16. The
deployment smoke test retried 4 times with 20-second backoff and still failed,
aborting the entire pipeline. This was not a one-off spike — the same failure
pattern occurred across multiple run attempts over several days. Google's status
page showed no declared incident; the throttling is inherent to preview-tier
capacity allocation.

**Why `gemini-2.5-flash-lite`:**
It is the current stable (non-preview) budget-tier Gemini model.
`gemini-2.0-flash-lite` was considered first but returns HTTP 404 ("no longer
available to new users") — Google sunset it between generations. The 2.5 variant
is the newest GA flash-lite release. Its pricing ($0.10/$0.40 per 1M
input/output tokens) is comparable to the preview model and remains firmly in the
budget tier.

**Controls applied:**
- Updated `configs/models.json` (token prices and budget-tier model entry).
- Updated `configs/litellm_config.yaml` (LiteLLM proxy routing).
- Updated `src/analyzer/configs/gemini_flash_lite.yaml` (detector model name).
- Updated all test references (`test_analyzer_progress.py`,
  `test_litellm_smoke.py`, `test_financial_validation.py`).
- Verified zero remaining references to `gemini-3.1-flash-lite-preview` or
  `gemini-2.0-flash-lite` in the repository.

**Residual risk:**
`gemini-2.5-flash-lite` is an older-generation model than the 3.1 preview.
Budget-tier LLM detection accuracy may be lower than what the newer model could
have achieved under stable conditions. This is an acceptable trade-off: an
unreliable model that produces `experiment_mode="error"` rows is worse for the
thesis than a slightly less capable model that completes its runs.

**Metric compatibility note:**
Any prior evaluation rows produced by `gemini-3.1-flash-lite-preview` are not
comparable with `gemini-2.5-flash-lite` results. Canonical runs must be re-run
from scratch with the new model under `--run-id-prefix canonical-v2`.

---

## Decision 10 — Agentic workflow framing and safety boundary

**Decision:**
For the agentic condition, PyPI-SCADA implements an automated, safety-bounded
RAG workflow inspired by modern coding agents such as Codex and Claude Code. The
model is required to plan its investigation, retrieve package evidence through
read-only tools, and produce a structured malicious/benign verdict. This design
preserves the key agentic behaviors relevant to package triage while avoiding
unsafe capabilities such as dependency installation, package execution,
arbitrary shell access, or unrestricted network access.

This is not a direct evaluation of Codex or Claude Code as products. Instead, it
evaluates a reproducible agentic detector architecture: planning, tool-mediated
evidence retrieval, iterative inspection, and structured verdict generation over
the same simulator-resolved package evidence used by the other modes.

**Controls applied:**
- Agentic model calls route through LiteLLM on `127.0.0.1:4000`; the analyzer
  process remains keyless.
- Agent tools are read-only over extracted package evidence (`list_files`,
  `read_file`, `search_files`, and `file_info`).
- The adapter does not expose shell execution, package installation, package
  imports, or arbitrary network access.
- Raw experiment logs record the plan phase, tool calls, model responses, and
  final detector row for audit.

**Residual risk:**
The bounded adapter is intentionally less capable than full coding-agent products
because it cannot run arbitrary commands or execute tests. This reduces ecological
validity relative to unrestricted coding agents, but it is required for safe,
reproducible malware evaluation.

---

## Decision 11 — Runtime Interpretation for GuardDog and Agentic Mode

**Decision:**
GuardDog and agentic mode are retained despite higher wall-clock cost because
they answer different research questions than the cheap single-shot detectors.
GuardDog represents a PyPI-malware-specific rule baseline, while agentic mode
represents a bounded read-only investigation workflow.

**Why GuardDog is slow:**
GuardDog is not expected to perform live PyPI requests during evaluation. The
adapter invokes `guarddog pypi scan <local-tempdir> --output-format=json` with
an explicit source-rule allowlist and scans the local `PackageInfo.files`
evidence set. Metadata heuristics that can query live registry metadata are
excluded.

The wall-clock cost comes from local work: creating a temporary source tree,
starting a fresh GuardDog subprocess per artifact, loading GuardDog/Semgrep-style
rules, scanning every file in large package trees, and repeating this for every
wheel/sdist selected by the canonical all-artifacts policy. The 180 second
timeout is a scanner bound, not evidence of network access.

**How to verify GuardDog is not using network evidence:**
Inspect the raw experiment JSONL for `static.command.start` events where
`detector=guarddog`. The recorded `argv` should contain a local temporary
directory and repeated `--rules` flags, not a package name or registry URL. If
stderr/stdout contains DNS, connection, HTTP, PyPI, or registry text, treat that
as a network-leak bug and preserve the row as `experiment_mode="error"`.

**Why agentic mode is slow:**
Agentic mode is intentionally multi-turn. The configured flow first asks the
model to produce an investigation plan, then enters a bounded tool loop where
the model can request read-only file-listing, file-search, and file-inspection
tools. Each loop iteration requires another LiteLLM HTTP request and resends
growing conversation context, tool schemas, tool outputs, and package evidence.

This makes agentic mode slower and more expensive than `llm_raw` or `hybrid`
single-shot prompts. The latency is expected provider/model latency plus token
volume plus serialized tool iterations. It is not equivalent to running Claude
Code or Codex interactively, and it does not install, import, or execute package
code.

**Interpretation for thesis metrics:**
Report runtime separately from detection quality. GuardDog latency should be
interpreted as the cost of a malware-specific static baseline. Agentic latency
should be interpreted as the cost of a richer investigation workflow. Static,
non-agentic LLM, and agentic lanes may be run separately to avoid duplicating
static scans and to keep wall-clock time manageable.

---

## Decision 12 — Malformed LLM Responses Are Protocol Errors, Not Benign Verdicts

**Decision:**
LLM, raw-LLM, and agentic adapters treat any model response that fails the
required JSON verdict contract as `experiment_mode="error"`. They no longer
default missing or malformed verdict JSON to benign. The raw response is retained
in `details.raw` and the row records `details.protocol_failure=true`.

**Why this matters:**
Counting empty or prose-only model outputs as benign creates false negatives and
can make an overloaded, truncated, or format-noncompliant model look like a
conservative detector. That is not scientifically valid. A detector that did not
produce a parseable verdict did not make a benign classification.

**Retry policy:**
Empty responses are marked `details.retryable=true` because they are usually
provider, timeout, overload, or transport symptoms. Non-empty malformed responses
are marked `details.retryable=false` by default because they may reflect prompt
noncompliance or model behavior, not a transient outage. A separate retry script
can later select only retryable rows.

**Historical cleanup:**
`scripts/normalize_llm_protocol_failures.py` converts older non-error LLM rows
with `details.raw` into explicit protocol-error rows after first checking for
unique-key collisions and creating a timestamped backup. Use this on old
databases before comparing them with canonical-v2 results.

**Interpretation for thesis metrics:**
Protocol-error rows are excluded from package-version metrics like other
`experiment_mode="error"` rows. Report their count separately when discussing
provider reliability, especially for agentic runs where long multi-turn calls
are more likely to hit rate limits or truncation.

---

## Decision 13 — Temporary Pause on Broad Agentic Runs

**Decision:**
As of 2026-04-21, broad agentic experiment runs are paused until after the
supervisor discussion following the Friday 2026-04-24 exam. Until that review,
routine experiment execution should use static, `hybrid`, and `llm_raw` lanes
only.

**Why this pause was chosen:**
Current observed spend is dominated by the agentic lane, and a large share of
that spend is being burned on agentic rows that still end in `experiment_mode =
"error"`. That makes broad tier-by-tier agentic execution hard to justify
before the methodology and budget tradeoff are discussed explicitly.

**Operational rule until the supervisor discussion:**
- Do not include agentic runs in routine budget, medium, or frontier experiment
  sweeps.
- Treat existing agentic rows as exploratory evidence, not canonical thesis
  comparison data.
- Keep canonical pre-discussion comparison tables limited to static,
  non-agentic `hybrid`, and non-agentic `llm_raw` conditions.

**What resumes after the discussion:**
After the supervisor review, either:
1. agentic remains an appendix/sidecar condition on a small curated subset,
2. agentic is redesigned to reduce cost and error burn before rerun, or
3. agentic is approved for a bounded canonical run with an explicit budget cap.

---

## Decision 14 — Replace preview Gemini medium/frontier routes with stable 2.5 models

**Decision:**
As of 2026-04-21, the medium-tier Google route is changed from
`gemini-3-flash-preview` to `gemini-2.5-flash`, and the frontier-tier Google
route is changed from `gemini-3.1-pro-preview` to `gemini-2.5-pro`.

**Why this change was made:**
The preview Gemini identifiers were adding unnecessary operational risk to the
Google lane. Even when the provider itself was reachable, preview routes are
more likely to be renamed, throttled, or removed. For thesis runs, stable GA
routes are preferable to preview names because they reduce avoidable 404/route
failures and make the methodology easier to defend.

**Source of truth used:**
The replacement IDs were taken from Google's official Gemini Developer API
model documentation. Pricing was refreshed from Google's official pricing page.

**Controls applied:**
- Updated analyzer configs:
  `src/analyzer/configs/gemini_flash.yaml` -> `gemini-2.5-flash`
  `src/analyzer/configs/gemini.yaml` -> `gemini-2.5-pro`
- Updated `configs/litellm_config.yaml` so LiteLLM exposes the same stable
  model names and routes them to `gemini/gemini-2.5-flash` and
  `gemini/gemini-2.5-pro`.
- Updated `configs/models.json` so the medium/frontier Google entries and token
  pricing match the stable 2.5 models.
- Updated smoke-test expectations and analyzer notes so the repo no longer
  advertises the preview IDs as current.

**Pricing note recorded in the repo:**
- `gemini-2.5-flash-lite` -> `$0.10 / $0.40` per 1M input/output tokens
- `gemini-2.5-flash` -> `$0.30 / $2.50`
- `gemini-2.5-pro` -> `$1.25 / $10.00`

The `gemini-2.5-pro` price uses the standard paid API row for prompts at or
below 200k input tokens, which matches the analyzer's prompt sizes more closely
than the >200k row.

**Metric compatibility note:**
Historical rows produced with `gemini-3-flash-preview` or
`gemini-3.1-pro-preview` should not be mixed into canonical post-swap Google
comparisons. Canonical runs must be re-run after the swap and queried
separately from preview-era results.
