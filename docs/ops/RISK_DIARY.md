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

## Decision 9 — Replace `gemini-3.1-flash-lite-preview` with `gemini-2.0-flash-lite`

**Decision:**
The budget-tier Google model is changed from `gemini-3.1-flash-lite-preview` to
`gemini-2.0-flash-lite` across all config files, the LiteLLM proxy routing, the
analyzer detector config, and test fixtures.

**Threat addressed (availability):**
`gemini-3.1-flash-lite-preview` returned HTTP 503 ("This model is currently
experiencing high demand") repeatedly during evaluation runs on 2026-04-16. The
deployment smoke test retried 4 times with 20-second backoff and still failed,
aborting the entire pipeline. This was not a one-off spike — the same failure
pattern occurred across multiple run attempts over several days. Google's status
page showed no declared incident; the throttling is inherent to preview-tier
capacity allocation.

**Why `gemini-2.0-flash-lite`:**
It is a GA (generally available) model, not a preview endpoint. GA models receive
higher capacity quotas and are subject to Google's SLA commitments. The pricing
($0.075/$0.30 per 1M input/output tokens) is comparable to the preview model and
remains firmly in the budget tier. Choosing `gemini-2.0-flash-lite` over a newer
preview preserves experiment stability: a model swap mid-dataset would mix results
from two different models under the same detector name, invalidating the comparison.

**Controls applied:**
- Updated `configs/models.json` (token prices and budget-tier model entry).
- Updated `configs/litellm_config.yaml` (LiteLLM proxy routing).
- Updated `src/analyzer/configs/gemini_flash_lite.yaml` (detector model name).
- Updated all test references (`test_analyzer_progress.py`,
  `test_litellm_smoke.py`, `test_financial_validation.py`).
- Verified zero remaining references to `gemini-3.1-flash-lite-preview` in the
  repository.

**Residual risk:**
`gemini-2.0-flash-lite` is an older-generation model with potentially lower
capability than `gemini-3.1-flash-lite-preview`. Budget-tier LLM detection
accuracy may be lower than what the newer model could have achieved under stable
conditions. This is an acceptable trade-off: an unreliable model that produces
`experiment_mode="error"` rows is worse for the thesis than a slightly less
capable model that completes its runs.

**Metric compatibility note:**
Any prior evaluation rows produced by `gemini-3.1-flash-lite-preview` are not
comparable with `gemini-2.0-flash-lite` results. Canonical runs must be re-run
from scratch with the new model under `--run-id-prefix canonical-v2`.
