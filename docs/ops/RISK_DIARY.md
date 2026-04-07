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

# proxy-runner: LLM vendor endpoints only
ANTHROPIC_CIDR="104.18.0.0/16"
OPENAI_CIDR="162.159.0.0/16"
GOOGLE_CIDR="142.250.0.0/15"
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $ANTHROPIC_CIDR -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $OPENAI_CIDR -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $GOOGLE_CIDR -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d api.together.xyz -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP
```

**Residual risk:**
DNS-over-HTTPS payloads tunnelling over localhost-forwarded ports; unlikely in the
lab network topology. Also, if the malware payload targets the local simulator's
HTTP port (8080), it could interact with the simulated index — logged but not blocked.
The vendor CIDR blocks used are broad Cloudflare ranges — they may cover non-LLM
endpoints. Accepted given the experimental context.

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
provides a production-grade implementation of the same isolation. The custom proxy
code remains in the repository but is not used.

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

## Decision 4 — Malicious zip extraction to tmpfs

**Decision:**
`upload_samples.py` extracts password-protected malicious zip archives into
`/tmp/pypi-scada-staging/` (which is a tmpfs mount on most Linux VMs). Each staging
directory is deleted immediately after the inner archive is uploaded to the simulator.
Extracted files are never written to the persistent filesystem.

**Threat addressed:**
Extracted malicious package files could persist on disk after the experiment,
representing an ongoing risk if the VM is repurposed or audited. tmpfs ensures
extracted content lives only in RAM and is gone on reboot or explicit cleanup.

**Controls applied:**
- Extraction target: `/tmp/pypi-scada-staging/<uuid>/` — unique per zip, removed with
  `shutil.rmtree` after upload.
- If `upload_samples.py` is interrupted mid-run, `/tmp/pypi-scada-staging/` may retain
  partial content. Operator cleans with `rm -rf /tmp/pypi-scada-staging/` before rerunning.

**Residual risk:**
A sufficiently large malicious archive could exhaust available tmpfs memory, causing
an OOM condition. Mitigated by the relatively small size of the known malicious samples
(all under 10 MB extracted).

---

## Decision 6 — Source-Aware Ground Truth Assignment (Folder-based Truth)

**Decision:**
Ground truth labels are assigned based on the source directory during sample
discovery, rather than via a name-based lookup table. Benign versions (e.g.,
0.5.14) and poisoned versions (e.g., 0.5.15) of the same package name are
labeled `False` and `True` respectively, based on their presence in the `benign/`
or `malware_backstabbers_knife/` directories.

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
- **Refactored Discovery:** `EvaluationRunner._discover_benign()` and
  `_discover_malware()` return the truth label as part of the archive metadata.
- **Detector Blindness:** The `ground_truth` label is passed to the database
  layer only *after* the detection adapters have completed their work. The
  detectors (SAST and LLMs) never receive the label.
- **Version Isolation:** The evaluation pipeline treats each archive as a
  discrete test instance, ensuring that a package's clean history does not
  contaminate the evaluation of its poisoned releases.

**Residual risk:**
"Pre-existing Knowledge Bias" in Frontier LLMs. If a model has seen security
reports for `num2words 0.5.15` during its training, it may flag the package
based on memory rather than code analysis. This is documented as a limitation
in the final thesis and addressed via the "Reasoning" analysis in the rubric.
