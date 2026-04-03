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
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, and `GOOGLE_API_KEY` are stored in
`~pypi-runner/.env` (permissions `0600`, owned by `pypi-runner`) and exported into
the shell session at login. They are never written into any YAML config file checked
into the repository.

**Threat addressed:**
Config files are committed to git. Keys embedded in YAML would appear in repository
history and be accessible to anyone with read access to the repo — including any
future public mirror. A leaked API key allows an adversary to consume paid API quota
and potentially access models with the experiment's identity.

**Controls applied:**
- `.env` is in `.gitignore`.
- YAML config files contain only structural parameters (model names, prompt paths,
  database paths). They contain no secret values.
- The `ANTHROPIC_API_KEY` variable is read by the Anthropic SDK automatically from
  the environment; no code change is required.

**Residual risk:**
Process environment inspection by a co-resident process with ptrace capability.
Accepted — the VM hosts only the experiment.

---

## Decision 3 — Network isolation during evaluation runs

**Decision:**
Before starting an evaluation run the VM's NIC is restricted to localhost-only traffic
(iptables or equivalent). The restriction is lifted after the run to allow result export.
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
# Applied before each evaluation run (operator step)
sudo iptables -P INPUT DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT  -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT

# Lifted after the run
sudo iptables -F
sudo iptables -P INPUT  ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

**Residual risk:**
DNS-over-HTTPS payloads tunnelling over localhost-forwarded ports; unlikely in the
lab network topology. Also, if the malware payload targets the local simulator's
HTTP port (8080), it could interact with the simulated index — logged but not blocked.

---

## Decision 5 — Isolated credential proxy for LLM API keys

**Decision:**
LLM API keys (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`) are held
exclusively by a dedicated `credential_proxy` service running as `proxy-runner`.
The analyzer process (`pypi-runner`) carries no API keys in its environment. All
LLM API calls are made by posting `{provider, model, system, messages}` to the
proxy at `http://127.0.0.1:9090/proxy/analyze`; the proxy returns the LLM
response. The analyzer SDK imports (`anthropic`, `openai`, `google.generativeai`)
are bypassed in proxy mode — the analyzer uses `requests` only.

**Threat addressed:**
Decision 2 moved API keys from config files into environment variables. A
sufficiently capable malicious package can still harvest environment variables
at import time or via `setup.py` execution within the analyzer process. It can
then encode the keys in a request payload (e.g. as part of the JSON it expects
from an LLM) and exfiltrate them through the single outbound channel that
existing iptables rules permit (api.anthropic.com port 443). The attacker gets
a paid-API credential without triggering any process-level anomaly.

**Controls applied:**
- `pypi-runner` environment: no `*_API_KEY` variables set. Any attempt to read
  them from `os.environ` in the analyzer raises `KeyError` (direct SDK path is
  not taken in proxy mode).
- `proxy-runner` account: separate unprivileged user, separate login shell,
  separate `~proxy-runner/.env` (chmod 600). Only this account's processes can
  read the keys.
- Egress policy enforced via the iptables `owner` match module:
  - `pypi-runner` processes: DROP all non-loopback outbound.
  - `proxy-runner` processes: ACCEPT outbound only to `api.anthropic.com`,
    `api.openai.com`, `generativelanguage.googleapis.com` port 443.
- The proxy binds to `127.0.0.1:9090` only — no external exposure.

**Residual risk:**
A malicious package that discovers the proxy endpoint at `127.0.0.1:9090` and
crafts a valid `/proxy/analyze` request could use the proxy as an unwitting
relay to exfiltrate content to the LLM provider (e.g. embedding secrets in a
user message). This residual is accepted: the payload would be package source
code already held on the execution VM, not new secrets, and the provider's
logging would record the request under the experiment's API key identity.
Mitigation: request size cap enforced in the proxy (payload > 64 KB rejected).

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
