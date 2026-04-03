# Deployment Manifest — PyPi-SCADA VM

Exact, sequential steps for a human operator to deploy and run the PyPi-SCADA
pipeline on the provisioned virtual machine. No automated agent executes these
commands. The operator runs each block manually.

---

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS (or compatible Debian-based distro) |
| Python | 3.11+ (`python3 --version`) |
| Tools | `git`, `unzip`, `curl`, `pip` |
| VM home | `/home/lexi/` (sudoer account used only for setup steps) |
| Samples archive | `~/samples/benign_and_controlls.zip` present |
| Malicious zips | `~/samples/*.zip` (excluding `benign_and_controlls.zip`) present |
| Pull script | `~/pull_script_with_fine_grain_acces_token.sh` present and executable |

Outbound network access to GitHub and PyPI is required for steps 1–5.
**Restrict network before step 7 (evaluation run).**

---

## Step 1 — Create the two unprivileged accounts

Two accounts are required. `pypi-runner` runs the analyzer pipeline; it has no
API keys. `proxy-runner` runs the credential proxy; it holds the API keys and
is the only account permitted to make outbound connections to LLM endpoints.
Neither account has sudo privileges.

Run as `lexi` (or any sudoer):

```bash
sudo useradd \
  --system \
  --create-home \
  --home-dir /home/pypi-runner \
  --shell /bin/bash \
  --comment "PyPi-SCADA experiment runner" \
  pypi-runner

sudo useradd \
  --system \
  --create-home \
  --home-dir /home/proxy-runner \
  --shell /bin/bash \
  --comment "PyPi-SCADA credential proxy" \
  proxy-runner
```

Verify no sudo access was granted to either account:

```bash
sudo -l -U pypi-runner
sudo -l -U proxy-runner
# Expected: "... is not allowed to run sudo on <hostname>."
```

---

## Step 2 — Clone the repository

The pull script uses a fine-grained GitHub personal access token.
Run it as `pypi-runner` so the repo is owned by that account from the start:

```bash
sudo -u pypi-runner bash /home/lexi/pull_script_with_fine_grain_acces_token.sh
```

This clones (or updates) the repo to a path determined by the script.
Confirm the result:

```bash
sudo -u pypi-runner ls /home/pypi-runner/pypi-scada-repo/
# Expected: README.md  requirements.txt  src/  samples/  docs/  demo/  ...
```

If the script places the repo under `/home/lexi/`, copy it:

```bash
sudo cp -r /home/lexi/pypi-scada-repo /home/pypi-runner/pypi-scada-repo
sudo chown -R pypi-runner:pypi-runner /home/pypi-runner/pypi-scada-repo
```

---

## Step 3 — Extract the benign + controls archive

The archive is 19.5 GB. Extraction takes several minutes.

```bash
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/samples-extracted
  unzip -q /home/lexi/samples/benign_and_controlls.zip \
        -d /home/pypi-runner/samples-extracted/
"
```

Verify the layout:

```bash
sudo -u pypi-runner ls /home/pypi-runner/samples-extracted/
# Expected: benign/  controls/  (at minimum)
```

---

## Step 4 — Stage the malicious zips

```bash
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/samples-extracted/malicious
  for f in /home/lexi/samples/*.zip; do
    name=\$(basename \"\$f\")
    if [ \"\$name\" != 'benign_and_controlls.zip' ]; then
      cp \"\$f\" /home/pypi-runner/samples-extracted/malicious/
    fi
  done
"
```

Verify:

```bash
sudo -u pypi-runner ls /home/pypi-runner/samples-extracted/malicious/
# Expected: colourama-*.zip  nmap-python-*.zip  num2words-*.zip  ... (no benign zip)
```

---

## Step 5 — Set up the Python virtual environment

```bash
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --quiet -r requirements.txt
  pip install --quiet twine
  echo 'venv ready'
"
```

---

## Step 6 — Configure API keys (proxy-runner only)

API keys belong to `proxy-runner` exclusively. `pypi-runner` must have no keys
in its environment.

```bash
sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << 'ENVEOF'
export ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
export OPENAI_API_KEY=sk-REPLACE_ME
export GEMINI_API_KEY=REPLACE_ME
ENVEOF
chmod 600 /home/proxy-runner/.env
echo 'source ~/.env' >> /home/proxy-runner/.bashrc
"
```

Edit `/home/proxy-runner/.env` and replace the placeholder values with real keys:

```bash
sudo -u proxy-runner nano /home/proxy-runner/.env
```

Confirm `pypi-runner` has no API keys set (both commands must produce empty output):

```bash
sudo -u pypi-runner bash -c 'echo ${ANTHROPIC_API_KEY:-}'
sudo -u pypi-runner bash -c 'echo ${OPENAI_API_KEY:-}'
```

---

## Step 7 — Configure egress filtering

Two-tier egress policy using the iptables `owner` match module:

- `pypi-runner` (analyzer) — no outbound connections beyond localhost.
- `proxy-runner` (credential proxy) — outbound only to authorised LLM endpoints.

Verify the `xt_owner` module is available:

```bash
sudo modprobe xt_owner
lsmod | grep xt_owner   # must return a line
```

Apply the rules (run as `lexi`):

```bash
# Drop all non-loopback outbound from pypi-runner
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner ! -o lo -j DROP

# Allow proxy-runner outbound to LLM endpoints only
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
  -d api.anthropic.com -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
  -d api.openai.com -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
  -d generativelanguage.googleapis.com -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP
```

**Note:** iptables resolves domain names to IP at rule-insertion time.
If the resolved IPs change (e.g. Anthropic rotates endpoints), re-apply
the rules. Alternatively, use the actual IP ranges from each provider's
published allowlist.

Verify the pypi-runner block:

```bash
sudo -u pypi-runner curl -s --max-time 5 https://api.anthropic.com/v1/models 2>&1 || true
# Expected: connection refused or timed out (not a successful response)
```

To remove all owner rules after the experiment:

```bash
sudo iptables -D OUTPUT -m owner --uid-owner pypi-runner ! -o lo -j DROP
sudo iptables -F OUTPUT   # or selectively delete by rule number
```

---

## Step 8 — Copy the repo to proxy-runner and start the credential proxy

The proxy needs its own copy of the repo (or at minimum `src/credential_proxy/`
and `src/utils/`). The simplest approach on the same VM is to allow
`proxy-runner` read access to `pypi-runner`'s clone:

```bash
sudo chmod o+x /home/pypi-runner /home/pypi-runner/pypi-scada-repo
```

Or copy just the needed source:

```bash
sudo cp -r /home/pypi-runner/pypi-scada-repo \
           /home/proxy-runner/pypi-scada-repo
sudo chown -R proxy-runner:proxy-runner /home/proxy-runner/pypi-scada-repo

sudo -u proxy-runner bash -c "
  cd /home/proxy-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --quiet -r requirements.txt
"
```

Open **Terminal A-proxy** as `proxy-runner`:

```bash
sudo -u proxy-runner -i
source ~/.env
source ~/pypi-scada-repo/venv/bin/activate
cd ~/pypi-scada-repo/src/credential_proxy
python server.py
```

Leave Terminal A-proxy running. Confirm startup:

```
Starting Credential Proxy on 127.0.0.1:9090
```

Verify the proxy is reachable from `pypi-runner`:

```bash
sudo -u pypi-runner curl -s http://127.0.0.1:9090/health
# Expected: {"status": "ok"}
```

---

## Step 9 — Open a pypi-runner session

All remaining steps run as `pypi-runner`. `pypi-runner` has no API keys.

```bash
sudo -u pypi-runner -i
# Prompt changes to: pypi-runner@<hostname>:~$
source ~/pypi-scada-repo/venv/bin/activate
```

---

## Step 11 — Upload samples (Terminal C)

```bash
cd ~/pypi-scada-repo
source venv/bin/activate

# Upload benign packages first (version ordering is handled automatically)
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080 \
  --only benign

# Upload control packages
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080 \
  --only controls

# Upload malicious packages (extracted from password-protected zips)
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080 \
  --only malicious
```

Dry-run mode (prints what would be uploaded, calls no twine):

```bash
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --dry-run
```

Verify the index after upload:

```bash
curl -s http://127.0.0.1:8080/simple/
# Expected: HTML index listing all uploaded package names

curl -s http://127.0.0.1:8080/api/versions/colorama
# Expected: {"project": "colorama", "versions": ["0.x.y", "0.x.z", ...]}
```

---

## Step 12 — Run the evaluation pipeline (Terminal C)

```bash
cd ~/pypi-scada-repo
python src/analyzer/evaluate.py src/analyzer/config.yaml
```

`pypi-runner` carries no API keys; the analyzer routes all LLM calls through
the credential proxy at `http://127.0.0.1:9090`. If the proxy is not running,
LLM adapters will fail with a connection error — SAST results are still written.

Results are written to `src/data/eval_results.db`. A metrics table is printed to
the console on completion.

---

## Directory Layout Reference (post-setup)

```
/home/pypi-runner/
├── .env                          # API keys (chmod 600)
├── .bashrc                       # sources .env on login
├── pypi-scada-repo/              # repository clone
│   ├── venv/                     # Python virtual environment
│   ├── src/
│   │   ├── simulator/            # Flask PyPI server
│   │   ├── injector/             # upload_samples.py + controller.sh
│   │   ├── analyzer/             # diff + eval pipeline
│   │   └── data/                 # SQLite DBs (written at runtime)
│   └── ...
└── samples-extracted/
    ├── benign/                   # extracted from benign_and_controlls.zip
    ├── controls/                 # extracted from benign_and_controlls.zip
    └── malicious/                # password-protected zips (not pre-extracted)
```

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `ModuleNotFoundError: src` on simulator start | Wrong working directory | `cd src/simulator` before `python main.py` |
| `twine: command not found` | venv not activated | `source ~/pypi-scada-repo/venv/bin/activate` |
| `BadZipFile` on malicious zip | Zip is not password-protected with `infected` | Check the zip source; report to maintainer |
| Simulator returns 400 on upload | `enforce_version_bump=true` and version already exists | Clear `src/simulator/data/` and restart simulator |
| `PermissionError` writing to data/ | Data dir owned by wrong user | `sudo chown -R pypi-runner:pypi-runner ~/pypi-scada-repo/src/data` |
| LLM adapter returns error | API key not exported | `echo $ANTHROPIC_API_KEY` — must be non-empty |
