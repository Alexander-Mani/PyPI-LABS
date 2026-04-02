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

## Step 1 — Create the unprivileged account

Run as `lexi` (or any sudoer):

```bash
sudo useradd \
  --system \
  --create-home \
  --home-dir /home/pypi-runner \
  --shell /bin/bash \
  --comment "PyPi-SCADA experiment runner" \
  pypi-runner
```

Verify no sudo access was granted:

```bash
sudo -l -U pypi-runner
# Expected output: "User pypi-runner is not allowed to run sudo on <hostname>."
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

## Step 6 — Configure API keys

```bash
sudo -u pypi-runner bash -c "
cat > /home/pypi-runner/.env << 'ENVEOF'
export ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
export OPENAI_API_KEY=sk-REPLACE_ME
export GOOGLE_API_KEY=REPLACE_ME
ENVEOF
chmod 600 /home/pypi-runner/.env
echo 'source ~/.env' >> /home/pypi-runner/.bashrc
"
```

Edit `/home/pypi-runner/.env` and replace the placeholder values with real keys:

```bash
sudo -u pypi-runner nano /home/pypi-runner/.env
```

---

## Step 7 — Restrict network (before evaluation)

Apply before starting any evaluation run. The simulator, injector, and analyzer
all communicate only over localhost; this rule set is sufficient:

```bash
sudo iptables -P INPUT  DROP
sudo iptables -P OUTPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -A INPUT  -i lo -j ACCEPT
sudo iptables -A OUTPUT -o lo -j ACCEPT
```

To restore full network access after the run:

```bash
sudo iptables -F
sudo iptables -P INPUT  ACCEPT
sudo iptables -P OUTPUT ACCEPT
```

---

## Step 8 — Open a pypi-runner session

All remaining steps run as `pypi-runner`. Open an interactive login shell:

```bash
sudo -u pypi-runner -i
# Prompt changes to: pypi-runner@<hostname>:~$
```

Source the environment in each terminal you open:

```bash
source ~/.env
source ~/pypi-scada-repo/venv/bin/activate
```

---

## Step 9 — Start the simulator (Terminal A)

```bash
cd ~/pypi-scada-repo/src/simulator
source ~/pypi-scada-repo/venv/bin/activate
python main.py
```

Leave Terminal A running. Confirm startup:

```
Starting PyPI Simulator on 127.0.0.1:8080
```

Check readiness from Terminal B:

```bash
curl -s http://127.0.0.1:8080/simple/
# Expected: empty HTML index (no packages yet)
```

---

## Step 10 — Upload samples (Terminal B)

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

## Step 11 — Run the evaluation pipeline (Terminal B)

```bash
source ~/.env
cd ~/pypi-scada-repo
source venv/bin/activate
python src/analyzer/evaluate.py src/analyzer/config.yaml
```

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
