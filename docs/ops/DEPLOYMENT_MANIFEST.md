# Deployment Manifest: PyPI-SCADA VM

The human operator executes these sequential steps to deploy the PyPI-SCADA pipeline on the provisioned virtual machine. This architecture implements **Entry-Point Scanning**, resolves package artifacts from the local PyPI simulator, and routes all LLM requests through a local LiteLLM proxy.

***

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Python | 3.11+ |
| Tools | `git`, `unzip`, `curl`, `pip`, `iptables` |
| VM home | `/home/lexi/` |
| Samples archive | `~/samples/benign_and_controlls.zip` |
| Malicious bundle | `~/samples/malware_backstabbers_knife.zip` (password: `infected`) |
| Environment | `~/.env` with `PULL_TOKEN`, `ANTHROPIC_API_KEY`, etc. |

***

## Step 0: Install System Dependencies

Ensure the required Debian/Ubuntu system packages are installed. A list of required packages is maintained in `requirements/apt.txt`.

```bash
sudo apt-get update
sudo apt-get install -y git unzip curl python3 python3-venv python3-pip iptables sqlite3
```

***

## Step 1: Create Unprivileged Accounts

Isolate the runner from the credentials.

```bash
sudo useradd --system --create-home --home-dir /home/pypi-runner --shell /bin/bash pypi-runner
sudo useradd --system --create-home --home-dir /home/proxy-runner --shell /bin/bash proxy-runner
```

***

## Step 2: Clone the Repository

Clone as `pypi-runner` using an ephemeral `.netrc` so the token is never stored in
`.git/config` or visible in the process table.

```bash
echo "machine github.com login Alexander-Mani password $PULL_TOKEN" \
  | sudo -u pypi-runner tee /home/pypi-runner/.netrc > /dev/null
sudo chmod 600 /home/pypi-runner/.netrc

sudo -u pypi-runner git clone \
  https://github.com/Alexander-Mani/PyPi-SCADA.git \
  /home/pypi-runner/pypi-scada-repo/

sudo -u pypi-runner rm /home/pypi-runner/.netrc
```

***

## Step 3: Stage Samples

The uploader and ground-truth builder expect a specific directory structure within the repository. `evaluate.py` uses this staged dataset for labels and candidate metadata, but downloads the artifacts it scans from the simulator.

```bash
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/benign
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/controls
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  
  unzip -q /home/lexi/samples/benign_and_controlls.zip -d /home/pypi-runner/pypi-scada-repo/samples/

  rm -rf /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  unzip -P infected -q /home/lexi/samples/malware_backstabbers_knife.zip -d /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife/
"
```

***

## Step 4: Setup Virtual Environments (Analyzer & Proxy)

Install dependencies using the hashed lockfile while the network is open.

```bash
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps -r requirements/requirements.txt
"

sudo cp /home/pypi-runner/pypi-scada-repo/requirements/proxy-requirements.txt /home/proxy-runner/
sudo chown proxy-runner:proxy-runner /home/proxy-runner/proxy-requirements.txt

sudo -u proxy-runner bash -c "
  python3 -m venv /home/proxy-runner/venv
  source /home/proxy-runner/venv/bin/activate
  pip install --require-hashes --no-deps -r /home/proxy-runner/proxy-requirements.txt
"
```

***

## Step 5: Configure API Keys

Stored exclusively on the `proxy-runner` account.

```bash
sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << ENVEOF
export ANTHROPIC_API_KEY=\"REPLACE_ME\"
export OPENAI_API_KEY=\"REPLACE_ME\"
export GEMINI_API_KEY=\"REPLACE_ME\"
export TOGETHER_API_KEY=\"REPLACE_ME\"
ENVEOF
chmod 600 /home/proxy-runner/.env
"
```

***

## Step 6: Configure Egress Filtering

Restrict `pypi-runner` to local traffic only. Allow `proxy-runner` to reach approved API hostnames resolved at deployment time and resolve DNS.

```bash
sudo modprobe xt_owner
sudo iptables -F OUTPUT || true

# pypi-runner: Allow local only
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner -o lo -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner -j DROP

# proxy-runner: Allow local, DNS (locked to safe resolvers), and resolved vendor API IPs
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT

# DNS restricted to Google (8.8.8.8, 8.8.4.4) and Cloudflare (1.1.1.1)
# - prevents DNS tunneling from malware under test
for _dns_ip in 8.8.8.8 8.8.4.4 1.1.1.1; do
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p udp --dport 53 -d "$_dns_ip" -j ACCEPT
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p tcp --dport 53 -d "$_dns_ip" -j ACCEPT
done

LLM_VENDOR_HOSTS=(
  api.anthropic.com
  api.openai.com
  generativelanguage.googleapis.com
  api.together.xyz
)
declare -A _allowed_vendor_ips=()
for _vendor_host in "${LLM_VENDOR_HOSTS[@]}"; do
  mapfile -t _vendor_ips < <(getent ahostsv4 "$_vendor_host" | awk '{print $1}' | sort -u)
  if [[ "${#_vendor_ips[@]}" -eq 0 ]]; then
    echo "ERROR: could not resolve IPv4 address for ${_vendor_host}" >&2
    exit 1
  fi
  for _vendor_ip in "${_vendor_ips[@]}"; do
    if [[ -n "${_allowed_vendor_ips[$_vendor_ip]:-}" ]]; then
      continue
    fi
    _allowed_vendor_ips[$_vendor_ip]=1
    sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d "$_vendor_ip" -p tcp --dport 443 -j ACCEPT
  done
done
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP
```

***

## Step 7: Start Services

### 7.1 Setup and Start LiteLLM Proxy
```bash
sudo cp /home/pypi-runner/pypi-scada-repo/configs/litellm_config.yaml /home/proxy-runner/litellm_config.yaml
sudo chown proxy-runner:proxy-runner /home/proxy-runner/litellm_config.yaml

sudo -u proxy-runner bash -c "
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  nohup litellm --config /home/proxy-runner/litellm_config.yaml --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
"
```

After `/health/readiness` returns healthy, run the budget-tier proxy smoke test
before evaluation:

```bash
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  python scripts/litellm_smoke.py --base-url http://127.0.0.1:4000 --retries 3 --retry-delay 20
"
```

### 7.2 PyPI Simulator
```bash
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo/src/simulator
  nohup python main.py > /home/pypi-runner/simulator.log 2>&1 &
"
```

***

## Step 8: Upload and Evaluate

```bash
# Upload to simulator index
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  python src/injector/upload_samples.py --samples-dir samples --only benign
  python src/injector/upload_samples.py --samples-dir samples --only controls
  python src/injector/upload_samples.py --samples-dir samples --only malicious
"

# Run Research Pipeline (Phased Execution)
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  python src/analyzer/evaluate.py --tier budget --dry-run-resolution --skip-validation
  python src/analyzer/evaluate.py --tier budget
"
```

The evaluation stage resolves packages from the simulator. It does not install or
execute package code. Optional overrides:

```bash
ARTIFACT_POLICY=pip        # pip, pip+sdist, or sdist
VERSIONS_PER_PROJECT=2     # latest-N stable versions per labelled project
UPLOAD_CATEGORIES=malicious # benign, controls, malicious, all; space-separated
INCLUDE_CONTROLS=1         # include high-volume benign controls
VERBOSE=1                  # DEBUG logs
```
