# Deployment Manifest: PyPI-SCADA VM

The human operator executes these sequential steps to deploy the PyPI-SCADA pipeline on the provisioned virtual machine. This architecture implements **Entry-Point Scanning** and routes all LLM requests through a local LiteLLM proxy.

***

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Python | 3.11+ |
| Tools | `git`, `unzip`, `curl`, `pip`, `iptables` |
| VM home | `/home/lexi/` |
| Samples archive | `~/samples/benign_and_controlls.zip` |
| Malicious zips | `~/samples/*.zip` (password: `infected`) |
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

The `evaluate.py` script expects a specific directory structure within the repository.

```bash
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/benign
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  
  unzip -q /home/lexi/samples/benign_and_controlls.zip -d /home/pypi-runner/pypi-scada-repo/samples/benign/
  
  for f in /home/lexi/samples/*.zip; do
    if [ \"\$(basename \"\$f\")\" != 'benign_and_controlls.zip' ]; then
      cp \"\$f\" /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife/
    fi
  done
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

Restrict `pypi-runner` to local traffic only. Allow `proxy-runner` to reach approved API CIDRs and resolve DNS.

```bash
sudo modprobe xt_owner
sudo iptables -F OUTPUT || true

# pypi-runner: Allow local only
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner -o lo -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner -j DROP

# proxy-runner: Allow local, DNS (locked to safe resolvers), and vendor CIDRs
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT

# DNS restricted to Google (8.8.8.8, 8.8.4.4) and Cloudflare (1.1.1.1)
# — prevents DNS tunneling from malware under test
for _dns_ip in 8.8.8.8 8.8.4.4 1.1.1.1; do
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p udp --dport 53 -d "$_dns_ip" -j ACCEPT
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p tcp --dport 53 -d "$_dns_ip" -j ACCEPT
done

sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d 104.18.0.0/16 -p tcp --dport 443 -j ACCEPT  # Anthropic/Cloudflare
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d 162.159.0.0/16 -p tcp --dport 443 -j ACCEPT # OpenAI/Cloudflare
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d 142.250.0.0/15 -p tcp --dport 443 -j ACCEPT # Google
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d api.together.xyz -p tcp --dport 443 -j ACCEPT # Together AI
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP
```

***

## Step 7: Start Services

### 7.1 Setup and Start LiteLLM Proxy
```bash
sudo -u proxy-runner bash -c "
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  nohup litellm --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
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
  python src/analyzer/evaluate.py --tier budget
"
```

