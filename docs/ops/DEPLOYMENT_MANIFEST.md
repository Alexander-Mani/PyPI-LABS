# Deployment Manifest PyPi-SCADA VM

The human operator executes these sequential steps to deploy the PyPi-SCADA pipeline on the provisioned virtual machine. Automated agents do not execute these commands. The architecture implements entry-point scanning over differential analysis. LiteLLM serves as the universal translation layer for all language model API requests.

***

## Prerequisites

| Requirement | Minimum |
|---|---|
| OS | Ubuntu 22.04 LTS |
| Python | 3.11+ (`python3 --version`) |
| Tools | `git`, `unzip`, `curl`, `pip` |
| VM home | `/home/lexi/` |
| Samples archive | `~/samples/benign_and_controlls.zip` present |
| Malicious zips | `~/samples/*.zip` present |
| Pull script | `~/pull_script_with_fine_grain_acces_token.sh` present |

Outbound network access to GitHub and PyPI is required for steps 1 through 5. The operator restricts network access before step 7.

***

## Step 1 Create unprivileged accounts

Two accounts isolate the pipeline components. The `pypi-runner` account runs the analyzer pipeline. The `proxy-runner` account runs LiteLLM and holds the API keys. Only `proxy-runner` makes outbound connections to external endpoints.

Run as `lexi` or another sudoer:

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

Verify lack of sudo access:

```bash
sudo -l -U pypi-runner
sudo -l -U proxy-runner
```

***

## Step 2 Clone the repository

The pull script requires a fine-grained GitHub personal access token. The operator runs it as `pypi-runner` to establish correct repository ownership.

```bash
sudo -u pypi-runner bash /home/lexi/pull_script_with_fine_grain_acces_token.sh
```

Copy the repository if the script placed it under `/home/lexi/`:

```bash
sudo cp -r /home/lexi/pypi-scada-repo /home/pypi-runner/pypi-scada-repo
sudo chown -R pypi-runner:pypi-runner /home/pypi-runner/pypi-scada-repo
```

***

## Step 3 Extract the benign and controls archive

Extraction takes several minutes.

```bash
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/samples-extracted
  unzip -q /home/lexi/samples/benign_and_controlls.zip \
        -d /home/pypi-runner/samples-extracted/
"
```

***

## Step 4 Stage the malicious zips

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

***

## Step 5 Set up the Python virtual environment

The virtual environment installs the analyzer dependencies from a hashed lockfile
compiled with `pip-tools`. All tools (`twine`, `bandit`, `semgrep`) must be declared
in `requirements.in` and present in `requirements.txt` with hashes before this step.

```bash
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r requirements.txt
"
```

Compile the lockfile locally before deploying (not on the VM):

```bash
pip install pip-tools
pip-compile --generate-hashes requirements.in -o requirements.txt
```

***

## Step 6 Configure API keys

The `proxy-runner` account owns the API keys. 

```bash
sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << 'ENVEOF'
export ANTHROPIC_API_KEY=sk-ant-REPLACE_ME
export OPENAI_API_KEY=sk-REPLACE_ME
export GEMINI_API_KEY=REPLACE_ME
export TOGETHER_API_KEY=REPLACE_ME
ENVEOF
chmod 600 /home/proxy-runner/.env
echo 'source ~/.env' >> /home/proxy-runner/.bashrc
"
```

Edit `/home/proxy-runner/.env` to insert real keys.

***

## Step 7 Configure egress filtering

The system implements a two-tier egress policy. The operator applies rules using explicit CIDR blocks for vendors.

```bash
sudo modprobe xt_owner

sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner ! -o lo -j DROP
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT

ANTHROPIC_CIDR="104.18.0.0/16" 
OPENAI_CIDR="162.159.0.0/16"
GOOGLE_CIDR="142.250.0.0/15"

sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $ANTHROPIC_CIDR -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $OPENAI_CIDR -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $GOOGLE_CIDR -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d api.together.xyz -p tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP
```

***

## Step 8 Start LiteLLM proxy

The proxy requires LiteLLM installed in its environment from a hashed lockfile.
`proxy-requirements.txt` must be compiled before deploying:

```bash
# Run locally before deployment:
pip-compile --generate-hashes proxy-requirements.in -o proxy-requirements.txt
```

Install on the VM:

```bash
sudo -u proxy-runner bash -c "
  python3 -m venv /home/proxy-runner/venv
  source /home/proxy-runner/venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r /home/pypi-runner/pypi-scada-repo/proxy-requirements.txt
"
```

Start the LiteLLM server:

```bash
sudo -u proxy-runner bash -c "
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  nohup litellm --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
"
```

Verify reachable status from `pypi-runner`:

```bash
sudo -u pypi-runner curl -s http://127.0.0.1:4000/health
```

***

## Step 9 Open the runner session

```bash
sudo -u pypi-runner -i
source ~/pypi-scada-repo/venv/bin/activate
```

***

## Step 10 Start the PyPI simulator

The analyzer pipeline requires an active local PyPI simulator. 

```bash
cd ~/pypi-scada-repo
source venv/bin/activate
cd src/simulator
python main.py
```

***

## Step 11 Upload samples

Execute the injection scripts against the local simulator in a new terminal.

```bash
cd ~/pypi-scada-repo
source venv/bin/activate

python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080 \
  --only benign

python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080 \
  --only controls

python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080 \
  --only malicious
```

***

## Step 12 Run the evaluation pipeline

Execute the analyzer.

```bash
cd ~/pypi-scada-repo
python src/analyzer/evaluate.py src/analyzer/config.yaml
```

***

# Automation Script (`deployment.sh`)

```bash
#!/bin/bash
set -e

echo "Sourcing operator environment variables..."
source ~/.env 

echo "Step 1: Creating unprivileged accounts"
sudo useradd --system --create-home --home-dir /home/pypi-runner --shell /bin/bash --comment "PyPi-SCADA experiment runner" pypi-runner || true
sudo useradd --system --create-home --home-dir /home/proxy-runner --shell /bin/bash --comment "PyPi-SCADA credential proxy" proxy-runner || true

echo "Step 2: Cloning the repository"
sudo -u pypi-runner git clone https://Alexander-Mani:"$PULL_TOKEN"@github.com/Alexander-Mani/PyPi-SCADA.git /home/pypi-runner/pypi-scada-repo/
sudo chown -R pypi-runner:pypi-runner /home/pypi-runner/pypi-scada-repo

echo "Step 3: Extracting samples"
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/samples-extracted
  unzip -q /home/lexi/samples/benign_and_controlls.zip -d /home/pypi-runner/samples-extracted/
"

echo "Step 4: Staging malicious zips"
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/samples-extracted/malicious
  for f in /home/lexi/samples/*.zip; do
    name=\$(basename \"\$f\")
    if [ \"\$name\" != 'benign_and_controlls.zip' ]; then
      cp \"\$f\" /home/pypi-runner/samples-extracted/malicious/
    fi
  done
"

echo "Step 5: Setting up Python virtual environment"
# requirements.txt must be a hashed lockfile compiled with pip-tools (see Step 5 above).
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r requirements.txt
"

echo "Step 6: Configuring API keys for proxy-runner"
sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << ENVEOF
export ANTHROPIC_API_KEY=\"\$ANTHROPIC_API_KEY\"
export OPENAI_API_KEY=\"\$OPENAI_API_KEY\"
export GEMINI_API_KEY=\"\$GEMINI_API_KEY\"
export TOGETHER_API_KEY=\"\$TOGETHER_API_KEY\"
ENVEOF
chmod 600 /home/proxy-runner/.env
echo 'source ~/.env' >> /home/proxy-runner/.bashrc
"

echo "Step 7: Configuring egress filtering"
sudo modprobe xt_owner

sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner ! -o lo -j DROP || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT || true

ANTHROPIC_CIDR="104.18.0.0/16" 
OPENAI_CIDR="162.159.0.0/16"
GOOGLE_CIDR="142.250.0.0/15"

sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $ANTHROPIC_CIDR -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $OPENAI_CIDR -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $GOOGLE_CIDR -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d api.together.xyz -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP || true

echo "Step 8: Starting LiteLLM proxy"
# proxy-requirements.txt must be a hashed lockfile compiled with pip-tools (see Step 8 above).
sudo -u proxy-runner bash -c "
  python3 -m venv /home/proxy-runner/venv
  source /home/proxy-runner/venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r /home/pypi-runner/pypi-scada-repo/proxy-requirements.txt
"

sudo -u proxy-runner bash -c "
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  nohup litellm --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
"

sleep 5
sudo -u pypi-runner curl -s http://127.0.0.1:4000/health

echo "Step 10: Starting the PyPI simulator"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo/src/simulator
  nohup python main.py > /home/pypi-runner/simulator.log 2>&1 &
"

sleep 5

echo "Step 11: Uploading samples"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo

  python src/injector/upload_samples.py --samples-dir /home/pypi-runner/samples-extracted --simulator-url http://127.0.0.1:8080 --only benign
  python src/injector/upload_samples.py --samples-dir /home/pypi-runner/samples-extracted --simulator-url http://127.0.0.1:8080 --only controls
  python src/injector/upload_samples.py --samples-dir /home/pypi-runner/samples-extracted --simulator-url http://127.0.0.1:8080 --only malicious
"

echo "Step 12: Running the evaluation pipeline"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  python src/analyzer/evaluate.py src/analyzer/config.yaml
"

echo "Deployment and evaluation complete."
```
