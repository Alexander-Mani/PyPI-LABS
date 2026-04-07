#!/bin/bash
set -e

# PyPI-SCADA Deployment Script (VM-Targeted)
# This script automates the setup of the entry-point scanning pipeline.
# It assumes a clean Ubuntu 22.04 LTS environment.

echo "Sourcing operator environment variables..."
if [ -f ~/.env ]; then
  source ~/.env 
else
  echo "ERROR: ~/.env not found. Ensure PULL_TOKEN and API keys are exported."
  exit 1
fi

echo "Step 0: Installing system dependencies"
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git unzip curl python3 python3-venv python3-pip iptables sqlite3

echo "Step 1: Creating unprivileged accounts"
id -u pypi-runner &>/dev/null || sudo useradd --system --create-home --home-dir /home/pypi-runner --shell /bin/bash --comment "PyPi-SCADA experiment runner" pypi-runner
id -u proxy-runner &>/dev/null || sudo useradd --system --create-home --home-dir /home/proxy-runner --shell /bin/bash --comment "PyPi-SCADA credential proxy" proxy-runner

echo "Step 2: Cloning the repository"
if [ ! -d "/home/pypi-runner/pypi-scada-repo" ]; then
  # Use an ephemeral .netrc so PULL_TOKEN is never embedded in the git remote URL
  # (.git/config) or visible in the process table during the clone.
  echo "machine github.com login Alexander-Mani password $PULL_TOKEN" \
    | sudo -u pypi-runner tee /home/pypi-runner/.netrc > /dev/null
  sudo chmod 600 /home/pypi-runner/.netrc

  sudo -u pypi-runner git clone \
    https://github.com/Alexander-Mani/PyPi-SCADA.git \
    /home/pypi-runner/pypi-scada-repo/ || { sudo -u pypi-runner rm -f /home/pypi-runner/.netrc; exit 1; }

  sudo -u pypi-runner rm -f /home/pypi-runner/.netrc
  sudo chown -R pypi-runner:pypi-runner /home/pypi-runner/pypi-scada-repo
else
  echo "Repository already exists at /home/pypi-runner/pypi-scada-repo, pulling latest changes."
  echo "machine github.com login Alexander-Mani password $PULL_TOKEN" \
    | sudo -u pypi-runner tee /home/pypi-runner/.netrc > /dev/null
  sudo chmod 600 /home/pypi-runner/.netrc

  sudo -u pypi-runner bash -c "cd /home/pypi-runner/pypi-scada-repo && git pull" || { sudo -u pypi-runner rm -f /home/pypi-runner/.netrc; exit 1; }

  sudo -u pypi-runner rm -f /home/pypi-runner/.netrc
fi

echo "Step 3: Staging samples for the research pipeline"
# The EvaluationRunner in evaluate.py expects samples under the repo root's samples/ directory.
sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/benign
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  
  echo 'Extracting benign and controls...'
  unzip -q /home/lexi/samples/benign_and_controlls.zip -d /home/pypi-runner/pypi-scada-repo/samples/benign/
  
  echo 'Staging malicious archives...'
  for f in /home/lexi/samples/*.zip; do
    name=\$(basename \"\$f\")
    if [ \"\$name\" != 'benign_and_controlls.zip' ]; then
      cp \"\$f\" /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife/
    fi
  done
"

echo "Step 4: Setting up Python virtual environment (pypi-runner)"
# requirements/requirements.txt is a hashed lockfile.
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r requirements/requirements.txt
"

echo "Step 5: Configuring API keys for proxy-runner"
echo "Validating API key environment variables..."
: "${ANTHROPIC_API_KEY:?ERROR: ANTHROPIC_API_KEY is not set in ~/.env}"
: "${OPENAI_API_KEY:?ERROR: OPENAI_API_KEY is not set in ~/.env}"
: "${GEMINI_API_KEY:?ERROR: GEMINI_API_KEY is not set in ~/.env}"
: "${TOGETHER_API_KEY:?ERROR: TOGETHER_API_KEY is not set in ~/.env}"

sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << ENVEOF
export ANTHROPIC_API_KEY=\"$ANTHROPIC_API_KEY\"
export OPENAI_API_KEY=\"$OPENAI_API_KEY\"
export GEMINI_API_KEY=\"$GEMINI_API_KEY\"
export TOGETHER_API_KEY=\"$TOGETHER_API_KEY\"
ENVEOF
chmod 600 /home/proxy-runner/.env
grep -qF 'source ~/.env' /home/proxy-runner/.bashrc || echo 'source ~/.env' >> /home/proxy-runner/.bashrc
"

echo "Step 6: Configuring egress filtering (iptables)"
sudo modprobe xt_owner

# Flush existing rules to avoid duplicates if re-running
sudo iptables -F OUTPUT || true

# pypi-runner: Allow local only (to talk to simulator and LiteLLM)
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner -o lo -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner pypi-runner -j DROP || true

# proxy-runner: Allow local, DNS, and specific vendor CIDRs
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT || true

# DNS restricted to Google Public DNS (8.8.8.8, 8.8.4.4) and Cloudflare (1.1.1.1).
# Global port-53 ACCEPT would allow DNS tunneling from malware under test.
for _dns_ip in 8.8.8.8 8.8.4.4 1.1.1.1; do
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p udp --dport 53 -d "$_dns_ip" -j ACCEPT || true
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p tcp --dport 53 -d "$_dns_ip" -j ACCEPT || true
done

ANTHROPIC_CIDR="104.18.0.0/16" 
OPENAI_CIDR="162.159.0.0/16"
GOOGLE_CIDR="142.250.0.0/15"

sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $ANTHROPIC_CIDR -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $OPENAI_CIDR -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d $GOOGLE_CIDR -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d api.together.xyz -p tcp --dport 443 -j ACCEPT || true
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP || true

echo "Step 7: Starting LiteLLM proxy"
# Copy the proxy lockfile over from pypi-runner's repo clone
sudo cp /home/pypi-runner/pypi-scada-repo/requirements/proxy-requirements.txt /home/proxy-runner/
sudo chown proxy-runner:proxy-runner /home/proxy-runner/proxy-requirements.txt

sudo -u proxy-runner bash -c "
  python3 -m venv /home/proxy-runner/venv
  source /home/proxy-runner/venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r /home/proxy-runner/proxy-requirements.txt
"

sudo -u proxy-runner bash -c "
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  pkill -u proxy-runner -f 'litellm --port 4000' || true
  nohup litellm --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
"

echo "Waiting for LiteLLM health check..."
sleep 8
sudo -u pypi-runner curl -s http://127.0.0.1:4000/health || echo "WARNING: LiteLLM health check failed."

echo "Step 8: Starting the PyPI simulator (background)"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo/src/simulator
  pkill -u pypi-runner -f 'python main.py' || true
  nohup python main.py > /home/pypi-runner/simulator.log 2>&1 &
"

sleep 5

echo "Step 9: Uploading samples to simulator index"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo

  # Use the staged samples in the repo for injection
  python src/injector/upload_samples.py --samples-dir /home/pypi-runner/pypi-scada-repo/samples --simulator-url http://127.0.0.1:8080 --only benign
  python src/injector/upload_samples.py --samples-dir /home/pypi-runner/pypi-scada-repo/samples --simulator-url http://127.0.0.1:8080 --only controls
  python src/injector/upload_samples.py --samples-dir /home/pypi-runner/pypi-scada-repo/samples --simulator-url http://127.0.0.1:8080 --only malicious
"

echo "Step 10: Running the evaluation pipeline (Entry-Point Scanning)"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  # Defaulting to budget tier for safety; reads configs/models.json automatically.
  python src/analyzer/evaluate.py --tier budget
"

echo "Deployment and evaluation complete. Results stored in src/data/eval_results.db"
