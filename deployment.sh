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
# requirements.txt must be a hashed lockfile compiled with pip-tools:
#   pip-compile --generate-hashes requirements.in -o requirements.txt
# twine, bandit, and semgrep must be listed in requirements.in.
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r requirements.txt
"

echo "Step 6: Configuring API keys for proxy-runner"
sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << ENVEOF
export ANTHROPIC_API_KEY=\"$ANTHROPIC_API_KEY\"
export OPENAI_API_KEY=\"$OPENAI_API_KEY\"
export GEMINI_API_KEY=\"$GEMINI_API_KEY\"
export TOGETHER_API_KEY=\"$TOGETHER_API_KEY\"
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
# proxy-runner/requirements.txt must be a hashed lockfile:
#   pip-compile --generate-hashes proxy-requirements.in -o proxy-runner/requirements.txt
sudo -u proxy-runner bash -c "
  python3 -m venv /home/proxy-runner/venv
  source /home/proxy-runner/venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r /home/proxy-runner/pypi-scada-repo/proxy-requirements.txt
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
