#!/bin/bash
set -euo pipefail

# Optional debug tracing:
#   DEBUG=1 bash deployment.sh
if [[ "${DEBUG:-0}" == "1" ]]; then
  PS4='+ [${BASH_SOURCE##*/}:${LINENO}] '
  set -x
fi

trap 'rc=$?; echo "ERROR: command failed (exit ${rc}) at line ${LINENO}: ${BASH_COMMAND}" >&2; exit ${rc}' ERR

# PyPI-SCADA Deployment Script (VM-Targeted)
# This script automates the setup of the entry-point scanning pipeline.
# It assumes a clean Ubuntu 22.04 LTS environment.

echo "Sourcing operator environment variables..."
if [ -f .env ]; then
  source .env 
else
  echo "ERROR: .env not found. Ensure PULL_TOKEN and API keys are exported."
  exit 1
fi

echo "Step 0: Installing system dependencies"
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git unzip curl python3 python3-venv python3-pip iptables sqlite3

echo "Step 1: Creating unprivileged accounts"
id -u pypi-runner &>/dev/null || sudo useradd --system --create-home --home-dir /home/pypi-runner --shell /bin/bash --comment "PyPi-SCADA experiment runner" pypi-runner
id -u proxy-runner &>/dev/null || sudo useradd --system --create-home --home-dir /home/proxy-runner --shell /bin/bash --comment "PyPi-SCADA credential proxy" proxy-runner

# Flush existing firewall rules from previous runs so pypi-runner has network access for git and pip
sudo iptables -F OUTPUT || true

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
# The uploader and evaluator ground-truth builder expect samples under the repo root.
# The evaluator scans artifacts downloaded back from the simulator, not this staging directory directly.
# Default behavior is interactive unzip prompts (preserves operator choice).
# Set FORCE_UNZIP_OVERWRITE=1 to force overwrite without prompts.
UNZIP_FLAGS="-q"
if [[ "${FORCE_UNZIP_OVERWRITE:-0}" == "1" ]]; then
  UNZIP_FLAGS="-oq"
fi

sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/benign
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/controls
  
  echo 'Extracting benign and controls...'
  # Extract at samples/ root so both benign/ and controls/ land in expected paths.
  unzip ${UNZIP_FLAGS} /home/lexi/samples/benign_and_controlls.zip -d /home/pypi-runner/pypi-scada-repo/samples/
  
  echo 'Extracting malicious bundle...'
  rm -rf /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  unzip -P infected ${UNZIP_FLAGS} /home/lexi/samples/malware_backstabbers_knife.zip -d /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife/
"

echo "Step 4: Setting up Python virtual environments"
# requirements/requirements.txt is a hashed lockfile.
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r requirements/requirements.txt
  # injector/upload_samples.py shells out to `python -m twine` from this venv.
  pip install --require-hashes --no-deps --quiet -r requirements/injector-requirements.txt
"

# Copy the proxy lockfile over from pypi-runner's repo clone
sudo cp /home/pypi-runner/pypi-scada-repo/requirements/proxy-requirements.txt /home/proxy-runner/
sudo chown proxy-runner:proxy-runner /home/proxy-runner/proxy-requirements.txt

sudo -u proxy-runner bash -c "
  python3 -m venv /home/proxy-runner/venv
  source /home/proxy-runner/venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r /home/proxy-runner/proxy-requirements.txt
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
sudo -u proxy-runner bash -c "
  source /home/proxy-runner/.env
  source /home/proxy-runner/venv/bin/activate
  # Avoid pkill -f self-match against this bash -c command line.
  existing_litellm_pids=\$(pgrep -x litellm || true)
  if [ -n \"\$existing_litellm_pids\" ]; then
    echo \"Stopping existing LiteLLM PIDs: \$existing_litellm_pids\"
    kill \$existing_litellm_pids 2>/dev/null || true
    sleep 1
  fi
  nohup litellm --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
"

echo "Waiting for LiteLLM health check (up to 60 s)..."
ready=0
for _i in {1..60}; do
  if sudo -u pypi-runner curl -fsS http://127.0.0.1:4000/health/readiness >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [ "$ready" -ne 1 ]; then
  echo "ERROR: LiteLLM did not become healthy within 60 seconds. Aborting."
  echo "LiteLLM process check (proxy-runner):"
  sudo -u proxy-runner pgrep -a -x litellm || true
  echo "Last 40 lines of /home/proxy-runner/litellm.log:"
  sudo -u proxy-runner tail -n 40 /home/proxy-runner/litellm.log || true
  exit 1
fi

echo "Step 8: Starting the PyPI simulator (background)"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo/src/simulator
  # Avoid pkill -f self-match against this bash -c command line.
  existing_sim_pids=\$(pgrep -u pypi-runner -f 'python main.py' | grep -vw \"\$\$\" || true)
  if [ -n \"\$existing_sim_pids\" ]; then
    echo \"Stopping existing simulator PIDs: \$existing_sim_pids\"
    kill \$existing_sim_pids 2>/dev/null || true
    sleep 1
  fi
  nohup python main.py > /home/pypi-runner/simulator.log 2>&1 &
"

sleep 5

# UPLOAD_CATEGORIES controls which sample categories are injected.
# Default: all three. Override: UPLOAD_CATEGORIES="malicious" bash deployment.sh
# The value is validated before outer-shell expansion into the sudo subshell.
_UPLOAD_CATS="${UPLOAD_CATEGORIES:-benign controls malicious}"
if [[ -z "${_UPLOAD_CATS//[[:space:]]/}" ]]; then
  echo "ERROR: UPLOAD_CATEGORIES cannot be empty" >&2
  exit 1
fi
for _cat in $_UPLOAD_CATS; do
  case "$_cat" in
    benign|controls|malicious|all) ;;
    *)
      echo "ERROR: invalid UPLOAD_CATEGORIES entry: $_cat" >&2
      echo "Allowed values: benign controls malicious all" >&2
      exit 1
      ;;
  esac
done

echo "Step 9: Uploading samples to simulator index (categories: ${_UPLOAD_CATS})"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  for _cat in ${_UPLOAD_CATS}; do
    python src/injector/upload_samples.py \
      --samples-dir /home/pypi-runner/pypi-scada-repo/samples \
      --simulator-url http://127.0.0.1:8080 \
      --only \"\$_cat\"
  done
"

# VERBOSE=1 enables --verbose flag on evaluate.py (DEBUG-level prompt/response logging).
_VERBOSE_FLAG=""
[[ "${VERBOSE:-0}" == "1" ]] && _VERBOSE_FLAG="--verbose"

_ARTIFACT_POLICY="${ARTIFACT_POLICY:-pip+sdist}"
case "$_ARTIFACT_POLICY" in
  pip|pip+sdist|sdist) ;;
  *)
    echo "ERROR: invalid ARTIFACT_POLICY: $_ARTIFACT_POLICY" >&2
    echo "Allowed values: pip, pip+sdist, sdist" >&2
    exit 1
    ;;
esac

_VERSIONS_PER_PROJECT="${VERSIONS_PER_PROJECT:-2}"
if ! [[ "$_VERSIONS_PER_PROJECT" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: VERSIONS_PER_PROJECT must be a positive integer" >&2
  exit 1
fi

_INCLUDE_CONTROLS_FLAG=""
[[ "${INCLUDE_CONTROLS:-0}" == "1" ]] && _INCLUDE_CONTROLS_FLAG="--include-controls"

echo "Step 10: Running the evaluation pipeline (Entry-Point Scanning)"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  # Defaulting to budget tier for safety; reads configs/models.json automatically.
  python src/analyzer/evaluate.py --tier budget --dry-run-resolution --skip-validation \
    --versions-per-project \"${_VERSIONS_PER_PROJECT}\" \
    --artifact-policy \"${_ARTIFACT_POLICY}\" ${_INCLUDE_CONTROLS_FLAG}
  python src/analyzer/evaluate.py --tier budget ${_VERBOSE_FLAG} \
    --versions-per-project \"${_VERSIONS_PER_PROJECT}\" \
    --artifact-policy \"${_ARTIFACT_POLICY}\" ${_INCLUDE_CONTROLS_FLAG}
"

echo "Deployment and evaluation complete. Results stored in src/data/eval_results.db"
