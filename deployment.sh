#!/bin/bash
set -euo pipefail

# Optional debug tracing:
#   DEBUG=1 bash deployment.sh
if [[ "${DEBUG:-0}" == "1" ]]; then
  PS4='+ [${BASH_SOURCE##*/}:${LINENO}] '
  set -x
fi

trap 'rc=$?; echo "ERROR: command failed (exit ${rc}) at line ${LINENO}: ${BASH_COMMAND}" >&2; exit ${rc}' ERR

_DEPLOY_PHASE="${DEPLOY_PHASE:-full}"
case "$_DEPLOY_PHASE" in
  setup|smoke|full) ;;
  *)
    echo "ERROR: invalid DEPLOY_PHASE: $_DEPLOY_PHASE" >&2
    echo "Allowed values: setup, smoke, full" >&2
    exit 1
    ;;
esac

GUARDDOG_SOURCE_RULES=(
  api-obfuscation
  shady-links
  obfuscation
  clipboard-access
  exfiltrate-sensitive-data
  download-executable
  exec-base64
  silent-process-execution
  dll-hijacking
  screenshot
  steganography
  code-execution
  unicode
  cmd-overwrite
  suspicious_passwd_access_linux
)
_GUARDDOG_RULE_ARGS=""
for _guarddog_rule in "${GUARDDOG_SOURCE_RULES[@]}"; do
  _GUARDDOG_RULE_ARGS+=" --rules ${_guarddog_rule}"
done

# PyPI-LABS Deployment Script (VM-Targeted)
# This script automates the setup of the entry-point scanning pipeline.
# It assumes a clean Ubuntu 22.04 LTS environment.

echo "Sourcing operator environment variables..."
if [ -f .env ]; then
  source .env 
else
  echo "ERROR: .env not found. Ensure PULL_TOKEN and API keys are exported."
  exit 1
fi

echo "Deployment phase: ${_DEPLOY_PHASE}"

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
    https://github.com/Alexander-Mani/PyPI-LABS.git \
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

# Malicious bundle is optional: when handing the project to a supervisor or
# examiner who cannot legally receive the live malware corpus, omit the zip.
# deployment.sh continues with benign and controls only.
_MALWARE_ZIP="${SAMPLES_DIR:-/home/operator/samples}/malware_backstabbers_knife.zip"
if [ -f "${_MALWARE_ZIP}" ]; then
  _MALWARE_EXTRACT="unzip -P infected ${UNZIP_FLAGS} \"${_MALWARE_ZIP}\" -d /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife/"
else
  echo "NOTICE: malicious bundle not found at ${_MALWARE_ZIP}; deployment will continue with benign and controls only."
  _MALWARE_EXTRACT="echo 'Skipping malicious bundle extraction (zip not present).'"
fi

sudo -u pypi-runner bash -c "
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/benign
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/controls

  echo 'Extracting benign and controls...'
  # Extract at samples/ root so both benign/ and controls/ land in expected paths.
  unzip ${UNZIP_FLAGS} ${SAMPLES_DIR:-/home/operator/samples}/benign_and_controlls.zip -d /home/pypi-runner/pypi-scada-repo/samples/

  echo 'Preparing malicious bundle directory...'
  rm -rf /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  mkdir -p /home/pypi-runner/pypi-scada-repo/samples/malware_backstabbers_knife
  ${_MALWARE_EXTRACT}
"

echo "Step 4: Setting up Python virtual environments"
# requirements/requirements.txt is a hashed lockfile.
sudo -u pypi-runner bash -c "
  cd /home/pypi-runner/pypi-scada-repo
  python3 -m venv venv
  source venv/bin/activate
  pip install --require-hashes --no-deps --quiet -r requirements/requirements.txt
  guarddog --version >/dev/null
  semgrep_smoke_dir=\$(mktemp -d)
  semgrep_state_dir=\$(mktemp -d)
  semgrep_output=\$(mktemp)
  cat > \"\$semgrep_smoke_dir/smoke.py\" <<'PYEOF'
import subprocess
subprocess.run("id", shell=True)
PYEOF
  SEMGREP_SETTINGS_FILE=\"\$semgrep_state_dir/settings.yml\" \
  SEMGREP_LOG_FILE=\"\$semgrep_state_dir/semgrep.log\" \
  SEMGREP_SEND_METRICS=off \
  semgrep scan \
    --config /home/pypi-runner/pypi-scada-repo/src/analyzer/static_rules/semgrep_python.yml \
    --json --metrics off --disable-version-check --no-git-ignore --quiet \
    \"\$semgrep_smoke_dir\" > \"\$semgrep_output\"
  python -c 'import json, pathlib, sys; data = json.loads(pathlib.Path(sys.argv[1]).read_text()); ids = {item.get(\"check_id\", \"\").split(\".\")[-1] for item in data.get(\"results\", [])}; expected = \"pypi-scada-python-subprocess-shell-true\"; print(\"Semgrep offline rules OK\" if expected in ids else f\"ERROR: Semgrep smoke missing {expected}; got {sorted(ids)}\"); sys.exit(0 if expected in ids else 1)' \"\$semgrep_output\"
  rm -rf \"\$semgrep_smoke_dir\" \"\$semgrep_state_dir\" \"\$semgrep_output\"
  guarddog_rules_output=\$(mktemp)
  guarddog pypi list-rules > \"\$guarddog_rules_output\"
  GUARDDOG_EXPECTED_RULES=\"${GUARDDOG_SOURCE_RULES[*]}\" python -c 'import os, pathlib, sys; text = pathlib.Path(sys.argv[1]).read_text(); found = set();
for line in text.splitlines():
    cols = [col.strip() for col in line.split(\"|\")]
    if len(cols) >= 4 and cols[1].lower() == \"source code\":
        found.add(cols[2])
expected = set(os.environ[\"GUARDDOG_EXPECTED_RULES\"].split()); missing = sorted(expected - found)
print(f\"GuardDog source rules OK ({len(expected)} rules)\" if not missing else f\"ERROR: GuardDog source rules missing: {missing}\")
sys.exit(1 if missing else 0)' \"\$guarddog_rules_output\"
  rm -f \"\$guarddog_rules_output\"
  # src.injector.upload_samples shells out to python -m twine from this venv.
  pip install --require-hashes --no-deps --quiet -r requirements/injector-requirements.txt
  echo 'Validating PyPI-LABS package imports...'
  PYTHONPATH=/home/pypi-runner/pypi-scada-repo python -c 'import src.utils.logger; import src.injector.upload_samples'
  echo 'Validating Twine upload runtime imports...'
  python -c 'import twine.commands.upload; from backports import tarfile'
  python -m twine upload --help >/dev/null
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
_GEMINI="${GEMINI:-on}"
case "$_GEMINI" in
  on|off) ;;
  *)
    echo "ERROR: invalid GEMINI: $_GEMINI" >&2
    echo "Allowed values: on, off" >&2
    exit 1
    ;;
esac

echo "Validating API key environment variables..."
: "${ANTHROPIC_API_KEY:?ERROR: ANTHROPIC_API_KEY is not set in ~/.env}"
: "${OPENAI_API_KEY:?ERROR: OPENAI_API_KEY is not set in ~/.env}"
: "${TOGETHER_API_KEY:?ERROR: TOGETHER_API_KEY is not set in ~/.env}"
if [[ "$_GEMINI" == "on" ]]; then
  : "${GEMINI_API_KEY:?ERROR: GEMINI_API_KEY is not set in ~/.env}"
fi
_GEMINI_API_KEY_VALUE="${GEMINI_API_KEY:-}"

sudo -u proxy-runner bash -c "
cat > /home/proxy-runner/.env << ENVEOF
export ANTHROPIC_API_KEY=\"$ANTHROPIC_API_KEY\"
export OPENAI_API_KEY=\"$OPENAI_API_KEY\"
export GEMINI_API_KEY=\"$_GEMINI_API_KEY_VALUE\"
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

# proxy-runner: Allow local, DNS, and resolved LLM vendor API endpoints
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -o lo -j ACCEPT || true

# DNS restricted to Google Public DNS (8.8.8.8, 8.8.4.4) and Cloudflare (1.1.1.1).
# Global port-53 ACCEPT would allow DNS tunneling from malware under test.
for _dns_ip in 8.8.8.8 8.8.4.4 1.1.1.1; do
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p udp --dport 53 -d "$_dns_ip" -j ACCEPT || true
  sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner \
    -p tcp --dport 53 -d "$_dns_ip" -j ACCEPT || true
done

LLM_VENDOR_HOSTS=(
  api.anthropic.com
  api.openai.com
  api.together.xyz
)
if [[ "$_GEMINI" == "on" ]]; then
  LLM_VENDOR_HOSTS+=(generativelanguage.googleapis.com)
fi
declare -A _allowed_vendor_ips=()
for _vendor_host in "${LLM_VENDOR_HOSTS[@]}"; do
  echo "Resolving LLM vendor host: ${_vendor_host}"
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
    echo "Allowing proxy-runner HTTPS egress to ${_vendor_host} (${_vendor_ip})"
    sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -d "$_vendor_ip" -p tcp --dport 443 -j ACCEPT || true
  done
done
sudo iptables -A OUTPUT -m owner --uid-owner proxy-runner -j DROP || true

echo "Running GuardDog source-only offline smoke test"
sudo -u pypi-runner bash -c "
  set -euo pipefail
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  tmpdir=\$(mktemp -d)
  trap 'rm -rf \"\$tmpdir\"' EXIT
  printf '%s\n' 'from setuptools import setup' 'setup(name=\"guarddog-smoke\")' > \"\$tmpdir/setup.py\"
  timeout 180 guarddog pypi scan \"\$tmpdir\" --output-format=json ${_GUARDDOG_RULE_ARGS} >/tmp/pypi-scada-guarddog-smoke.json
  python -c 'import json, pathlib, sys; data=json.loads(pathlib.Path(\"/tmp/pypi-scada-guarddog-smoke.json\").read_text()); errors=data.get(\"errors\") or {}; print(\"GuardDog offline source-only smoke OK\" if not errors else f\"ERROR: GuardDog offline smoke reported rule errors: {errors}\"); sys.exit(1 if errors else 0)'
"

echo "Step 7: Starting LiteLLM proxy"
sudo cp /home/pypi-runner/pypi-scada-repo/configs/litellm_config.yaml /home/proxy-runner/litellm_config.yaml
sudo chown proxy-runner:proxy-runner /home/proxy-runner/litellm_config.yaml
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
  nohup litellm --config /home/proxy-runner/litellm_config.yaml --port 4000 > /home/proxy-runner/litellm.log 2>&1 &
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

_MODEL_PROFILE="${MODEL_PROFILE:-budget}"
if [[ -z "${_MODEL_PROFILE//[[:space:]]/}" ]]; then
  echo "ERROR: MODEL_PROFILE cannot be empty" >&2
  exit 1
fi

echo "Running LiteLLM model-profile smoke test (profile: ${_MODEL_PROFILE})"
if ! sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  python scripts/litellm_smoke.py --base-url http://127.0.0.1:4000 --profile \"${_MODEL_PROFILE}\" --gemini \"${_GEMINI}\" --retries 3 --retry-delay 20
"; then
  echo "ERROR: LiteLLM smoke test failed. Aborting before evaluation."
  echo "Focused LiteLLM failure context (filtered last 220 log lines):"
  sudo -u proxy-runner bash -c "
    tail -n 220 /home/proxy-runner/litellm.log 2>/dev/null |
      grep -Ei 'gemini|google|timeout|timed out|429|503|401|403|unavailable|resource_exhausted|invalid_api_key|connecterror|ratelimit|quota|overload|high demand|serviceunavailable|authentication|badrequest' || true
  "
  echo "Last 80 lines of /home/proxy-runner/litellm.log:"
  sudo -u proxy-runner tail -n 80 /home/proxy-runner/litellm.log || true
  exit 1
fi

if [[ "${DEPLOY_PAUSE:-0}" == "1" ]]; then
  read -r -p "Basic deployment update done. Press Enter to continue..."
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
# Set UPLOAD_CATEGORIES=none to skip upload during setup-only deployment refreshes.
# The value is validated before outer-shell expansion into the sudo subshell.
_UPLOAD_CATS="${UPLOAD_CATEGORIES:-benign controls malicious}"
if [[ -z "${_UPLOAD_CATS//[[:space:]]/}" ]]; then
  echo "ERROR: UPLOAD_CATEGORIES cannot be empty" >&2
  exit 1
fi
for _cat in $_UPLOAD_CATS; do
  case "$_cat" in
    benign|controls|malicious|all|none) ;;
    *)
      echo "ERROR: invalid UPLOAD_CATEGORIES entry: $_cat" >&2
      echo "Allowed values: benign controls malicious all none" >&2
      exit 1
      ;;
  esac
done

if [[ " ${_UPLOAD_CATS} " == *" none "* ]]; then
  if [[ "${_UPLOAD_CATS}" != "none" ]]; then
    echo "ERROR: UPLOAD_CATEGORIES=none cannot be combined with other categories" >&2
    exit 1
  fi
  echo "Step 9: Skipping sample upload (UPLOAD_CATEGORIES=none)"
else
  echo "Step 9: Uploading samples to simulator index (categories: ${_UPLOAD_CATS})"
  sudo -u pypi-runner bash -c "
    source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
    cd /home/pypi-runner/pypi-scada-repo
    for _cat in ${_UPLOAD_CATS}; do
      PYTHONPATH=/home/pypi-runner/pypi-scada-repo python -m src.injector.upload_samples \
        --samples-dir /home/pypi-runner/pypi-scada-repo/samples \
        --simulator-url http://127.0.0.1:8080 \
        --only \"\$_cat\"
    done
  "
fi

if [[ "$_DEPLOY_PHASE" == "setup" ]]; then
  echo "Deployment setup complete. Evaluation was skipped because DEPLOY_PHASE=setup."
  exit 0
fi

# VERBOSE=1 enables --verbose flag on evaluate.py (DEBUG-level prompt/response logging).
_VERBOSE_FLAG=""
[[ "${VERBOSE:-0}" == "1" ]] && _VERBOSE_FLAG="--verbose"

_INCLUDE_CONTROLS_FLAG=""
[[ "${INCLUDE_CONTROLS:-0}" == "1" ]] && _INCLUDE_CONTROLS_FLAG="--include-controls"

_EVAL_PROGRESS="${EVAL_PROGRESS:-auto}"
case "$_EVAL_PROGRESS" in
  auto|always|never) ;;
  *)
    echo "ERROR: invalid EVAL_PROGRESS: $_EVAL_PROGRESS" >&2
    echo "Allowed values: auto, always, never" >&2
    exit 1
    ;;
esac

echo "Step 10: Running the evaluation pipeline (phase: ${_DEPLOY_PHASE})"
sudo -u pypi-runner bash -c "
  source /home/pypi-runner/pypi-scada-repo/venv/bin/activate
  cd /home/pypi-runner/pypi-scada-repo
  # Defaulting to the budget model profile for safety; reads configs/evaluation_profiles.yaml.
  python src/analyzer/evaluate.py --profile \"${_MODEL_PROFILE}\" --gemini \"${_GEMINI}\" --dry-run-resolution --skip-validation \
    --progress \"${_EVAL_PROGRESS}\" ${_INCLUDE_CONTROLS_FLAG}
  python src/analyzer/evaluate.py --profile \"${_MODEL_PROFILE}\" --gemini \"${_GEMINI}\" ${_VERBOSE_FLAG} \
    --progress \"${_EVAL_PROGRESS}\" ${_INCLUDE_CONTROLS_FLAG}
"

echo "Deployment ${_DEPLOY_PHASE} phase complete. Results stored in src/data/eval_results.db"
