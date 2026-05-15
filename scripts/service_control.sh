#!/usr/bin/env bash
set -euo pipefail

# service_control.sh
# Manage PyPI-LABS runtime services (LiteLLM + simulator).
#
# Defaults are VM-oriented and can be overridden with flags.
#
# Examples:
#   scripts/service_control.sh start
#   scripts/service_control.sh stop
#   scripts/service_control.sh restart
#   scripts/service_control.sh status
#   scripts/service_control.sh start --repo-root "$PWD" --runner-user "$USER" --proxy-user "$USER"

ACTION=""
REPO_ROOT="/home/pypi-runner/pypi-scada-repo"
RUNNER_USER="pypi-runner"
PROXY_USER="proxy-runner"
SIM_PORT="8080"
LITELLM_PORT="4000"
SIM_LOG="/home/pypi-runner/simulator.log"
LITELLM_LOG="/home/proxy-runner/litellm.log"
LITELLM_CONFIG=""
NO_SUDO=0

usage() {
  cat <<'USAGE'
Usage: service_control.sh <start|stop|restart|status> [options]

Options:
  --repo-root <path>      Repository root (default: /home/pypi-runner/pypi-scada-repo)
  --runner-user <user>    User running simulator (default: pypi-runner)
  --proxy-user <user>     User running LiteLLM (default: proxy-runner)
  --sim-port <port>       Simulator port for status checks (default: 8080)
  --litellm-port <port>   LiteLLM port for status checks (default: 4000)
  --sim-log <path>        Simulator log file path
  --litellm-log <path>    LiteLLM log file path
  --litellm-config <path> LiteLLM model routing config path
  --no-sudo               Run commands directly (for same-user local dev)
  -h, --help              Show this help

Actions:
  start    Start LiteLLM and simulator
  stop     Stop LiteLLM and simulator
  restart  Stop then start
  status   Show process and endpoint health status
USAGE
}

log() {
  printf '%s\n' "$*"
}

run_as() {
  local user="$1"
  local cmd="$2"

  if [[ "$NO_SUDO" -eq 1 ]]; then
    bash -lc "$cmd"
  else
    sudo -u "$user" bash -lc "$cmd"
  fi
}

require_action() {
  if [[ -z "$ACTION" ]]; then
    usage
    exit 1
  fi
}

parse_args() {
  if [[ $# -eq 0 ]]; then
    usage
    exit 1
  fi

  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
  esac

  ACTION="$1"
  shift

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --repo-root)
        REPO_ROOT="${2:-}"
        shift 2
        ;;
      --runner-user)
        RUNNER_USER="${2:-}"
        shift 2
        ;;
      --proxy-user)
        PROXY_USER="${2:-}"
        shift 2
        ;;
      --sim-port)
        SIM_PORT="${2:-}"
        shift 2
        ;;
      --litellm-port)
        LITELLM_PORT="${2:-}"
        shift 2
        ;;
      --sim-log)
        SIM_LOG="${2:-}"
        shift 2
        ;;
      --litellm-log)
        LITELLM_LOG="${2:-}"
        shift 2
        ;;
      --litellm-config)
        LITELLM_CONFIG="${2:-}"
        shift 2
        ;;
      --no-sudo)
        NO_SUDO=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        log "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

validate_env() {
  if ! [[ "$SIM_PORT" =~ ^[0-9]+$ ]] || ! [[ "$LITELLM_PORT" =~ ^[0-9]+$ ]]; then
    log "ERROR: --sim-port and --litellm-port must be numeric"
    exit 1
  fi

  if [[ ! -d "$REPO_ROOT" ]]; then
    log "ERROR: repo root not found: $REPO_ROOT"
    exit 1
  fi
}

resolve_litellm_config() {
  if [[ -n "$LITELLM_CONFIG" ]]; then
    return
  fi

  if [[ "$NO_SUDO" -eq 1 ]]; then
    LITELLM_CONFIG="$REPO_ROOT/configs/litellm_config.yaml"
  else
    LITELLM_CONFIG="/home/$PROXY_USER/litellm_config.yaml"
  fi
}

ensure_litellm_config() {
  resolve_litellm_config

  if [[ -f "$LITELLM_CONFIG" ]]; then
    return
  fi

  local repo_config="$REPO_ROOT/configs/litellm_config.yaml"
  if [[ "$NO_SUDO" -eq 0 && "$LITELLM_CONFIG" == "/home/$PROXY_USER/litellm_config.yaml" && -f "$repo_config" ]]; then
    sudo cp "$repo_config" "$LITELLM_CONFIG"
    sudo chown "$PROXY_USER:$PROXY_USER" "$LITELLM_CONFIG"
    return
  fi

  log "ERROR: LiteLLM config not found: $LITELLM_CONFIG"
  exit 1
}

stop_litellm() {
  log "Stopping LiteLLM (user: $PROXY_USER)..."
  run_as "$PROXY_USER" "pkill -u $PROXY_USER -f 'litellm .*--port $LITELLM_PORT' || true"
}

stop_simulator() {
  log "Stopping simulator (user: $RUNNER_USER)..."
  run_as "$RUNNER_USER" "pkill -u $RUNNER_USER -f 'python main.py' || true"
}

start_litellm() {
  log "Starting LiteLLM on port $LITELLM_PORT (user: $PROXY_USER)..."
  ensure_litellm_config
  run_as "$PROXY_USER" "
    test -f /home/$PROXY_USER/.env || { echo 'ERROR: missing /home/$PROXY_USER/.env'; exit 1; }
    test -f /home/$PROXY_USER/venv/bin/activate || { echo 'ERROR: missing /home/$PROXY_USER/venv'; exit 1; }
    test -f '$LITELLM_CONFIG' || { echo 'ERROR: missing $LITELLM_CONFIG'; exit 1; }
    source /home/$PROXY_USER/.env
    source /home/$PROXY_USER/venv/bin/activate
    nohup litellm --config '$LITELLM_CONFIG' --port $LITELLM_PORT > '$LITELLM_LOG' 2>&1 &
  "
}

start_simulator() {
  log "Starting simulator on port $SIM_PORT (user: $RUNNER_USER)..."
  run_as "$RUNNER_USER" "
    test -f '$REPO_ROOT/venv/bin/activate' || { echo 'ERROR: missing $REPO_ROOT/venv'; exit 1; }
    source '$REPO_ROOT/venv/bin/activate'
    cd '$REPO_ROOT/src/simulator'
    nohup python main.py > '$SIM_LOG' 2>&1 &
  "
}

status_litellm() {
  log "LiteLLM process:"
  if pgrep -a -u "$PROXY_USER" -f "litellm .*--port $LITELLM_PORT" >/dev/null 2>&1; then
    pgrep -a -u "$PROXY_USER" -f "litellm .*--port $LITELLM_PORT"
  else
    log "  not running"
  fi

  log "LiteLLM health endpoint:"
  if curl -s "http://127.0.0.1:$LITELLM_PORT/health/readiness" >/dev/null 2>&1; then
    log "  up (127.0.0.1:$LITELLM_PORT/health/readiness)"
  else
    log "  down/unreachable"
  fi
}

status_simulator() {
  log "Simulator process:"
  if pgrep -a -u "$RUNNER_USER" -f "python main.py" >/dev/null 2>&1; then
    pgrep -a -u "$RUNNER_USER" -f "python main.py"
  else
    log "  not running"
  fi

  log "Simulator endpoint:"
  if curl -s "http://127.0.0.1:$SIM_PORT/simple/" >/dev/null 2>&1; then
    log "  up (127.0.0.1:$SIM_PORT/simple/)"
  else
    log "  down/unreachable"
  fi
}

start_all() {
  stop_litellm
  stop_simulator
  start_litellm
  start_simulator
  sleep 2
  status_all
}

stop_all() {
  stop_litellm
  stop_simulator
  sleep 1
  status_all
}

status_all() {
  log ""
  log "=== Service Status ==="
  status_litellm
  log ""
  status_simulator
  log "======================"
}

main() {
  parse_args "$@"
  require_action
  validate_env

  case "$ACTION" in
    start)
      start_all
      ;;
    stop)
      stop_all
      ;;
    restart)
      stop_all
      start_all
      ;;
    status)
      status_all
      ;;
    *)
      log "Unknown action: $ACTION"
      usage
      exit 1
      ;;
  esac
}

main "$@"
