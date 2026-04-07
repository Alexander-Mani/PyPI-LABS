#!/usr/bin/env bash
set -euo pipefail

# network_exposure_recon.sh
#
# Purpose:
#   Recon which local services are potentially exposed beyond loopback and test
#   TCP reachability for selected ports.
#
# Usage examples:
#   scripts/network_exposure_recon.sh
#   scripts/network_exposure_recon.sh --ports 4000,8080,22
#   scripts/network_exposure_recon.sh --target-host 10.0.0.15 --ports 4000,8080
#   scripts/network_exposure_recon.sh --report-file logs/recon.txt

PORTS_CSV="4000,8080"
TARGET_HOST=""
REPORT_FILE=""
TIMEOUT_SECS=2

print_help() {
  cat <<'USAGE'
Usage: network_exposure_recon.sh [options]

Options:
  --ports <csv>          Comma-separated TCP ports to evaluate (default: 4000,8080)
  --target-host <host>   Optional host/IP to actively probe from this machine
  --timeout <sec>        TCP probe timeout in seconds (default: 2)
  --report-file <path>   Optional path to write full report
  -h, --help             Show this help

What the script does:
1) Collects local IPv4 interfaces.
2) Reads listening TCP sockets via ss.
3) Classifies each target port binding as loopback-only or potentially network-exposed.
4) Probes connectivity to each port on:
   - 127.0.0.1
   - each local IPv4 address
   - target host (if provided)
USAGE
}

log() { printf '%s\n' "$*"; }

have_cmd() { command -v "$1" >/dev/null 2>&1; }

tcp_probe() {
  local host="$1"
  local port="$2"

  if have_cmd nc; then
    if nc -z -w "$TIMEOUT_SECS" "$host" "$port" >/dev/null 2>&1; then
      echo "open"
    else
      echo "closed_or_filtered"
    fi
    return
  fi

  if have_cmd timeout; then
    if timeout "$TIMEOUT_SECS" bash -c "</dev/tcp/${host}/${port}" >/dev/null 2>&1; then
      echo "open"
    else
      echo "closed_or_filtered"
    fi
    return
  fi

  # Last-resort /dev/tcp probe without timeout.
  if bash -c "</dev/tcp/${host}/${port}" >/dev/null 2>&1; then
    echo "open"
  else
    echo "closed_or_filtered"
  fi
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ports)
      PORTS_CSV="${2:-}"
      shift 2
      ;;
    --target-host)
      TARGET_HOST="${2:-}"
      shift 2
      ;;
    --timeout)
      TIMEOUT_SECS="${2:-}"
      shift 2
      ;;
    --report-file)
      REPORT_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      log "Unknown option: $1"
      print_help
      exit 1
      ;;
  esac
done

if [[ -z "$PORTS_CSV" ]]; then
  log "ERROR: --ports cannot be empty"
  exit 1
fi

if ! [[ "$TIMEOUT_SECS" =~ ^[0-9]+$ ]]; then
  log "ERROR: --timeout must be an integer"
  exit 1
fi

IFS=',' read -r -a PORTS <<< "$PORTS_CSV"

OUTPUT=""
append() {
  OUTPUT+="$1"
  OUTPUT+=$'\n'
}

NOW_UTC="$(date -u +'%Y-%m-%d %H:%M:%S UTC')"
HOSTNAME_VAL="$( (hostname 2>/dev/null || uname -n) | tr -d '\n' )"
KERNEL_VAL="$(uname -sr)"

append "# Network Exposure Recon Report"
append ""
append "Timestamp: $NOW_UTC"
append "Host: $HOSTNAME_VAL"
append "Kernel: $KERNEL_VAL"
append "Selected ports: $PORTS_CSV"
append ""

# Local IPv4 addresses
LOCAL_IPS=()
if have_cmd ip; then
  while IFS= read -r line; do
    # shellcheck disable=SC2206
    arr=($line)
    # format from: ip -4 -o addr show scope global -> <idx>: <iface> ... <ip/cidr>
    cidr="${arr[3]:-}"
    ipaddr="${cidr%%/*}"
    [[ -n "$ipaddr" ]] && LOCAL_IPS+=("$ipaddr")
  done < <(ip -4 -o addr show scope global 2>/dev/null || true)
fi

if [[ ${#LOCAL_IPS[@]} -eq 0 ]] && have_cmd hostname; then
  for ip in $(hostname -I 2>/dev/null || true); do
    [[ -n "$ip" ]] && LOCAL_IPS+=("$ip")
  done
fi

# De-duplicate
if [[ ${#LOCAL_IPS[@]} -gt 0 ]]; then
  mapfile -t LOCAL_IPS < <(printf '%s\n' "${LOCAL_IPS[@]}" | awk '!seen[$0]++')
fi

append "## Local IPv4 Interfaces"
if [[ ${#LOCAL_IPS[@]} -eq 0 ]]; then
  append "- None detected (or insufficient permissions)."
else
  for ip in "${LOCAL_IPS[@]}"; do
    append "- $ip"
  done
fi
append ""

# Listener table from ss
SS_LINES=()
if have_cmd ss; then
  while IFS= read -r line; do
    [[ -n "$line" ]] && SS_LINES+=("$line")
  done < <(ss -ltnH 2>/dev/null || true)
fi

append "## Listener Classification"
if [[ ${#SS_LINES[@]} -eq 0 ]]; then
  append "No TCP listeners detected (or ss unavailable / permission restricted)."
  append ""
else
  for raw_port in "${PORTS[@]}"; do
    port="$(echo "$raw_port" | tr -d '[:space:]')"
    [[ -z "$port" ]] && continue

    any_bind=false
    loopback_bind=false
    v6_any_bind=false
    specific_binds=()

    for ln in "${SS_LINES[@]}"; do
      local_field="$(echo "$ln" | awk '{print $4}')"

      case "$local_field" in
        "0.0.0.0:${port}"|"*:${port}")
          any_bind=true
          ;;
        "127.0.0.1:${port}")
          loopback_bind=true
          ;;
        "[::]:${port}"|":::${port}")
          v6_any_bind=true
          ;;
        *":${port}")
          host_part="${local_field%:${port}}"
          host_part="${host_part#[}"
          host_part="${host_part%]}"
          if [[ "$host_part" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            specific_binds+=("$host_part")
          fi
          ;;
      esac
    done

    # Deduplicate specific binds
    if [[ ${#specific_binds[@]} -gt 0 ]]; then
      mapfile -t specific_binds < <(printf '%s\n' "${specific_binds[@]}" | awk '!seen[$0]++')
    fi

    exposure="not_listening"
    if [[ "$any_bind" == true || "$v6_any_bind" == true || ${#specific_binds[@]} -gt 0 ]]; then
      exposure="potentially_exposed"
    elif [[ "$loopback_bind" == true ]]; then
      exposure="loopback_only"
    fi

    append "- Port $port"
    append "  - Classification: $exposure"
    append "  - Binds any IPv4: $any_bind"
    append "  - Binds any IPv6: $v6_any_bind"
    append "  - Binds loopback: $loopback_bind"
    if [[ ${#specific_binds[@]} -gt 0 ]]; then
      append "  - Binds specific IPv4: $(IFS=,; echo "${specific_binds[*]}")"
    fi
  done
  append ""
fi

append "## Active TCP Reachability"
append "Probe timeout: ${TIMEOUT_SECS}s"
append ""

PROBE_TARGETS=("127.0.0.1")
for ip in "${LOCAL_IPS[@]}"; do
  PROBE_TARGETS+=("$ip")
done
if [[ -n "$TARGET_HOST" ]]; then
  PROBE_TARGETS+=("$TARGET_HOST")
fi

# Deduplicate probe targets
mapfile -t PROBE_TARGETS < <(printf '%s\n' "${PROBE_TARGETS[@]}" | awk '!seen[$0]++')

for target in "${PROBE_TARGETS[@]}"; do
  append "- Target: $target"
  for raw_port in "${PORTS[@]}"; do
    port="$(echo "$raw_port" | tr -d '[:space:]')"
    [[ -z "$port" ]] && continue
    result="$(tcp_probe "$target" "$port")"
    append "  - tcp/$port: $result"
  done
done
append ""

append "## Notes"
append "- 'potentially_exposed' means the service is not loopback-only; firewall rules may still block remote access."
append "- To confirm from another machine, run this script there with --target-host <this_host_internal_ip>."
append "- For service identity, run manually with elevated privileges: sudo ss -ltnp"

if [[ -n "$REPORT_FILE" ]]; then
  mkdir -p "$(dirname "$REPORT_FILE")"
  printf '%s' "$OUTPUT" > "$REPORT_FILE"
  log "Wrote report: $REPORT_FILE"
fi

printf '%s' "$OUTPUT"
