#!/usr/bin/env bash
# controller.sh — PyPI Injector
#
# Uploads packages from the dataset directory to the simulator.
# Uses twine with the simulator's /legacy/ endpoint.
#
# Usage:
#   ./controller.sh [malicious|benign|all]
#
# Requires: twine, pip, yq (for YAML parsing)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/config.yaml"

# ---------------------------------------------------------------------------
# Parse config with yq (or python fallback)
# ---------------------------------------------------------------------------
_cfg() {
    python3 -c "import yaml, sys; cfg=yaml.safe_load(open('${CONFIG}')); print(cfg$1)" 2>/dev/null
}

UPLOAD_URL=$(_cfg "['simulator']['upload_url']")
REPO_URL=$(_cfg "['simulator']['repository_url']")
TWINE_USER=$(_cfg "['credentials']['username']")
TWINE_PASS=$(_cfg "['credentials']['password']")
MALICIOUS_DIR="${SCRIPT_DIR}/$(_cfg "['dataset']['malicious_dir']")"
BENIGN_DIR="${SCRIPT_DIR}/$(_cfg "['dataset']['benign_dir']")"

MODE="${1:-all}"

log() { echo "[injector] $(date '+%H:%M:%S') $*"; }

upload_dir() {
    local dir="$1"
    local label="$2"

    if [[ ! -d "${dir}" ]]; then
        log "WARN: ${label} directory not found: ${dir}"
        return
    fi

    log "Uploading ${label} packages from: ${dir}"

    for pkg in "${dir}"/*.tar.gz "${dir}"/*.whl; do
        [[ -f "${pkg}" ]] || continue
        log "  -> $(basename "${pkg}")"
        TWINE_USERNAME="${TWINE_USER}" \
        TWINE_PASSWORD="${TWINE_PASS}" \
        twine upload \
            --repository-url "${UPLOAD_URL}" \
            --skip-existing \
            "${pkg}" || log "  WARN: upload failed for $(basename "${pkg}")"
    done
}

verify_upload() {
    local pkg_name="$1"
    log "Verifying ${pkg_name} via pip dry-run..."
    pip install \
        --dry-run \
        --index-url "${REPO_URL}" \
        "${pkg_name}" 2>&1 | tail -5
}

case "${MODE}" in
    malicious) upload_dir "${MALICIOUS_DIR}" "malicious" ;;
    benign)    upload_dir "${BENIGN_DIR}"    "benign"    ;;
    all)
        upload_dir "${MALICIOUS_DIR}" "malicious"
        upload_dir "${BENIGN_DIR}"    "benign"
        ;;
    *)
        echo "Usage: $0 [malicious|benign|all]"
        exit 1
        ;;
esac

log "Done."
