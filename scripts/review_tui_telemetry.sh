#!/usr/bin/env bash
set -u

# Collect Review TUI deployment-context telemetry without changing repo state.
# Writes a timestamped log under /tmp and mirrors it to stdout.

LOG="/tmp/pypi-scada-tui-telemetry-$(date -u +%Y%m%d-%H%M%S).log"
LOCAL_REPO="${LOCAL_REPO:-$PWD}"
DEPLOYED_REPO="${DEPLOYED_REPO:-/home/pypi-runner/pypi-scada-repo}"
DEPLOYED_PY="$DEPLOYED_REPO/venv/bin/python"

{
  echo "=== identity ==="
  date -u
  hostname || true
  whoami || true
  id || true
  pwd
  echo "SHELL=$SHELL"
  echo "PATH=$PATH"

  echo
  echo "=== python launchers ==="
  command -v python || true
  command -v python3 || true
  type -a python 2>/dev/null || true
  type -a python3 2>/dev/null || true
  python3 -c 'import sys; print("python3 executable:", sys.executable)' 2>&1 || true

  echo
  echo "=== local repo ==="
  cd "$LOCAL_REPO" 2>/dev/null || true
  pwd || true
  git rev-parse --show-toplevel 2>&1 || true
  git rev-parse HEAD 2>&1 || true
  git status --short 2>&1 || true
  test -f configs/review_tui.yaml && nl -ba configs/review_tui.yaml | sed -n '1,40p' || true
  test -f scripts/review_tui.py && sha256sum scripts/review_tui.py || true
  test -f scripts/check_review_tui_context.py && sha256sum scripts/check_review_tui_context.py || true

  echo
  echo "=== deployed repo ==="
  cd "$DEPLOYED_REPO" 2>/dev/null || true
  pwd || true
  sudo -u pypi-runner git -C "$DEPLOYED_REPO" rev-parse HEAD 2>&1 || true
  sudo -u pypi-runner git -C "$DEPLOYED_REPO" status --short 2>&1 || true
  sudo -u pypi-runner test -f "$DEPLOYED_REPO/configs/review_tui.yaml" && \
    sudo -u pypi-runner nl -ba "$DEPLOYED_REPO/configs/review_tui.yaml" | sed -n '1,40p' || true
  sudo -u pypi-runner test -f "$DEPLOYED_REPO/scripts/review_tui.py" && \
    sudo -u pypi-runner sha256sum "$DEPLOYED_REPO/scripts/review_tui.py" || true
  sudo -u pypi-runner test -f "$DEPLOYED_REPO/scripts/check_review_tui_context.py" && \
    sudo -u pypi-runner sha256sum "$DEPLOYED_REPO/scripts/check_review_tui_context.py" || true

  echo
  echo "=== deployed venv ==="
  ls -l "$DEPLOYED_PY" 2>&1 || true
  sudo -u pypi-runner "$DEPLOYED_PY" -c 'import sys; print(sys.executable); import loguru; print("loguru ok")' 2>&1 || true
  sudo -u pypi-runner bash -lc "cd '$DEPLOYED_REPO' && source venv/bin/activate && echo VENV_PY=\$(command -v python) && python -c 'import sys, loguru; print(sys.executable); print(\"loguru ok\")' && command -v bandit semgrep guarddog" 2>&1 || true

  echo
  echo "=== TUI diagnostic from local checkout ==="
  cd "$LOCAL_REPO" 2>/dev/null || true
  python3 scripts/check_review_tui_context.py --context deployed 2>&1 || true

  echo
  echo "=== TUI diagnostic from deployed checkout ==="
  cd "$DEPLOYED_REPO" 2>/dev/null || true
  sudo -u pypi-runner python3 scripts/check_review_tui_context.py --context deployed 2>&1 || true

  echo
  echo "=== direct known-good static command ==="
  cat <<'CMD'
sudo -u pypi-runner bash -lc 'cd /home/pypi-runner/pypi-scada-repo && source venv/bin/activate && export PATH=/home/pypi-runner/pypi-scada-repo/venv/bin:$PATH && python src/analyzer/evaluate.py --profile budget --gemini on --sast-only --run-id-prefix canonical-v2-static --progress never'
CMD
} 2>&1 | tee "$LOG"

echo
echo "Telemetry log: $LOG"
