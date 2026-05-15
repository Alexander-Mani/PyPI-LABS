# Service Control Script

Use this script to shut services off and on for PyPI-LABS.

Script:
- `scripts/service_control.sh`

Managed services:
- LiteLLM proxy (`litellm --config /home/proxy-runner/litellm_config.yaml --port 4000` by default)
- PyPI simulator (`python main.py` under `src/simulator`)

## Usage

```bash
# Show current status
scripts/service_control.sh status

# Stop both services
scripts/service_control.sh stop

# Start both services
scripts/service_control.sh start

# Restart both services
scripts/service_control.sh restart
```

## VM Defaults

The script defaults to VM-style users and paths:
- repo root: `/home/pypi-runner/pypi-scada-repo`
- simulator user: `pypi-runner`
- proxy user: `proxy-runner`
- ports: simulator `8080`, LiteLLM `4000`

## Local Dev (single user)

If you run everything as your own user:

```bash
scripts/service_control.sh start \
  --no-sudo \
  --repo-root "$PWD" \
  --runner-user "$USER" \
  --proxy-user "$USER" \
  --sim-log "$PWD/logs/simulator.log" \
  --litellm-log "$PWD/logs/litellm.log"
```

## Optional Overrides

```bash
scripts/service_control.sh status \
  --repo-root /custom/path \
  --sim-port 8080 \
  --litellm-port 4000 \
  --litellm-config /custom/litellm_config.yaml
```

## Notes

- `start` and `restart` stop existing matching processes first.
- `status` checks both process presence (`pgrep`) and HTTP endpoint reachability.
- This script only manages process lifecycle; it does not change firewall rules.
