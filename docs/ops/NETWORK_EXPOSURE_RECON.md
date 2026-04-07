# Network Exposure Recon

This document describes how to test whether project services are exposed on an internal network.

## Script

Use:

- `scripts/network_exposure_recon.sh`

The script checks:
1. Local TCP listeners (`ss -ltn`)
2. Binding scope per selected port (`loopback_only` vs `potentially_exposed`)
3. Active TCP reachability against:
- `127.0.0.1`
- all detected local IPv4 addresses
- an optional remote target host

## Typical Ports for PyPi-SCADA

- `4000` (LiteLLM proxy)
- `8080` (PyPI simulator)

## Usage

Run on current machine:

```bash
scripts/network_exposure_recon.sh --ports 4000,8080
```

Write a report file:

```bash
scripts/network_exposure_recon.sh \
  --ports 4000,8080 \
  --report-file logs/network-exposure-recon.txt
```

Probe another host from this machine:

```bash
scripts/network_exposure_recon.sh \
  --ports 4000,8080 \
  --target-host 10.0.0.15
```

## How To Test Both Machines

### On machine A (server/VM)

```bash
scripts/network_exposure_recon.sh --ports 4000,8080
```

Record the internal IP from the report.

### On machine B (your workstation)

Run the same script with machine A as target:

```bash
scripts/network_exposure_recon.sh --ports 4000,8080 --target-host <machine-A-ip>
```

If `tcp/4000` or `tcp/8080` is `open` from machine B, the service is reachable over the network path between machines.

## Interpretation

- `loopback_only`: service should not be directly reachable from other hosts.
- `potentially_exposed`: service is bound to non-loopback (`0.0.0.0`, specific LAN IP, or `::`).
  Firewall or routing may still block inbound access.
- `closed_or_filtered`: either no listener, or blocked by firewall/network policy.

## Notes

- For process-level ownership/PID details, run manually with privilege:

```bash
sudo ss -ltnp
```

- This script is TCP-focused. It does not perform UDP exposure tests.
