# Deployment & Injector Update — Task Checklist

Tasks are executed sequentially. Mark `[x]` when done.

---

## A — Governance Documents

- [x] A-1 Create `RISK_DIARY.md` — unprivileged account rationale, API key policy,
       network isolation, tmpfs extraction decision
- [x] A-2 Create `DEPLOYMENT_MANIFEST.md` — exact shell commands for VM setup,
       `pypi-runner` account creation, sample extraction, venv, and pipeline execution

---

## B — Injector Update

- [x] B-1 Create `src/injector/upload_samples.py`
       - Walks `samples-extracted/benign/` and `samples-extracted/controls/`; sorts
         archives by version (older first); uploads via twine
       - Walks `samples-extracted/malicious/`; extracts each `.zip` with
         `password=b"infected"`; uploads inner archive via twine
       - CLI: `--samples-dir`, `--simulator-url`, `--only {benign,controls,malicious,all}`,
         `--dry-run`
       - Reuses `src/utils/logger.py`; does not touch `controller.sh` or `pull_benign.py`

---

## C — Documentation Updates

- [x] C-1 Update `docs/USAGE.md` — add "VM Deployment" section with `upload_samples.py`
       CLI reference and per-mode invocation examples
- [x] C-2 Update `README.md` — add "Deploying to a VM" section linking
       `DEPLOYMENT_MANIFEST.md` and `RISK_DIARY.md`

---

## D — Credential Proxy (superseded by LiteLLM)

**NOTE:** The items below describe the custom Flask credential proxy that was built
to implement key isolation. This proxy (`src/credential_proxy/server.py`, port 9090)
has been **superseded by LiteLLM** (port 4000). The threat model from Decision 5 in
`RISK_DIARY.md` remains valid and is now implemented via LiteLLM. The custom proxy
code remains in the repository but is not active.

- [x] D-1 Create `src/credential_proxy/server.py` — Flask proxy (superseded)
- [x] D-2 Create `src/credential_proxy/config.yaml` — bind address `127.0.0.1:9090` (superseded)
- [x] D-3 Modify `src/analyzer/detection_controller.py` — proxy dispatch wired in
       (currently targets port 9090; update to 4000 / LiteLLM format when configs are updated)
- [x] D-4 Update `src/analyzer/config.yaml` and all four `configs/*.yaml` —
       `proxy_url` added (currently `http://127.0.0.1:9090`; update to `http://127.0.0.1:4000`)
- [x] D-5 Update `RISK_DIARY.md` — Decision 5 updated to reflect LiteLLM
- [x] D-6 Update `DEPLOYMENT_MANIFEST.md` — `proxy-runner` account, iptables rules, LiteLLM startup

---

## Verification Checklist

- [ ] V-1 `sudo -l -U pypi-runner` shows no sudoers entry
- [ ] V-2 `upload_samples.py --dry-run` prints archive list without calling twine
- [ ] V-3 Benign upload: `curl /simple/` lists expected packages after `--only benign`
- [ ] V-4 Malicious upload: `curl /api/versions/colourama` returns version list after
       `--only malicious`
- [ ] V-5 `evaluate.py` completes without `PermissionError` under `pypi-runner`
