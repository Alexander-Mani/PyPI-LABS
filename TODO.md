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

## Verification Checklist

- [ ] V-1 `sudo -l -U pypi-runner` shows no sudoers entry
- [ ] V-2 `upload_samples.py --dry-run` prints archive list without calling twine
- [ ] V-3 Benign upload: `curl /simple/` lists expected packages after `--only benign`
- [ ] V-4 Malicious upload: `curl /api/versions/colourama` returns version list after
       `--only malicious`
- [ ] V-5 `evaluate.py` completes without `PermissionError` under `pypi-runner`
