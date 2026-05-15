# PyPI-LABS

**PyPI LLM Analysis Benchmark with Static Baselines**

BSc Computer Science thesis, Reykjavik University, Spring 2026.

PyPI-LABS is an isolated lab benchmark for studying malicious Python packages. It stages real-world malicious package artifacts in a local PEP 503 server, extracts static entry-point evidence (`setup.py`, `__init__.py`, `pyproject.toml`, and direct imports), and compares static analysis baselines with single-shot LLM detectors. Samples are unpacked for inspection but never installed or executed.

The GitHub repo was renamed to `PyPI-LABS` in May 2026; the on-disk directory is still `PyPi-SCADA` for working-tree continuity, and that legacy name only appears in literal paths such as the deployed checkout at `/home/pypi-runner/pypi-scada-repo`.

---

## Hand-in note for supervisor and examiner

This README is the Rekstrarhandbók (operations manual). The companion Notendahandbók (user manual) is [`docs/USAGE.md`](docs/USAGE.md). For an interactive way to drive the system without memorising commands, run [`scripts/review_tui.py`](scripts/review_tui.py) — it wraps every operation in a menu (deployment, dry runs, experiments, database inspection, logs, tests).

Key locations:

- Thesis source: `overleaf_docs/thesis/` (nested git repo, compiled on Overleaf with IEEE biblatex)
- Project-management document: `overleaf_docs/project_management_doc/` (separate nested git repo)
- Frozen results cut: `data_processing/frozen_cut_20260426/`

Code access is through this repository — no Skemman code submission required.

---

## Architecture

```
src/
  simulator/       Flask-based PEP 503 server (pip + twine compatible)
  injector/        Uploads benign and malicious packages to the simulator
  analyzer/        Entry-point scanning + SAST/LLM detection pipeline
  data/            Shared SQLite utilities
  utils/           Shared logger and TUI helpers

samples/
  benign/                           Legitimate historical versions from PyPI
  malware_backstabbers_knife/       Malicious samples by attack vector
```

- **Simulator** — minimal PyPI-compatible HTTP server with attack-simulation flags (`allow_similar_names` for typosquatting, `allow_arbitrary_versions` for dependency confusion, `enforce_version_bump` for the wheel-vs-sdist constraint).
- **Injector** — `src/injector/upload_samples.py` batch-uploads benign, controls, and malware archives in version order, skipping anything already in the simulator.
- **Analyzer** — `src/analyzer/evaluate.py` resolves package artifacts from the simulator, extracts `setup.py`, `pyproject.toml`, `__init__.py` and their direct imports up to 3 levels deep via BFS, then runs SAST baselines (`bandit`, offline `semgrep`, source-only `guarddog`) plus single-shot LLM detectors (raw and hybrid lanes; legacy agentic kept for reference). LLM calls route through LiteLLM on `127.0.0.1:4000`.

Diagram sources: [`docs/diagrams/mermaid/`](docs/diagrams/mermaid/README.md). Methodology trade-offs and known limitations: [`docs/research/CONCERNS.md`](docs/research/CONCERNS.md).

---

## Sample Dataset

The dataset covers four real-world attack vectors with 9 packages total. Each has a detailed forensic profile in [`samples/SAMPLES.md`](samples/SAMPLES.md).

| Attack Vector | Malicious Package | Target/LKGR | Detection Method |
|---|---|---|---|
| Dependency Confusion | torchtriton | synthetic stub | Entry-point SAST + LLM |
| Dependency Confusion | totallysafe | synthetic stub | Entry-point SAST + LLM |
| Account Takeover | num2words | 15 benign versions (up to 0.5.14) | Entry-point SAST + LLM |
| Account Takeover | ultralytics | 465 benign versions (up to 8.3.40) | Entry-point SAST + LLM |
| Multi-stage Execution | secmeasure | none | Entry-point SAST + LLM |
| Multi-stage Execution | sisaws | sisa (14 versions) | Entry-point SAST + LLM |
| Multi-stage Execution | termncolor | termcolor (20 versions) | Entry-point SAST + LLM |
| Typosquatting | colourama | colorama (46 versions) | Entry-point SAST + LLM |
| Typosquatting | nmap-python | python-nmap (18 versions) | Entry-point SAST + LLM |

Malicious samples come from the [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) and contemporary threat intel sources. Benign samples are real historical releases downloaded directly from PyPI. The benign corpus is split into four tiers (differential baselines, targeted controls, synthetic stubs, and ten high-volume controls covering ~5,500 versions of `boto3`, `urllib3`, `requests`, etc.); the high-volume controls are skipped by the analyzer's default mode to avoid thousands of redundant API calls. See [`samples/SAMPLES.md`](samples/SAMPLES.md) for the full tier breakdown and per-package forensics.

---

## Runtime topology

Two Linux user accounts on the VM, kept deliberately apart:

- **`pypi-runner`** — owns the simulator, injector, and analyzer. Never holds API keys. Simulator on `127.0.0.1:8080`; talks to the proxy on `127.0.0.1:4000` over loopback only.
- **`proxy-runner`** — owns the LiteLLM proxy and is the only account that reads vendor API keys from a `.env` file. The analyzer never sees vendor credentials.

Two checkouts: the operator/dev checkout you edit code in, and the deployed runner checkout at `/home/pypi-runner/pypi-scada-repo` that the analyzer runs from. Edits in one don't appear in the other until pulled.

Two network phases: bootstrap allows outbound for `apt`, `pip`, and `git clone`; once the first-time setup finishes, the runtime phase restricts the analyzer to loopback and routes external egress only through `proxy-runner` via iptables owner rules. The rationale, including the March 2026 LiteLLM supply-chain incident, is in [`docs/ops/RISK_DIARY.md`](docs/ops/RISK_DIARY.md).

---

## Setting up a Debian VM

PyPI-LABS runs inside a dedicated Debian 12 (Bookworm) VM, not on a host workstation and not in a container — archive extraction and the static analyzers themselves are non-trivial parsing surface, and kernel-level isolation plus VM snapshots are the safety net.

Pick the hypervisor that matches your host OS (links to current official docs):

- VirtualBox (Windows, macOS Intel, Linux): <https://www.virtualbox.org/wiki/End-user_documentation>
- Hyper-V (Windows 10/11 Pro+): <https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v>
- UTM (Apple Silicon and Intel macOS): <https://docs.getutm.app/installation/macos/>

Get the Debian 12 netinst ISO from <https://www.debian.org/distrib/>.

VM shape:

- Disk: 30 GB
- RAM: 4 GB minimum
- CPU: 2 vCPU
- Network: NAT during setup, switch to host-only after the first-time script finishes
- Snapshot immediately after setup completes (clean baseline) and again after the first sample upload (populated baseline). Roll back between evaluation runs.

---

## First-time setup

Two scripts in sequence: `scripts/debian_first_time_setup.sh` (OS-level prerequisites) then `deployment.sh` (assembles the application under `/home/pypi-runner/pypi-scada-repo`). Both are idempotent.

Two prerequisites before invoking them: a `.env` file (next subsection) and the sample bundles staged on disk (subsection after). The repo is public, so `git clone` needs no GitHub credentials. `PULL_TOKEN` is only relevant if you point `deployment.sh` at a private fork — leave it blank otherwise.

### The `.env` file (required)

`deployment.sh` reads `.env` from its own working directory (typically `~/PyPi-SCADA/.env`). Copy the template and fill in values:

```bash
cp .env.example .env
$EDITOR .env
```

Variables:

- `PULL_TOKEN` — optional. Leave blank for a public clone of `Alexander-Mani/PyPI-LABS`. Set it to a fine-grained, pull-only GitHub PAT only if you are running `deployment.sh` against a private fork.
- `ANTHROPIC_API_KEY` — <https://console.anthropic.com> → Settings → API keys.
- `OPENAI_API_KEY` — <https://platform.openai.com> → Dashboard → API keys.
- `TOGETHER_API_KEY` — <https://www.together.ai> → Settings → API keys.
- `GEMINI_API_KEY` — <https://aistudio.google.com> → Get API key. Only needed when `GEMINI=on` (default).

`deployment.sh` then writes the four vendor keys (never `PULL_TOKEN`) to `/home/proxy-runner/.env` mode 600. The analyzer never sees vendor keys directly.

### Sample bundles

Stage these zip files in the operator's home directory before invoking `deployment.sh`:

- `benign_and_controlls.zip` (required) — the benign and high-volume control corpus. Note the filename has two `l`s.
- `malware_backstabbers_knife.zip` (optional) — the malicious corpus, encrypted with password `infected` (the Backstabber's Knife Collection community password). Omit this file when handing the project to a supervisor or examiner who cannot legally receive the live malware corpus; `deployment.sh` prints a `NOTICE` and continues with benign and controls only. Analyzer actions that touch malicious packages will simply find an empty malware directory and skip those rows; the review TUI and the controls-only evaluation paths still work.

The default staging directory is `/home/operator/samples/`. Override it by exporting `SAMPLES_DIR` before running `deployment.sh`:

```bash
export SAMPLES_DIR=/home/<your-user>/samples
```

`deployment.sh` extracts the supplied bundles into `/home/pypi-runner/pypi-scada-repo/samples/` under the deployed-runner checkout.

Four steps:

1. **First-time setup script.** Installs apt packages from `requirements/apt.txt`, creates the `pypi-runner` and `proxy-runner` accounts, builds the venv, installs hash-pinned Python deps, then chains into `deployment.sh DEPLOY_PHASE=setup` and `=smoke`. For a fresh install you only run this:

   ```bash
   cd ~/PyPi-SCADA
   ./scripts/debian_first_time_setup.sh
   ```

2. **Re-run setup if needed** (only for recovering a partial deployment):

   ```bash
   ./deployment.sh DEPLOY_PHASE=setup
   ```

3. **Smoke test** — confirms simulator on `127.0.0.1:8080`, proxy on `127.0.0.1:4000`, analyzer imports, and the test suite all work. Don't skip this:

   ```bash
   ./deployment.sh DEPLOY_PHASE=smoke
   ```

4. **Snapshot the VM** through your hypervisor menu (VirtualBox, Hyper-V, or UTM — no shell command). This is the baseline to roll back to between runs.

---

## Running the system

The easiest way to drive day-to-day operations is the interactive review TUI:

```bash
python scripts/review_tui.py
```

It wraps every operation in a menu — deployment, dry runs, experiments, database inspection, logs, tests — with safety tags and confirmation prompts. Sample-set, Gemini, and analysis-DB context are togglable from inside the menu. The TUI calls the same scripts described below; it just removes the need to memorise flags.

For scripted day-to-day operations, `scripts/service_control.sh` wraps start/stop/status for the simulator, injector, analyzer, and LiteLLM proxy:

```bash
scripts/service_control.sh start all
scripts/service_control.sh stop all
```

Confirm both services are up:

```bash
curl -sf http://127.0.0.1:4000/health
curl -sf http://127.0.0.1:8080/simple/
```

Logs: analyzer at `src/analyzer/logs/analyzer-*.log`, LiteLLM at `/home/proxy-runner/litellm.log`. Vendor API calls always traverse `proxy-runner` — if a model call times out, check the proxy log first. Upstream failures land in `eval_results.db` as error rows that `scripts/error_correct_production_data.py` can rerun.

---

## Reviewer / examiner quick checks

Safe checks that do not execute sample packages, runnable on a clean operator checkout without going through full VM setup. Current validation environment is `.venv` with Python 3.14.

```bash
./.venv/bin/python src/analyzer/evaluate.py --help
./.venv/bin/python scripts/summarize_thesis_eval_db.py --help
./.venv/bin/python data_processing/scripts/build_frozen_cut.py --help
MPLCONFIGDIR=/tmp/matplotlib-cache ./.venv/bin/pytest tests/
```

Validate the packaged frozen cut against a temporary output root:

```bash
MPLCONFIGDIR=/tmp/matplotlib-cache ./.venv/bin/python \
  data_processing/scripts/build_frozen_cut.py \
  --db data_processing/source_eval_results.db \
  --out-root /tmp/pypi_labs_frozen_cut_check
```

The validation DB `data_processing/source_eval_results.db` is gitignored — see [`data_processing/README.md`](data_processing/README.md) for how to obtain it and verify its SHA against `source_manifest.json`. The repo-root `eval_results.db` is not the frozen-cut source.

For end-to-end validation follow the Debian VM path above rather than running the lab pipeline directly on a workstation.

---

## Evaluation Terms

- `dataset`: primary benchmark surface, nine malicious package versions plus four targeted benign counterparts.
- `controls`: separate false-positive benchmark over ten high-volume benign packages.
- `raw`: single-shot LLM prompt containing source evidence only.
- `hybrid`: single-shot LLM prompt containing source evidence plus mechanical static-analysis context.
- `agentic`: legacy/non-primary multi-step workflow, not a primary scored detector lane.

## Key Constraints

- Python 3.14 in the current validated local environment.
- SQLite only (no external database).
- Config-driven via YAML; no hardcoded secrets. API keys are held by `proxy-runner` and reached through LiteLLM.
- Dependencies installed exclusively via hashed lockfiles (`pip install --require-hashes --no-deps`).
- All logging through shared `src/utils/logger.py` (loguru).
- Flat-file storage for the simulator's package index.

---

## Security and isolation rationale

Supporting documents under `docs/ops/` and `docs/research/`:

- [`docs/ops/RISK_DIARY.md`](docs/ops/RISK_DIARY.md) — decision log for each isolation, credential, and process-boundary choice (e.g. the March 2026 LiteLLM supply-chain incident that drove the proxy-runner split).
- [`docs/ops/DEPLOYMENT_MANIFEST.md`](docs/ops/DEPLOYMENT_MANIFEST.md) — deeper deployment reference with full account creation, sample extraction, and service ordering.
- [`docs/ops/NETWORK_EXPOSURE_RECON.md`](docs/ops/NETWORK_EXPOSURE_RECON.md) — verification scripts confirming loopback-only analyzer and scoped proxy egress.
- [`docs/ops/DEPENDENCY_SECURITY_SOP.md`](docs/ops/DEPENDENCY_SECURITY_SOP.md) — hash-pinned dependency SOP.
- [`docs/research/CONCERNS.md`](docs/research/CONCERNS.md) — methodology trade-offs and known limitations; the companion to `data_processing/frozen_cut_20260426/`.

---

## Troubleshooting

The following are failure modes that have actually occurred during the project, with their usual causes and resolutions.

**`deployment.sh` aborts with `ERROR: .env not found`.** The script needs the four vendor API keys before it can proceed. Copy `.env.example` to `.env` in the same directory as `deployment.sh` and fill in the values described in the "The `.env` file (required)" subsection above. `PULL_TOKEN` can stay empty for the public clone.

**Missing `.env` for the proxy.** The `proxy-runner` LiteLLM process fails to start, the analyzer detector calls all return `unauthorized` or time out, and the log under `/home/proxy-runner/litellm.log` mentions missing API keys. The cause is that `~proxy-runner/.env` was never staged. Copy the master `.env` into that account's home directory, set the owner to `proxy-runner`, set mode to `600`, then restart the proxy with `scripts/service_control.sh restart proxy`.

**Sample bundle password rejected.** The deployment script fails during extraction with a "wrong password" error from `unzip`. The cause is almost always a typo in `MALWARE_ZIP_PASSWORD` in the deployment environment file. The correct password for the Backstabber's Knife bundle is `infected`. Re-export the variable and re-run `deployment.sh DEPLOY_PHASE=setup`.

**`requirements.txt` hash mismatch after a `pip` upgrade.** `pip install --require-hashes` fails complaining about a hash mismatch on a transitive dependency after `pip` itself was upgraded. This usually means a wheel was built against a different `pip` version than the lockfile expects. The lockfile is authoritative: pin `pip` to the version recorded under `requirements/` (see `docs/ops/DEPENDENCY_SECURITY_SOP.md`) and reinstall.

**LiteLLM proxy not bound to `127.0.0.1:4000`.** Detectors fail with `connection refused` against the proxy. Check with `ss -ltnp | grep 4000`. If the proxy is bound to the wrong interface, look at `configs/litellm_config.yaml` and the systemd unit fragment. In normal deployment the proxy must bind loopback only. Restart it after fixing the bind address.

**Simulator port collision.** The simulator refuses to start because port 8080 is already in use, most often because of another local web service inside the VM or a stale `src/simulator/main.py` that did not exit cleanly. Identify the offender with `ss -ltnp | grep 8080`, stop it, and re-run `scripts/service_control.sh start simulator`. If you genuinely need a different port, change `server.port` in `src/simulator/config.yaml` and update `--simulator-url` accordingly when invoking the injector and analyzer.

**Analyzer hangs at the SAST step.** The analyzer console stops updating during GuardDog or Semgrep against an unusually large package version. This is expected behaviour (see `docs/ops/RISK_DIARY.md` Decision 11): GuardDog in particular pays a large startup and full-tree scanning cost on big packages. If the hang exceeds the configured timeout, the row is written as an error and can be repaired later. Do not kill the process mid-scan unless the timeout has clearly expired.

**Frozen-cut validation diff non-empty.** A re-run of `data_processing/scripts/build_frozen_cut.py --db data_processing/source_eval_results.db --out-root /tmp/...` produces files that do not byte-match the packaged `data_processing/frozen_cut_20260426/`. The most likely cause is running against the wrong database. Only `data_processing/source_eval_results.db` matches the SHA recorded in `data_processing/frozen_cut_20260426/source_manifest.json`. The repository root `eval_results.db` is not the frozen-cut evidence source.

**Analyzer accidentally run as the operator account.** The analyzer starts, but logs show paths under the operator home directory rather than `/home/pypi-runner/pypi-scada-repo`, and database writes land in the operator checkout's `src/data/eval_results.db` instead of the deployed runner's database. The cause is invoking `evaluate.py` from the wrong account. Always run analyzer commands as `pypi-runner`, for example with `sudo -u pypi-runner -i`. The operator checkout is for editing code, not for running evaluations.

---

## Resources

- [`scripts/review_tui.py`](scripts/review_tui.py) -- interactive menu wrapping deployment, dry runs, experiments, DB inspection, logs, and tests
- [`docs/USAGE.md`](docs/USAGE.md) -- Notendahandbók (user manual)
- [`docs/ops/`](docs/ops/) -- security decisions, deployment manifest, dependency SOP, network exposure recon
- [`overleaf_docs/thesis/`](overleaf_docs/thesis/) -- thesis source (nested git repo)
- [`overleaf_docs/project_management_doc/`](overleaf_docs/project_management_doc/) -- project-management document (nested git repo)
- [Kanban](https://github.com/users/Alexander-Mani/projects/2) -- task management
- [GitHub](https://github.com/Alexander-Mani/PyPI-LABS) -- version control (public clone, no token required)
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) -- malicious sample source (access via University of Bonn)
