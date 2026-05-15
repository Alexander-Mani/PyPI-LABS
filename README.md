# PyPI-LABS

**PyPI LLM Analysis Benchmark with Static Baselines**

BSc Computer Science thesis, Reykjavik University, Spring 2026.

PyPI-LABS is an isolated lab benchmark for studying malicious Python packages. It stages real-world malicious package artifacts in a local PEP 503 server, extracts static entry-point evidence (`setup.py`, `__init__.py`, `pyproject.toml`, and direct imports), and compares static analysis baselines with single-shot LLM detectors. The analyzer downloads and unpacks artifacts for inspection. It does not install or execute sample packages.

The GitHub repository was renamed to `PyPI-LABS` in May 2026; older clones using `https://github.com/Alexander-Mani/PyPi-SCADA.git` continue to work through GitHub's automatic redirect, but new clones should use the current URL in the Resources section below. The local on-disk directory is still named `PyPi-SCADA` for working-tree continuity. PyPI-LABS is the project name used in the thesis, in the user-facing tooling, and in the rest of this document; `PyPi-SCADA` only remains as a literal path component (for example in the deployed runner checkout at `/home/pypi-runner/pypi-scada-repo`).

---

## Hand-in note for supervisor and examiner

This README is the Rekstrarhandbók (operations manual) for PyPI-LABS. It describes how to set up a Debian VM, deploy the system inside it, run the analyzer pipeline, and recover from common failure modes. The companion Notendahandbók (user manual) for day-to-day analyzer use is [`docs/USAGE.md`](docs/USAGE.md).

The thesis source lives in the nested repository under `overleaf_docs/thesis/` and is compiled on Overleaf with the IEEE biblatex style. The frozen results cut packaged for thesis reuse is at `data_processing/frozen_cut_20260426/`. The separate project-management document is under `overleaf_docs/project_management_doc/`. Both Overleaf folders are their own git repositories and have independent commit histories from the main repository, so checking the main repository status does not tell you whether thesis edits are committed.

Code access for supervisor and examiner is provided through this repository. The hand-in does not require checking the code into Skemman; access is via the GitHub URL in the Resources section below.

---

## Architecture

The system has three components under `src/` and a curated sample dataset under `samples/`.
Canonical Mermaid source for the current system diagrams lives under [`docs/diagrams/mermaid/`](docs/diagrams/mermaid/README.md); rendered thesis assets are committed under `overleaf_docs/thesis/images/`.

```
src/
  simulator/       Flask-based PEP 503 server (pip + twine compatible)
  injector/        Uploads benign and malicious packages to the simulator
  analyzer/        Entry-point scanning + SAST/LLM detection pipeline
  data/            Shared SQLite utilities (db_core, db_manager)
  utils/           Shared logger (loguru) and TUI helpers (rich)

samples/
  benign/          Legitimate historical versions downloaded from PyPI
  malware_backstabbers_knife/   Malicious samples by attack vector
```

### Simulator (`src/simulator/`)

A minimal PyPI-compatible HTTP server for controlled experiments. Hosts a flat-file package index and exposes endpoints for `pip install`, `twine upload`, artifact download, and metadata checks used by the injector and analyzer.

- `main.py` -- `PyPISimulatorApp`, `PackageIndex` (Flask app, upload handling)
- `simple.py` -- `SimpleAPI`, `ProjectIndex`, `SimpleIndexRenderer` (PEP 503 HTML index)
- `metadata.py` -- `MetadataStore` (SQLite metadata for uploaded packages)
- `config.yaml` -- bind address, storage paths, attack-simulation flags

Attack simulation flags control the simulator's acceptance behavior:
- `allow_similar_names` -- disables Levenshtein guards (enables typosquatting)
- `allow_arbitrary_versions` -- accepts inflated version numbers (enables dependency confusion)
- `enforce_version_bump` -- rejects duplicate distribution files while still allowing multiple artifacts for the same release, matching PyPI wheel/sdist behavior

### Injector (`src/injector/`)

Feeds packages from the sample dataset into the simulator in the correct chronological order.

- `upload_samples.py` -- batch uploader for benign, controls, and malware; sorts benign and control archives by version before upload, supports the single encrypted malware bundle layout, skips artifacts already present in the simulator, and writes per-run upload logs while keeping the terminal output compact.

### Analyzer (`src/analyzer/`)

The primary detection pipeline is the **entry-point scanning evaluation pipeline**, which resolves package artifacts from the local PyPI simulator without installing or executing them. This captures install-time (`setup.py`, `pyproject.toml`) and import-time (`__init__.py`) attack surface while keeping malware inert.

**Entry-point scanning evaluation pipeline** (primary):
- `evaluate.py` -- `EvaluationRunner` (resolve from simulator → download artifact → extract → filter → detect → print TP/TN/FP/FN/F1 table)
- `entry_extractor.py` -- `EntryPointExtractor`, `PackageInfo` (unpacks `.tar.gz`/`.whl`/`.zip`, extracts `setup.py`, `__init__.py`, `pyproject.toml` and their imports up to **3 levels deep** via BFS)
- `heuristic_filter.py` -- `HeuristicFilter` (flags `base64_or_hex`, `network_in_install_hook`, `shell_execution`, `bundled_binary` before LLM evaluation)
- `detection_controller.py` -- `EvalController` (orchestration layer)
- `adapters.py` -- static baselines (`bandit`, custom offline-rule `semgrep`, source-only `guarddog`), `LLMAdapter` (single-shot hybrid prompts with static context), `LLMRawAdapter` (single-shot raw prompts with source only), and `AgenticAdapter` (legacy/non-primary multi-step workflow); all LLM calls route through LiteLLM on `http://127.0.0.1:4000`
- `configs/` -- per-model YAML configs and the `models.json` pricing/tier registry.
- `TODO.md` -- Phase III and IV task tracking
- `CONCERNS.md` -- documented design decisions and data interpretation caveats

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

Malicious samples are sourced from the [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) and contemporary threat intelligence databases. Benign samples are real historical releases downloaded directly from PyPI.

The benign dataset is structured in four tiers, each serving a distinct pipeline role:

| Tier | Location | Packages | Purpose |
|---|---|---|---|
| Differential baselines | `benign/{num2words,ultralytics}/` | All versions ≤ LKGR | Benign counterparts for account-takeover malware (false-positive baseline) |
| Targeted controls | `benign/{colorama,python-nmap,termcolor,sisa}/` | All versions of target | Benign counterparts for typosquatting/multi-stage malware (false-positive baseline) |
| Synthetic stubs | `benign/{torchtriton,totallysafe}/` | 1 generated version | Benign counterpart for dependency-confusion malware (false-positive baseline) |
| High-volume controls | `benign/controls/{boto3,...}/` | All historical versions | Latency benchmark and broad false-positive baseline |

The high-volume controls cover the 10 most-downloaded PyPI packages (`boto3`, `urllib3`, `requests`, `certifi`, `botocore`, `setuptools`, `packaging`, `idna`, `charset-normalizer`, `python-dateutil`), approximately 5,500 versions in total. They are kept under `benign/controls/` and skipped by the evaluation runner's default mode to avoid thousands of redundant API calls.

**Sample management scripts:**

These helper scripts live in the ignored local/VM `samples/` workspace and are not repo-tracked files:
- `samples/download_benign.py` -- downloads versions from PyPI for differential baseline and targeted control tiers
- `samples/create_synthetic.py` -- builds minimal benign stubs for dependency confusion packages
- `samples/download_controls.py` -- downloads all historical versions of the top-10 packages into `benign/controls/`; supports `--dry-run`

---

## Runtime topology

PyPI-LABS runs across two Linux user accounts that are deliberately kept apart, and across two distinct phases of network policy. The split exists because the analyzer touches malware archives while the LLM proxy is the only component that holds API keys; keeping them on separate accounts means a compromise in one cannot directly leak credentials from the other.

The `pypi-runner` account owns the simulator, the injector, and the analyzer. It never holds API keys. It runs the simulator on `127.0.0.1:8080` and talks to the LiteLLM proxy on `127.0.0.1:4000` over the loopback interface only. The `proxy-runner` account owns the LiteLLM proxy and is the only account on the machine that reads vendor API keys from a `.env` file. Vendor calls from any analyzer detector are routed through this proxy; the analyzer process itself never sees a vendor credential.

There are two checkout layouts to keep straight. The operator (or dev) checkout is the working tree you edit code in, typically in your own home directory or wherever you cloned during development. The deployed runner checkout is at `/home/pypi-runner/pypi-scada-repo` and is the working tree the analyzer actually runs from inside the VM. They are separate trees with independent state, so code edits on the operator checkout are not visible to the deployed runner until they are pulled.

Networking goes through two phases. During bootstrap, the VM has outbound network access so `apt`, `pip`, and `git clone` can fetch their dependencies. Once the first-time setup script finishes, the runtime (post-hardening) phase begins: the analyzer process is restricted to loopback, the simulator and proxy are reachable only through `127.0.0.1`, and external egress for vendor traffic is allowed only from the `proxy-runner` account through iptables owner rules. The rationale for this split, including the March 2026 LiteLLM supply-chain incident that motivated treating the proxy as a separate credential-bearing component, is documented in [`docs/ops/RISK_DIARY.md`](docs/ops/RISK_DIARY.md).

---

## Setting up a Debian VM

PyPI-LABS is designed to run inside a dedicated Debian 12 (Bookworm) virtual machine, not on a host workstation and not inside a Linux container. The system handles live malware artifacts: archives are extracted, parsed, and read by static analyzers, all of which have non-trivial parsing surface and have historically been targeted by adversarial inputs. A VM gives kernel-level isolation between the analyzer and the host, the option to take VM-level snapshots before each sample run and roll back afterwards, and a network namespace that can be scoped down to host-only mode for the actual evaluation. Containers share the host kernel and would give weaker isolation guarantees against archive-extractor or analyzer bugs, which is why PyPI-LABS is optimised for the Debian VM path rather than for `docker run`.

Pick a hypervisor that matches your host operating system. The following are the supported options; each link points to its current official setup documentation rather than reproducing the install steps in this manual:

- VirtualBox (Windows, macOS Intel, and Linux): <https://www.virtualbox.org/wiki/End-user_documentation>
- Hyper-V (Windows 10/11 Pro and above): <https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/quick-start/enable-hyper-v>
- UTM (Apple Silicon and Intel macOS): <https://docs.getutm.app/installation/macos/>

Download the Debian 12 installer from <https://www.debian.org/distrib/>. A standard netinst ISO is sufficient and is the smallest download.

Create the VM with the following shape. These numbers come from the deployment that produced the frozen results cut and have a small amount of headroom for re-runs.

- Disk: 30 GB. The sample bundle, virtualenv, and SQLite databases fit comfortably within this.
- Memory: 4 GB RAM minimum. The LLM proxy, simulator, and analyzer can run concurrently on this allocation.
- CPU: 2 vCPU.
- Networking: NAT during setup so the VM can fetch `apt` packages, pull the repository, and install hashed Python dependencies. After setup finishes, switch the adapter to host-only for evaluation runs. The proxy reaches vendor APIs only through explicit iptables rules created during deployment, and switching to host-only enforces that nothing else leaks.
- Snapshots: take the first snapshot immediately after `scripts/debian_first_time_setup.sh` finishes successfully and before any malware sample is staged. This is the clean baseline you can roll back to. Take a second snapshot after the first sample bundle is uploaded, so subsequent reruns can start from a known-good but populated state.

Snapshot discipline matters because the system explicitly does not install or execute sample packages, but the act of extracting and reading them is itself parsing surface. Rolling back to the pre-sample snapshot after each sweep guarantees that no residual state from a previous run can confuse a later one.

---

## First-time setup

The canonical first-run path uses two scripts in sequence: `scripts/debian_first_time_setup.sh` to bring the OS-level prerequisites into place, and `deployment.sh` to assemble the application layout under `/home/pypi-runner/pypi-scada-repo`. Both are idempotent and safe to re-run if you need to recover from a partial setup.

Before you start, make sure three things are in place. A `.env` file with your vendor API keys must be staged for the `proxy-runner` account at `~proxy-runner/.env`; this is the only credential file on the system, and the analyzer never reads it. The encrypted malware sample bundle (`malware_backstabbers_knife.zip`, password `infected`) and the benign and controls bundle must be available to the operator account so the deployment script can extract them. If you are cloning the repository over HTTPS rather than SSH, a Git access token in `~/.netrc` is the easiest way for the script to authenticate.

The four steps in order:

1. **Run the first-time setup script.** From the operator account in the freshly installed Debian VM, run `scripts/debian_first_time_setup.sh`. This installs the system packages listed in `requirements/apt.txt` (Python 3, venv, git, curl, unzip, iptables, sqlite3, and a few build helpers), creates the dedicated `pypi-runner` and `proxy-runner` system users, builds the Python virtual environment, and installs the hash-pinned dependencies from `requirements/requirements.txt` with `--require-hashes --no-deps`. The script ends by calling `deployment.sh DEPLOY_PHASE=setup` followed by `DEPLOY_PHASE=smoke`, so for a fresh install you usually do not need to invoke `deployment.sh` separately.

   ```bash
   cd ~/PyPi-SCADA
   ./scripts/debian_first_time_setup.sh
   ```

2. **Run `deployment.sh DEPLOY_PHASE=setup` if needed.** If the first-time script ran cleanly, this step is already done. If you are repairing a partially-deployed VM, invoke it explicitly: it lays the repository under `/home/pypi-runner/pypi-scada-repo`, extracts the sample bundles into the tmpfs-backed staging directory, brings up the simulator, primes the injector, registers the analyzer entry points, and brings up the LiteLLM proxy on `127.0.0.1:4000`.

   ```bash
   MALWARE_ZIP_PASSWORD=infected ./deployment.sh DEPLOY_PHASE=setup
   ```

3. **Confirm the smoke test passes.** `deployment.sh DEPLOY_PHASE=smoke` runs the first health check: it verifies that the simulator answers on `127.0.0.1:8080`, that the proxy answers on `127.0.0.1:4000`, that the analyzer entry points are importable, and that the test suite passes. Green looks like a clean exit code. Failures usually surface here rather than later, so do not skip this step.

   ```bash
   ./deployment.sh DEPLOY_PHASE=smoke
   ```

4. **Snapshot the VM.** Once the smoke test is green, take a VM-level snapshot from your hypervisor's interface. This is the clean baseline to which you will return between evaluation runs. From this point onwards the operator never needs to run the setup scripts again unless the dependency lockfile changes.

   > Snapshot the running VM in VirtualBox, Hyper-V, or UTM. No shell command — use the hypervisor menu.

---

## Running the system

Day-to-day operations are handled through `scripts/service_control.sh`, which wraps systemd-style start, stop, and status helpers for the four long-running components: the simulator, the injector worker, the analyzer worker, and the LiteLLM proxy.

To start everything in the right order — the proxy and simulator come up first, the injector and analyzer wait for them:

```bash
scripts/service_control.sh start all
```

To bring the system down at the end of a session:

```bash
scripts/service_control.sh stop all
```

To confirm the proxy and the simulator are both reachable from inside the VM:

```bash
curl -sf http://127.0.0.1:4000/health
curl -sf http://127.0.0.1:8080/simple/
```

Logs are documented in the Logs table in [`docs/USAGE.md`](docs/USAGE.md). The analyzer log under `src/analyzer/logs/analyzer-*.log` is the first place to look when a run is misbehaving. The LiteLLM log under `/home/proxy-runner/litellm.log` is where you check whether vendor calls reached the proxy at all.

Vendor API calls always traverse `proxy-runner`. If the analyzer log shows a model call timing out, check the proxy log before assuming the network is at fault. If both show the call reaching the proxy and the proxy reaching the vendor, the failure is upstream and will appear in `eval_results.db` as an error row that the repair script (`scripts/error_correct_production_data.py`) can rerun later.

---

## Reviewer / examiner quick checks

These checks do not execute sample packages and are safe to run on a clean operator checkout without going through the full VM setup. Use the existing project virtualenv when one is present; the current validation environment is `.venv` with Python 3.14. Fresh installs should use the hash-pinned lockfile under `requirements/`. On Python 3.14, `pygit2` may require system `libgit2` headers if no compatible wheel is available.

```bash
./.venv/bin/python src/analyzer/evaluate.py --help
./.venv/bin/python scripts/summarize_thesis_eval_db.py --help
./.venv/bin/python data_processing/scripts/build_frozen_cut.py --help
MPLCONFIGDIR=/tmp/matplotlib-cache ./.venv/bin/pytest tests/
```

To validate the packaged frozen cut without modifying the committed outputs, point the build at the local analysis DB copy and a temporary output root:

```bash
MPLCONFIGDIR=/tmp/matplotlib-cache ./.venv/bin/python \
  data_processing/scripts/build_frozen_cut.py \
  --db data_processing/source_eval_results.db \
  --out-root /tmp/pypi_labs_frozen_cut_check
```

The repository root `eval_results.db` is not the frozen-cut evidence source. The validation DB is `data_processing/source_eval_results.db`, which lives alongside the packaged frozen-cut outputs and matches the SHA recorded in `data_processing/frozen_cut_20260426/source_manifest.json`. The file is gitignored; see `data_processing/README.md` for how to obtain it.

For end-to-end validation that actually exercises the simulator, injector, and analyzer together, follow the Debian VM path above rather than running the lab pipeline directly on a workstation.

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

The supporting documents in `docs/ops/` explain why each isolation decision was made and how to verify the system is behaving accordingly.

[`docs/ops/RISK_DIARY.md`](docs/ops/RISK_DIARY.md) is the decision log. It records each substantive isolation, credential, and process-boundary decision and the incident or argument that motivated it. The March 2026 LiteLLM PyPI supply-chain incident, for example, is what motivated treating LiteLLM as a separate credential-bearing component rather than as harmless analyzer internals.

[`docs/ops/DEPLOYMENT_MANIFEST.md`](docs/ops/DEPLOYMENT_MANIFEST.md) is the deeper deployment reference. It expands the first-time setup steps above with the full sequence used on the provisioned experiment VM, including the exact account creation, sample extraction, and service ordering.

[`docs/ops/NETWORK_EXPOSURE_RECON.md`](docs/ops/NETWORK_EXPOSURE_RECON.md) provides verification scripts that confirm the runtime network surface matches the intended policy: loopback-only for the analyzer, scoped egress for the proxy. Run it after deployment if you want to double-check that nothing else can talk out.

[`docs/ops/DEPENDENCY_SECURITY_SOP.md`](docs/ops/DEPENDENCY_SECURITY_SOP.md) is the short standard operating procedure for the hash-pinned dependency workflow used by the lockfiles under `requirements/`.

[`docs/research/CONCERNS.md`](docs/research/CONCERNS.md) is a methodology document covering the deliberate design trade-offs in ground-truth labelling, evaluation interpretation, and the known limitations a reader should keep in mind before drawing conclusions from the metrics. It is the companion to the results in `data_processing/frozen_cut_20260426/`.

---

## Troubleshooting

The following are failure modes that have actually occurred during the project, with their usual causes and resolutions.

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

- [`docs/USAGE.md`](docs/USAGE.md) -- Notendahandbók (user manual)
- [`docs/ops/`](docs/ops/) -- security decisions, deployment manifest, dependency SOP, network exposure recon
- [`overleaf_docs/thesis/`](overleaf_docs/thesis/) -- thesis source (nested git repo)
- [`overleaf_docs/project_management_doc/`](overleaf_docs/project_management_doc/) -- project-management document (nested git repo)
- [Kanban](https://github.com/users/Alexander-Mani/projects/2) -- task management
- [GitHub](https://github.com/Alexander-Mani/PyPI-LABS) -- version control (private, request access)
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) -- malicious sample source (access via University of Bonn)
