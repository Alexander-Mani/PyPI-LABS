# PyPi-SCADA

**Python Package Index: Supply Chain Attack Detection Analysis**

BSc Computer Science thesis, Reykjavik University, Spring 2026.

PyPi-SCADA is an isolated lab environment for studying PyPI supply chain attacks. It replays real-world malicious package uploads against a local PEP 503 server, scans package entry points (`setup.py`, `__init__.py`, `pyproject.toml`), and benchmarks SAST and LLM detectors against a ground-truth dataset from the Backstabber's Knife Collection.

---

## Architecture

The system has three components under `src/` and a curated sample dataset under `samples/`.

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

A minimal PyPI-compatible HTTP server for controlled experiments. Hosts a flat-file package index and exposes endpoints for `pip install`, `twine upload`, artifact download, and metadata checks used by the injector/analyzer.

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

- `upload_samples.py` -- batch uploader for benign, controls, and malware; sorts benign/control archives by version before upload, supports the single encrypted malware bundle layout, skips artifacts already present in the simulator, and writes per-run upload logs while keeping the terminal output compact.

### Analyzer (`src/analyzer/`)

The primary detection pipeline is the **entry-point scanning evaluation pipeline**, which resolves package artifacts from the local PyPI simulator without installing or executing them. This architecture captures install-time (`setup.py`, `pyproject.toml`) and import-time (`__init__.py`) attack surface while keeping malware inert.

**Entry-point scanning evaluation pipeline** (primary):
- `evaluate.py` -- `EvaluationRunner` (resolve from simulator → download artifact → extract → filter → detect → print TP/TN/FP/FN/F1 table)
- `entry_extractor.py` -- `EntryPointExtractor`, `PackageInfo` (unpacks `.tar.gz`/`.whl`/`.zip`, extracts `setup.py`, `__init__.py`, `pyproject.toml` and their imports up to **3 levels deep** via BFS)
- `heuristic_filter.py` -- `HeuristicFilter` (flags `base64_or_hex`, `network_in_install_hook`, `shell_execution`, `bundled_binary` before LLM evaluation)
- `detection_controller.py` -- `EvalController` (orchestration layer)
- `adapters.py` -- `StaticAdapter` (SAST), `LLMAdapter` (Single-shot), `LLMRawAdapter` (raw), `AgenticAdapter` (Multi-turn); all LLM calls route through LiteLLM on `http://127.0.0.1:4000`
- `configs/` -- per-model YAML configs and the `models.json` pricing/tier registry.
- `TODO.md` -- Phase III & IV task tracking
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
| High-volume controls | `benign/controls/{boto3,...}/` | All historical versions | Latency benchmark + broad false-positive baseline |

The high-volume controls cover the 10 most-downloaded PyPI packages (`boto3`, `urllib3`, `requests`, `certifi`, `botocore`, `setuptools`, `packaging`, `idna`, `charset-normalizer`, `python-dateutil`) — approximately 5,500 versions total. They are kept under `benign/controls/` and skipped by the evaluation runner's default mode to avoid thousands of redundant API calls.

**Sample management scripts:**

These helper scripts live in the ignored local/VM `samples/` workspace and are not repo-tracked files:
- `samples/download_benign.py` -- downloads versions from PyPI for differential baseline and targeted control tiers
- `samples/create_synthetic.py` -- builds minimal benign stubs for dependency confusion packages
- `samples/download_controls.py` -- downloads all historical versions of the top-10 packages into `benign/controls/`; supports `--dry-run`

---

## Quickstart

```bash
# 1. Clone and set up environment
git clone https://github.com/Alexander-Mani/PyPi-SCADA.git
cd PyPi-SCADA
python3.11 -m venv .venv && source .venv/bin/activate
# requirements/requirements.txt is a hashed lockfile (see docs/ops/DEPENDENCY_SECURITY_SOP.md)
pip install --require-hashes --no-deps -r requirements/requirements.txt

# 2. Collect benign samples
# These helpers are local/VM sample-workspace files, not repo-tracked files.
python samples/download_benign.py
python samples/create_synthetic.py
# Optional: high-volume controls (≈5 500 files, takes a while)
python samples/download_controls.py

# 3. Start the simulator and upload the dataset
cd src/simulator && python main.py
cd ../..
python src/injector/upload_samples.py --samples-dir samples --simulator-url http://127.0.0.1:8080

# 4. Verify simulator-resolved evaluation scope
python src/analyzer/evaluate.py --dry-run-resolution --skip-validation

# 5. Run the evaluation pipeline against simulator-fetched artifacts
#    SAST only — no LiteLLM required
python src/analyzer/evaluate.py --sast-only

#    Full pipeline — start LiteLLM proxy first (see docs/ops/DEPLOYMENT_MANIFEST.md Step 7)
#    Default model profile is 'budget'; results stored in src/data/eval_results.db
python src/analyzer/evaluate.py --profile budget
#    SSH/tmux dashboard; detailed detector logs are still per-run.
python src/analyzer/evaluate.py --profile budget --progress always

# 6. Run the test suite
pytest tests/
```

---

## Key Constraints

- Python 3.11+
- SQLite only (no external database)
- Config-driven via YAML (no hardcoded secrets; API keys held by `proxy-runner` via LiteLLM)
- Dependencies installed exclusively via hashed lockfiles (`pip install --require-hashes --no-deps`)
- All logging through shared `src/utils/logger.py` (loguru)
- Flat-file storage for the simulator's package index

---

## Deploying to a VM

For deployment to the provisioned experiment VM the pipeline must run under an
unprivileged `pypi-runner` account (no sudo). Full setup instructions are in
[`docs/ops/DEPLOYMENT_MANIFEST.md`](docs/ops/DEPLOYMENT_MANIFEST.md). Security decisions — including
the rationale for the unprivileged account, API key handling, network isolation during
evaluation, and tmpfs extraction of malicious archives — are documented in
[`docs/ops/RISK_DIARY.md`](docs/ops/RISK_DIARY.md).

Use `upload_samples.py` on the VM:

```bash
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080
```

See `docs/USAGE.md` section 3 for the full CLI reference.

---

## Resources

- [Kanban](https://github.com/users/Alexander-Mani/projects/2) -- task management
- [GitHub](https://github.com/Alexander-Mani/PyPi-SCADA) -- version control (private, request access)
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) -- malicious sample source (access via University of Bonn)
