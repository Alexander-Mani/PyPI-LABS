# PyPi-SCADA

**Python Package Index: Supply Chain Attack Detection Analysis**

BSc Computer Science thesis, Reykjavik University, Spring 2026.

PyPi-SCADA is an isolated lab environment for studying PyPI supply chain attacks. It replays real-world malicious package uploads against a local PEP 503 server, diffs consecutive versions, and benchmarks detection tools (SAST + LLM) against a ground-truth dataset.

---

## Architecture

The system has three components under `src/` and a curated sample dataset under `samples/`.

```
src/
  simulator/       Flask-based PEP 503 server (pip + twine compatible)
  injector/        Uploads benign and malicious packages to the simulator
  analyzer/        Diff engine + SAST/LLM detection pipeline
  data/            Shared SQLite utilities (db_core, db_manager)
  utils/           Shared logger (loguru) and TUI helpers (rich)

samples/
  benign/          Legitimate historical versions downloaded from PyPI
  malware_backstabbers_knife/   Malicious samples by attack vector
```

### Simulator (`src/simulator/`)

A minimal PyPI-compatible HTTP server for controlled experiments. Hosts a flat-file package index and exposes endpoints for `pip install`, `twine upload`, and the analyzer's version-listing API.

- `main.py` -- `PyPISimulatorApp`, `PackageIndex` (Flask app, upload handling)
- `simple.py` -- `SimpleAPI`, `ProjectIndex`, `SimpleIndexRenderer` (PEP 503 HTML index)
- `metadata.py` -- `MetadataStore` (SQLite metadata for uploaded packages)
- `config.yaml` -- bind address, storage paths, attack-simulation flags

Attack simulation flags control the simulator's acceptance behavior:
- `allow_similar_names` -- disables Levenshtein guards (enables typosquatting)
- `allow_arbitrary_versions` -- accepts inflated version numbers (enables dependency confusion)
- `enforce_version_bump` -- requires new version on each upload (enables credential takeover replay)

### Injector (`src/injector/`)

Feeds packages from the sample dataset into the simulator in the correct chronological order.

- `controller.sh` -- shell wrapper around `twine` that uploads `.tar.gz`/`.whl` files to the simulator's `/legacy/` endpoint
- `pull_benign.py` -- downloads benign version pairs from PyPI into the dataset directory
- `benign_samples.yaml` -- defines which version pairs to download per attack category
- `config.yaml` -- simulator URLs, dataset paths, twine credentials

### Analyzer (`src/analyzer/`)

Two parallel detection pipelines. The diff-based pipeline connects to the live simulator; the evaluation pipeline runs directly against the sample archives on disk.

**Diff-based pipeline** (connected to simulator):
- `main.py` -- `DetectionAnalyzer` (poll simulator → fetch archives → diff → detect → store)
- `diff.py` -- `DiffEngine`, `PackageExtractor`, `DiffParser` (extracts `.tar.gz`/`.whl`, computes unified diffs)
- `detection_controller.py` -- `DetectionController`, `StaticDetectorAdapter`, `LLMDetectorAdapter` (Bandit/Semgrep + LLM on diffs)
- `sql.py` -- `SQL` (SQLite CRUDs for diff-pipeline results)
- `config.yaml` -- simulator URL, detector selection, LLM provider, results DB path

**Entry-point scanning evaluation pipeline** (offline, against sample archives):
- `evaluate.py` -- `EvaluationRunner` (discovers archives → extract → filter → detect → print TP/TN/FP/FN/F1 table)
- `entry_extractor.py` -- `EntryPointExtractor`, `PackageInfo` (unpacks `.tar.gz`/`.whl`/`.zip`, extracts `setup.py`, `__init__.py`, `pyproject.toml` and their 1-level imports)
- `heuristic_filter.py` -- `HeuristicFilter` (flags `base64_or_hex`, `network_in_install_hook`, `shell_execution`, `bundled_binary` before LLM evaluation)
- `detection_controller.py` also contains `EvalController`, `EntryPointStaticAdapter`, `EntryPointLLMAdapter`, `AgenticAdapter` (appended; existing diff classes unchanged)
- `configs/` -- per-model YAML configs (`model_name`, `temperature`, `system_prompt`, `user_template`); `claude_opus.yaml`, `gpt.yaml`, `gemini.yaml`, `claude_agentic.yaml`
- `TODO.md` -- sequential task checklist for the evaluation module
- `CONCERNS.md` -- documented design decisions and data interpretation caveats

---

## Sample Dataset

The dataset covers four real-world attack vectors with 9 packages total. Each has a detailed forensic profile in [`samples/SAMPLES.md`](samples/SAMPLES.md).

| Attack Vector | Malicious Package | Target/LKGR | Detection Method |
|---|---|---|---|
| Dependency Confusion | torchtriton | synthetic stub | Metadata anomaly + SAST |
| Dependency Confusion | totallysafe | synthetic stub | Metadata anomaly + SAST |
| Account Takeover | num2words | 15 benign versions (up to 0.5.14) | Intra-package diff |
| Account Takeover | ultralytics | 465 benign versions (up to 8.3.40) | Intra-package diff |
| Multi-stage Execution | secmeasure | none (SAST only) | First-version SAST |
| Multi-stage Execution | sisaws | sisa (14 versions) | Cross-package diff |
| Multi-stage Execution | termncolor | termcolor (20 versions) | Cross-package diff |
| Typosquatting | colourama | colorama (46 versions) | Cross-package diff |
| Typosquatting | nmap-python | python-nmap (18 versions) | Cross-package diff |

Malicious samples are sourced from the [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) and contemporary threat intelligence databases. Benign samples are real historical releases downloaded directly from PyPI.

The benign dataset is structured in four tiers, each serving a distinct pipeline role:

| Tier | Location | Packages | Purpose |
|---|---|---|---|
| Differential baselines | `benign/{num2words,ultralytics}/` | All versions ≤ LKGR | Account-takeover intra-package diff |
| Targeted controls | `benign/{colorama,python-nmap,termcolor,sisa}/` | All versions of target | Typosquatting/multi-stage cross-package diff |
| Synthetic stubs | `benign/{torchtriton,totallysafe}/` | 1 generated version | Dependency-confusion metadata+SAST baseline |
| High-volume controls | `benign/controls/{boto3,...}/` | All historical versions | Latency benchmark + false-positive baseline |

The high-volume controls cover the 10 most-downloaded PyPI packages (`boto3`, `urllib3`, `requests`, `certifi`, `botocore`, `setuptools`, `packaging`, `idna`, `charset-normalizer`, `python-dateutil`) — approximately 5,500 versions total. They are kept under `benign/controls/` and skipped by the evaluation runner's default mode to avoid thousands of redundant API calls.

**Sample management scripts:**
- `samples/download_benign.py` -- downloads versions from PyPI for differential baseline and targeted control tiers
- `samples/create_synthetic.py` -- builds minimal benign stubs for dependency confusion packages
- `samples/download_controls.py` -- downloads all historical versions of the top-10 packages into `benign/controls/`; supports `--dry-run`

---

## Quickstart

```bash
# 1. Clone and set up environment
git clone https://github.com/Alexander-Mani/PyPi-SCADA.git
cd PyPi-SCADA
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Collect benign samples
python samples/download_benign.py
python samples/create_synthetic.py
# Optional: high-volume controls (≈5 500 files, takes a while)
python samples/download_controls.py

# 3. Run the offline evaluation pipeline (no simulator needed)
#    SAST only — no API keys required
python src/analyzer/evaluate.py
#    With LLM pipelines — set keys first
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...       # optional
export GEMINI_API_KEY=...       # optional
python src/analyzer/evaluate.py

# 4. Start the simulator (for the diff-based pipeline)
cd src/simulator && python main.py

# 5. Inject packages (in another terminal)
cd src/injector && bash controller.sh all

# 6. Run the diff-based analyzer (in another terminal)
cd src/analyzer && python main.py
```

---

## Key Constraints

- Python 3.9+
- SQLite only (no external database)
- Config-driven via YAML (no hardcoded secrets; API keys via environment variables)
- All logging through shared `src/utils/logger.py` (loguru)
- Flat-file storage for the simulator's package index

---

## Resources

- [Kanban](https://github.com/users/Alexander-Mani/projects/2) -- task management
- [GitHub](https://github.com/Alexander-Mani/PyPi-SCADA) -- version control (private, request access)
- [Backstabber's Knife Collection](https://dasfreak.github.io/Backstabbers-Knife-Collection/) -- malicious sample source (access via University of Bonn)
