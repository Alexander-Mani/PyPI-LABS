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

Detects supply chain attacks by diffing consecutive package versions and running detection tools on the changes.

- `main.py` -- `DetectionAnalyzer` (orchestrates: poll simulator, fetch archives, diff, detect, store results)
- `diff.py` -- `DiffEngine`, `PackageExtractor`, `DiffParser` (extracts `.tar.gz`/`.whl` archives, computes unified diffs, filters non-code files)
- `detection_controller.py` -- `DetectionController`, `StaticDetectorAdapter`, `LLMDetectorAdapter` (runs Bandit/Semgrep and LLM APIs on parsed diffs)
- `sql.py` -- `SQL` (SQLite CRUDs for detection results, run tracking)
- `config.yaml` -- simulator URL, detector selection, LLM provider config, results DB path

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

**Sample management scripts:**
- `samples/download_benign.py` -- downloads all historical versions from PyPI for each target package
- `samples/create_synthetic.py` -- builds minimal benign stubs for dependency confusion packages

---

## Quickstart

```bash
# 1. Clone and set up environment
git clone https://github.com/Alexander-Mani/PyPi-SCADA.git
cd PyPi-SCADA
python -m venv .venv && source .venv/bin/activate
pip install flask loguru rich pyyaml requests bandit semgrep

# 2. Collect benign samples
python samples/download_benign.py
python samples/create_synthetic.py

# 3. Start the simulator
cd src/simulator && python main.py

# 4. Inject packages (in another terminal)
cd src/injector && bash controller.sh all

# 5. Run the analyzer (in another terminal)
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
