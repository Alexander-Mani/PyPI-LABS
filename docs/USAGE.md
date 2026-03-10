# PyPi-SCADA — Usage Guide

Quick reference for running the Simulator and Injector locally.

---

## Prerequisites

```bash
# From workspace/
pip install -e .          # installs all dependencies (Flask, twine, loguru, etc.)
```

Dependencies are declared in `pyproject.toml`. Python 3.9+ required.

---

## 1. Simulator

The Simulator is a Flask server that acts as a local PyPI mirror.
It speaks PEP 503 (so `pip install` works against it) and accepts `twine` uploads.

### Start

```bash
cd workspace/simulator/
python main.py
```

Runs on `http://127.0.0.1:8080` by default (see `config.yaml` to change host/port).

Directories created automatically on first run:
- `data/index/`    — flat-file package storage
- `data/sim.db`    — SQLite metadata
- `logs/`          — simulator log

### Endpoints

| Endpoint | Method | Purpose |
|---|---|---|
| `GET /simple/` | GET | PEP 503 root index (all projects) |
| `GET /simple/<project>/` | GET | PEP 503 project page (all files) |
| `GET /packages/<project>/<filename>` | GET | Download a distribution file |
| `POST /legacy/` | POST | twine upload endpoint |
| `GET /api/versions/<project>` | GET | Analyzer helper — list all uploaded versions |

### Test it manually

```bash
# List all packages in the index
curl http://127.0.0.1:8080/simple/

# List files for a specific package
curl http://127.0.0.1:8080/simple/my-package/

# Ask which versions were uploaded (used by the Analyzer)
curl http://127.0.0.1:8080/api/versions/my-package

# Install a package from the simulator (pip)
pip install --index-url http://127.0.0.1:8080/simple/ my-package
```

### Config (`simulator/config.yaml`)

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  debug: false

storage:
  index_dir: "data/index"      # where .tar.gz / .whl files are stored
  metadata_db: "data/sim.db"   # SQLite metadata

attack_simulation:
  allow_similar_names: true    # typosquatting: no Levenshtein guards
  allow_arbitrary_versions: true  # dep confusion: any version accepted
  enforce_version_bump: true   # cred takeover: re-uploading same version → 400
```

---

## 2. Injector

The Injector uploads `.tar.gz` / `.whl` packages to the running Simulator via `twine`.

### Prerequisites

- Simulator must be running first.
- Package files (`.tar.gz` or `.whl`) placed in the dataset directories:
  - `data/samples/malicious/`
  - `data/samples/benign/`

### Run

```bash
cd workspace/injector/

# Upload everything (malicious + benign)
./controller.sh all

# Upload only malicious packages
./controller.sh malicious

# Upload only benign packages
./controller.sh benign
```

### Verify an upload

After uploading, use the simulator's version API or pip dry-run:

```bash
# Check versions recorded in the simulator
curl http://127.0.0.1:8080/api/versions/my-package

# pip dry-run (won't actually install)
pip install --dry-run \
    --index-url http://127.0.0.1:8080/simple/ \
    my-package
```

### Config (`injector/config.yaml`)

```yaml
simulator:
  upload_url: "http://127.0.0.1:8080/legacy/"
  repository_url: "http://127.0.0.1:8080/simple/"

dataset:
  malicious_dir: "../data/samples/malicious"
  benign_dir: "../data/samples/benign"

credentials:
  username: "__token__"
  password: "sim-token"   # any string — simulator has no real auth
```

---

## Typical Workflow

```
1. Start simulator      →  cd workspace/simulator && python main.py
2. Place packages       →  drop .tar.gz/.whl into data/samples/{malicious,benign}/
3. Run injector         →  cd workspace/injector && ./controller.sh all
4. Confirm uploads      →  curl http://127.0.0.1:8080/simple/
5. Run analyzer (IIb)   →  cd workspace/analyzer && python main.py   (coming soon)
```

---

## Logs

| Component | Log file |
|---|---|
| Simulator | `workspace/simulator/logs/simulator.log` |
| Injector  | `workspace/injector/logs/injector.log` *(planned)* |

Log level and file path are controlled by `logging:` in each component's `config.yaml`.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'src'`**
Run from inside the component directory (`workspace/simulator/`), not from `workspace/`.
`main.py` inserts the parent path into `sys.path` automatically.

**`twine upload` fails with connection error**
Simulator is not running. Start it first with `python main.py`.

**Upload rejected: `Version already exists`**
`enforce_version_bump: true` is set in `simulator/config.yaml`. Either bump the version in your package or set the flag to `false` for testing.

**`controller.sh: python3: command not found`**
The injector uses Python as a YAML parser fallback. Make sure `python3` and `pyyaml` are available in your PATH.
