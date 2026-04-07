# PyPi-SCADA — Usage Guide

Quick reference for running the Simulator and Injector locally.

---

## Prerequisites

```bash
# From repo root — requires a hashed lockfile (see docs/ops/DEPENDENCY_SECURITY_SOP.md)
pip install --require-hashes --no-deps -r requirements/requirements.txt
```

Dependencies are declared in `requirements/requirements.in` and compiled to a hashed `requirements/requirements.txt` with `pip-tools`. Python 3.11+ required.

---

## 1. Simulator

The Simulator is a Flask server that acts as a local PyPI mirror.
It speaks PEP 503 (so `pip install` works against it) and accepts `twine` uploads.

### Start

```bash
cd src/simulator/
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
  - `samples/malware_backstabbers_knife/`
  - `samples/benign/`

### Run

```bash
cd src/injector/

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
  malicious_dir: "../../samples/malware_backstabbers_knife"
  benign_dir: "../../samples/benign"

credentials:
  username: "__token__"
  password: "sim-token"   # any string — simulator has no real auth
```

---

## 3. VM Deployment — `upload_samples.py`

For the provisioned VM environment where samples arrive as a pre-zipped archive
(`benign_and_controlls.zip`) and individual password-protected malicious zip files,
use `upload_samples.py` instead of `controller.sh`.

See `docs/ops/DEPLOYMENT_MANIFEST.md` for full setup steps (account creation, sample
extraction, venv). The account and security constraints are documented in
`docs/ops/RISK_DIARY.md`.

### Prerequisites

- Simulator running on `http://127.0.0.1:8080`
- Samples extracted into a directory with this layout:

```
samples-extracted/
├── benign/       # per-package subdirs of .tar.gz / .whl
├── controls/     # same layout; infrastructure packages
└── malware_backstabbers_knife/    # password-protected .zip files (password: "infected")
```

### Run

```bash
cd ~/pypi-scada-repo
source venv/bin/activate

# Upload all categories (benign → controls → malicious)
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080

# Upload a single category
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --only benign

python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --only controls

python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --only malicious

# Dry run — prints archive list, calls no twine
python src/injector/upload_samples.py \
  --samples-dir /home/pypi-runner/samples-extracted \
  --dry-run
```

### CLI reference

| Flag | Default | Description |
|---|---|---|
| `--samples-dir` | `/home/pypi-runner/samples-extracted` | Path to extracted samples root |
| `--simulator-url` | `http://127.0.0.1:8080` | Base URL of the simulator |
| `--only` | `all` | Category filter: `benign`, `controls`, `malicious`, or `all` |
| `--dry-run` | off | Print what would be uploaded without calling twine |

### Behaviour notes

- Benign and control archives within each package subdirectory are sorted by version
  (older first) before upload, ensuring correct ordering in `list_versions()`.
- Malicious zips are extracted to `/tmp/pypi-scada-staging/<uuid>/` (tmpfs) and the
  staging directory is deleted immediately after each upload.
- Already-uploaded files are skipped (`--skip-existing` passed to twine); reruns are
  safe.
- Upload failures are logged and counted but do not abort the run; the exit code is
  non-zero if any failure occurred.

---

## Typical Workflow

```
1. Start simulator      →  cd src/simulator && python main.py
2. Place packages       →  drop .tar.gz/.whl into samples/benign/ or samples/malware_backstabbers_knife/
3. Run injector         →  cd src/injector && ./controller.sh all
4. Confirm uploads      →  curl http://127.0.0.1:8080/simple/
5. Run evaluation       →  python src/analyzer/evaluate.py  (entry-point scan, offline)
   With LLM detectors   →  start LiteLLM first (see docs/ops/DEPLOYMENT_MANIFEST.md Step 7)
```

---

## Logs

| Component | Log file |
|---|---|
| Simulator | `src/simulator/logs/simulator.log` |
| Injector  | configured via `src/injector/config.yaml` |
| Analyzer  | configured via `src/analyzer/config.yaml` |
| LiteLLM   | `/home/proxy-runner/litellm.log` (VM deployment only) |

Log level and file path are controlled by `logging:` in each component's `config.yaml`.

---

## LiteLLM Proxy (LLM evaluation only)

All LLM detector calls route through LiteLLM running as `proxy-runner` on
`http://127.0.0.1:4000`. The analyzer process holds no API keys.

**Local dev:** Start LiteLLM manually with API keys in your environment:

```bash
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export GEMINI_API_KEY=...
litellm --port 4000
```

**VM deployment:** See `docs/ops/DEPLOYMENT_MANIFEST.md` Step 7 — LiteLLM runs as
`proxy-runner` with keys in `~proxy-runner/.env` and egress restricted to
vendor CIDR blocks via iptables owner rules.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'src'`**
Run scripts from the repo root (`python src/analyzer/evaluate.py`), not from inside the component directory.
`main.py` and `evaluate.py` insert the project root into `sys.path` automatically.

**`twine upload` fails with connection error**
Simulator is not running. Start it first with `python main.py`.

**Upload rejected: `Version already exists`**
`enforce_version_bump: true` is set in `simulator/config.yaml`. Either bump the version in your package or set the flag to `false` for testing.

**`controller.sh: python3: command not found`**
The injector uses Python as a YAML parser fallback. Make sure `python3` and `pyyaml` are available in your PATH.
