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
| `GET /api/versions/<project>` | GET | Metadata helper — list all uploaded versions |
| `GET /api/files/<project>` | GET | Injector helper — list uploaded `(version, filename)` artifacts |

### Test it manually

```bash
# List all packages in the index
curl http://127.0.0.1:8080/simple/

# List files for a specific package
curl http://127.0.0.1:8080/simple/my-package/

# Ask which versions were uploaded (used by the Analyzer)
curl http://127.0.0.1:8080/api/versions/my-package

# Ask which distribution files were uploaded (used by upload idempotency)
curl http://127.0.0.1:8080/api/files/my-package

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
  enforce_version_bump: true   # duplicate file upload -> 400; wheel+sdist is allowed
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
PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir samples \
  --simulator-url http://127.0.0.1:8080
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

---

## 3. VM Deployment — `upload_samples.py`

For the provisioned VM environment where samples arrive as a benign/control
archive (`benign_and_controlls.zip`) and one password-protected malicious bundle
(`malware_backstabbers_knife.zip`, password `infected`), use
`upload_samples.py`.

See `docs/ops/DEPLOYMENT_MANIFEST.md` for full setup steps (account creation, sample
extraction, venv). The account and security constraints are documented in
`docs/ops/RISK_DIARY.md`.

### Prerequisites

- Simulator running on `http://127.0.0.1:8080`
- Samples extracted into a directory with this layout. Controls may be either
  top-level `controls/` or nested `benign/controls/`; the VM uploader supports both.

```
samples-extracted/
├── benign/       # per-package subdirs of .tar.gz / .whl
├── controls/     # same layout; infrastructure packages
└── malware_backstabbers_knife/
    └── <package>/<version>/<archive.whl|archive.tar.gz>
```

### Run

```bash
cd ~/pypi-scada-repo
source venv/bin/activate

# Upload all categories (benign → controls → malicious)
PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080

# Upload a single category
PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --only benign

PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --only controls

PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --only malicious

# Dry run — prints archive list, calls no twine
PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --dry-run

# Force progress UI even when stdout/stderr is not detected as a TTY
PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --progress always
```

### CLI reference

| Flag | Default | Description |
|---|---|---|
| `--samples-dir` | `/home/pypi-runner/samples-extracted` | Path to extracted samples root |
| `--simulator-url` | `http://127.0.0.1:8080` | Base URL of the simulator |
| `--only` | `all` | Category filter: `benign`, `controls`, `malicious`, or `all` |
| `--dry-run` | off | Print what would be uploaded without calling twine |
| `--progress` | `auto` | Upload progress display: `auto`, `always`, or `never` |

### Behaviour notes

- Benign and control archives within each package subdirectory are sorted by version
  (older first) before upload, ensuring correct ordering in `list_versions()`.
- Malicious package archives are normally extracted from the single encrypted
  deployment bundle before upload; legacy per-package container zips are still
  extracted to `/tmp/pypi-scada-staging/<uuid>/` and cleaned immediately.
- The malware upload log reports distribution artifacts, not unique malicious
  package projects. The analyzer later performs bounded package/version/artifact
  selection from the simulator index.
- Already-uploaded simulator artifacts are detected via `/api/files/<project>`
  and skipped before calling twine; reruns are safe while still allowing a wheel
  and sdist for the same release.
- Interactive runs use a compact per-package progress display by default. Detailed
  per-archive upload decisions are still written to `src/injector/logs/upload_samples-*.log`.
- Upload failures are logged and counted but do not abort the run; the exit code is
  non-zero if any failure occurred.

---

## 4. Analyzer

`evaluate.py` treats the simulator as the package index. It queries the simulator,
downloads selected artifacts, and statically scans the downloaded archive without
installing or executing it.

Static baselines are `bandit`, `semgrep`, and `guarddog`. Semgrep uses the
checked-in custom offline ruleset under `src/analyzer/static_rules/` rather than
a Semgrep Registry config; this is a curated syntax-pattern baseline, not the
hosted Registry Python pack. GuardDog is constrained to source-code rules
against the same extracted `PackageInfo.files` evidence set used by the other
detectors; its live PyPI metadata heuristics are intentionally not used.

Default selection policy:

- Versions: latest stable labelled PEP 440 version per package.
- Artifacts: all simulator artifacts for the selected package version.
- Metrics: package-version level; artifact rows remain in SQLite for audit.
- Controls: skipped unless `--include-controls` is passed or the selected
  evaluation profile enables controls.

```bash
# Confirm what would be evaluated, without downloading/scanning.
python src/analyzer/evaluate.py --dry-run-resolution --skip-validation

# Static-baseline simulator-resolved run; no LiteLLM required.
python src/analyzer/evaluate.py --sast-only

# Budget profile LLM run; frontier-tier configs should be reserved for final verified execution.
python src/analyzer/evaluate.py --profile budget

# Canonical post-custom-Semgrep runs should use a filterable run_id prefix.
python src/analyzer/evaluate.py --profile budget --run-id-prefix canonical-v2

# If Gemini has a temporary provider outage, use the explicit reduced profile.
python src/analyzer/evaluate.py --profile budget_no_gemini

# Cheap smoke profiles: latest version of 2 malicious packages + 2 control packages.
python src/analyzer/evaluate.py --profile test
python src/analyzer/evaluate.py --profile test_no_gemini

# Force the live evaluation dashboard in an SSH/tmux session.
python src/analyzer/evaluate.py --profile budget_no_gemini --progress always
```

Useful flags:

| Flag | Default | Description |
|---|---|---|
| `--include-controls` | off | Include high-volume benign controls; some profiles enable this automatically |
| `--dry-run-resolution` | off | Print selected simulator artifacts without scanning |
| `--profile` | `budget` | Model profile from `configs/evaluation_profiles.yaml` |
| `--tier` | off | Legacy tier filter; use profiles for reproducible runs |
| `--progress` | `auto` | Live evaluation dashboard: `auto`, `always`, or `never` |
| `--run-id-prefix` | off | Prefix generated run IDs, e.g. `canonical-v2-*`, so old methodology rows can be filtered out |

Profiles can also carry resolver settings. The `test` and `test_no_gemini`
profiles enable controls and cap package selection to 2 malicious packages and
2 control packages. The evaluator then scans all artifacts for each selected
package's latest labelled version.

LKGR samples remain part of the dataset for provenance and baseline context, but
canonical scoring uses only the latest labelled stable version per package. Old
database rows may contain `sample_limits` in `resolver_policy`; canonical runs
after this methodology change use `package_limits`, so final thesis metrics
should be regenerated from fresh runs.

Interactive evaluation runs use a compact dashboard for artifact progress,
in-flight detector status, remaining artifacts, and accumulated API cost by
provider. Dry-run resolution always stays plain text, even with
`--progress always`, so the planned artifact list remains readable. Full
detector-by-detector details are written to `src/analyzer/logs/analyzer-*.log`.

---

## Typical Workflow

```
1. Start simulator      →  cd src/simulator && python main.py
2. Place packages       →  drop .tar.gz/.whl into samples/benign/ or samples/malware_backstabbers_knife/
3. Run injector         →  PYTHONPATH=$PWD python -m src.injector.upload_samples --samples-dir samples --simulator-url http://127.0.0.1:8080
4. Confirm uploads      →  curl http://127.0.0.1:8080/simple/
5. Dry-run resolver     →  python src/analyzer/evaluate.py --dry-run-resolution --skip-validation
6. Run evaluation       →  python src/analyzer/evaluate.py  (downloads from simulator, then scans)
   With LLM detectors   →  start LiteLLM first (see docs/ops/DEPLOYMENT_MANIFEST.md Step 7)
```

---

## Logs

| Component | Log file |
|---|---|
| Simulator | `src/simulator/logs/simulator.log` |
| Injector  | console progress plus `src/injector/logs/upload_samples-*.log` |
| Analyzer  | console progress plus `src/analyzer/logs/analyzer-*.log` |
| LiteLLM   | `/home/proxy-runner/litellm.log` (VM deployment only) |

Log level and file path are controlled by `logging:` in each component's `config.yaml`.

---

## LiteLLM Proxy (LLM evaluation only)

All LLM detector calls route through LiteLLM running as `proxy-runner` on
`http://127.0.0.1:4000`. The analyzer process holds no API keys. The proxy
configuration in `configs/litellm_config.yaml` maps analyzer model names to
provider-specific LiteLLM routes. Evaluation model sets are selected through
`configs/evaluation_profiles.yaml`; `budget_no_gemini` exists for explicitly
documented temporary Gemini outages, while `test` and `test_no_gemini` are
bounded smoke profiles for cheap iteration.

**Local dev:** Start LiteLLM manually with API keys in your environment:

```bash
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export GEMINI_API_KEY=...
export TOGETHER_API_KEY=...
litellm --config configs/litellm_config.yaml --port 4000
```

**VM deployment:** See `docs/ops/DEPLOYMENT_MANIFEST.md` Step 7 — LiteLLM runs as
`proxy-runner` with keys in `~proxy-runner/.env` and egress restricted to
deployment-time resolved vendor API IPs via iptables owner rules.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'src'`**
Run scripts from the repo root (`python src/analyzer/evaluate.py`), not from inside the component directory.
`main.py` and `evaluate.py` insert the project root into `sys.path` automatically.

**`twine upload` fails with connection error**
Simulator is not running. Start it first with `python main.py`.

**Upload rejected: `Distribution file already exists`**
`enforce_version_bump: true` is set in `simulator/config.yaml`. Re-running the
uploader should skip existing artifacts automatically via `/api/files/<project>`.

**SQLite says `attempt to write a readonly database` during inspection**
Open the evaluation database in read-only immutable mode when inspecting it from
outside the `pypi-runner` account:

```bash
sqlite3 'file:src/data/eval_results.db?mode=ro&immutable=1' \
  'select id, detector, experiment_mode, details from eval_result order by id desc limit 20;'
```
