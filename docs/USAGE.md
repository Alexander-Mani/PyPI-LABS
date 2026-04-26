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
- Sample set: `dataset` by default. Use `--sample-set controls` for the
  controls-only false-positive lane or `--sample-set both` to add controls on
  top of the canonical dataset.

```bash
# Confirm what would be evaluated, without downloading/scanning.
python src/analyzer/evaluate.py --dry-run-resolution --skip-validation

# Static-baseline simulator-resolved run; no LiteLLM required.
python src/analyzer/evaluate.py --sast-only

# Budget profile LLM run; frontier/all-model profiles should be reserved for verified execution.
python src/analyzer/evaluate.py --profile budget

# Controls-only false-positive benchmark on the canonical budget lane.
python src/analyzer/evaluate.py --profile budget --sample-set controls

# Run only the medium, frontier, or exhaustive all-model suite.
python src/analyzer/evaluate.py --profile medium
python src/analyzer/evaluate.py --profile frontier
python src/analyzer/evaluate.py --profile all_models

# Canonical post-custom-Semgrep runs should use a filterable run_id prefix.
python src/analyzer/evaluate.py --profile budget --run-id-prefix canonical-v2

# If Gemini has a temporary provider outage, keep the same profile and toggle it off.
python src/analyzer/evaluate.py --profile budget --gemini off

# Cheap smoke profile: latest version of 2 malicious packages + 2 control packages.
python src/analyzer/evaluate.py --profile test
python src/analyzer/evaluate.py --profile test --gemini off

# Force the live evaluation dashboard in an SSH/tmux session.
python src/analyzer/evaluate.py --profile budget --gemini off --progress always
```

Useful flags:

| Flag | Default | Description |
|---|---|---|
| `--sample-set` | `dataset` | Resolved sample universe: `dataset`, `controls`, or `both` |
| `--include-controls` | off | Legacy alias for `--sample-set both` |
| `--dry-run-resolution` | off | Print selected simulator artifacts without scanning |
| `--profile` | `budget` | Model profile from `configs/evaluation_profiles.yaml` |
| `--gemini` | `on` | Include Gemini/Google model configs: `on` or `off` |
| `--tier` | off | Legacy tier filter; use profiles for reproducible runs |
| `--progress` | `auto` | Live evaluation dashboard: `auto`, `always`, or `never` |
| `--raw-experiment-log` | `on` | Write raw JSONL flight recorder under `logs/experiments/`; use `off` only for throwaway runs |
| `--run-id-prefix` | off | Prefix generated run IDs, e.g. `canonical-v2-*`, so old methodology rows can be filtered out |
| `--identity-alias-probe` | off | Run the standalone masked-identity validity probe: one `hybrid:zero_shot` call per non-agentic model, no static, no raw, no agentic |

Profiles can also carry resolver settings. The full `budget`, `medium`,
`frontier`, and `all_models` profiles scan all selected latest labelled package
versions and all artifacts for those versions. The `test` profile enables
controls and caps package selection to 2 malicious packages and 2 control
packages; use `--gemini off` to run the same smoke scope without Google models.
Legacy `*_no_gemini` profiles remain for compatibility but the preferred path is
the `--gemini` toggle.

The experiment TUI now carries the same choice through a shared `Sample Set`
toggle in the experiment section. Canonical full/non-agentic/agentic runs,
`Static baseline once`, `Validity: identity alias probe, all models`, and
`Validity: production model memory probe, all models` inherit that selector.
Gemini-only and bake-off lanes stay on their own fixed scopes.

Agentic mode is a LiteLLM-backed, read-only RAG workflow inspired by
coding-agent workflows such as Codex and Claude Code. It plans an
investigation, inspects extracted package evidence through constrained tools,
and returns a structured verdict. It does not install packages, execute package
code, run shell commands, or evaluate Codex/Claude Code directly.

Runtime note: GuardDog and agentic mode are expected to be slower than Bandit,
Semgrep, and single-shot LLM modes. GuardDog pays local rule-scanner startup and
large-tree scanning cost per artifact; agentic mode pays for multiple LiteLLM
turns and serialized read-only tool use. See `docs/ops/RISK_DIARY.md` Decision
11 for thesis-facing interpretation guidance.

The model-memory probe is a separate validity sidecar for checking whether
models recognize package names and versions from public incident reporting. It
does not send source code, ground-truth labels, Backstabber's Knife references,
or dataset membership, and it does not write `eval_results.db` rows. The v2
probe treats exact-version recognition as the primary metric and broader
package-level association as a secondary signal. Schema-invalid outputs,
length-truncated blanks, and transport failures are tracked explicitly as probe
failures, not treated as negative answers.

```bash
# Preview the name/version cases and selected models without API calls.
python scripts/model_memory_probe.py --scope curated --profile budget --dry-run

# Run the curated source-free recognition probe and write JSONL under logs/model_memory_probe/.
python scripts/model_memory_probe.py --scope curated --profile budget
python scripts/model_memory_probe.py --scope curated --profile frontier --gemini off

# Run the production-wide source-free probe across the canonical non-agentic lineup.
python scripts/model_memory_probe.py --scope production --profile all_models --resolver-profile all_models --max-tokens 8192 --timeout 120 --retries 2 --retry-delay 20 --progress always

# Run the same production probe against the controls-only sample set.
python scripts/model_memory_probe.py --scope production --profile all_models --resolver-profile all_models --sample-set controls --max-tokens 8192 --timeout 120 --retries 2 --retry-delay 20 --progress always

# Recompute the v2 summary for an existing JSONL run without rerunning the probe.
python scripts/summarize_model_memory_probe.py logs/model_memory_probe/<file>.jsonl
```

Treat the production memory probe as a validity study, not as a replacement for
the detector metrics. Exact-version recognition is the strongest evidence.
Package-only recognition can still matter, but it is easier to inflate with
public package familiarity or vague incident association.

The identity-alias probe is a second validity sidecar for checking whether
source-based LLM verdicts are sensitive to recognizable public incident identity.
It does not try to prove that a model was trained on package artifacts. The
realistic risk is prior knowledge from public advisories, news, forums, package
lists, or writeups. The probe masks package names and versions as neutral aliases
such as `X001` / `V001`, then runs only one cheap lane: `hybrid:zero_shot` across
the selected non-agentic models.

```bash
# Run the cheap alias probe across all configured non-agentic models.
python src/analyzer/evaluate.py --profile all_models --identity-alias-probe

# Run the alias probe against controls only.
python src/analyzer/evaluate.py --profile all_models --identity-alias-probe --sample-set controls

# Use the Gemini toggle if Google routing is unavailable or too expensive.
python src/analyzer/evaluate.py --profile all_models --identity-alias-probe --gemini off

# Verify that model-facing request blobs did not contain original package identity.
python scripts/check_identity_alias_leaks.py --run-id canonical-v2-alias-<uuid>
```

Alias probe rows are written to `eval_results.db` under the original package and
version for grouping, but result `details` include `identity_mask="alias"` and
`alias_probe=true`. Treat these rows as validity evidence, not replacement
canonical metrics. If a canonical run detects a package but the alias probe
misses it, interpret that as identity sensitivity. For typosquats, package
identity can itself be legitimate attack evidence, so alias misses are not proof
of memorization.

The Gemini stability probe is a separate operational sidecar for answering
"when are the configured Google routes stable enough to run?" It writes
append-only JSONL under `logs/gemini_stability_probe/` and does not touch
`eval_results.db`.

```bash
# One pass over all configured Gemini routes.
python scripts/gemini_stability_probe.py

# Manual long run until Ctrl-C.
python scripts/gemini_stability_probe.py --until-interrupt --interval-seconds 300

# Summarize an existing JSONL probe log by UTC hour.
python scripts/gemini_stability_probe.py --summarize logs/gemini_stability_probe/<file>.jsonl
```

Treat this as operator telemetry, not experiment data or thesis metrics.

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
Real evaluation runs also write a raw machine-readable flight recorder to
`logs/experiments/<run_id>.jsonl` plus content blobs in
`logs/experiments/<run_id>.blobs/`. Use this with `jq` or Python to verify exact
simulator endpoints, extracted files, detector inputs, raw outputs, and DB writes.

LLM and agentic detectors must return the required JSON verdict object. If a
provider returns an empty body, prose, truncated output, or JSON without a valid
`verdict`, the row is stored as `experiment_mode="error"` with
`details.protocol_failure=true`. Empty model responses are marked
`details.retryable=true`; malformed non-empty outputs are preserved as errors but
are not automatically retryable. These rows are excluded from package-version
metrics rather than counted as benign.

## Production Eval DB Repair And Thesis Summary

The authoritative analysis DB is deployment-context specific. In the deployed
runner topology documented here, the active DB lives at:

- `/home/pypi-runner/pypi-scada-repo/src/data/eval_results.db`

Do not assume the operator checkout and the deployed runner checkout share the
same working tree or DB path. Two dedicated scripts support the thesis-analysis
workflow against the configured analysis DB:

```bash
# Preview all non-validation error rows in the analysis DB.
./.venv/bin/python scripts/error_correct_production_data.py --db /home/pypi-runner/pypi-scada-repo/src/data/eval_results.db --dry-run

# Create append-only correction runs with compact live progress.
./.venv/bin/python scripts/error_correct_production_data.py --db /home/pypi-runner/pypi-scada-repo/src/data/eval_results.db --apply --progress always

# Generate thesis-ready CSV/Markdown summaries from the canonical latest-complete runs.
./.venv/bin/python scripts/summarize_thesis_eval_db.py --db /home/pypi-runner/pypi-scada-repo/src/data/eval_results.db --out-dir analysis/eval_db/latest
```

`error_correct_production_data.py` now scans the configured analysis DB for all
matching `experiment_mode="error"` rows, across run families by default, but it
excludes validation tiers and existing `:repair` runs unless you opt in. It
supports filters such as `--sample-set`, `--run-id`, `--detector`, and
`--intended-mode`, then classifies each matched row as rerunnable or skipped
before any DB backup or API spend happens.

The repair path re-downloads only the affected artifacts, rebuilds the extracted
package, reapplies alias masking for alias-probe rows, and writes the rerun
result into a new timestamped correction run for each selected source run.
Original source rows remain untouched. Non-agentic repairs force a larger token
budget and stronger retry policy. Agentic repairs keep the same detector identity
but add script-level retries for deployment-availability failures. If no rows
match, or all matched rows are skipped during preflight, the script exits
nonzero and does not create a backup. By default the operator output is compact:
it prints grouped preflight counts, runs a live repair progress view, and writes
detailed analyzer engine logs to a separate repair log file instead of dumping
prompt/extractor traces inline.

`summarize_thesis_eval_db.py` uses the same latest-complete selection policy and
emits:

- run inventory
- repair inventory and row-level repair comparisons
- raw detector-level TP/TN/FP/FN metrics
- cleaned detector-level TP/TN/FP/FN metrics
- raw and cleaned package-version coverage/error metrics
- raw detector cost summaries plus repair-run cost summaries
- raw and cleaned error inventory
- raw and cleaned alias-sensitivity comparisons against canonical hybrid zero-shot rows

The repair and summary scripts intentionally serve different purposes:

- `error_correct_production_data.py` is the operator-facing whole-DB repair tool
- `summarize_thesis_eval_db.py` remains the canonical thesis-analysis reducer

Both should point at the configured analysis DB for the selected environment.

---

## Review Runner TUI

For manual review sessions, use the wrapper TUI instead of remembering every
script and flag:

```bash
python scripts/review_tui.py
```

The experiment menu includes `Validity: identity alias probe, all models` for
the standalone masked-identity probe. It respects the Gemini toggle and runs the
same `--profile all_models --identity-alias-probe` path shown above.

The TUI reads `configs/review_tui.yaml`. By default `--context auto` prefers the
deployed VM checkout at `/home/pypi-runner/pypi-scada-repo` when that repo and
venv exist; otherwise it falls back to the local checkout. Use `--context local`
for local-only review, or `--context deployed` to fail fast if the deployed
target is missing.

Each TUI context carries its own explicit `analysis_db_path`. The shipped
deployed context points at:

- `/home/pypi-runner/pypi-scada-repo/src/data/eval_results.db`

The operator checkout can be a different repo, account, and path entirely. The
TUI now uses the configured analysis DB path for status, archive, repair,
normalization, and summary actions instead of guessing from repo layout.

The menu is split into `Deployment`, `Dry Runs`, `Run Experiment Suite`,
`Database`, `Logs`, and `Tests`. `Deployment` prepares or refreshes the VM and
can run a deployment smoke test; it is not treated as an experiment by default.
`Dry Runs` resolves package/artifact plans without writing DB rows. `Run
Experiment Suite` contains actual analyzer runs and warns when the active
context's configured analysis DB already contains result rows.

The `Database` section also exposes the production-study DB workflow directly:
- preview non-validation DB error reruns against the configured analysis DB
- create append-only correction runs for those matching error rows with live progress
- summarize canonical raw and cleaned thesis-analysis views from the same configured DB

The canonical experiment actions are organized so static baselines run only via
`Static baseline once`. Full budget/medium/frontier model runs skip static
detectors and cover only hybrid, raw LLM, and agentic adapters. Non-agentic and
agentic-only subset lanes remain available for cost and latency control. The
Gemini ON/OFF toggle rewrites deployment, dry-run, smoke, and experiment
commands. The TUI also exposes a source-free model-memory probe preview under
`Dry Runs` and paid probe actions under `Deployment`; these write JSONL audit
records only and are not benchmark detector runs.

The TUI prints the exact command before running each action and asks for
confirmation before actions that mutate the local DB, change deployment state,
run long tests, or may spend API money.

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
`configs/evaluation_profiles.yaml`; use `--gemini off` for temporary Gemini
outages. `test` is the bounded smoke profile for cheap iteration.

Current canonical Google routes are:
- budget: `gemini-2.5-flash-lite`
- medium: `gemini-2.5-flash`
- frontier: `gemini-2.5-pro`

Current canonical open-weight Together routes are:
- budget: `together_ai/Qwen/Qwen3.5-9B`
- medium: `together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo`
- frontier: `together_ai/moonshotai/Kimi-K2.5`

Google is now handled in two modes:
- normal mixed-provider runs keep the stable 2.5 routes with short retry
  logic, but medium/frontier now also use the hardened output contract:
  changed from no explicit structured-output contract, no explicit
  `max_tokens`, and no explicit `reasoning_effort` in `gemini_flash.yaml` /
  `gemini.yaml` to JSON-schema structured output with `max_tokens: 1024`,
  `reasoning_effort="none"` for Flash, and `reasoning_effort="minimal"` for
  Pro, because a live mixed-provider `medium` validation on 2026-04-25 still
  showed `gemini_flash -> unparseable_model_response (no_json_object)` while
  the hardened `gemini_only` lane passed cleanly
- dedicated `gemini_only` / `gemini_only_test` profiles run only the medium and
  frontier Gemini models with a much longer 429/high-demand retry budget
- the dedicated `gemini_only*` lane still owns the long Google-only retry
  behavior and originally introduced the hardened output handling:
  `gemini_resilient_flash` and `gemini_resilient_pro` now request JSON-schema
  structured output with `max_tokens: 1024`; Flash uses
  `reasoning_effort="none"` while Pro uses `reasoning_effort="minimal"`

The analyzer records `requested_model` and `actual_model` on fallbacked rows so
a rescued run stays auditable. Together routes now use
`response_format={"type":"json_object"}` for JSON classification tasks instead
of provider-specific reasoning kwargs.

Do not compare future canonical runs against older rows produced with
`gemini-3-flash-preview` or `gemini-3.1-pro-preview` without an explicit note;
those preview routes are historical and no longer the configured defaults.

**Local dev:** Start LiteLLM manually with API keys in your environment:

```bash
export ANTHROPIC_API_KEY=...
export OPENAI_API_KEY=...
export GEMINI_API_KEY=...
export TOGETHER_API_KEY=...
litellm --config configs/litellm_config.yaml --port 4000
```

Preview every configured LiteLLM model without making API calls:

```bash
python scripts/litellm_smoke.py --all-models --dry-run
```

Send the minimal `Reply with OK.` smoke request to every configured model:

```bash
python scripts/litellm_smoke.py --all-models --retries 3 --retry-delay 20
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
sqlite3 'file:/home/pypi-runner/pypi-scada-repo/src/data/eval_results.db?mode=ro&immutable=1' \
  'select id, detector, experiment_mode, details from eval_result order by id desc limit 20;'
```

**Start a clean evaluation database between runs**
Archive the current evaluation DB and SQLite sidecars by UTC timestamp, then
initialize a fresh empty schema:

```bash
python scripts/archive_eval_db.py
```

Useful safety options:

```bash
python scripts/archive_eval_db.py --dry-run
python scripts/archive_eval_db.py --no-init
```

**Normalize historical malformed LLM rows**
Older runs may contain non-error LLM rows with `details.raw` because malformed
model responses used to be parsed as benign. Preview and then apply the
normalizer before interpreting those rows:

```bash
python scripts/normalize_llm_protocol_failures.py --db /home/pypi-runner/pypi-scada-repo/src/data/eval_results.db
python scripts/normalize_llm_protocol_failures.py --db /home/pypi-runner/pypi-scada-repo/src/data/eval_results.db --apply
```

The script creates a timestamped backup unless `--no-backup` is passed. It
checks for unique-key collisions before mutating rows.
