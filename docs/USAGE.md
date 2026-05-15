# PyPI-LABS — Notendahandbók (User Manual)

This is the day-to-day user manual for PyPI-LABS. It assumes the system is already deployed on a Debian VM; for setup, see [`../README.md`](../README.md). The on-disk directory and the deployed runner checkout are still named `PyPi-SCADA` for git continuity; PyPI-LABS is the project name used throughout.

## Before you start

Confirm three things:

- the VM is running and you have SSH access
- the `pypi-runner` system user exists (created during first-time setup)
- the LiteLLM `.env` is staged for `proxy-runner` (also done during first-time setup)

Switch into the runner account and activate its virtualenv:

```bash
sudo -u pypi-runner -i
cd /home/pypi-runner/pypi-scada-repo
source .venv/bin/activate
```

Every command below runs from inside this shell.

## 1. Start the system

Bring the simulator, the LiteLLM proxy, the injector worker, and the analyzer worker up in the right order:

```bash
scripts/service_control.sh start all
```

Confirm the proxy and the simulator answer:

```bash
curl -sf http://127.0.0.1:4000/health
curl -sf http://127.0.0.1:8080/simple/
```

Both should print output and exit zero. If either fails, jump to *If something goes wrong* at the bottom of this file.

## 2. Upload sample packages

The first time you bring the VM up, push the benign, control, and malicious archives into the simulator. The uploader is idempotent, so re-running it is safe and skips anything already present.

```bash
PYTHONPATH=$PWD python -m src.injector.upload_samples \
  --samples-dir /home/pypi-runner/samples-extracted \
  --simulator-url http://127.0.0.1:8080
```

Verify a known package landed:

```bash
curl -sf http://127.0.0.1:8080/api/versions/colorama
```

## 3. Run a quick smoke evaluation

The `test` profile runs against two malicious and two control packages. It finishes in under a minute and confirms the pipeline is healthy before you commit to a longer run.

```bash
python src/analyzer/evaluate.py --profile test
```

## 4. Run the full evaluation

The `budget` profile is the canonical cost-tier for thesis runs. It takes tens of minutes depending on provider latency. The `--run-id-prefix canonical-v2` flag tags the rows so you can filter them out of older methodology runs later.

```bash
python src/analyzer/evaluate.py --profile budget --run-id-prefix canonical-v2
```

Rows are appended to `src/data/eval_results.db` as the run progresses.

## 5. Read the results

Reduce the database into thesis-ready tables:

```bash
python scripts/summarize_thesis_eval_db.py \
  --db /home/pypi-runner/pypi-scada-repo/src/data/eval_results.db \
  --out-dir analysis/eval_db/latest
```

Open `analysis/eval_db/latest/summary.md`. The three columns to read first are:

- `experiment_mode` — which detector lane produced the row (`static`, `hybrid`, `raw`, or `error` for protocol failures)
- `f1` — the F1 score for that lane on this run
- `error_only_package_versions` — package versions where every detector errored, so they are missing from the scored metrics

For the reference numbers the thesis cites, compare against [`../data_processing/frozen_cut_20260426/results_digest.md`](../data_processing/frozen_cut_20260426/results_digest.md).

## 6. Stop the system

```bash
scripts/service_control.sh stop all
```

The SQLite databases persist across stops; nothing is lost.

## If something goes wrong

**The proxy is not on `127.0.0.1:4000`.** Check who is listening and restart the proxy:

```bash
ss -ltnp | grep 4000
scripts/service_control.sh restart proxy
```

**The simulator refuses to start because port 8080 is busy.** Find the offender and stop it, then start the simulator again:

```bash
ss -ltnp | grep 8080
scripts/service_control.sh start simulator
```

**The analyzer log shows paths under the operator home directory, not `/home/pypi-runner/pypi-scada-repo`.** You are running as the wrong user. Re-enter the runner account:

```bash
sudo -u pypi-runner -i
```

**Frozen-cut validation produces a non-empty diff.** You are running against the wrong database. Only `data_processing/source_eval_results.db` matches the SHA recorded in `data_processing/frozen_cut_20260426/source_manifest.json`. The repository-root `eval_results.db` is not the frozen-cut evidence source.

## Need more detail?

- Full CLI flag list: `python src/analyzer/evaluate.py --help`
- Interactive menu instead of the CLI: `python scripts/review_tui.py`
- Setup from a clean VM: [`../README.md`](../README.md)
- Security and isolation decisions: [`../docs/ops/RISK_DIARY.md`](ops/RISK_DIARY.md)
- The older verbose version of this manual: `git log -- docs/USAGE.md` (the previous 682-line revision is in history)
