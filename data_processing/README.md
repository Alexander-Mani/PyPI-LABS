# Data Processing

This directory packages reproducible analysis outputs for thesis/report/presentation work.

Current packaged cut:
- `frozen_cut_20260426/`

Primary entrypoints:
- `python data_processing/scripts/build_frozen_cut.py`
- `python data_processing/scripts/plot_frozen_cut.py --out-root data_processing/frozen_cut_20260426`

## Source evaluation database

Both entrypoints read from `data_processing/source_eval_results.db`, the SQLite evaluation database that produced the packaged `frozen_cut_20260426/` outputs. The file is gitignored under the project-wide `*.db` rule because it is roughly 22 MB and contains row-level run evidence rather than curated results. The supervisor and examiner obtain a copy directly from the project author. The SHA-256 of the canonical DB is recorded in [`frozen_cut_20260426/source_manifest.json`](frozen_cut_20260426/source_manifest.json) under `db.sha256`, so a received copy can be verified before any of the build scripts are run against it.

Reviewer validation command:

```bash
MPLCONFIGDIR=/tmp/matplotlib-cache ./.venv/bin/python \
  data_processing/scripts/build_frozen_cut.py \
  --db data_processing/source_eval_results.db \
  --out-root /tmp/pypi_labs_frozen_cut_check
```

What this package does:
- regenerates dataset and controls eval summaries from the supplied evaluation DB
- stages the selected model-memory probe summaries used in the frozen writeup
- writes a compact markdown digest for report and presentation use
- produces matplotlib figures as `png` and `pdf`
- records provenance in `source_manifest.json`

What it does not do:
- it does not become a new source of evaluation truth
- it does not copy the SQLite DB into the package
- it does not track raw repair logs or the full raw probe JSONL corpus as generated artifacts

Related note:
- `docs/research/frozen_results_cut_20260426.md`
