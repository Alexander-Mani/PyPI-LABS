# Data Processing

This directory packages reproducible analysis outputs for thesis/report/presentation work.

Current packaged cut:
- `frozen_cut_20260426/`

Primary entrypoints:
- `python data_processing/scripts/build_frozen_cut.py`
- `python data_processing/scripts/plot_frozen_cut.py --out-root data_processing/frozen_cut_20260426`

Reviewer validation command:

```bash
MPLCONFIGDIR=/tmp/matplotlib-cache ./.venv/bin/python \
  data_processing/scripts/build_frozen_cut.py \
  --db analysis/eval_results.db \
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
