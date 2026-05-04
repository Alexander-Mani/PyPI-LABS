# Frozen Cut 2026-04-26

This bundle is the reproducible packaging layer for the frozen thesis analysis cut built from:
- `eval_results.db`
- dataset memory probe `model-memory-probe-20260426-022803.summary.{json,md}`
- controls memory probe `model-memory-probe-20260426-125455.summary.{json,md}`

Regenerate everything with:

```bash
python data_processing/scripts/build_frozen_cut.py
```

Main contents:
- `report_points.md`: thesis-facing writing points
- `presentation_points.md`: slide-facing talking points
- `results_digest.md`: generated results digest from the packaged outputs
- `source_manifest.json`: source provenance and hashes
- `outputs/eval/`: dataset and controls eval summary artifacts
- `outputs/memory_probe/`: selected memory-probe summaries
- `outputs/derived/`: small derived CSV tables for plotting/review
- `figures/`: report/presentation-ready figures

Interpretation rules for this cut:
- raw canonical rows are primary evidence
- cleaned overlays are robustness sidecars only
- agentic is not treated as a competitive result lane
- memory-probe exact-version recognition is the strong validity signal
- memory-probe package-only association is weaker familiarity evidence
