# Report Points

Use these rules consistently in the thesis/report text:

- Treat `outputs/eval/dataset/raw_*` artifacts as the primary dataset evidence surface.
- Treat `outputs/eval/controls/raw_*` artifacts as a separate false-positive benchmark, not an extension of the main dataset tables.
- Use cleaned overlays only for robustness discussion, not for the primary headline claims.
- Do not present frontier agentic as a successful comparison lane unless a later cut materially changes the evidence.
- Use exact-version recognition from the memory probe as the strong memorisation signal; package-only association is weaker familiarity evidence.

Recommended section mapping:

- `Results -> Static Baseline Comparison`
  - use `outputs/eval/dataset/raw_primary_detector_metrics.csv`
  - support controls FP caveats with `outputs/eval/controls/raw_primary_detector_metrics.csv`
- `Results -> LLM Profile Comparison`
  - use the best detector rows by budget / medium / frontier from `results_digest.md`
- `Results -> Prompt Strategy Comparison`
  - use `figures/raw_vs_hybrid_means.{png,pdf}`
- `Results -> Runtime and API Cost Comparison`
  - use `figures/cost_performance_tradeoff.{png,pdf}` plus `outputs/eval/dataset/cost_summary.csv`
- `Results -> Error Rate and Provider Reliability`
  - use `figures/dataset_error_burden.{png,pdf}` and `outputs/eval/dataset/raw_error_inventory.csv`
- `Results -> Per-Attack-Vector Observations`
  - use `figures/alias_losses_by_attack_vector.{png,pdf}` and `outputs/eval/dataset/raw_alias_sensitivity.csv`
- `Validity and Threats to Validity`
  - use `outputs/memory_probe/dataset/*.summary.json`
  - use `outputs/memory_probe/controls/*.summary.json`
  - use `figures/memory_probe_exact_vs_association.{png,pdf}`

Key writing discipline:
- separate detector quality from provider/runtime failure
- separate identity sensitivity from exact-version memory
- separate dataset accuracy claims from controls false-positive claims
