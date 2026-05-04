# Presentation Points

Suggested slide block for the defense/results presentation:

1. `Frozen Analysis Cut`
- cite `source_manifest.json`
- explain dataset, controls, and memory-probe inputs

2. `Dataset vs Controls`
- use `results_digest.md`
- stress that controls are a false-positive benchmark, not extra recall cases

3. `Best Rows by Tier`
- use `figures/best_rows_by_tier.{png,pdf}`

4. `Raw Beats Hybrid`
- use `figures/raw_vs_hybrid_means.{png,pdf}`

5. `Controls False Positives`
- use `figures/controls_false_positive_totals.{png,pdf}`

6. `Reliability and Error Burden`
- use `figures/dataset_error_burden.{png,pdf}`
- tie this explicitly to RQ3

7. `Alias Sensitivity`
- use `figures/alias_losses_by_attack_vector.{png,pdf}`
- explain that identity masking can remove both true positives and benign false positives

8. `Memory-Probe Validity`
- use `figures/memory_probe_exact_vs_association.{png,pdf}`
- explain exact-version vs package-only association

9. `Cost / Performance Tradeoff`
- use `figures/cost_performance_tradeoff.{png,pdf}`

10. `Answers to RQ1-RQ3`
- use `results_digest.md` for the exact wording anchors

Backup slide sources:
- `outputs/eval/dataset/raw_primary_detector_metrics.md`
- `outputs/eval/controls/raw_primary_detector_metrics.md`
- `outputs/eval/dataset/raw_error_inventory.md`
- `outputs/eval/dataset/raw_alias_sensitivity.md`
