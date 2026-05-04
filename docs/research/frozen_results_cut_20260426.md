# Frozen Results Cut: 2026-04-26

This note freezes the current analysis state while the broader DB error-rerun job continues in the background. It is the working interpretation layer for the thesis writeup and the final presentation.

## Evidence Base

Primary sources:

- `eval_results.db`
- `model_memory_probe/model-memory-probe-20260426-022803.summary.{md,json}` for the dataset probe
- `model_memory_probe/model-memory-probe-20260426-125455.summary.{md,json}` for the controls probe

Summaries used:

- dataset: `scripts/summarize_thesis_eval_db.py --db eval_results.db --sample-set dataset`
- controls: `scripts/summarize_thesis_eval_db.py --db eval_results.db --sample-set controls`

Interpretation rules:

- raw canonical rows are the primary evidence
- cleaned overlays are robustness sidecars only
- agentic is reported as an operationally failed lane, not a competitive detector lane
- memory-probe exact-version recognition is the strong validity signal
- memory-probe package-only association is weaker evidence of familiarity

## Dataset Results

Main points:

- `llm_raw` beats `hybrid` consistently on the current dataset cut
  - budget mean F1: `0.8898` raw vs `0.6924` hybrid
  - medium mean F1: `0.9004` raw vs `0.7710` hybrid
  - frontier mean F1: `0.9195` raw vs `0.8017` hybrid
- strongest current budget row:
  - `gpt_nano llm_raw role_based`, `F1=0.9474`, `recall=1.0000`, `precision=0.9000`
- strongest current medium rows are tied at `F1=0.9412`
- frontier peak:
  - `claude_opus llm_raw role_based`, `F1=1.0000`
  - caveat: `error_only_package_versions=1`
- strongest complete frontier rows cluster at `F1=0.9412`
- static baselines remain useful but weaker overall
  - `guarddog` best F1: `0.8750`
  - `bandit`: `0.7500`
  - `semgrep`: `0.5000`

## Controls Results

Controls are a separate false-positive benchmark, not an extension of the main dataset tables.

Main points:

- several detectors stay clean across all 10 controls in the current raw cut
- worst false-positive pressure comes from:
  - `together_frontier`: `9` total FP across its mode rows
  - `bandit`: `5`
  - `semgrep`: `3`
  - `claude_sonnet`: `3`
  - `gemini_flash_lite`: `3`

This means the thesis should not collapse to a simple “LLMs outperform static tools” story. The cleaner framing is:

- some detectors are strong on malware and stable on common benign packages
- some detectors over-associate benign production packages with supply-chain risk

## Reliability and Validity

### Reliability

Dataset raw errors are dominated by:

- frontier agentic `deployment_unavailable_429`: `37`
- budget Together truncation (`empty_finish_reason_length`): `22`
- frontier Together Qwen truncation (`empty_finish_reason_length`): `7`
- smaller `claude_opus` null/unparseable rows and one `gpt` unparseable row

Cleaned overlays already present in the DB repaired:

- `13` dataset rows
- `20` controls rows

These repairs are useful robustness evidence, but they are not the primary thesis metric surface for this frozen cut.

### Alias Sensitivity

Dataset alias probe:

- `169` comparisons
- `10` raw lost detections under masking
- concentrated in:
  - `colourama==0.1.6`: `6`
  - `torchtriton==2.0.0+0d7e753227`: `2`
  - `ultralytics==8.3.46`: `1`
  - `num2words==0.5.16`: `1`

By attack vector:

- `Typosquatting`: `6`
- `Dependency Confusion`: `2`
- `Account Takeover`: `2`

Controls alias probe:

- `130` comparisons
- `2` lost detections
- both are benign controls:
  - `urllib3==2.6.3`
  - `requests==2.33.1`

Interpretation:

- identity sensitivity is strongest for typosquatting
- alias masking can also remove false positives, not only true positives

### Memory Probe

Dataset probe (`022803`):

- `169` calls
- `38` package recognitions
- `14` exact-version recognitions
- strongest exact-version signal:
  - `gemini`: `7`
  - `claude_opus`: `5`
  - `claude_sonnet`: `1`
  - `together_frontier`: `1`
- `together_budget` is operationally unusable in this probe

Controls probe (`125455`):

- `130` calls
- `53` package recognitions
- only `3` exact-version recognitions
- `50` package-only associations

Interpretation:

- exact-version recognition is the stronger memorisation signal
- controls show that package familiarity is common even for benign production packages
- package-only association must not be written as proof of malicious incident recall

## Thesis Insertions

The current data supports these writeup choices in `overleaf_thesis/main.tex`:

- `Results -> Static Baseline Comparison`
  - add one compact dataset table and one controls FP comparison
- `Results -> LLM Profile Comparison`
  - report strongest budget, medium, and frontier rows
  - treat `all_models` as the alias sidecar, not a fourth primary accuracy tier
- `Results -> Prompt Strategy Comparison`
  - state directly that raw outperforms hybrid across all three tiers
- `Results -> Agentic vs. Non-Agentic Comparison`
  - report this as an operational negative result
- `Results -> Runtime and API Cost Comparison`
  - emphasize cost/performance separation across budget, medium, and frontier
- `Results -> Error Rate and Provider Reliability`
  - make reliability a first-class RQ3 result
- `Results -> Per-Attack-Vector Observations`
  - use alias sensitivity to show typosquatting is the most identity-sensitive vector
- `Validity and Threats to Validity`
  - add evidence-backed memory-probe and alias-probe interpretation

## Presentation Insertions

Add a results block after methodology and before timeline/risk filler slides.

Recommended slide sequence:

1. frozen analysis cut and evidence base
2. dataset versus controls
3. best detector per tier
4. raw versus hybrid
5. static versus LLM comparison
6. controls false positives
7. provider reliability and error burden
8. alias sensitivity
9. memory-probe validity
10. direct answers to RQ1, RQ2, and RQ3
