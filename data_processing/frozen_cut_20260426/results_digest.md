# Results Digest

This digest is generated from the packaged evaluation summaries and selected memory-probe summaries.

## Evidence Base

- Dataset eval summaries: `outputs/eval/dataset/`
- Controls eval summaries: `outputs/eval/controls/`
- Dataset memory probe: `outputs/memory_probe/dataset/`
- Controls memory probe: `outputs/memory_probe/controls/`

## Headline Dataset Rows

- Static best: `guarddog zero_shot` with `F1=0.8750`.
- Budget best: `gpt_nano llm_raw role_based` with `F1=0.9474`, `recall=1.0000`, `precision=0.9000`.
- Medium top rows form a tie cluster at `F1=0.9412` across `claude_sonnet, gemini_flash, gpt_mini, together_medium` in raw mode.
- Frontier best: `claude_opus llm_raw role_based` with `F1=1.0000` and `error_only_package_versions=1`.

## Raw vs Hybrid Means

- Budget: raw `F1=0.8898` vs hybrid `F1=0.6924`.
- Medium: raw `F1=0.9004` vs hybrid `F1=0.7710`.
- Frontier: raw `F1=0.9195` vs hybrid `F1=0.8017`.

## Controls False-Positive Pressure

- `together_frontier` summed FP across mode rows: `9`.
- `bandit` summed FP across mode rows: `5`.
- `gemini_flash_lite` summed FP across mode rows: `3`.
- `claude_sonnet` summed FP across mode rows: `3`.
- `semgrep` summed FP across mode rows: `3`.

## Reliability

- `claude_agentic` `deployment_unavailable_429` in `profile:frontier:agentic-only`: `37` rows.
- `together_budget` `empty_finish_reason_length` in `profile:budget:llm-no-agentic`: `22` rows.
- `together_frontier_qwen` `empty_finish_reason_length` in `profile:frontier:llm-no-agentic`: `7` rows.
- `together_frontier_qwen` `empty_finish_reason_length` in `profile:all_models:identity-alias-probe`: `6` rows.
- `claude_opus` `empty_null_content` in `profile:frontier:llm-no-agentic`: `3` rows.

## Alias Sensitivity

- Dataset lost detections under alias masking: `10`.
- Dataset alias losses in `Typosquatting`: `6`.
- Dataset alias losses in `Dependency Confusion`: `2`.
- Dataset alias losses in `Account Takeover`: `2`.
- Most affected package: `colourama==0.1.6` with `6` lost detections.
- Controls lost detections under alias masking: `2`.

## Memory Probe

- Dataset probe: `169` calls, `14` exact-version recognitions, `24` package-only associations, `113` recognized false, `18` unknown.
- Controls probe: `130` calls, `3` exact-version recognitions, `50` package-only associations, `61` recognized false, `18` unknown.

## Cost / Performance Anchors

- Budget: `gpt_nano` llm_raw role_based -> `F1=0.9474`, detector run cost `$0.034980`, mean row cost `$0.000216`.
- Medium: `gemini_flash` llm_raw zero_shot -> `F1=0.9412`, detector run cost `$0.064314`, mean row cost `$0.000397`.
- Frontier: `claude_opus` llm_raw role_based -> `F1=1.0000`, detector run cost `$1.310040`, mean row cost `$0.008087`.
