# Thesis Eval DB Summary

- Sample set: `dataset`

## Selected Raw Runs

- `sast-only` -> `canonical-v2-static-aa42fb43-5c83-482c-a354-6ba52f687f4a` (sample_set=dataset, 13 package/version units, 81 rows)
- `profile:budget:llm-no-agentic` -> `canonical-v2-budget-1459a5c3-0dd6-4b47-8027-40f58d759034` (sample_set=dataset, 13 package/version units, 648 rows)
- `profile:medium:llm-no-agentic` -> `canonical-v2-medium-f129dbec-47af-47a7-b037-8be8c1a2c958` (sample_set=dataset, 13 package/version units, 648 rows)
- `profile:frontier:llm-no-agentic` -> `canonical-v2-frontier-82ee1e93-edc0-47af-9e63-380d2422c95a` (sample_set=dataset, 13 package/version units, 810 rows)
- `profile:frontier:agentic-only` -> `canonical-v2-frontier-agentic-75d9db82-0437-4d0d-a53a-6ca9d8a74142` (sample_set=dataset, 11 package/version units, 37 rows)
- `profile:all_models:identity-alias-probe` -> `canonical-v2-alias-83d6c7de-2aa3-49fb-a097-a717183120df` (sample_set=dataset, 13 package/version units, 351 rows)

## Selected Latest Correction Runs

- `canonical-v2-alias-83d6c7de-2aa3-49fb-a097-a717183120df--repair-20260426-181336` <= `canonical-v2-alias-83d6c7de-2aa3-49fb-a097-a717183120df` (7 repaired rows, cost=$0.113030)
- `canonical-v2-budget-1459a5c3-0dd6-4b47-8027-40f58d759034--repair-20260426-181336` <= `canonical-v2-budget-1459a5c3-0dd6-4b47-8027-40f58d759034` (6 repaired rows, cost=$0.005420)

## Raw Primary Detector Metrics

- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:zero_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:few_shot` TP=5 TN=3 FP=1 FN=4 precision=0.8333 recall=0.5556 f1=0.6667 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:role_based` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:few_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:role_based` TP=6 TN=3 FP=1 FN=3 precision=0.8571 recall=0.6667 f1=0.7500 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:role_based` TP=9 TN=3 FP=1 FN=0 precision=0.9000 recall=1.0000 f1=0.9474 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:few_shot` TP=5 TN=3 FP=0 FN=3 precision=1.0000 recall=0.6250 f1=0.7692 covered=11 error_only=2
- `profile:budget:llm-no-agentic` `together_budget:hybrid:role_based` TP=4 TN=3 FP=0 FN=4 precision=1.0000 recall=0.5000 f1=0.6667 covered=11 error_only=2
- `profile:budget:llm-no-agentic` `together_budget:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5000 f1=0.6667 covered=12 error_only=1
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7500 f1=0.8571 covered=12 error_only=1
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:role_based` TP=8 TN=2 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=11 error_only=2
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:agentic-only` `claude_agentic:agentic:role_based` TP=0 TN=0 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=0 error_only=11
- `profile:frontier:agentic-only` `claude_agentic:agentic:zero_shot` TP=0 TN=0 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=0 error_only=11
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:few_shot` TP=7 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8750 f1=0.9333 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8750 f1=0.9333 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:role_based` TP=8 TN=4 FP=0 FN=0 precision=1.0000 recall=1.0000 f1=1.0000 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8750 f1=0.9333 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `gemini:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:zero_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:few_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:few_shot` TP=5 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6250 f1=0.7692 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:role_based` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:few_shot` TP=7 TN=3 FP=1 FN=2 precision=0.8750 recall=0.7778 f1=0.8235 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:role_based` TP=8 TN=3 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:zero_shot` TP=7 TN=3 FP=1 FN=2 precision=0.8750 recall=0.7778 f1=0.8235 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:zero_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:few_shot` TP=5 TN=3 FP=1 FN=4 precision=0.8333 recall=0.5556 f1=0.6667 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:zero_shot` TP=3 TN=4 FP=0 FN=6 precision=1.0000 recall=0.3333 f1=0.5000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:zero_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `sast-only` `bandit:static:zero_shot` TP=6 TN=3 FP=1 FN=3 precision=0.8571 recall=0.6667 f1=0.7500 covered=13 error_only=0
- `sast-only` `guarddog:static:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `sast-only` `semgrep:static:zero_shot` TP=3 TN=4 FP=0 FN=6 precision=1.0000 recall=0.3333 f1=0.5000 covered=13 error_only=0

## Cleaned Primary Detector Metrics

- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:zero_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:few_shot` TP=5 TN=3 FP=1 FN=4 precision=0.8333 recall=0.5556 f1=0.6667 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:role_based` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:few_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:role_based` TP=6 TN=3 FP=1 FN=3 precision=0.8571 recall=0.6667 f1=0.7500 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:role_based` TP=9 TN=3 FP=1 FN=0 precision=0.9000 recall=1.0000 f1=0.9474 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:role_based` TP=5 TN=3 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=12 error_only=1
- `profile:budget:llm-no-agentic` `together_budget:hybrid:zero_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:role_based` TP=8 TN=2 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=11 error_only=2
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:agentic-only` `claude_agentic:agentic:role_based` TP=0 TN=0 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=0 error_only=11
- `profile:frontier:agentic-only` `claude_agentic:agentic:zero_shot` TP=0 TN=0 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=0 error_only=11
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:few_shot` TP=7 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8750 f1=0.9333 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8750 f1=0.9333 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:role_based` TP=8 TN=4 FP=0 FN=0 precision=1.0000 recall=1.0000 f1=1.0000 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8750 f1=0.9333 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `gemini:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:zero_shot` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:few_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:few_shot` TP=5 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6250 f1=0.7692 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:role_based` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:few_shot` TP=7 TN=3 FP=1 FN=2 precision=0.8750 recall=0.7778 f1=0.8235 covered=13 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:role_based` TP=8 TN=3 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=12 error_only=1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:zero_shot` TP=7 TN=3 FP=1 FN=2 precision=0.8750 recall=0.7778 f1=0.8235 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:few_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:role_based` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:zero_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:few_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:zero_shot` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:zero_shot` TP=4 TN=4 FP=0 FN=5 precision=1.0000 recall=0.4444 f1=0.6154 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:few_shot` TP=5 TN=3 FP=1 FN=4 precision=0.8333 recall=0.5556 f1=0.6667 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:role_based` TP=5 TN=4 FP=0 FN=4 precision=1.0000 recall=0.5556 f1=0.7143 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:zero_shot` TP=3 TN=4 FP=0 FN=6 precision=1.0000 recall=0.3333 f1=0.5000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:few_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:role_based` TP=8 TN=4 FP=0 FN=1 precision=1.0000 recall=0.8889 f1=0.9412 covered=13 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:zero_shot` TP=6 TN=4 FP=0 FN=3 precision=1.0000 recall=0.6667 f1=0.8000 covered=13 error_only=0
- `sast-only` `bandit:static:zero_shot` TP=6 TN=3 FP=1 FN=3 precision=0.8571 recall=0.6667 f1=0.7500 covered=13 error_only=0
- `sast-only` `guarddog:static:zero_shot` TP=7 TN=4 FP=0 FN=2 precision=1.0000 recall=0.7778 f1=0.8750 covered=13 error_only=0
- `sast-only` `semgrep:static:zero_shot` TP=3 TN=4 FP=0 FN=6 precision=1.0000 recall=0.3333 f1=0.5000 covered=13 error_only=0

## Raw Remaining Error Inventory

- `profile:all_models:identity-alias-probe` `together_budget:zero_shot` `empty_finish_reason_length` -> 1
- `profile:all_models:identity-alias-probe` `together_frontier_qwen:zero_shot` `empty_finish_reason_length` -> 6
- `profile:budget:llm-no-agentic` `together_budget:few_shot` `empty_finish_reason_length` -> 3
- `profile:budget:llm-no-agentic` `together_budget:role_based` `empty_finish_reason_length` -> 11
- `profile:budget:llm-no-agentic` `together_budget:zero_shot` `empty_finish_reason_length` -> 8
- `profile:frontier:agentic-only` `claude_agentic:role_based` `deployment_unavailable_429` -> 18
- `profile:frontier:agentic-only` `claude_agentic:zero_shot` `deployment_unavailable_429` -> 19
- `profile:frontier:llm-no-agentic` `claude_opus:few_shot` `empty_null_content` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:few_shot` `unparseable_model_response` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:role_based` `empty_null_content` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:zero_shot` `empty_null_content` -> 1
- `profile:frontier:llm-no-agentic` `gpt:zero_shot` `unparseable_model_response` -> 1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:few_shot` `empty_finish_reason_length` -> 2
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:role_based` `empty_finish_reason_length` -> 4
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:zero_shot` `empty_finish_reason_length` -> 1

## Cleaned Remaining Error Inventory

- `profile:budget:llm-no-agentic` `together_budget:role_based` `empty_finish_reason_length` -> 9
- `profile:budget:llm-no-agentic` `together_budget:zero_shot` `empty_finish_reason_length` -> 7
- `profile:frontier:agentic-only` `claude_agentic:role_based` `deployment_unavailable_429` -> 18
- `profile:frontier:agentic-only` `claude_agentic:zero_shot` `deployment_unavailable_429` -> 19
- `profile:frontier:llm-no-agentic` `claude_opus:few_shot` `empty_null_content` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:few_shot` `unparseable_model_response` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:role_based` `empty_null_content` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:zero_shot` `empty_null_content` -> 1
- `profile:frontier:llm-no-agentic` `gpt:zero_shot` `unparseable_model_response` -> 1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:few_shot` `empty_finish_reason_length` -> 2
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:role_based` `empty_finish_reason_length` -> 4
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:zero_shot` `empty_finish_reason_length` -> 1

## Alias Sensitivity

- Raw alias comparison rows: 169
- Raw lost detections under alias masking: 10
- Cleaned alias comparison rows: 169
- Cleaned lost detections under alias masking: 8

## Repair Comparison

- Total corrected source error rows compared: 13
- Corrected to non-error: 13
- Still error after correction: 0
