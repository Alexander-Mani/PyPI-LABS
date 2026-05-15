# Thesis Eval DB Summary

- Sample set: `controls`

## Selected Raw Runs

- `sast-only` -> `canonical-v2-static-ac678c29-68bb-419f-8c58-becfa903eb0a` (sample_set=controls, 10 package/version units, 30 rows)
- `profile:budget:llm-no-agentic` -> `canonical-v2-budget-72786291-e57a-4d48-b9e1-2d9951ce832d` (sample_set=controls, 10 package/version units, 240 rows)
- `profile:medium:llm-no-agentic` -> `canonical-v2-medium-6437a998-9051-43e1-bb6a-138d64f76048` (sample_set=controls, 10 package/version units, 240 rows)
- `profile:frontier:llm-no-agentic` -> `canonical-v2-frontier-d1172173-f62d-46a2-9247-b1fec3c7a393` (sample_set=controls, 10 package/version units, 300 rows)
- `profile:all_models:identity-alias-probe` -> `canonical-v2-alias-974c6857-1fda-4221-9ea2-aa501b62920e` (sample_set=controls, 10 package/version units, 130 rows)

## Selected Latest Correction Runs

- `canonical-v2-alias-974c6857-1fda-4221-9ea2-aa501b62920e--repair-20260426-181336` <= `canonical-v2-alias-974c6857-1fda-4221-9ea2-aa501b62920e` (3 repaired rows, cost=$0.027297)
- `canonical-v2-budget-72786291-e57a-4d48-b9e1-2d9951ce832d--repair-20260426-181336` <= `canonical-v2-budget-72786291-e57a-4d48-b9e1-2d9951ce832d` (4 repaired rows, cost=$0.002096)
- `canonical-v2-frontier-d1172173-f62d-46a2-9247-b1fec3c7a393--repair-20260426-181336` <= `canonical-v2-frontier-d1172173-f62d-46a2-9247-b1fec3c7a393` (13 repaired rows, cost=$0.228275)

## Raw Primary Detector Metrics

- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:few_shot` TP=0 TN=8 FP=2 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:few_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:few_shot` TP=0 TN=8 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=8 error_only=2
- `profile:budget:llm-no-agentic` `together_budget:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:role_based` TP=0 TN=8 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=8 error_only=2
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:few_shot` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:role_based` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:zero_shot` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:few_shot` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:role_based` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:zero_shot` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `gemini:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:few_shot` TP=0 TN=7 FP=3 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:role_based` TP=0 TN=6 FP=4 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:zero_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:role_based` TP=0 TN=8 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=8 error_only=2
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:zero_shot` TP=0 TN=8 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=8 error_only=2
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:few_shot` TP=0 TN=9 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=9 error_only=1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:role_based` TP=0 TN=8 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=8 error_only=2
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:zero_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:zero_shot` TP=0 TN=8 FP=2 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:few_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `sast-only` `bandit:static:zero_shot` TP=0 TN=5 FP=5 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `sast-only` `guarddog:static:zero_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `sast-only` `semgrep:static:zero_shot` TP=0 TN=7 FP=3 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0

## Cleaned Primary Detector Metrics

- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `claude_haiku:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:few_shot` TP=0 TN=8 FP=2 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:few_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gemini_flash_lite:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `gpt_nano:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:budget:llm-no-agentic` `together_budget:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `claude_opus:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gemini:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `gpt:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:few_shot` TP=0 TN=7 FP=3 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:role_based` TP=0 TN=6 FP=4 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:hybrid:zero_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:hybrid:zero_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `claude_sonnet:llm_raw:zero_shot` TP=0 TN=8 FP=2 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:few_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:role_based` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gemini_flash:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `gpt_mini:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:hybrid:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:few_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:role_based` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `profile:medium:llm-no-agentic` `together_medium:llm_raw:zero_shot` TP=0 TN=10 FP=0 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `sast-only` `bandit:static:zero_shot` TP=0 TN=5 FP=5 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `sast-only` `guarddog:static:zero_shot` TP=0 TN=9 FP=1 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0
- `sast-only` `semgrep:static:zero_shot` TP=0 TN=7 FP=3 FN=0 precision=0.0000 recall=0.0000 f1=0.0000 covered=10 error_only=0

## Raw Remaining Error Inventory

- `profile:all_models:identity-alias-probe` `together_budget:zero_shot` `empty_finish_reason_length` -> 2
- `profile:all_models:identity-alias-probe` `together_frontier_qwen:zero_shot` `empty_finish_reason_length` -> 1
- `profile:budget:llm-no-agentic` `together_budget:few_shot` `empty_finish_reason_length` -> 2
- `profile:budget:llm-no-agentic` `together_budget:role_based` `empty_finish_reason_length` -> 2
- `profile:frontier:llm-no-agentic` `claude_opus:few_shot` `Error code: 400 - {'error': {'message': 'litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR36GDnwxExqvzphAYf"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]. Received Model Group=claude-opus-4-6\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR36GDnwxExqvzphAYf"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]', 'type': None, 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:few_shot` `Error code: 400 - {'error': {'message': 'litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR3mUQF2Kqs3PXmZjzo"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]. Received Model Group=claude-opus-4-6\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR3mUQF2Kqs3PXmZjzo"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]', 'type': None, 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:role_based` `Error code: 400 - {'error': {'message': 'litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR36Puxyjjm1p8H1cAt"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]. Received Model Group=claude-opus-4-6\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR36Puxyjjm1p8H1cAt"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]', 'type': None, 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:role_based` `Error code: 400 - {'error': {'message': 'litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR3nuivqa93fh3qqRWZ"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]. Received Model Group=claude-opus-4-6\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR3nuivqa93fh3qqRWZ"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]', 'type': None, 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:zero_shot` `Error code: 400 - {'error': {'message': 'litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR36Qep16G8AKCmwJkT"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]. Received Model Group=claude-opus-4-6\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR36Qep16G8AKCmwJkT"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]', 'type': None, 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `claude_opus:zero_shot` `Error code: 400 - {'error': {'message': 'litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR3kRPxPHxfuvrJhVBN"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]. Received Model Group=claude-opus-4-6\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: AnthropicException - {"type":"error","error":{"type":"invalid_request_error","message":"provider_credit_exhausted; repaired in cleaned overlay"},"request_id":"req_011CaSR3kRPxPHxfuvrJhVBN"}No fallback model group found for original model_group=claude-opus-4-6. Fallbacks=[{\'together_ai/Qwen/Qwen3.5-9B\': [\'together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite\', \'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo\']}, {\'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo\': [\'together_ai/deepseek-ai/DeepSeek-V3.1\', \'together_ai/MiniMaxAI/MiniMax-M2.5\']}]', 'type': None, 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:few_shot` `empty_finish_reason_length` -> 1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:role_based` `empty_finish_reason_length` -> 4
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:zero_shot` `Error code: 400 - {'error': {'message': "litellm.BadRequestError: Together_aiException - Input validation errorNo fallback model group found for original model_group=together_ai/Qwen/Qwen3.5-397B-A17B. Fallbacks=[{'together_ai/Qwen/Qwen3.5-9B': ['together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite', 'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo']}, {'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo': ['together_ai/deepseek-ai/DeepSeek-V3.1', 'together_ai/MiniMaxAI/MiniMax-M2.5']}]. Received Model Group=together_ai/Qwen/Qwen3.5-397B-A17B\nAvailable Model Group Fallbacks=None\nError doing the fallback: litellm.BadRequestError: Together_aiException - Input validation errorNo fallback model group found for original model_group=together_ai/Qwen/Qwen3.5-397B-A17B. Fallbacks=[{'together_ai/Qwen/Qwen3.5-9B': ['together_ai/meta-llama/Meta-Llama-3-8B-Instruct-Lite', 'together_ai/Qwen/Qwen2.5-7B-Instruct-Turbo']}, {'together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo': ['together_ai/deepseek-ai/DeepSeek-V3.1', 'together_ai/MiniMaxAI/MiniMax-M2.5']}]", 'type': 'invalid_request_error', 'param': None, 'code': '400'}}` -> 1
- `profile:frontier:llm-no-agentic` `together_frontier_qwen:zero_shot` `empty_finish_reason_length` -> 1

## Cleaned Remaining Error Inventory

- None

## Alias Sensitivity

- Raw alias comparison rows: 130
- Raw lost detections under alias masking: 2
- Cleaned alias comparison rows: 130
- Cleaned lost detections under alias masking: 2

## Repair Comparison

- Total corrected source error rows compared: 20
- Corrected to non-error: 20
- Still error after correction: 0
