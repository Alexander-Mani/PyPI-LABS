# Model Memory Probe Summary

- Run ID: `memory-probe-86ca160e-871d-4ef3-853b-c101db234525`
- Scope: `production`
- Model source: `profile:all_models`
- Case source: `profile:all_models`
- Calls: `169`
- Total cost: `$0.246805`

## Overall

| Metric | Value |
| --- | ---: |
| Parsed OK | 160 |
| Transport failures | 4 |
| Recognized true | 16 |
| Recognized false | 144 |
| Recognized unknown | 9 |

## By Model

| Config | Model | Calls | Parsed | True | False | Unknown | Transport | Cost USD | Mean Latency s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| claude_haiku | claude-haiku-4-5 | 13 | 13 | 0 | 13 | 0 | 0 | 0.016529 | 0.966 |
| claude_opus | claude-opus-4-6 | 13 | 13 | 8 | 5 | 0 | 0 | 0.050095 | 3.044 |
| claude_sonnet | claude-sonnet-4-6 | 13 | 13 | 3 | 10 | 0 | 0 | 0.022602 | 3.527 |
| gemini | gemini-2.5-pro | 13 | 13 | 3 | 10 | 0 | 0 | 0.018188 | 3.275 |
| gemini_flash | gemini-2.5-flash | 13 | 13 | 0 | 13 | 0 | 0 | 0.001273 | 0.836 |
| gemini_flash_lite | gemini-2.5-flash-lite | 13 | 13 | 0 | 13 | 0 | 0 | 0.000353 | 0.703 |
| gpt | gpt-5.4 | 13 | 13 | 0 | 13 | 0 | 0 | 0.011890 | 1.082 |
| gpt_mini | gpt-5.4-mini | 13 | 13 | 0 | 13 | 0 | 0 | 0.003567 | 1.320 |
| gpt_nano | gpt-5.4-nano | 13 | 13 | 0 | 13 | 0 | 0 | 0.000969 | 1.003 |
| together_budget | together_ai/Qwen/Qwen3.5-9B | 13 | 5 | 0 | 5 | 8 | 4 | 0.007590 | 42.920 |
| together_frontier | together_ai/moonshotai/Kimi-K2.5 | 13 | 13 | 2 | 11 | 0 | 0 | 0.046910 | 10.620 |
| together_frontier_qwen | together_ai/Qwen/Qwen3.5-397B-A17B | 13 | 12 | 0 | 12 | 1 | 0 | 0.064609 | 9.992 |
| together_medium | together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo | 13 | 13 | 0 | 13 | 0 | 0 | 0.002232 | 0.756 |

## By Sample Role

| Role | Calls | Parsed | True | False | Unknown | Transport | Cost USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| benign | 52 | 48 | 1 | 47 | 4 | 0 | 0.082245 |
| malware | 117 | 112 | 15 | 97 | 5 | 4 | 0.164559 |
