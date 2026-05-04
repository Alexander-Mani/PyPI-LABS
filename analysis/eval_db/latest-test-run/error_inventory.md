# Error Inventory

| family | detector | prompt_strategy | error_category | rows |
| --- | --- | --- | --- | --- |
| profile:all_models:identity-alias-probe | together_budget | zero_shot | empty_finish_reason_length | 1 |
| profile:all_models:identity-alias-probe | together_frontier_qwen | zero_shot | empty_finish_reason_length | 6 |
| profile:budget:llm-no-agentic | together_budget | few_shot | empty_finish_reason_length | 3 |
| profile:budget:llm-no-agentic | together_budget | role_based | empty_finish_reason_length | 11 |
| profile:budget:llm-no-agentic | together_budget | zero_shot | empty_finish_reason_length | 8 |
| profile:frontier:agentic-only | claude_agentic | role_based | deployment_unavailable_429 | 18 |
| profile:frontier:agentic-only | claude_agentic | zero_shot | deployment_unavailable_429 | 19 |
| profile:frontier:llm-no-agentic | claude_opus | few_shot | empty_null_content | 1 |
| profile:frontier:llm-no-agentic | claude_opus | few_shot | unparseable_model_response | 1 |
| profile:frontier:llm-no-agentic | claude_opus | role_based | empty_null_content | 1 |
| profile:frontier:llm-no-agentic | claude_opus | zero_shot | empty_null_content | 1 |
| profile:frontier:llm-no-agentic | gpt | zero_shot | unparseable_model_response | 1 |
| profile:frontier:llm-no-agentic | together_frontier_qwen | few_shot | empty_finish_reason_length | 2 |
| profile:frontier:llm-no-agentic | together_frontier_qwen | role_based | empty_finish_reason_length | 4 |
| profile:frontier:llm-no-agentic | together_frontier_qwen | zero_shot | empty_finish_reason_length | 1 |
