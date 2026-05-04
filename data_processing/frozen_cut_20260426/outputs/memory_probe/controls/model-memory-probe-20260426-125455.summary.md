# Model Memory Probe Summary

- Run ID: `memory-probe-c128b7b3-b3f3-4cfe-9714-20a9f3d6be1d`
- Schema version: `2`
- Scope: `production`
- Sample set: `controls`
- Model source: `profile:all_models`
- Case source: `profile:all_models (sample_set=controls)`
- Calls: `130`
- Total cost: `$0.461541`

## Overall

| Metric | Value |
| --- | ---: |
| Parsed OK | 112 |
| Schema invalid | 6 |
| Length-empty results | 12 |
| Blank-content results | 0 |
| Transport failures | 0 |
| Package recognized true | 53 |
| Exact-version recognized true | 3 |
| Package-only associations | 50 |
| Recognized false | 61 |
| Recognized unknown | 18 |
| Benign package false positives | 0 |
| Benign exact false positives | 0 |
| Suspicious exact claims | 0 |

## Transport Status Counts

None

## By Model

| Config | Model | Calls | Parsed | Schema Invalid | Length Empty | Package True | Exact True | False | Unknown | Benign Pkg FP | Benign Exact FP | Transport | Cost USD | Mean Latency s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| claude_haiku | claude-haiku-4-5 | 10 | 6 | 4 | 0 | 4 | 0 | 2 | 4 | 0 | 0 | 0 | 0.019553 | 1.512 |
| claude_opus | claude-opus-4-6 | 10 | 8 | 2 | 0 | 10 | 0 | 0 | 2 | 0 | 0 | 0 | 0.069465 | 4.807 |
| claude_sonnet | claude-sonnet-4-6 | 10 | 10 | 0 | 0 | 6 | 1 | 4 | 0 | 0 | 0 | 0 | 0.034914 | 5.333 |
| gemini | gemini-2.5-pro | 10 | 10 | 0 | 0 | 6 | 0 | 4 | 0 | 0 | 0 | 0 | 0.020988 | 4.726 |
| gemini_flash | gemini-2.5-flash | 10 | 10 | 0 | 0 | 0 | 0 | 10 | 0 | 0 | 0 | 0 | 0.002031 | 0.926 |
| gemini_flash_lite | gemini-2.5-flash-lite | 10 | 10 | 0 | 0 | 8 | 0 | 2 | 0 | 0 | 0 | 0 | 0.000735 | 3.323 |
| gpt | gpt-5.4 | 10 | 10 | 0 | 0 | 4 | 0 | 6 | 0 | 0 | 0 | 0 | 0.019048 | 1.583 |
| gpt_mini | gpt-5.4-mini | 10 | 10 | 0 | 0 | 2 | 0 | 8 | 0 | 0 | 0 | 0 | 0.004972 | 1.619 |
| gpt_nano | gpt-5.4-nano | 10 | 10 | 0 | 0 | 0 | 0 | 10 | 0 | 0 | 0 | 0 | 0.001264 | 0.963 |
| together_budget | together_ai/Qwen/Qwen3.5-9B | 10 | 0 | 0 | 10 | 0 | 0 | 0 | 10 | 0 | 0 | 0 | 0.025356 | 107.115 |
| together_frontier | together_ai/moonshotai/Kimi-K2.5 | 10 | 10 | 0 | 0 | 6 | 2 | 4 | 0 | 0 | 0 | 0 | 0.081499 | 61.043 |
| together_frontier_qwen | together_ai/Qwen/Qwen3.5-397B-A17B | 10 | 8 | 0 | 2 | 1 | 0 | 7 | 2 | 0 | 0 | 0 | 0.178626 | 52.140 |
| together_medium | together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo | 10 | 10 | 0 | 0 | 6 | 0 | 4 | 0 | 0 | 0 | 0 | 0.003092 | 1.459 |

## By Sample Role

| Role | Calls | Parsed | Length Empty | Package True | Exact True | False | Unknown | Transport | Cost USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| control | 130 | 112 | 12 | 53 | 3 | 61 | 18 | 0 | 0.461541 |

## By Attack Vector

| Attack Vector | Calls | Parsed | Length Empty | Package True | Exact True | False | Unknown | Transport | Cost USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| none | 130 | 112 | 12 | 53 | 3 | 61 | 18 | 0 | 0.461541 |

## Exact-Version Recognitions

| Package | Version | Role | Model | Basis | Scope | Related Versions | Confidence |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| idna | 3.11 | control | claude_sonnet | public_incident | exact_version | 3.7, 3.11 | 0.85 |
| packaging | 26.0 | control | together_frontier | public_reporting | exact_version | 26.0 | 0.95 |
| python-dateutil | 2.9.0.post0 | control | together_frontier | public_incident | exact_version | 2.9.0.post0 | 0.95 |

## Package-Only Associations

| Package | Version | Role | Model | Basis | Scope | Related Versions | Confidence |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| packaging | 26.0 | control | claude_haiku | none | package_only |  | 0.0 |
| requests | 2.33.1 | control | claude_haiku | none | package_only |  | 0.0 |
| setuptools | 82.0.1 | control | claude_haiku | public_reporting | package_only |  | 0.3 |
| urllib3 | 2.6.3 | control | claude_haiku | public_reporting | package_only | 1.26.5, 1.26.6, 2.0.0 | 0.3 |
| boto3 | 1.42.81 | control | gemini_flash_lite | public_reporting | same_package_other_version | 1.26.0 | 0.8 |
| botocore | 1.42.81 | control | gemini_flash_lite | public_reporting | same_package_other_version | 1.42.0 | 0.8 |
| certifi | 2026.2.25 | control | gemini_flash_lite | public_reporting | same_package_other_version | 2023.07.22, 2023.11.17 | 0.8 |
| charset-normalizer | 3.4.6 | control | gemini_flash_lite | public_incident | same_package_other_version | 3.1.0,3.2.0,3.3.0,3.3.1,3.3.2 | 0.9 |
| python-dateutil | 2.9.0.post0 | control | gemini_flash_lite | public_reporting | same_package_other_version | 2.9.0 | 0.8 |
| requests | 2.33.1 | control | gemini_flash_lite | public_reporting | same_package_other_version | 2.28.1 | 0.8 |
| setuptools | 82.0.1 | control | gemini_flash_lite | public_reporting | same_package_other_version | 68.0.0 | 0.8 |
| urllib3 | 2.6.3 | control | gemini_flash_lite | public_incident | same_package_other_version | 1.26.0 | 0.8 |
| botocore | 1.42.81 | control | claude_sonnet | public_reporting | package_only |  | 0.2 |
| certifi | 2026.2.25 | control | claude_sonnet | public_reporting | same_package_other_version | 2022.12.07, 2023.7.22 | 0.5 |
| requests | 2.33.1 | control | claude_sonnet | public_reporting | same_package_other_version | 2.6.0 | 0.6 |
| setuptools | 82.0.1 | control | claude_sonnet | public_reporting | same_package_other_version | 65.5.1 | 0.6 |
| urllib3 | 2.6.3 | control | claude_sonnet | public_reporting | same_package_other_version | 1.26.5 | 0.5 |
| botocore | 1.42.81 | control | gpt_mini | public_reporting | package_only |  | 0.78 |
| setuptools | 82.0.1 | control | gpt_mini | public_incident | package_only |  | 0.86 |
| botocore | 1.42.81 | control | together_medium | public_reporting | package_only |  | 0.0 |
| charset-normalizer | 3.4.6 | control | together_medium | public_reporting | package_only |  | 0.0 |
| idna | 3.11 | control | together_medium | public_reporting | package_only |  | 0.0 |
| requests | 2.33.1 | control | together_medium | public_reporting | package_only |  | 0.0 |
| setuptools | 82.0.1 | control | together_medium | public_reporting | package_only |  | 0.0 |
| urllib3 | 2.6.3 | control | together_medium | public_reporting | package_only |  | 0.0 |
| boto3 | 1.42.81 | control | claude_opus | guess | package_only |  | 0.5 |
| botocore | 1.42.81 | control | claude_opus | none | package_only |  | 0.3 |
| certifi | 2026.2.25 | control | claude_opus | public_reporting | same_package_other_version | 2022.12.07, 2023.7.22 | 0.7 |
| charset-normalizer | 3.4.6 | control | claude_opus | none | package_only |  | 0.3 |
| idna | 3.11 | control | claude_opus | public_reporting | same_package_other_version |  | 0.5 |
| packaging | 26.0 | control | claude_opus | guess | package_only |  | 0.3 |
| python-dateutil | 2.9.0.post0 | control | claude_opus | public_reporting | same_package_other_version |  | 0.55 |
| requests | 2.33.1 | control | claude_opus | public_reporting | same_package_other_version | The legitimate `requests` package by Kenneth Reitz has versions up to 2.31.x (as of mid-2023) and later 2.32.x. Version 2.33.1 does not correspond to a known legitimate release. | 0.7 |
| setuptools | 82.0.1 | control | claude_opus | public_reporting | same_package_other_version | versions before 65.5.1, versions before 70.0 | 0.6 |
| urllib3 | 2.6.3 | control | claude_opus | public_reporting | same_package_other_version | 1.26.5, 1.26.18, 2.0.6, 2.0.7 | 0.6 |
| botocore | 1.42.81 | control | gpt | public_reporting | package_only |  | 0.31 |
| requests | 2.33.1 | control | gpt | public_reporting | same_package_other_version | requests 2.32.0, requests 2.31.0 | 0.72 |
| setuptools | 82.0.1 | control | gpt | public_reporting | package_only |  | 0.31 |
| urllib3 | 2.6.3 | control | gpt | public_reporting | same_package_other_version | 1.26.x, 2.0.0-2.0.6 | 0.82 |
| botocore | 1.42.81 | control | gemini | public_incident | same_package_other_version | 1.29.76 | 0.9 |
| certifi | 2026.2.25 | control | gemini | public_reporting | package_only |  | 0.5 |
| packaging | 26.0 | control | gemini | public_incident | same_package_other_version | 23.2 | 1.0 |
| python-dateutil | 2.9.0.post0 | control | gemini | public_reporting | same_package_other_version | 2.7.0 | 0.8 |
| requests | 2.33.1 | control | gemini | public_reporting | same_package_other_version | 2.31.0 | 1.0 |
| urllib3 | 2.6.3 | control | gemini | public_reporting | same_package_other_version | 2.0.0-2.0.7, <1.26.18 | 1.0 |
| botocore | 1.42.81 | control | together_frontier | public_reporting | same_package_other_version | 1.42.0, 1.42.1 | 0.9 |
| idna | 3.11 | control | together_frontier | public_reporting | same_package_other_version | <3.7 | 0.9 |
| setuptools | 82.0.1 | control | together_frontier | public_reporting | same_package_other_version | < 70.0.0 | 0.9 |
| urllib3 | 2.6.3 | control | together_frontier | public_reporting | same_package_other_version | 1.26.17, 1.26.18, 2.0.4, 2.0.6, 2.0.7 | 0.9 |
| certifi | 2026.2.25 | control | together_frontier_qwen | public_reporting | same_package_other_version | 2022.04.08, 2023.06.01 | 0.95 |

## Benign False Associations

None

## Suspicious Exact-Version Claims

None
