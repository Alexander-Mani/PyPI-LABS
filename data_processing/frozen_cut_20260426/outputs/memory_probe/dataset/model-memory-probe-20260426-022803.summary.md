# Model Memory Probe Summary

- Run ID: `memory-probe-61a0b8b9-bbbe-43e9-a670-f8d70c8e966b`
- Schema version: `2`
- Scope: `production`
- Model source: `profile:all_models`
- Case source: `profile:all_models`
- Calls: `169`
- Total cost: `$0.413106`

## Overall

| Metric | Value |
| --- | ---: |
| Parsed OK | 151 |
| Schema invalid | 8 |
| Length-empty results | 8 |
| Blank-content results | 0 |
| Transport failures | 2 |
| Package recognized true | 38 |
| Exact-version recognized true | 14 |
| Package-only associations | 24 |
| Recognized false | 113 |
| Recognized unknown | 18 |
| Benign package false positives | 8 |
| Benign exact false positives | 4 |
| Suspicious exact claims | 1 |

## Transport Status Counts

| Status | Count |
| --- | ---: |
| transport_timeout | 2 |

## By Model

| Config | Model | Calls | Parsed | Schema Invalid | Length Empty | Package True | Exact True | False | Unknown | Benign Pkg FP | Benign Exact FP | Transport | Cost USD | Mean Latency s |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| claude_haiku | claude-haiku-4-5 | 13 | 10 | 3 | 0 | 0 | 0 | 10 | 3 | 0 | 0 | 0 | 0.023800 | 1.114 |
| claude_opus | claude-opus-4-6 | 13 | 13 | 0 | 0 | 11 | 5 | 2 | 0 | 3 | 2 | 0 | 0.083710 | 4.193 |
| claude_sonnet | claude-sonnet-4-6 | 13 | 13 | 0 | 0 | 5 | 1 | 8 | 0 | 0 | 0 | 0 | 0.042111 | 4.132 |
| gemini | gemini-2.5-pro | 13 | 13 | 0 | 0 | 10 | 7 | 3 | 0 | 3 | 2 | 0 | 0.027286 | 3.630 |
| gemini_flash | gemini-2.5-flash | 13 | 13 | 0 | 0 | 0 | 0 | 13 | 0 | 0 | 0 | 0 | 0.002531 | 0.861 |
| gemini_flash_lite | gemini-2.5-flash-lite | 13 | 13 | 0 | 0 | 4 | 0 | 9 | 0 | 2 | 0 | 0 | 0.000789 | 1.004 |
| gpt | gpt-5.4 | 13 | 13 | 0 | 0 | 1 | 0 | 12 | 0 | 0 | 0 | 0 | 0.021200 | 1.358 |
| gpt_mini | gpt-5.4-mini | 13 | 13 | 0 | 0 | 2 | 0 | 11 | 0 | 0 | 0 | 0 | 0.006428 | 1.186 |
| gpt_nano | gpt-5.4-nano | 13 | 13 | 0 | 0 | 0 | 0 | 13 | 0 | 0 | 0 | 0 | 0.001645 | 1.067 |
| together_budget | together_ai/Qwen/Qwen3.5-9B | 13 | 0 | 5 | 6 | 0 | 0 | 0 | 13 | 0 | 0 | 2 | 0.017809 | 77.004 |
| together_frontier | together_ai/moonshotai/Kimi-K2.5 | 13 | 13 | 0 | 0 | 5 | 1 | 8 | 0 | 0 | 0 | 0 | 0.075320 | 15.725 |
| together_frontier_qwen | together_ai/Qwen/Qwen3.5-397B-A17B | 13 | 11 | 0 | 2 | 0 | 0 | 11 | 2 | 0 | 0 | 0 | 0.106690 | 18.996 |
| together_medium | together_ai/meta-llama/Llama-3.3-70B-Instruct-Turbo | 13 | 13 | 0 | 0 | 0 | 0 | 13 | 0 | 0 | 0 | 0 | 0.003788 | 1.157 |

## By Sample Role

| Role | Calls | Parsed | Length Empty | Package True | Exact True | False | Unknown | Transport | Cost USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| benign | 52 | 44 | 4 | 8 | 4 | 36 | 8 | 1 | 0.127703 |
| malware | 117 | 107 | 4 | 30 | 10 | 77 | 10 | 1 | 0.285404 |

## By Attack Vector

| Attack Vector | Calls | Parsed | Length Empty | Package True | Exact True | False | Unknown | Transport | Cost USD |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Account Takeover | 26 | 24 | 2 | 4 | 1 | 20 | 2 | 0 | 0.062996 |
| Dependency Confusion | 26 | 24 | 0 | 10 | 5 | 14 | 2 | 0 | 0.062112 |
| Multi-stage Execution | 65 | 58 | 2 | 10 | 3 | 48 | 7 | 1 | 0.149676 |
| Typosquatting | 52 | 45 | 4 | 14 | 5 | 31 | 7 | 1 | 0.138322 |

## Exact-Version Recognitions

| Package | Version | Role | Model | Basis | Scope | Related Versions | Confidence |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| torchtriton | 2.0.0+0d7e753227 | malware | claude_sonnet | public_incident | exact_version | 2.0.0+0d7e753227 | 0.95 |
| colorama | 0.4.6 | benign | claude_opus | public_incident | exact_version | 0.4.6 | 0.85 |
| python-nmap | 0.7.1 | benign | claude_opus | public_reporting | exact_version | 0.7.1 | 0.85 |
| ultralytics | 8.3.46 | malware | claude_opus | public_incident | exact_version | 8.3.41, 8.3.42, 8.3.45, 8.3.46 | 0.95 |
| torchtriton | 2.0.0+0d7e753227 | malware | claude_opus | public_incident | exact_version | 2.0.0+0d7e753227 | 0.95 |
| nmap-python | 0.6.1 | malware | claude_opus | public_reporting | exact_version | 0.6.1 | 0.85 |
| sisa | 0.922 | benign | gemini | public_incident | exact_version | 0.922 | 1.0 |
| python-nmap | 0.7.1 | benign | gemini | public_incident | exact_version | 0.7.1 | 1.0 |
| torchtriton | 2.0.0+0d7e753227 | malware | gemini | public_incident | exact_version | 2.0.0+0d7e753227 | 1.0 |
| totallysafe | 2.0.0 | malware | gemini | public_incident | exact_version | 2.0.0 | 1.0 |
| secmeasure | 0.1.2 | malware | gemini | public_incident | exact_version | 0.1.2 | 1.0 |
| sisaws | 2.1.6 | malware | gemini | public_incident | exact_version | 2.1.6 | 1.0 |
| colourama | 0.1.6 | malware | gemini | public_incident | exact_version | 0.1.6 | 1.0 |
| torchtriton | 2.0.0+0d7e753227 | malware | together_frontier | public_incident | exact_version | 2.0.0+0d7e753227 | 0.95 |

## Package-Only Associations

| Package | Version | Role | Model | Basis | Scope | Related Versions | Confidence |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| termcolor | 3.3.0 | benign | gemini_flash_lite | public_incident | same_package_other_version | >=1.1.0,<2.0.0 | 0.8 |
| colorama | 0.4.6 | benign | gemini_flash_lite | public_reporting | same_package_other_version | 0.4.5 | 0.8 |
| colourama | 0.1.6 | malware | gemini_flash_lite | public_reporting | same_package_other_version | 0.4.1 | 0.8 |
| nmap-python | 0.6.1 | malware | gemini_flash_lite | public_reporting | same_package_other_version | 0.6.0 | 0.8 |
| ultralytics | 8.3.46 | malware | claude_sonnet | public_reporting | same_package_other_version | 8.3.41, 8.3.45 | 0.85 |
| totallysafe | 2.0.0 | malware | claude_sonnet | public_reporting | package_only |  | 0.6 |
| colourama | 0.1.6 | malware | claude_sonnet | public_reporting | same_package_other_version | 0.1.6 (queried, uncertain); typosquat versions generally 0.1.x | 0.85 |
| nmap-python | 0.6.1 | malware | claude_sonnet | public_reporting | package_only |  | 0.72 |
| ultralytics | 8.3.46 | malware | gpt_mini | public_reporting | package_only |  | 0.78 |
| torchtriton | 2.0.0+0d7e753227 | malware | gpt_mini | public_incident | package_only |  | 0.78 |
| termcolor | 3.3.0 | benign | claude_opus | public_reporting | same_package_other_version | 2.0.0, 2.1.0 | 0.55 |
| totallysafe | 2.0.0 | malware | claude_opus | public_reporting | package_only |  | 0.55 |
| secmeasure | 0.1.2 | malware | claude_opus | public_reporting | package_only |  | 0.65 |
| sisaws | 2.1.6 | malware | claude_opus | public_reporting | same_package_other_version | Various versions reported as malicious on PyPI | 0.55 |
| termncolor | 3.1.0 | malware | claude_opus | public_reporting | package_only |  | 0.75 |
| colourama | 0.1.6 | malware | claude_opus | public_reporting | package_only |  | 0.75 |
| torchtriton | 2.0.0+0d7e753227 | malware | gpt | public_incident | same_package_other_version | torchtriton 2.0.0 | 0.98 |
| colorama | 0.4.6 | benign | gemini | public_incident | same_package_other_version | 0.4.3 | 1.0 |
| termncolor | 3.1.0 | malware | gemini | public_incident | same_package_other_version | 1.0 | 0.9 |
| nmap-python | 0.6.1 | malware | gemini | public_incident | same_package_other_version | 0.1.4 | 1.0 |
| ultralytics | 8.3.46 | malware | together_frontier | public_incident | same_package_other_version | 8.3.41, 8.3.42, 8.3.43, 8.3.44, 8.3.45 | 0.9 |
| totallysafe | 2.0.0 | malware | together_frontier | public_incident | package_only |  | 0.8 |
| termncolor | 3.1.0 | malware | together_frontier | public_reporting | package_only |  | 0.8 |
| colourama | 0.1.6 | malware | together_frontier | public_reporting | package_only |  | 0.9 |

## Benign False Associations

| Package | Version | Role | Model | Basis | Scope | Related Versions | Confidence |
| --- | --- | --- | --- | --- | --- | --- | ---: |
| termcolor | 3.3.0 | benign | gemini_flash_lite | public_incident | same_package_other_version | >=1.1.0,<2.0.0 | 0.8 |
| colorama | 0.4.6 | benign | gemini_flash_lite | public_reporting | same_package_other_version | 0.4.5 | 0.8 |
| termcolor | 3.3.0 | benign | claude_opus | public_reporting | same_package_other_version | 2.0.0, 2.1.0 | 0.55 |
| colorama | 0.4.6 | benign | claude_opus | public_incident | exact_version | 0.4.6 | 0.85 |
| python-nmap | 0.7.1 | benign | claude_opus | public_reporting | exact_version | 0.7.1 | 0.85 |
| sisa | 0.922 | benign | gemini | public_incident | exact_version | 0.922 | 1.0 |
| colorama | 0.4.6 | benign | gemini | public_incident | same_package_other_version | 0.4.3 | 1.0 |
| python-nmap | 0.7.1 | benign | gemini | public_incident | exact_version | 0.7.1 | 1.0 |

## Suspicious Exact-Version Claims

| Package | Version | Role | Model | Reason | Fact |
| --- | --- | --- | --- | --- | --- |
| torchtriton | 2.0.0+0d7e753227 | malware | together_frontier | fact_mentions_other_versions_only | In December 2022, attackers uploaded a malicious torchtriton 2.0.0 package to PyPI targeting PyTorch nightly builds, exfiltrating environment variables and secrets to a remote server. |
