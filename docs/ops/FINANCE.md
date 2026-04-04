# PyPi-SCADA Financial Strategy and API Budget

This document outlines the financial controls and budget allocation for the PyPi-SCADA evaluation phase. It defines the mechanism for managing API costs across multiple language model vendors.

## 1. Financial Isolation Strategy

The project uses an air-gapped financial control model. An independent virtual bank account at Indó holds the exact experimental budget. A dedicated virtual debit card connects to the four required API vendors. The operator locks the card in the mobile application between evaluation runs.

This prevents runaway infrastructure costs. API vendors cannot overdraft the account. When funds deplete, the APIs return HTTP 402 Payment Required errors. This safely halts the evaluation pipeline.

## 2. API Budget Allocation

The initial evaluation budget is $100 USD. The allocation reflects the specific roles of the 2026 frontier models in the Entry-Point Engine architecture.

### Anthropic ($30)
This funds the primary detection engine. The frontier tier uses `claude-opus-4-6`. The medium tier uses `claude-sonnet-4-6`. The budget tier uses `claude-haiku-4-5` for benign control filtering and rapid iteration. All calls route through LiteLLM.

### OpenAI ($30)
This funds the deep reasoning baseline. The frontier tier uses `gpt-5.4`. The medium tier uses `gpt-5.4-mini`. The budget tier uses `gpt-5.4-nano` for high-volume development runs.

### Together AI ($25)
This funds the open-source baseline. The frontier tier uses `Qwen/Qwen3.5-397B-A17B` and `deepseek-ai/DeepSeek-V3.2-Exp`. The medium tier uses `meta-llama/Llama-3.3-70B-Instruct-Turbo` and `mistralai/Mistral-Small-3.1-24B-Instruct-2503`. The budget tier uses `Qwen/Qwen3.5-9B`. All accessed via Together AI's OpenAI-compatible API through LiteLLM.

### Google Cloud ($15)
This funds the massive context safety net. The pipeline routes complex dependency confusion attacks to Gemini 2.5 Pro. This provides the necessary context window to process multiple files simultaneously without truncation.

## 3. Reimbursement Documentation

The operator must maintain a strict paper trail to secure university reimbursement. 

* **Vendor Receipts:** The operator downloads all PDF invoices generated during prepaid top-ups or monthly billing cycles.
* **Database Logs:** LiteLLM calculates the exact USD cost of every API request based on token consumption. The analyzer pipeline writes this metric into the `eval_results.db` SQLite database. The operator uses SQL queries to correlate costs directly to experimental runs.
* **Bank Statements:** The operator exports the monthly Indó statement to verify ISK to USD conversion rates and foreign transaction fees.

---

## 4. Budget Mitigation: Phased Execution Strategy

To protect the budget from pipeline errors, all evaluation batches must follow a phased execution model:

* **Phase 1 (Reconnaissance):** All initial pipeline testing and debugging must be conducted exclusively using the `budget` tier models.
* **Phase 2 (Tactical Baseline):** Full dataset runs are executed on the `medium` tier to establish the primary cost-vs-accuracy benchmark.
* **Phase 3 (Frontier Deployment):** The `frontier` tier models are only triggered for the final, definitive benchmarking run once all code is frozen and proven safe.
