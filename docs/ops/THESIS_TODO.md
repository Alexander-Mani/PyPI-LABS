# PyPi-SCADA Thesis: Writing & Engineering TODOs

## 1. Writing: Incorporate "Active Interception" Concept (High Priority)
*Drafting notes to frame the Entry-Point Engine as a prototype for real-time proxy defense.*

- [ ] **Introduction:** Frame the "holy grail" of supply chain security as proactive, zero-day prevention (intercepting malicious intent *during* package installation).
- [ ] **Discussion / Industry Context:** Contrast reactive signature-based tools (`pip-audit`, OSV) with emerging active proxy interception solutions (Socket.dev, Phylum, Snyk). Discuss the engineering challenges of real-time interception:
  - The `setup.py` execution trap (malware runs before download finishes).
  - The latency budget (LLM scans cannot break CI/CD speed).
  - The false-positive penalty (breaking legitimate developer builds).
- [ ] **Future Work:** Propose commercializing the PyPi-SCADA Entry-Point Engine + LiteLLM pipeline into a REST API. Describe an "Infected Endpoint" custom PyPI registry that developers route through to perform zero-day heuristic analysis before a package payload reaches their host machine.

## 2. Engineering: Model Loading and Phased Execution

- [x] Implement model loading from `configs/models.json` in the Entry-Point Engine.
- [x] Update `src/analyzer/evaluate.py` to parse `configs/models.json` and accept a `--tier` argument (e.g., `python evaluate.py --tier budget`) to enforce the phased execution strategy.

---

## 3. Engineering: Pipeline Hardening (Eat Our Own Dog Food)
*Demonstrate supply chain security best practices on our own infrastructure.*

- [x] Transition from floating dependencies (`pip install twine`) to a cryptographic lockfile.
- [x] Use `pip-tools` (or `uv`) to compile `requirements/requirements.in` into a hashed `requirements/requirements.txt`.
- [x] Update `deployment.sh` to install via `pip install --require-hashes --no-deps -r requirements/requirements.txt`.
- [ ] Add a brief "Standard Operating Procedure" section in the thesis explaining why this is critical to prevent the researchers from being compromised.

## 4. Engineering: Evaluation Metrics Logging
*Ensure the LiteLLM architecture captures the necessary data for the thesis defense.*

- [ ] Ensure the SQLite `Result DB` is properly logging LiteLLM outputs.
- [ ] Calculate and log: **Precision, Recall, and F1-Score** for each model against the Backstabber samples.
- [ ] Capture Latency metrics: **Time to First Token (TTFT)** and total generation time (critical to prove the "Active Interception" latency budget is viable).
- [ ] Capture Cost-per-Diff/Entry-Point based on token usage and vendor pricing tiers.



# New mode pipline

**Note: The 4-mode architecture described below is fully implemented and complete.**

You must update several specific sections of your report to reflect the new four-mode architecture.

### 1.2 Goals
[cite_start]The current text states the project compares language models and agentic tools against static tools[cite: 30]. Update this to explicitly define the four distinct execution modes. State that the system evaluates Static Only, LLM Only, Hybrid, and Agentic pipelines sequentially against the identical sample set.

### 3 Methodology and Evaluation
[cite_start]The report currently lists three distinct pipelines[cite: 93]. Change this to four. The previous single-prompt language model analysis splits into two paths. Define Mode B as raw file ingestion. Define Mode C as the hybrid approach using static extraction. 

### 3.1 Input Strategy
[cite_start]The report details entry-point scanning and heuristic pre-filtering[cite: 120, 133]. Specify that these steps apply strictly to Mode A, Mode C, and Mode D. Add a new subsection detailing Mode B. Explain the raw file ingestion bypass mechanism. State that it forces the model to analyze the full context window to establish a cost baseline.

### 3.3.1 Prompt Strategies
[cite_start]The section defines zero-shot, few-shot, and role-based strategies[cite: 169, 170, 172]. Add the technical implementation details. State that a YAML configuration system stores and versions these templates. Explain that the adapter dynamically loads these templates based on the current execution state.

### 3.5 Cost and Performance Metrics
[cite_start]The text tracks wall-clock time and token costs[cite: 210, 213]. Update the database description. State that the SQLite schema uses a composite key mapping the run identifier to the experiment mode enumerator. Clarify that the static analysis pipeline explicitly logs a token cost of zero. 

### 5.1.3 PyPI Detection Analyzer
[cite_start]Update the architectural descriptions[cite: 291, 295, 297]. Replace the current controller explanation with the strict `DetectorAdapter` interface. Detail the individual adapters for the Static, LLM, and Agentic execution paths. Note the parser modification required for raw string loading. Describe the updated database schema containing the new `experiment_mode` and `prompt_strategy` columns.

### Table 9: Current Project Backlog
[cite_start]Add the required implementation phases to your backlog[cite: 421]. Include the database schema migration. Add the prompt configuration management system. Add the adapter interface refactoring. Add the raw extraction bypass development. Assign these tasks high priority within Phase III.
