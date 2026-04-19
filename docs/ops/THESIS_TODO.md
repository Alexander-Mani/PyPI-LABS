# PyPi-SCADA Thesis: Writing & Engineering TODOs

## 0. Final-Week Canonical-v2 Execution Plan (Added 2026-04-17)

Operator discipline for the final stretch through SM3. Report submission deadline is Friday 2026-04-24; SM3 runs 2026-04-27 through 2026-04-29.

### Pre-flight discipline before any canonical-v2 run

1. **Per-tier LiteLLM smoke.** Run `python scripts/litellm_smoke.py --profile budget`, then `medium`, then `frontier`, then `all_models`, in order. Each smoke call is cheap and catches model-ID drift, provider-alias changes, and 5xx throttling before the tier burns real budget.
2. **DB archive between tiers.** Archive the current `eval_results.db` before each tier (e.g., using `scripts/archive_eval_db.py` or the Review TUI's DB section). This localises any mid-run routing bug to one tier's rows instead of the full canonical set.
3. **Run-id prefix is mandatory.** Every canonical execution passes `--run-id-prefix canonical-v2` so the thesis metric filter `run_id LIKE 'canonical-v2-%'` captures exactly those rows. The Review TUI rewrites this automatically; manual CLI invocations must set it.
4. **Confirm `include_controls` at the CLI.** The canonical profiles (`budget`, `budget_no_gemini`, `medium`, `frontier`, `all_models`) do NOT set `include_controls: true` in their YAML; only the `test` and `test_no_gemini` profiles do. Canonical-v2 runs that need benign control packages (boto3, botocore, etc.) must pass `--include-controls` explicitly. Resolution rule in `evaluate.py`: `include_controls=args.include_controls or bool(profile_include_controls)` — the CLI flag can enable but not disable the profile setting.
5. **Pre-canonical investigations resolved.** Do not burn frontier budget until the `nmap-python` hybrid-FN gap (see `src/analyzer/CONCERNS.md` §7) is either fixed or documented as an intentional prompt-strategy finding.

### Tier sequencing

Run in order, one tier per day, budget → frontier, to bound blast-radius of any routing/provider failure and to stage cost exposure.

1. **Budget** — smallest cost, fastest wall-time; full malicious set plus benign controls.
2. **Medium** — same sample set; gates frontier.
3. **Frontier** — same sample set, most expensive; run only after budget + medium complete cleanly.
4. **all_models** — aggregate pass if residual budget allows.

Archive the DB between tiers. Treat any mid-tier failure as "do not proceed to the next tier until root-caused."

### Timeline

| Date | Milestone |
|---|---|
| 2026-04-18 (Sat) | Resolve `nmap-python` hybrid-FN investigation; run budget-tier canonical-v2 |
| 2026-04-19 (Sun) | Medium-tier canonical-v2; frontier-tier LiteLLM smoke |
| 2026-04-20 (Mon) | Frontier-tier canonical-v2; populate result tables from `canonical-v2` rows; first-interpretation paragraphs for RQ1/RQ2/RQ3 |
| 2026-04-21 (Tue) | Discussion rewrite with actual numbers; Timewarrior hours export; final Overleaf compile |
| 2026-04-22 (Wed) | Spellcheck pass; final PDF; submit to Canvas/supervisor/examiner |
| 2026-04-23 (Thu) | Buffer day for reruns if a provider outage requires one |
| 2026-04-24 (Fri) | **Report submission deadline (two working days before SM3)** |
| 2026-04-25 – 04-26 (Sat/Sun) | Slide build; two dry-run presentation rehearsals |
| 2026-04-27 – 04-29 (Mon–Wed) | SM3 meeting |

### Optional weekend work (skip if time-constrained)

- **Frontier-recall robustness check.** One frontier model × named sample (`colourama`) vs obscure typosquat. Details in `src/analyzer/CONCERNS.md` §8. Directly strengthens the external-validity discussion under RQ1, but the thesis is defensible without it as long as the limitation is explicitly named.

### Scope lock — do not do between now and SM3

- Do not add a new detector, model, profile, or comparison axis. Scope creep this close to submission is a bigger risk than any marginal finding it might produce.
- Do not change evaluation-metric definitions after canonical-v2 runs start. Freezes must hold or the `canonical-v2` filter loses its meaning.
- Do not swap models mid-tier if one is slow or throttled. Preserve the error row (`experiment_mode="error"`) and move on; variance across models is itself evidence for RQ3 (cost / reliability / reproducibility limits).

### Presentation-framing reminders

- **Lean into proof-of-concept framing.** Nine malicious packages is a curated hard-case set, not a benchmark. Present behavioural trends and per-vector observations, not generalizable detection rates. The validity section already says this; keep the same framing in slides and discussion so the examiner does not have to redescribe the scope themselves.
- **Own the solo-work + AI-assisted-review compensation honestly.** `CODE_REVIEW_METHOD.md` documents how AI-assisted review stood in for peer review in a solo capstone. State this in the AI-usage disclosure and do not downplay it — transparency is the right move with examiners, and the disclosure is already in the thesis (`sec:ai_usage`).
- **Narrate the risk diary.** Decisions 1–9 and R-01 through R-06 are specific, defensible, and uncommon in undergraduate work. In the 15–20 minute presentation, budget at least one slide and one minute to walk through two or three of them in the examiner's direction; do not let them stay buried in the report.

---

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
