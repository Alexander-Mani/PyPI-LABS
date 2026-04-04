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

- [ ] Implement model loading from `configs/models.json` in the Entry-Point Engine.
- [ ] Update `src/analyzer/evaluate.py` to parse `configs/models.json` and accept a `--tier` argument (e.g., `python evaluate.py --tier budget`) to enforce the phased execution strategy.

---

## 3. Engineering: Pipeline Hardening (Eat Our Own Dog Food)
*Demonstrate supply chain security best practices on our own infrastructure.*

- [ ] Transition from floating dependencies (`pip install twine`) to a cryptographic lockfile.
- [ ] Use `pip-tools` (or `uv`) to compile `requirements.in` into a hashed `requirements.txt`.
- [ ] Update `deployment.sh` to install via `pip install --require-hashes --no-deps -r requirements.txt`.
- [ ] Add a brief "Standard Operating Procedure" section in the thesis explaining why this is critical to prevent the researchers from being compromised.

## 4. Engineering: Evaluation Metrics Logging
*Ensure the LiteLLM architecture captures the necessary data for the thesis defense.*

- [ ] Ensure the SQLite `Result DB` is properly logging LiteLLM outputs.
- [ ] Calculate and log: **Precision, Recall, and F1-Score** for each model against the Backstabber samples.
- [ ] Capture Latency metrics: **Time to First Token (TTFT)** and total generation time (critical to prove the "Active Interception" latency budget is viable).
- [ ] Capture Cost-per-Diff/Entry-Point based on token usage and vendor pricing tiers.
