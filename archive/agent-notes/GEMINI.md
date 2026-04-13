# PyPI-SCADA: Project Memory

## Project Overview
PyPI-SCADA is a cybersecurity research project benchmarking SAST vs. Large Language Models (LLMs) for detecting supply chain attacks on the Python Package Index.

## Core Mandates & Architecture
- **Design Pivot (Crucial):** The project has pivoted from "Differential Analysis" (comparing versions) to **"Entry-Point Scanning"**.
  - **Targets:** `setup.py`, `__init__.py`, `pyproject.toml`, and their direct imports/metadata.
  - **Reasoning:** Differential analysis fails for typosquatting/dependency confusion where no "clean" previous version exists, and is vulnerable to "version dilution" attacks.
- **LLM Routing:** All LLM calls must route through LiteLLM proxy at `http://127.0.0.1:4000`. No API keys are stored in the analyzer.
- **Testing Grid:** Models are categorized into `frontier`, `medium`, and `budget` tiers via `configs/models.json`.
- **Infrastructure:**
  - `Injector`: Automates malicious/benign package uploads via `twine`.
  - `Simulator`: Flask-based PEP 503 compliant repository.
  - `Analyzer`: Core detection engine (Entry-Point Extractor + Heuristic Filter + LLM/SAST Adapters).

## Current Phase: Phase III (April 6–12, 2026)
- **Focus:** SAST & LLM Adapter Integration.
- **Goal:** Fully develop and deploy the analyzer's integration with Bandit, Semgrep, and LLM APIs (Gemini, GPT, etc.).

## Key References
- `docs/pypi-scada-status-report-ii.md`: Detailed methodology and scoring rubric.
- `src/analyzer/CONCERNS.md`: Technical risks and implementation notes.
- `src/analyzer/TODO.md`: Immediate tasks for Phase III.
