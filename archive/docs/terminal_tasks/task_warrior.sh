#!/bin/bash

# Define Project Name
PROJ="Thesis"

# --- Phase I: Research (Jan 12 - Feb 15) ---
# Due dates aligned with Sunday of the respective week

# Taskset Ia (Jan 18 - Jan 25)
task add project:$PROJ phase:I priority:H due:2026-01-18 "Setup: Provision VM on Frostbyte infrastructure"
task add project:$PROJ phase:I priority:H due:2026-01-18 "Tools: Init Git and Overleaf skeleton"
task add project:$PROJ phase:I priority:M due:2026-01-18 "Planning: Create Product Backlog and Sprints"
task add project:$PROJ phase:I priority:M due:2026-01-25 "Research: Deep dive into SilentSync, Colorama, Credential Takeover, Torchtriton"
task add project:$PROJ phase:I priority:H due:2026-01-25 "Selection: Finalize LLM APIs and SAST tools"
task add project:$PROJ phase:I priority:M due:2026-01-25 "Thesis: Write Project Description and Objectives"

# Taskset Ib (Feb 1)
task add project:$PROJ phase:I priority:H due:2026-02-01 "Design: Architect Simulator-Diffing-Analysis pipeline"
task add project:$PROJ phase:I priority:H due:2026-02-01 "Risk Analysis: Create formal Ahættugreining for Sitrep 1"
task add project:$PROJ phase:I priority:M due:2026-02-01 "Thesis: Draft State of the Art/Background section"

# Taskset Ic (Feb 8)
task add project:$PROJ phase:I priority:M due:2026-02-08 "Prototyping: Hello World connecting Python to LLM API"
task add project:$PROJ phase:I priority:L due:2026-02-08 "Environment: Configure Python 3.9+ env"
task add project:$PROJ phase:I priority:H due:2026-02-08 "Presentation: Prepare slides for Sitrep 1"

# Taskset Id (Feb 15) - SITREP 1
task add project:$PROJ phase:I priority:H due:2026-02-13 "Meeting: Attend Sitrep 1"
task add project:$PROJ phase:I priority:M due:2026-02-15 "Thesis: Complete first draft of Introduction"

# --- Phase II: Development (Feb 16 - Mar 15) ---

# Taskset IIa (Feb 22)
task add project:$PROJ phase:II priority:H due:2026-02-22 "Dev: Implement PyPI Simulator Core"
task add project:$PROJ phase:II priority:M due:2026-02-22 "Dev: Implement local storage/DB for packages"
task add project:$PROJ phase:II priority:L due:2026-02-22 "Thesis: Document Simulator Architecture"

# Taskset IIb (Mar 1)
task add project:$PROJ phase:II priority:H due:2026-03-01 "Dev: Implement Diffing Engine (Version A vs B)"
task add project:$PROJ phase:II priority:M due:2026-03-01 "Testing: Unit test diffing logic"
task add project:$PROJ phase:II priority:L due:2026-03-01 "Thesis: Write Diffing Methodology subsection"

# Taskset IIc (Mar 8)
task add project:$PROJ phase:II priority:H due:2026-03-08 "Dev: Build Pipeline Controller (Orchestration)"
task add project:$PROJ phase:II priority:M due:2026-03-08 "Dev: Implement Logging System"
task add project:$PROJ phase:II priority:H due:2026-03-08 "Presentation: Prepare slides for Sitrep 2"

# Taskset IId (Mar 15) - SITREP 2
task add project:$PROJ phase:II priority:H due:2026-03-13 "Meeting: Attend Sitrep 2 (Demo Prototype)"
task add project:$PROJ phase:II priority:M due:2026-03-15 "Dev: Refine Simulator based on initial tests"
task add project:$PROJ phase:II priority:M due:2026-03-15 "Thesis: Update Implementation chapter"

# --- Phase III: Benchmarking (Mar 16 - Apr 26) ---

# Taskset IIIa (Mar 22)
task add project:$PROJ phase:III priority:H due:2026-03-22 "Dev: Integrate Bandit and Semgrep"
task add project:$PROJ phase:III priority:M due:2026-03-22 "Config: Configure SAST rulesets for supply chain"

# Taskset IIIb (Mar 29)
task add project:$PROJ phase:III priority:H due:2026-03-29 "Dev: Integrate Gemini/GPT APIs"
task add project:$PROJ phase:III priority:H due:2026-03-29 "AI: Develop System Prompts for detection"

# Taskset IIIc (Apr 5)
task add project:$PROJ phase:III priority:H due:2026-04-05 "Dataset: Generate Malicious Samples (SilentSync, Colorama, etc)"
task add project:$PROJ phase:III priority:M due:2026-04-05 "Dataset: Select Benign Control versions"
task add project:$PROJ phase:III priority:M due:2026-04-05 "Thesis: Write Experimental Setup section"

# Taskset IIId (Apr 12)
task add project:$PROJ phase:III priority:H due:2026-04-12 "Integration: Connect Simulator -> Diff -> Analysis -> DB"
task add project:$PROJ phase:III priority:M due:2026-04-12 "Testing: Perform Dry Run of full system"

# Exam Period Tasks (Apr 13 - Apr 26)
task add project:$PROJ phase:III priority:M due:2026-04-19 "Execution: Run automated benchmarking suite"
task add project:$PROJ phase:III priority:L due:2026-04-26 "Data: Monitor results and ensure stability"
task add project:$PROJ phase:III priority:H due:2026-04-26 "Presentation: Draft Final Defense Slides"

# --- Phase IV: Finalizing (Apr 27 - May 24) ---

# Taskset IVa (May 3) - SITREP 3
task add project:$PROJ phase:IV priority:H due:2026-05-01 "Meeting: Attend Sitrep 3 (Generalprufa)"
task add project:$PROJ phase:IV priority:H due:2026-05-03 "Analysis: Compare Detection Rates AI vs SAST"
task add project:$PROJ phase:IV priority:M due:2026-05-03 "Thesis: Write Results and Evaluation chapters"

# Taskset IVb (May 10)
task add project:$PROJ phase:IV priority:H due:2026-05-10 "Thesis: Write Discussion and Conclusion"
task add project:$PROJ phase:IV priority:M due:2026-05-10 "Docs: Write README and User Manuals"
task add project:$PROJ phase:IV priority:M due:2026-05-10 "Review: Full thesis read-through"

# Taskset IVc (May 17)
task add project:$PROJ phase:IV priority:H due:2026-05-17 "Code: Final polish and cleanup for submission"
task add project:$PROJ phase:IV priority:H due:2026-05-17 "Submission: Submit Thesis to Skemman"

# Taskset IVd (May 24) - FINAL
task add project:$PROJ phase:IV priority:H due:2026-05-22 "Defense: Final Public Presentation"

echo "All Thesis tasks imported successfully."
