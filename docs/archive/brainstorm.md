# Project Concept: Supply Chain Attack Detection in PyPI

## Overview

This project investigates software supply-chain attacks targeting the Python Package Index (PyPI). The focus is on detecting malicious behavior introduced through new package releases or updates, especially cases where harmful code is added via accepted contributions or compromised maintainer accounts.

The project emphasizes **static, version-differential analysis** and evaluates how well different detection approaches perform under realistic and adversarial conditions, using a fully isolated, simulated PyPI environment.

---

## Core Research Questions

- How effective is static analysis at detecting supply-chain attacks in PyPI packages?
- Does comparing package versions (diff-based analysis) improve detection of malicious updates?
- How do traditional heuristic-based detectors compare to AI-assisted analysis techniques?
- What types of malicious changes are hardest to detect without increasing false positives?
- Can malicious packages be grouped into campaigns based on shared characteristics?

---

## Threat Model

The project considers two primary supply-chain attack scenarios:

1. **Malicious Package Publication**
   - New packages uploaded with hidden malicious functionality
   - Often uses typosquatting or misleading package descriptions

2. **Malicious Code Injection via Updates**
   - Harmful code introduced in later versions of trusted packages
   - Can result from compromised maintainer credentials or accepted malicious contributions
   - Manifests as subtle changes between versions rather than overtly malicious initial releases

The project explicitly focuses on the second scenario through version-differential analysis.

---

## System Description

The system functions as a **continuous monitoring and analysis pipeline**:

1. **Monitoring**
   - Watches for new or updated package releases in a PyPI-like registry

2. **Ingestion**
   - Downloads source distributions
   - Extracts metadata and source code

3. **Static Analysis**
   - Parses Python code using AST analysis
   - Detects suspicious constructs such as:
     - Dynamic execution (`exec`, `eval`)
     - Obfuscated or encoded payloads
     - Install-time hooks
     - Hardcoded network indicators

4. **Version-Differential Analysis**
   - Compares new releases against previous versions
   - Flags newly introduced risky behavior or dependencies

5. **Scoring and Explainability**
   - Combines findings into a risk score
   - Produces human-readable explanations for each alert

6. **Campaign Clustering**
   - Groups related packages based on shared code patterns, metadata, or infrastructure indicators

---

## Simulated PyPI Environment

All experiments are conducted in a **fully isolated, local PyPI-like registry** that allows:

- Controlled upload of test packages and versions
- Replay of historical attack scenarios
- Safe experimentation without interacting with real-world registries
- Reproducible evaluation timelines

No malicious code is executed, and no real packages or registries are affected.

---

## Adversarial Evaluation (Thought Experiment Component)

As part of the research, the project includes a **controlled adversarial evaluation**:

- The system is tested against deliberately crafted package variants that attempt to evade detection
- These variants preserve high-level behavior patterns but alter code structure or representation
- The goal is to evaluate robustness, not to develop real-world exploits

This component helps identify:
- Detection blind spots
- Trade-offs between sensitivity and false positives
- Opportunities to harden detection logic

All adversarial testing is performed exclusively within the simulated environment.

---

## Replication of Historical Incidents

The project attempts to replicate observable characteristics of documented PyPI supply-chain attacks, such as:

- Suspicious install-time behavior
- Obfuscated code introduced in later versions
- Campaign-like similarities across multiple packages

Rather than reproducing malware, the project recreates **detection-relevant signals** described in public incident reports and evaluates whether the system would have flagged them.

---

## Evaluation Methodology

The system is evaluated based on:

- Detection accuracy (true positives vs false positives)
- Detection latency
- Explainability and analyst usability
- Robustness under adversarial transformations
- Ability to identify campaign-level activity

Datasets include:
- Publicly documented malicious PyPI packages
- Benign popular packages used as a control group
- Synthetic test cases generated in the simulated environment

---

## Ethical Considerations

- No execution of untrusted code
- No interaction with real registries or live targets
- No development or distribution of functional malware
- All experiments are static, isolated, and research-focused

---

## Expected Outcome

The project produces:
- A working prototype for monitoring and analyzing PyPI packages
- A comparative evaluation of detection techniques
- Insights into the effectiveness of version-aware static analysis
- A reproducible experimental framework for future research

The primary contribution is analytical and evaluative, not operational exploitation.

---

## Summary

This project treats software supply-chain security as a detection and analysis problem rather than an exploitation challenge. By combining static analysis, version-differential techniques, and controlled adversarial testing, it aims to better understand how and when malicious code enters trusted ecosystems, and how early such activity can realistically be detected.

