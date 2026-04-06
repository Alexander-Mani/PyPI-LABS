<!-- source_file: PyPI-SCADA-II-MAIN-Prime!-4.pdf -->
<!-- source_sha256: 07224af524c27202fe2fbe3a54dc79e4fcfa275f25175a79f46c2095c46ae129 -->
<!-- extracted_utc: 2026-04-06T17:50:29Z -->
<!-- extractor: pdftotext 26.03.0 (-layout, UTF-8) -->

## Page 1

March 2026

PyPI-SCADA:
Cybersecurity Research
Project
Python Package
Index Supply Chain
Attack Detection
Analysis
Student:
Alexander Máni Einarsson
Project Supervisor:
Dr. Jacky Mallett
Examiner:
Kristrún Lilja Júlíusdóttir

## Page 2

                   Supply Chain              Retail &

                     Example
Farms
                                           Production
        Tractors                  Trucks

                      Warehouse

## Page 3

Developers                                Production
             Twine & CI/CD          pip

                             PyPI

## Page 4

              Python Package Index Today
          8 Million+   1 Million+   740 Thousand+    103 Billion+
          Releases     PyPI Users      Projects       Packages
                                                    Downloaded
                                                     Last Month

USED BY

## Page 5

                      Fruit                Retail &

                   Poisoning
Farms
                                         Production
        Tractors                Trucks

                    Warehouse

## Page 6

           Fruit Poisoning
           An attacker compromises a maintainer
Meaning:   account and pushes a malicious update
           through normal release channels

           In Dataset:
            num2words: Forward proxy phishing intercepted MFA tokens
            in real time, targetting __init__.py
            ultralytics: GitHub Actions script exploited via malicious PR,
            targeting the release artifact, poisoning the published wheel

## Page 7

                         Typo & Combo              Retail &
Malicious Actor
                  Tractors
                           Squatting             Production
                                        Trucks

                          Warehouse
  Farms

## Page 8

   Typo & Combo Squatting
           Attackers register package names with
Meaning:   slight spelling variations of popular
           libraries

       In Dataset:
       • colourama (targeting colorama): Base64-encoded clipboard
       hijacker that swapped cryptocurrency wallet addresses
       • nmap-python (targeting python-nmap): Combosquatting,
       reversed word order, embedded trojan
       • termncolor (targeting termcolor): multi-stage execution

## Page 9

                               Dependency                      Retail &
Malicious Actor
                      Tractors
                                Confusion                    Production
                                                    Trucks

  Farms

                                        Warehouse

    Public        Private   Malicious

## Page 10

    Dependency Confusion
           pip queries both private and public
Meaning:   registries simultaneously, installs higher
           version number, regardless of source

       In Dataset:
       torchtriton: PyTorch maintained an internal dependency for
       nightly builds. Attacker registered torchtriton v2.0.0 on public
       PyPI with an artificially high version. Targeting SSH keys
       totallysafe: Early proof-of-concept showing arbitrary code
       execution via setup script

## Page 11

Current Landscape
of Detection
Getting attacked is part of the current
security architecture.
   PyPI operates on a post incident and
   reporting basis.
   Reliance on community identification
   Although PyPI has hardened its defenses
   with preventive measures such as:
       Mandatory MFA
       Freezing domain credentials on
       domain expiry
       Some static analyzes
       Trust chains

## Page 12

What Will PyPI-SCADA Do?
      The project isn’t promising a silver bullet. It’s building the
                    scale to work on the problem.

                               HOW:
 A high-fidelity laboratory benchmark of SAST vs. Large Language
                              Models.
Benchmarking with real benign updates and real supply chain attack
  payloads with the support of the Backstabbers knife collection

## Page 13

Evaluation Methodology
  SAST        Bandit (AST linting) + Semgrep (pattern matching) +
Baseline:     heuristic pre-filter

              Gemini 3.1 Pro, GPT-5.4, Claude Opus 4.6, Llama 4
LLM Single
              Maverick, Mistral 3, DeepSeek-V3.2. Tested across three
 Prompt:      prompt strategies: zero-shot, few-shot, and role-based

              Claude Code and Codex, multi step autonomous
Agentic
              analysis, test the usage of agentic AI architecture in
Pipeline:     analysis.

             All three pipelines receive the same input

## Page 14

Malicious Sample Set

## Page 15

                         Design Pivot
            OLD (Differential Analysis)       → NEW (Entry-Point Scanning)
        Why pivot:                               What was pivoted to:
OLD approach: comparing version N to            NEW approach entry point focus:
version N+1:                                      Extracts setup.py, __init__.py,
   Fails for typosquatting (no previous           pyproject.toml + their imports
   version exists)                                Works for ALL attack vectors regardless of
   Fails for dependency confusion                 version history
   (malicious from v1)                            Heuristic pre-filter: base64 blobs, network
   Vulnerable to version dilution: attacker       imports, exec/eval calls, bundled binaries
   publishes clean v2.1 after malicious
   v2.0, malware becomes invisible to
   future diffs

## Page 16

Project Timeline: Completed
           Phase I                                      Phase II
Orientation (Jan 12–25)                    Simulator and Storage (Feb 16–Mar 1)
 • Infrastructure setup                        PEP 503 compliant repository simulator
 • Attack vector research, SilentSync,         Metadata storage and database layer
typosquatting, related threats             Diffing Engine(PIVOTED)
 • Tooling and technology selection            Logic for extracting and analyzing
Architectural Design (Jan 26–Feb 8)            package version changes
 • System architecture for simulator and   Sample curation(Mar 2 - Mar 9)
analyzer                                       Benign
 • Formal risk analysis                        Malicious samples across different
Status Meeting 1 (Feb 9–15)                    attack vectors
 • Initial presentation                    Status Meeting 2 (Mar 18)
 • Project scope and plan validation           Technical prototype Preview

## Page 17

Project Timeline: Phase 3 of 4
  Dataset Finalization (Mar 18– Mar 21)
     Finalize selection of samples
  Analyzer Finalization (Mar 22– Apr 5)
     Fully develop and deploy the analyzer
  Pipeline Integration (Apr 6–12)
     Align analyzer to the pivot
     Integration of SAST tools, Bandit and Semgrep
     LLM APIs, Gemini and GPT, with custom prompt engineering
  Execution Period (Apr 13–26)
     Automated benchmarking during university exam window

## Page 18

Project Timeline: Phase 4 of 4
  Evaluation (Apr 27–May 3)
     Thesis Finalization
     Status Meeting 3, dress rehearsal
     Detection rate vs false positive analysis

  Final Documentation (May 4–17)
     Conclusions and discussion
     Code polishing and Skemman submission

  Final Presentation (May 18–22)
     Public defense
     Project wrap-up

## Page 19

Risk
Assessment

## Page 20

Design of PyPI-SCADA

    Injector                      Simulator                         Detection-Analyzer
    Grabs samples and adds them   Basic laboratory environment of   Loads multiples detection
    to the sim via pip/twine      the python package index          components, package data based
                                                                    on heuristic and benchmarks

## Page 21

PyPI Injector

## Page 22

PyPI
Simulator

## Page 23

PyPI
Analyzer

## Page 24

Worked Hours

## Page 25

                    Prototype Demo
Flask simulator running
   on localhost:8080

                          Packages uploaded
                               via twine:

                               Listed in
                             Simple Index

## Page 26

               Prototype Demo
                        Version list for
                          package

                         JSON version API
                        returns structured
                            metadata

 pip install resolves
packages from local
  server correctly.

## Page 27

Results and
Future Works
 Results will be used to generate
 statistical data, that will be displayed
 in the report
 Future work could pertain to how to
 secure, audit and maintain a useful
 analysis suite as a sidecar to the PyPI
 eco system
     Given a lot of wealthy stakeholders
     are connected to this supply chain

## Page 28

      Schedule Status
         Phase I (Research & Design): Complete
  Phase II (Simulator & Entry-Point Engine): Complete
                                   →
 Phase III (SAST & LLM Integration):  Starting this week
Phase IV (Benchmarking & Thesis): Scheduled Apr–May

           146 of 380 hours logged (38%)
                 9 weeks remaining
          234 hours remaining fits schedule

                  Project is on track.

## Page 29

         Feedback & Questions
  Supply chain           Detection         Timeline &     Risk assessment
    analogy             landscape           schedule

                                             System       Results & future
                     Project scope and
   PyPI at scale                          architecture         work
                       methodology

                                          Worked hours
  Attack vectors       Design pivot
(Account Takeover,
  Typosquatting,
   Dependency
    Confusion)           Dataset         Prototype demo

## Page 30

                             References
I. Market Scale & Industrial Adoption
    PyPI Stats: Real-time download metrics for over 730,000 packages.
    TheirStack: Corporate adoption profiles identifying industry-wide reliance on pip.
    PyPI.org: The central repository for current project metadata and releases.

II. Threat Analysis & Case Studies
     The Hacker News (2026): Analysis of the dYdX ecosystem compromise.
     Checkmarx / Unit 42: Technical deep dives into the Colorama campaign and malicious
     packages.
     Ultralytics Attack: Forensic analysis of weaponized high-traffic computer vision libraries.

III. Platform Defense & Registry Mitigation
      PyPI Security Blog: Official reports on phishing attacks and "domain resurrection" exploits.
      Registry Policy Updates: Documentation on mitigating domain abuse and credential theft.
