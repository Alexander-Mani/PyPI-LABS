<!-- source_file: RU_BS_COMPSCI_STATUS_MEETING_3-2.pdf -->
<!-- source_sha256: 93af645e77f555601bf7b3643c5e6ac8fbf2c63139863e33ef132cb901e81c06 -->
<!-- extracted_utc: 2026-04-06T17:37:53Z -->
<!-- extractor: pdftotext 26.03.0 (-layout, UTF-8) -->

## Page 1

                   Reykjavik University

                      PyPI-SCADA
    Python Package Index: Supply Chain Attack Detection Analysis
                        Situation Report II

                                 Author:
              Alexander Máni Einarsson - alexanderme22@ru.is

                         Project Supervisor
               Dr. Jacqueline Clare Mallett - jacky@ru.is

                                  Examiner:
Kristrún Lilja Júlíusdóttir - kristrun.lilja.juliusdottir@orkuveitan.is

                             April 6, 2026

## Page 2

© 2026 Reykjavik University

## Page 3

Table of Contents

1 Project Description                                                                              1
  1.1 Background . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .       1
  1.2 Goals . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .    1
  1.3 Tech Stack . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .     1

2 Dataset and Threat Models                                                                        2
  2.1 Dependency Confusion . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .         2
  2.2 Account Takeover (Fruit Poisoning) . . . . . . . . . . . . . . . . . . . . . . . . .         3
  2.3 Typosquatting and Combosquatting . . . . . . . . . . . . . . . . . . . . . . . . .           3
  2.4 Multi-Stage Execution Architecture . . . . . . . . . . . . . . . . . . . . . . . . .         3
  2.5 Benign Controls . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .      3
  2.6 Dataset Summary . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .        4

3 Methodology and Evaluation                                                                       4
  3.1 Input Strategy: From Differential Analysis to Entry-Point Scanning . . . . . . .             5
      3.1.1 Why Differential Analysis Falls Short . . . . . . . . . . . . . . . . . . . .          5
      3.1.2 Entry-Point Focused Scanning . . . . . . . . . . . . . . . . . . . . . . . .           6
      3.1.3 Heuristic Pre-Filtering . . . . . . . . . . . . . . . . . . . . . . . . . . . .        6
      3.1.4 Metadata Signals . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .         7
  3.2 Traditional Static Analysis Baseline . . . . . . . . . . . . . . . . . . . . . . . . .       7
  3.3 LLM Evaluation Strategy . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .          7
      3.3.1 Prompt Strategies . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .        7
      3.3.2 Scoring Rubric . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .         8
      3.3.3 False Positive Tracking . . . . . . . . . . . . . . . . . . . . . . . . . . . .        8
  3.4 Agentic Pipeline Testing . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .       9
  3.5 Cost and Performance Metrics . . . . . . . . . . . . . . . . . . . . . . . . . . . .        10

4 Risk Analysis                                                                                   11

5 Requirements and Design                                                                         13
  5.1 System Architecture . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .       13
      5.1.1 PyPI Injector . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .       13
      5.1.2 PyPI Basic Simulator . . . . . . . . . . . . . . . . . . . . . . . . . . . . .        14
      5.1.3 PyPI Detection Analyzer . . . . . . . . . . . . . . . . . . . . . . . . . . .         15
  5.2 Simulator Prototype . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .       16

6 Progress and Time Tracking                                                                      18
  6.1 Completed Tasks . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .       18
  6.2 Worked Hours . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .      20

## Page 4

1     Project Description

1.1    Background
The software supply chain is a growing vector for cyberattacks. As the central repository for the
Python ecosystem, the Python Package Index (PyPI) manages over 730,000 packages and serves
billions of downloads annually [1]. Recent security incidents, including Department of Justice
subpoenas regarding PyPI user data [2], highlight the platform’s role as a high-value target
for state-sponsored and criminal actors. Vulnerabilities in dependency chains can propagate
downstream, affecting enterprises that depend on open-source components.
    This project, conducted at the Frostbyte Cybersecurity Research Laboratory at Reyk-
javik University, evaluates the efficacy of Large Language Models (LLMs) compared to tradi-
tional Static Application Security Testing (SAST) tools in detecting malicious code uploads.

1.2    Goals
The project aims to construct a secure automated pipeline to:

    • Simulate Repository Environments: Operate a PEP 503 compliant mirror to host
      and test malicious packages safely.

    • Extract and Analyze Entry Points: Parse package archives to isolate the files where
      supply chain malware most commonly executes (setup.py, __init__.py, and their direct
      imports), applying heuristic pre-filtering before detection.

    • Benchmark Detection Efficacy: Compare LLMs (e.g., Gemini, GPT) and agentic cod-
      ing tools (Claude Code, Codex) against SAST tools (Bandit, Semgrep) across four attack
      vectors: dependency confusion (torchtriton), account takeover (num2words, ultralytics),
      typosquatting (colourama, termncolor), and multi-stage execution (secmeasure, sisaws).

1.3    Tech Stack
The system is developed using a Python-centric architecture designed for modularity and safety.

    • Core Language: Python 3.9+ for all logic components.

    • Web Framework: Flask (Python) to serve the PEP 503 compliant simulator index.

    • Automation: Bash/Shell scripts utilizing twine and pip for package injection and veri-
      fication.

    • Data Management: SQLite (sqlite3) for metadata storage and result persistence.

    • Configuration: YAML for prompt templates and standardized detection settings.

                                               1

## Page 5

The system utilizes a multi-layered detection architecture as shown in Table 1.

                           Table 1: Detection Methodology Tech Stack

                                                                         Open Source LLMs
    Category        Traditional / Baseline    Proprietary LLMs
                                                                         (via Together AI)
                                              OpenAI GPT-5.4
                                                                          Qwen3.5-397B-A17B
    Frontier        Bandit + Semgrep +        Anthropic Claude Opus 4.6
                                                                          DeepSeek-V3.2-Exp
                    Heuristic Static Checks   Google Gemini 3.1 Pro Preview

                                              OpenAI GPT-5.4 Mini         Meta Llama 3.3 70B
    Medium          Bandit + Semgrep +        Anthropic Claude Sonnet 4.6 Instruct Turbo
                    Heuristic Static Checks   Google Gemini 3 Flash Preview
                                                                          Mistral Small 3

                                              OpenAI GPT-5.4 Nano
    Budget / Eco-   Bandit + Semgrep +        Anthropic Claude Haiku 4.5 Qwen3.5 9B
    nomical         Heuristic Static Checks   Google Gemini 3.1 Flash-Lite Preview

2       Dataset and Threat Models
The PyPI-SCADA project evaluates code against a set of malicious Python packages and benign
controls. Selected samples represent each supply chain attack category, with priority given
to recent incidents that had documented impact on the ecosystem. Older historical samples
are supplemented from the Backstabber’s Knife Collection compiled by Dr. Marc Ohm at
the University of Bonn. His work categorizing open-source supply chain attacks provided the
groundwork for this research [3]. The simulation environment hosts these packages to safely
observe pipeline behavior.

2.1      Dependency Confusion
Dependency confusion exploits how package managers resolve versions. Many organizations host
internal packages on private servers and tell developers to install them with specific configuration
flags. The pip package manager queries both private and public registries at the same time and
installs whichever version has the highest number, regardless of where it came from.
    Attackers take advantage of this by registering the names of known internal packages on
public PyPI with artificially high version numbers. The torchtriton attack shows this vector
clearly. PyTorch maintained an internal dependency named torchtriton for its nightly builds.
An attacker registered torchtriton version 2.0.0+0d7e753227 on the public registry. Automated
build systems silently pulled the malicious package instead of the private one. Once installed,
the payload ran an ELF binary that sent system data and SSH keys to an external server via
DNS tunneling.
    The totallysafe package serves as an early proof of concept for this vector [3]. Synthetic
benign stubs represent the private registry state for these samples.

                                                 2

## Page 6

2.2    Account Takeover (Fruit Poisoning)
Account takeover attacks target real, trusted packages. Attackers gain access to maintainer
accounts and push malicious updates through normal release channels. Downstream projects
automatically pull these updates because of existing trust in the package.
    The num2words incident involved a forward proxy phishing attack. The proxy server in-
tercepted maintainer multi-factor authentication tokens in real time. Attackers then uploaded
versions 0.5.15 and 0.5.16 directly to PyPI. The modified package init script silently loaded a
malicious dynamic link library.
    The ultralytics incident used a GitHub Actions script injection vulnerability rather than
stolen credentials. Attackers submitted a malicious pull request to run code in the base reposi-
tory, injecting the XMRig cryptominer into the release artifact during the build. The source code
commit history stayed clean while the published PyPI wheel contained the injected payload.

2.3    Typosquatting and Combosquatting
Typosquatting relies on developer mistakes. Attackers register package names with slight spelling
variations of popular libraries [4]. These packages have no legitimate version history and run
their payloads immediately on install.
   The colourama package targeted the colorama text styling library. It contained a base64-
encoded payload that monitored the system clipboard and swapped copied cryptocurrency wallet
addresses with attacker-controlled ones. The nmap-python package targeted the python-nmap
wrapper through combosquatting, reversing the word order to create a believable alternative
name. Both samples come from the Backstabber’s Knife Collection [3].

2.4    Multi-Stage Execution Architecture
Modern PyPI malware often uses multi-stage setups. The uploaded package contains only a
small stager script that downloads the main payload from an external command and control
server. This keeps the initial package small enough to avoid static analysis tools. One sample
from each of the previous categories that uses a multi-stage execution chain is included to cover
complex payloads.
    The secmeasure package posed as a string cleaning utility. Its init script ran a hex-encoded
network request that downloaded the SilentSync remote access trojan from GitHub Codespaces.
The sisaws package delivered the same payload while pretending to be an Argentine national
health information system API. The termncolor package combined multi-stage execution with
typosquatting. It quietly imported a secondary rogue package named colorinal that started a
DLL side-loading attack to gain persistence on the system.

2.5    Benign Controls
The dataset also requires clean packages to set baseline behavior and measure false positive rates.
The selection criteria are defined: well-known packages like requests serve as large-scale controls,
and smaller single-purpose utilities match the code size of typical typosquatting targets. These
benign packages go through the same entry-point extraction and scanning steps as the malicious

                                                 3

## Page 7

ones. The final benign package list is scheduled for the beginning of Phase III alongside dataset
preparation, as the design pivot from differential analysis to entry-point scanning changed what
properties the benign samples need to have.

2.6          Dataset Summary
Table 2 lists the malicious packages used in the simulation environment and maps them to their
attack vectors.

                            Table 2: PyPI-SCADA Malicious Sample Set

    Package Name   Attack Vector          Legitimate Target      Payload Mechanism

    torchtriton    Dependency Confusion   Internal PyTorch lib   ELF binary execution, DNS tunneling exfiltration

    totallysafe    Dependency Confusion   None                   Setup script arbitrary code execution

    num2words      Account Takeover       num2words              Obfuscated DLL loader injected via phishing

    ultralytics    Account Takeover       ultralytics            XMRig cryptominer injected via CI/CD exploit

    secmeasure     Phising/Fabrication    None                   Hex-encoded stager downloading SilentSync RAT

    termncolor     Typosquatting          termcolor              Rogue package import triggering DLL side-loading

    colourama      Typosquatting          colorama               Base64 payload for clipboard crypto address hijacking

    sisaws         Combosquatting         sisa                   Stager mimicking health API to drop SilentSync RAT

    nmap-python    Combosquatting         python-nmap            Embedded trojan targeting network scanner wrapper

   Table 3 lists the benign control packages used to establish standard behavioral profiles and
computational baselines within the evaluation framework.

3        Methodology and Evaluation
The evaluation framework tests detection across three distinct pipelines: traditional static anal-
ysis, single-prompt LLM analysis, and agentic LLM analysis. Each pipeline receives the same
input: the entry-point source files extracted from each package as described in Section 3.1. This
shared input ensures fair comparison across all detection methods. The system records detection
accuracy, false positive rates, execution time, and cost for every run.
    The evaluation uses a focused sample set of nine malicious packages and a small number of
benign controls rather than a large-scale dataset. This scope fits the proof-of-concept nature of
the project. Results indicate observable trends in detection behavior rather than statistically
generalizable conclusions.

                                                        4

## Page 8

                            Table 3: PyPI-SCADA Benign Control Sample Set

  Package Name         Primary Function                          Control Value

  boto3                Amazon Web Services integration SDK       Tests baseline AST processing speed and cloud API heuristics

  urllib3              Thread-safe HTTP client                   Tests network socket monitoring and connection pool false positives

  requests             High-level HTTP library                   Establishes standard baseline for legitimate network calls

  certifi              SSL certificate parsing                   Tests file I/O operations and cryptographic validation routines

  botocore             Low-level AWS engine                      Tests JSON parsing and deep structural execution paths

  setuptools           Package configuration utility             Tests baseline execution safety for complex installation hooks

  packaging            Version resolution tool                   Tests string manipulation and regular expression safety

  idna                 Domain name encoding                      Tests internationalized data processing strings

  charset-normalizer   Text encoding prediction                  Tests deep file inspection and byte-level analysis

  python-dateutil      Datetime parsing                          Tests standard utility module imports and system clock calls

3.1         Input Strategy: From Differential Analysis to Entry-Point Scan-
            ning
An early design of this project relied on a differential analysis engine that compared consecutive
package versions and fed only the changed code to the detection pipelines. During development,
fundamental limitations with this approach were identified, leading to an entry-point focused
scanning strategy instead. This subsection documents the reasoning behind that decision.

3.1.1          Why Differential Analysis Falls Short
Differential analysis assumes a clean previous version exists to compare against. This holds
for account takeover attacks where a trusted package receives a malicious update. It does not
hold for typosquatting or dependency confusion, where the package is malicious from its first
version and no legitimate baseline exists. These attack vectors make up a significant portion of
real-world PyPI threats [3].
    A deeper problem emerges even for attacks that do involve version updates. An attacker
who injects malware in version 2.0 can publish version 2.1 with only cosmetic changes such
as linting fixes or docstring updates. The diff engine would see only the harmless changes
in 2.1. The malware from 2.0 is now part of the established codebase and invisible to any
future diff. If a monitoring system misses the exact version where injection occurs, the malware
persists undetected through all later releases. Differential analysis is therefore limited to catching
malware at the precise moment of injection, a constraint that makes it brittle as a standalone
detection strategy.

                                                             5

## Page 9

3.1.2    Entry-Point Focused Scanning
Instead of diffing between versions, the pipeline scans the files where PyPI malware most com-
monly executes. Research on real-world supply chain attacks consistently identifies a small set
of entry points that attackers target. FortiGuard Labs reported that a majority of confirmed
malicious PyPI packages in Q2 2025 used install scripts as their execution vector, and most had
low file counts designed to keep the package footprint small [5]. Datadog’s GuardDog tool uses
the same insight, scanning setup.py for command overwrites, __init__.py for dynamic code
execution, and package metadata for typosquatting signals [6].
    The pipeline follows this pattern. For each package, the system extracts and sends the
following files to the detection pipelines:

  1. setup.py / pyproject.toml: The build and install configuration. Attackers commonly
     overwrite install commands or embed code execution here.

  2. __init__.py: The package initialization script. Malware that runs on import (rather
     than on install) typically lives here.

  3. Any file imported by the above: If the init script imports a secondary module, that
     module is included. This covers multi-stage chains like termncolor importing colorinal.

   This approach reduces the input to a small, high-signal set of files rather than the full package
source or a version diff. It works regardless of whether the package has version history, handling
typosquatting and dependency confusion samples the same way as account takeover samples.

3.1.3    Heuristic Pre-Filtering
Before sending code to the LLM pipelines, the system runs a lightweight heuristic pass to flag
obvious indicators. These heuristics are modeled after the patterns identified by GuardDog [6]
and the behavioral signals observed by FortiGuard Labs [5]:

  1. Presence of base64-encoded or hex-encoded strings in entry-point files.

  2. Network imports (urllib, requests, socket, http) in setup.py or __init__.py.

  3. Use of exec(), eval(), or subprocess calls in install hooks.

  4. Obfuscated variable names or unusually compressed code.

  5. Binary files (.so, .dll, .exe) bundled inside a pure-Python package.

   These checks are not meant to be a detection system on their own. They run in milliseconds
and serve as a triage layer. Packages that trigger no heuristics still proceed to the full LLM
and SAST analysis. The heuristic flags are logged alongside the detection results to measure
whether pre-filtering correlates with true positives.

                                                 6

## Page 10

3.1.4    Metadata Signals
Package metadata provides detection signals that do not require reading any code at all. At-
tributes like account age, time between account creation and first upload, version number pat-
terns, and presence or absence of a linked source repository all carry information about package
legitimacy [6]. PyPI itself introduced automatic typosquatting detection during project creation
in 2025 [7].
    This project does not implement a metadata-based detector. However, metadata attributes
are recorded and reported for each sample in the dataset to support future work that combines
code-level and metadata-level signals. The potential of metadata analysis as a complementary
detection layer is discussed in the final thesis.

3.2     Traditional Static Analysis Baseline
The first pipeline runs standard static application security testing (SAST) tools against each
package’s extracted entry-point files. Bandit and Semgrep were selected as the baseline because
they represent the most widely adopted open-source options for Python security scanning. Ban-
dit operates as an AST-based linter with 68 built-in security checks for Python [8]. Semgrep
uses pattern matching rules and provides access to a community registry with over a thousand
rules across multiple languages [8]. Together they cover the detection strategies most commonly
available to PyPI maintainers today.
    The system logs every finding from both tools, recording true positives, false positives, false
negatives, and execution time. These results set the performance floor that the LLM pipelines
must beat to justify their added complexity and cost. False positive behavior from the SAST
tools is tracked using the same framework described in Section 3.3.3.

3.3     LLM Evaluation Strategy
The second pipeline sends the same extracted entry-point files to large language models with
detection prompts. Each model receives identical instructions describing the task, the expected
output format, and the scoring criteria. The evaluation covers both proprietary models (Gemini,
GPT, Claude) and open-source alternatives hosted via Groq (Llama 3, Mistral, DeepSeek-V3)
as listed in Table 1.

3.3.1    Prompt Strategies
Recent work shows that prompt design has a significant effect on LLM detection performance.
Ibiyo et al. found that few-shot prompting reached 97% accuracy on malicious PyPI code,
substantially outperforming zero-shot and RAG-based approaches [9]. Ryan et al. observed
that temperature settings and prompt structure both influenced detection rates across 13 tested
models [10]. To account for this sensitivity, three prompt strategies are tested per model:
  1. Zero-shot: The model receives only the extracted source files and a description of the
     task with no examples.

  2. Few-shot: The model receives two annotated examples (one malicious, one benign) before
     the target package files.

                                                7

## Page 11

  3. Role-based: The model receives a system prompt framing it as a security analyst, com-
     bined with the zero-shot task description.

    All prompt templates are versioned in YAML configuration files alongside the model param-
eters used for each run. This ensures that any result can be reproduced by replaying the same
configuration against the same package version.

3.3.2     Scoring Rubric
Each model response is scored against a fixed rubric applied manually by the author. Table
4 defines the scoring criteria for malicious samples, and Table 5 defines the criteria for benign
samples.

                  Table 4: Scoring Rubric: Malicious Samples (max 4 points)

   Criterion                    Points         Description

   Correct detection                2          Model flags the sample as malicious.

   Vector identification            2          Model correctly names the attack category
                                               (e.g., typosquatting, dependency confusion).

   Partial detection                1          Model flags something suspicious but
                                               misidentifies the category or gives a vague
                                               explanation.

   Miss                             0          Model fails to flag the malicious sample en-
                                               tirely.

3.3.3     False Positive Tracking
False positives are a central problem in both SAST and LLM-based detection. Traditional
tools like Bandit routinely produce false positive rates between 15% and 30% [11], and LLMs
introduce their own failure mode: hallucinated threats where the model fabricates a plausible
but nonexistent vulnerability in clean code. Ryan et al. found a significant gap between how
well LLMs detect malicious packages at a high level versus how accurately they identify specific
indicators, meaning models often flag the right package for the wrong reason [10]. A detector
that catches every malicious package but also flags half the benign ones is not useful in practice.
    False positives are tracked separately from missed detections. Every benign sample that a
tool or model flags as malicious is recorded with the stated reason. For LLMs, the system addi-
tionally logs whether the model invented a threat that does not exist in the code (a hallucinated

                                                8

## Page 12

                    Table 5: Scoring Rubric: Benign Samples (max 2 points)

   Criterion                  Points          Description

   Correct clearance              2           Model correctly identifies the sample as safe.

   Minor false flag               1           Model raises a low-confidence warning but
                                              does not classify the sample as malicious.

   False positive                 0           Model incorrectly classifies a benign sample
                                              as malicious.

positive) or whether it misread a legitimate pattern as suspicious (a misclassified positive). This
distinction matters because hallucinated positives suggest a reasoning failure, while misclassified
positives suggest a calibration issue that better prompting might fix.
    Scoring is performed by the author alone, which is noted as a limitation since there is no
second rater to measure inter-rater agreement. To reduce subjectivity, the rubric criteria are
binary where possible: either the model named the correct vector or it did not, and either the
benign sample was flagged or it was not.

3.4    Agentic Pipeline Testing
The third pipeline extends the evaluation to agentic architectures. Instead of a single prompt
and response, this pipeline gives coding agents the same base instructions and extracted entry-
point files, then lets them work autonomously. The evaluation covers tools like Claude Code and
Codex, which operate as terminal-based agents that can read files, run commands, and iterate
on their analysis across multiple steps [12].
    This pipeline tests whether the agentic loop (read, reason, act, iterate) catches things that
a single-pass analysis misses. The agents have an inherent structural advantage over the single-
prompt models because they can use tools, inspect files from multiple angles, and refine their
reasoning across turns. This is not treated as a controlled comparison against the single-
prompt pipeline. Instead, it addresses a separate question: can off-the-shelf coding agents
match purpose-built research systems when given appropriate instructions rather than custom
architectures?
    This question is motivated by recent findings. The CHASE framework used a custom hierar-
chical agent architecture to achieve 98.4% recall with a 0.08% false positive rate on 3,000 PyPI
packages [13]. The LAMPS system showed that coordinated multi-agent detection outperformed
single LLM evaluation on real-world datasets [14]. Both systems required significant engineer-
ing effort to build. The experiment tests whether commercially available agents can approach
similar results with minimal setup.

                                                9

## Page 13

   The agents receive the same base instructions and scoring rubric as the single-prompt models.
Their responses are scored using the same rubric in Table 4.

3.5    Cost and Performance Metrics
Any practical deployment of LLM-based detection must weigh detection gains against resource
usage. The testing engine records two cost dimensions for every run:

  1. Time: Wall-clock execution time from input submission to final output, measured in
     seconds. For SAST tools this is the scan duration. For LLMs this includes API latency.
     For agents this covers the full session from first call to final response.

  2. Money: For LLM and agent pipelines, input and output token counts are logged per API
     call and converted to dollar costs using published per-token pricing from each provider at
     the time of testing. SAST tools run locally and have no per-scan monetary cost, so their
     dollar figure is zero.

   For the agentic pipeline, costs are higher because agents make multiple API calls per analysis.
Total tokens consumed across all calls in each session are tracked to capture the full expense.
This follows the general pattern observed in agentic security analysis, where systems trade higher
compute costs for improved accuracy and reasoning depth [13].
   Cost and time are presented alongside detection results so that each method can be evaluated
on the tradeoff between how much it catches and what it costs to run. If an LLM catches more
malware but costs significantly more per package, that tradeoff matters for anyone considering
deployment at repository scale.

                                               10

## Page 14

4    Risk Analysis
Risk is quantified as Risk = P robability × Impact. Here 1 is the minimum and 5 is the highest
for probability and impact, giving a risk factor between 1 and 25.

    Risk                      Prob.        Imp.         Factor        Mitigation Strat-
                                                                      egy

    Malware Execu-               1           5             5          Use of      isolated
    tion                                                              VMs.

    Development En-              1           5             5          Use of fixed ver-
    vironment Weak                                                    sions of python
    to Supply Chain                                                   packages that are
    Attacks                                                           deemed safe.

    Scope Creep                  3           4            12          Refactor tasks to fit
                                                                      a laboratory proof
                                                                      of concept.

    LLM API Costs                4           2             8          Utilization       of
                                                                      project funding and
                                                                      Groq-hosted open
                                                                      models.

    False   Positives            3           4            12          Benchmark against
    Undermining                                                       curated      benign
    Evaluation   Va-                                                  datasets and man-
    lidity                                                            ually validate edge
                                                                      cases.

    Reproducibility              2           4             8          Store       prompts,
    Risk of Experi-                                                   configurations, and
    mental Results                                                    hashes of analyzed
                                                                      packages to ensure
                                                                      replayability.

                                             11

## Page 15

   Design     Pivot             2            3            6          Document reason-
   Mid-Project                                                       ing for changes (see
                                                                     Section 3.1). Keep
                                                                     original code for ref-
                                                                     erence.

Risk Diary (Sitrep 2): The differential analysis approach turned out to be unsuitable for
typosquatting and dependency confusion samples. It was also vulnerable to version dilution
attacks as described in Section 3.1. This led to a design pivot toward entry-point focused
scanning. The scope creep risk (factor 12) was partially triggered by this change but stayed
contained by keeping the project scoped as a proof of concept.

                                            12

## Page 16

5     Requirements and Design

5.1     System Architecture
5.1.1     PyPI Injector
The Injector automates the upload of test data. It includes:

    • Controller: A shell script utilizing twine to target the simulation server.

    • sql.py: A SQL API abstraction for serving samples from the Sample Dataset (e.g.,
      SilentSync, Colorama).

    • YAML Config: Defines standard configurations and prompt templates for different de-
      tection methods.

                                               13

## Page 17

5.1.2   PyPI Basic Simulator
A minimal PEP 503 compliant environment:

   • main.py: A Flask-based application serving the PyPI simulation index.

   • simple.py: Implements the /simple/<project>/ endpoints for pip compatibility.

   • SQL API: Stores metadata for simulated versions.

                                           14

## Page 18

5.1.3    PyPI Detection Analyzer
The core detection engine. An early design centered on a differential analysis module (diff.py)
that compared consecutive package versions. During development, this approach was found to
be unsuitable as documented in Section 3.1. The analyzer now operates on extracted entry-point
files rather than version diffs.
   • entry_extractor.py (Package Parser): Unpacks package archives from the simulator,
     locates setup.py, __init__.py, and pyproject.toml, and follows imports from these entry-
     point files to include secondary modules. This replaced the earlier diff-based parser.

   • heuristic_filter.py: Scans extracted files for base64/hex blobs, network imports in install
     hooks, exec/eval calls, and bundled binaries. Logs all flags alongside detection output.

   • detection_controller.py:          Orchestrates the StaticDetectorAdapter and
     LLMDetectorAdapter to invoke relevant APIs and tools (Gemini, GPT, Bandit,
     etc.). Each adapter receives the same extracted entry-point files and returns structured
     results to the controller.

   • Result DB: Persists RUN_IDS, detection verdicts, false positive classifications, token
     counts, and execution times for every run. Ground truth labels never enter the analyzer.
     The database stores test states as run identifiers for later evaluation against the scoring
     rubric described in Section 3.

                                              15

## Page 19

5.2    Simulator Prototype
The PyPI simulator is operational and accepts package uploads, serves a PEP 503 compliant
index, and supports installation via pip. The following screenshots show the current state of the
prototype.

               Starting the PyPI Simulator Flask application on localhost:8080.

         Uploading num2words and colorama wheel files to the simulator using twine.

        The Simple Index root page listing available packages (colorama, num2words).

      Package index page for colorama showing download links for uploaded wheel files.

                                               16

## Page 20

  JSON API response listing available versions (0.5.13, 0.5.14) for the num2words package.

        Installing num2words and colorama from the local simulator index using pip.

The simulator handles the full upload-to-install cycle. Packages uploaded via twine appear in
the Simple Index within seconds and install correctly through pip when pointed at the local
server. The version API endpoint returns structured JSON that the analyzer uses to determine
which versions to extract and scan.

                                             17

## Page 21

6     Progress and Time Tracking
The project fulfills the 12 ECTS requirement (approx. 300–360 man-hours).

      Phase          Focus                                                Planned (h)

      Phase 1        Lab Induction & Research                                  80

      Phase 2        Simulator & Entry-Point Engine Development                100

      Phase 3        SAST & LLM Adapter Integration                            100

      Phase 4        Benchmarking & Final Thesis                               100

      Total                                                                   380

Schedule Status: The project is on schedule. Phase I (research, design, setup) and Phase
II (simulator and engine development) are done. The simulator serves packages via PEP 503
endpoints and accepts uploads through twine. The detection analyzer has been redesigned from
diff-based to entry-point scanning as documented in Section 3.1. The methodology, dataset, and
scoring framework are fully defined. Phase III (SAST and LLM adapter integration) begins this
week. With 146 hours logged out of 380 planned, the remaining 234 hours fit the 9 weeks left
before final submission.

6.1   Completed Tasks
The following tasks have been completed across Phase I and Phase II.

                                             18

## Page 22

 Category        Task Description                                       Status

   Dataset       Dataset acquisition: Full access to the Backstab-     Completed
                 ber’s Knife Collection secured via Dr. Ohm (Uni-
                 versity of Bonn).

Infrastructure   Provisioned virtual machine on Frostbyte infras-      Completed
                 tructure.

    Tools        Initialized Git repository and Overleaf thesis        Completed
                 skeleton.

   Design        Architected           simulator–injector–analyzer     Completed
                 pipeline.

  Research       Finalized selection of LLM APIs and SAST tools.       Completed

Development      Implemented PyPI simulator core (Flask, PEP           Completed
                 503 endpoints, SQL metadata store).

Development      Implemented package injector with twine upload        Completed
                 and pip verification.

Development      Built pipeline controller for detection adapter or-   Completed
                 chestration.

   Design        Found diff engine limitations, redesigned ana-        Completed
                 lyzer to entry-point scanning.

   Thesis        Wrote dataset section with threat model descrip-      Completed
                 tions for all nine samples.

   Thesis        Wrote methodology section covering three              Completed
                 pipelines, scoring rubric, and FP tracking.

Presentation     Prepared and delivered Sitrep 1 presentation.         Completed
                                     19
                   Table 8: Finished Tasks and Milestones

## Page 23

6.2    Worked Hours
The following is copied from time warrior, a terminal based time utility

Wk Date        Day Tags                               Start      End    Time     Total
--- ---------- --- ------------------------------- -------- -------- ------- ---------
W3 2026-01-12 Mon final-project, lecture           15:30:00 16:30:00 1:00:00   1:00:00
W3 2026-01-17 Sat final-project, reading           12:00:00 16:00:00 4:00:00   4:00:00
W3 2026-01-18 Sun final-project, reading           15:00:00 18:30:00 3:30:00   3:30:00
W4 2026-01-19 Mon final-project, lecture           15:30:00 16:30:00 1:00:00   1:00:00
W4 2026-01-20 Tue final-project, planning          11:00:00 16:00:00 5:00:00   5:00:00
W4 2026-01-21 Wed final-project, meeting           16:00:00 16:30:00 0:30:00   0:30:00
W5 2026-01-26 Mon final-project, planning           8:30:00 12:00:00 3:30:00
                   final-project, lecture          15:30:00 16:30:00 1:00:00   4:30:00
W5 2026-01-30 Fri final-project, meeting           13:00:00 13:30:00 0:30:00   0:30:00
W6 2026-02-02 Mon final-project, lecture           15:30:00 16:30:00 1:00:00   1:00:00
W6 2026-02-03 Tue final-project                    16:18:18 22:28:17 6:09:59   6:09:59
W6 2026-02-04 Wed final-project                    14:37:41 0:00:00 9:22:19    9:22:19
W6 2026-02-05 Thu final-project, writing           20:00:00 23:00:00 3:00:00   3:00:00
W6 2026-02-07 Sat final-project, writing           19:00:00 22:00:00 3:00:00   3:00:00
W6 2026-02-08 Sun final-project, writing           17:00:00 22:30:00 5:30:00   5:30:00
W7 2026-02-09 Mon final-project, presentation      15:00:00 19:00:00 4:00:00   4:00:00
W7 2026-02-10 Tue final-project, presentation      11:00:00 17:00:00 6:00:00   6:00:00
W7 2026-02-11 Wed final-project, planning          16:30:00 20:00:00 3:30:00   3:30:00
W7 2026-02-13 Fri development, final-project       17:00:00 20:00:00 3:00:00   3:00:00
W7 2026-02-14 Sat development, final-project       10:00:00 19:00:00 9:00:00   9:00:00
W8 2026-02-16 Mon development, final-project       14:00:00 19:00:00 5:00:00   5:00:00
W8 2026-02-17 Tue final-project, planning          15:26:18 0:00:00 8:33:42    8:33:42
W8 2026-02-18 Wed development, final-project       10:00:00 14:00:00 4:00:00
                   development, final-project      16:30:00 20:00:00 3:30:00   7:30:00
W8 2026-02-20 Fri development, final-project       16:00:00 19:00:00 3:00:00   3:00:00
W8 2026-02-22 Sun final-project, testing           16:00:00 19:00:00 3:00:00   3:00:00
W9 2026-02-23 Mon final-project, planning          16:00:00 18:00:00 2:00:00   2:00:00
W9 2026-02-24 Tue final-project, reading, writing 10:00:00 17:00:00 7:00:00    7:00:00
W9 2026-02-25 Wed final-project, meeting           17:00:00 17:30:00 0:30:00   0:30:00
W10 2026-03-04 Wed final-project, reading           8:00:00 10:00:00 2:00:00
                   final-project, reading          17:00:00 19:00:00 2:00:00   4:00:00
W11 2026-03-09 Mon final-project, writing          15:00:00 20:00:00 5:00:00   5:00:00
W11 2026-03-10 Tue final-project, writing          10:00:00 17:00:00 7:00:00   7:00:00
W11 2026-03-11 Wed final-project, writing          16:40:00 19:00:00 2:20:00   2:20:00
W11 2026-03-13 Fri final-project, writing          10:00:00 13:00:00 3:00:00
                   final-project, writing          15:00:00 16:00:00 1:00:00
                   final-project, meeting          16:00:00 16:30:00 0:30:00   4:30:00
W11 2026-03-14 Sat final-project, writing          10:00:00 16:00:00 6:00:00   6:00:00

                                              20

## Page 24

W11 2026-03-15 Sun final-project, writing               13:00:00 20:00:00 7:00:00     7:00:00

                                                                         Total:    145:56:00

                         Table 9: Current Project Backlog

   ID       Phase        Description                                      Priority

   1        Phase I      Planning: Create product backlog and sprint      Medium
                         structure, (kanban, github projects).

   2        Phase I      Research: Deep dive into SilentSync, Col-        Medium
                         orama, and related tooling.

   3        Phase I      Thesis: Write project description and objec-     Medium
                         tives.

   4        Phase I      Thesis: Draft proper background section.         Medium

   7        Phase I      Presentation: Prepare slides for Sitrep 1.         High

   5        Phase I      Prototyping: Connecting Python to LLM            Medium
                         APIs.

   8        Phase I      Meeting: Attend Sitrep 1.                          High

   6        Phase I      Environment: Configure Python 3.9+ devel-          Low
                         opment environment.

   9        Phase I      Thesis: Complete first draft of introduction.    Medium

   10       Phase II     Development:    Implement PyPI simulator           High
                         core.

                                         21

## Page 25

                 Table 9: Current Project Backlog

ID    Phase      Description                                      Priority

11   Phase II    Development: Implement local storage/DB          Medium
                 for packages.

12   Phase II    Thesis: Document simulator architecture.           Low

13   Phase II    Development: Implement entry-point extrac-        High
                 tor and heuristic filter (replaced diff engine
                 after design pivot).

14   Phase II    Testing:   Unit test entry-point extraction      Medium
                 logic.

16   Phase II    Development: Build pipeline controller (or-       High
                 chestration).

17   Phase II    Development: Implement logging system.           Medium

18   Phase II    Presentation: Prepare slides for Sitrep 2.        High

19   Phase II    Meeting: Attend Sitrep 2 (demo prototype).        High

20   Phase II    Development: Refine simulator based on ini-      Medium
                 tial tests.

21   Phase II    Thesis: Update implementation chapter.           Medium

22   Phase III   Development: Integrate Bandit and Sem-            High
                 grep.

                                 22

## Page 26

                 Table 9: Current Project Backlog

ID    Phase      Description                                     Priority

23   Phase III   Configuration: Configure SAST rulesets for      Medium
                 supply chain.

24   Phase III   Development: Integrate Gemini/GPT APIs.          High

25   Phase III   AI: Develop system prompts for detection.        High

26   Phase III   Dataset:     Generate malicious       samples    High
                 (SilentSync, Colorama, etc.).

27   Phase III   Dataset: Finalize benign control package list    High
                 (deferred from Phase II due to input strategy
                 redesign).

28   Phase III   Thesis: Write experimental setup section.       Medium

29   Phase III   Integration: Connect Simulator → Entry-          High
                 Point Extractor → Analysis → DB.

30   Phase III   Testing: Perform dry run of full system.        Medium

31   Phase III   Execution: Run automated benchmarking           Medium
                 suite.

33   Phase III   Presentation: Draft final defense slides.        High

34   Phase IV    Meeting: Attend Sitrep 3 (Generalprufa).         High

35   Phase IV    Analysis: Compare detection rates AI vs          High
                 SAST.

                                 23

## Page 27

                Table 9: Current Project Backlog

ID    Phase     Description                                  Priority

36   Phase IV   Thesis: Write results and evaluation chap-   Medium
                ters.

37   Phase IV   Thesis: Write discussion and conclusion.      High

38   Phase IV   Documentation: Write README and user         Medium
                manuals.

39   Phase IV   Review: Full thesis read-through.            Medium

40   Phase IV   Code: Final polish and cleanup for submis-    High
                sion.

41   Phase IV   Submission: Submit thesis to Skemman.         High

42   Phase IV   Defense: Final public presentation.           High

                               24

## Page 28

References
 [1] “PyPI — The Python Package Index,” PyPI, Accessed: Feb. 8, 2026. [Online]. Available:
     https://pypi.org/.
 [2] “PyPI was subpoenaed,” PyPI, Accessed: Mar. 15, 2026. [Online]. Available:
     https://blog.pypi.org/posts/2023-05-24-pypi-was-subpoenaed/.
 [3] M. Ohm, H. Plate, A. Sykosch, and M. Meier, “Backstabber’s Knife Collection: A Review
     of Open Source Software Supply Chain Attacks,” in Detection of Intrusions and
     Malware, and Vulnerability Assessment, C. Maurice, L. Bilge, G. Stringhini, and
     N. Neves, Eds., Cham: Springer International Publishing, 2020, pp. 23–43, isbn:
     978-3-030-52683-2. doi: 10.1007/978-3-030-52683-2_2.
 [4] S. Neupane, G. Holmes, E. Wyss, D. Davidson, and L. De Carli, “Beyond Typosquatting:
     An In-depth Look at Package Confusion,” in 32nd USENIX Security Symposium
     (USENIX Security 23), Anaheim, CA: USENIX Association, 2023, pp. 3439–3456, isbn:
     978-1-939133-37-3. [Online]. Available:
     https://www.usenix.org/conference/usenixsecurity23/presentation/neupane.
 [5] J. Lee. “Malicious Packages Across Open-Source Registries: Detection Statistics and
     Trends (Q2 2025),” Fortinet Blog, Accessed: Mar. 13, 2026. [Online]. Available:
     https://www.fortinet.com/blog/threat-research/malicious-packages-across-
     open-source-registries.
 [6] C. Tafani-Dereeper and E. Wang. “Finding malicious PyPI packages through static code
     analysis: Meet GuardDog,” Accessed: Mar. 13, 2026. [Online]. Available:
     https://securitylabs.datadoghq.com/articles/guarddog-identify-malicious-
     pypi-packages/.
 [7] “PyPI in 2025: A Year in Review,” Accessed: Mar. 13, 2026. [Online]. Available:
     https://blog.pypi.org/posts/2025-12-31-pypi-2025-in-review/.
 [8] “Python static analysis comparison: Bandit vs Semgrep,” Semgrep, Accessed: Mar. 13,
     2026. [Online]. Available: https://semgrep.dev/blog/2021/python-static-
     analysis-comparison-bandit-semgrep.
 [9] M. Ibiyo, T. Louangdy, P. T. Nguyen, C. D. Sipio, and D. D. Ruscio. “Detecting
     Malicious Source Code in PyPI Packages with LLMs: Does RAG Come in Handy?”
     arXiv: 2504.13769 [cs], Accessed: Mar. 13, 2026. [Online]. Available:
     http://arxiv.org/abs/2504.13769, pre-published.
[10] A. Ryan et al. “Mind the Gap: Evaluating LLMs for High-Level Malicious Package
     Detection vs. Fine-Grained Indicator Identification.” arXiv: 2602.16304 [cs], Accessed:
     Mar. 13, 2026. [Online]. Available: http://arxiv.org/abs/2602.16304, pre-published.
[11] W. Guo et al. “Cutting the Gordian Knot: Detecting Malicious PyPI Packages via a
     Knowledge-Mining Framework.” arXiv: 2601.16463 [cs], Accessed: Mar. 13, 2026.
     [Online]. Available: http://arxiv.org/abs/2601.16463, pre-published.
[12] Anthropic. “Claude code overview,” Anthropic, Accessed: Mar. 13, 2026. [Online].
     Available: https://code.claude.com/docs/en/overview.

                                             25

## Page 29

[13] T. Toda and T. Mori. “CHASE: LLM Agents for Dissecting Malicious PyPI Packages.”
     arXiv: 2601.06838 [cs], Accessed: Mar. 13, 2026. [Online]. Available:
     http://arxiv.org/abs/2601.06838, pre-published.
[14] M. Umar Zeshan, M. Ibiyo, C. Di Sipio, P. T. Nguyen, and D. Di Ruscio, “Many hands
     make light work: An LLM-based multi-agent system for detecting malicious PyPI
     packages,” Journal of Systems and Software, vol. 236, p. 112 792, Jun. 1, 2026, issn:
     0164-1212. doi: 10.1016/j.jss.2026.112792. Accessed: Mar. 13, 2026. [Online].
     Available:
     https://www.sciencedirect.com/science/article/pii/S0164121226000269.

                                            26
