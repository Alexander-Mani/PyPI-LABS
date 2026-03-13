# PyPi-SCADA Sample Dataset Documentation

This document provides a detailed forensic backstory for every package in the PyPi-SCADA sample corpus -- both the malicious artifacts and their benign counterparts. It explains how each attack works mechanically, why the samples were chosen, and how they fit into the detection pipeline.

---

## Table of Contents

- [How the Attack Vectors Work](#how-the-attack-vectors-work)
  - [Dependency Confusion](#dependency-confusion)
  - [Account Takeover (Fruit Poisoning)](#account-takeover-fruit-poisoning)
  - [Multi-Stage Execution (Trojans)](#multi-stage-execution-trojans)
  - [Typosquatting and Combosquatting](#typosquatting-and-combosquatting)
- [Package Forensic Profiles](#package-forensic-profiles)
  - [torchtriton (Dependency Confusion)](#1-torchtriton)
  - [totallysafe (Dependency Confusion)](#2-totallysafe)
  - [num2words (Account Takeover)](#3-num2words)
  - [ultralytics (Account Takeover)](#4-ultralytics)
  - [sisaws (Multi-Stage Execution)](#6-sisaws)
  - [termncolor (Multi-Stage Execution)](#7-termncolor)
  - [colourama (Typosquatting)](#8-colourama)
  - [nmap-python (Typosquatting)](#9-nmap-python)
- [Detection Strategy by Vector](#detection-strategy-by-vector)
- [Directory Structure](#directory-structure)
- [Sources](#sources)

---

## How the Attack Vectors Work

### Dependency Confusion

Dependency confusion exploits a fundamental flaw in how `pip` resolves packages across multiple registries.

Many organizations host internal, proprietary Python packages on a **private package server** (e.g., Artifactory, AWS CodeArtifact, or a self-hosted PEP 503 index). Developers install these internal packages using pip's `--extra-index-url` flag:

```bash
pip install torchtriton --extra-index-url https://internal.company.com/simple/
```

The critical vulnerability: **pip does not prioritize the private index**. When `--extra-index-url` is used, pip queries *both* the private server and the public PyPI, merges all results, and installs **whichever version has the highest version number** regardless of which index it came from.

An attacker exploits this by:

1. Identifying the name of an internal package (from job postings, leaked requirements files, open-source build scripts, or DNS probing)
2. Registering that exact name on **public PyPI** -- which is open for anyone to upload to
3. Assigning an absurdly high version number (e.g., `99.0.0` or `2.0.0+0d7e753227`)
4. Embedding a malicious payload in the package

When the company's CI/CD pipeline or a developer runs `pip install`, pip sees:

```
Private index:  torchtriton 1.0.0  (legitimate)
Public PyPI:    torchtriton 2.0.0  (malicious)

pip picks: 2.0.0  <-- highest version wins
```

The legitimate internal package is silently replaced by the attacker's code. The internal package was **never on public PyPI** -- the name was simply unclaimed empty space until the attacker grabbed it. This is why there are no "historical benign versions" to download from pypi.org for these packages. The benign versions only ever existed on private servers that we cannot access.

For the PyPi-SCADA simulator, we create **synthetic benign stubs** to represent what the private registry would have hosted, then inject the malicious version with the inflated number to demonstrate the attack.

**Key detection signals:**
- A brand-new package name appears on the index with no prior history
- The version number is anomalously high for a first upload
- The package contains suspicious behavioral patterns (network calls, file exfiltration, binary execution)

---

### Account Takeover (Fruit Poisoning)

"Fruit Poisoning" is the most dangerous category because the attacker compromises a **real, trusted, widely-used package**. Rather than tricking users with a fake name, the attacker gains control of the legitimate maintainer's account and pushes a malicious update through the normal release process.

This is typically achieved via:
- **Phishing** -- forward-proxy phishing sites that intercept MFA session tokens in real-time
- **Credential stuffing** -- reusing leaked passwords from other breaches
- **CI/CD compromise** -- exploiting GitHub Actions workflows to steal PyPI API tokens

Because the poisoned version comes from the real package on the real PyPI under the real maintainer account, automated dependency management tools (Dependabot, Renovate) immediately detect the "update" and open pull requests across thousands of downstream projects, massively amplifying the infection.

**Why this is the ideal case for differential analysis:** The package has a long, legitimate version history. The Last Known Good Release (LKGR) is the version immediately before the compromise. By diffing LKGR against the malicious version, the analyzer can isolate exactly what the attacker injected -- it stands out starkly against the package's established behavioral baseline.

---

### Multi-Stage Execution (Trojans)

Modern PyPI malware increasingly uses multi-stage execution architecture to evade detection. The package uploaded to PyPI contains only a lightweight "dropper" or "stager" -- a small script that, upon installation, reaches out to a remote Command and Control (C2) server to download the actual heavy-duty payload.

This design has two advantages for the attacker:
1. The PyPI package itself is tiny and appears relatively benign to static analysis, since the actual malware is never stored in the package
2. The C2 payload can be updated, swapped, or disabled without re-uploading to PyPI

The stager typically hides in `setup.py` (executed during `pip install`) or `__init__.py` (executed on first import). It uses obfuscation techniques -- hex-encoded strings, Base64, `exec()` calls -- to hide what is often just a single `curl` or `wget` command that fetches the real payload.

**Key detection signals:**
- `setup.py` or `__init__.py` containing `subprocess`, `os.system`, `exec()`, or encoded strings
- Network calls to external URLs during installation
- Suspiciously small package with minimal legitimate functionality
- Obfuscated variable names or encoded command strings

---

### Typosquatting and Combosquatting

Typosquatting is the simplest attack vector: register a package name that is a plausible misspelling or variation of a popular package, then wait for developers to make a typo.

Common techniques:
- **Alternate spelling**: `colourama` for `colorama` (British vs. American English)
- **Word reordering (combosquatting)**: `nmap-python` for `python-nmap`
- **Character substitution**: `requesTs` for `requests`
- **Prefix/suffix addition**: `python-requests` for `requests`

The malicious package typically executes its payload immediately upon installation via `setup.py`. Because the attacker controls the package from its very first version, **there is no benign version history** -- the package was malicious from birth.

**Why intra-package diffing fails:** There is no version N-1 to compare against. Detection requires:
1. **Name similarity analysis**: Levenshtein distance or similar metrics against the top-N most downloaded packages
2. **Cross-package diffing**: Compare the typosquat's code against the legitimate target's code to identify injected payloads

---

## Package Forensic Profiles

### 1. torchtriton

| Field | Value |
|---|---|
| **Attack Vector** | Dependency Confusion |
| **Malicious Version** | `2.0.0+0d7e753227` |
| **Infection Date** | December 25, 2022 |
| **LKGR** | N/A (never on public PyPI) |
| **Legitimate Target** | Internal PyTorch dependency (private index) |
| **Benign Sample** | `samples/benign/torchtriton/` (synthetic stub) |

**Backstory:** PyTorch, the premier open-source machine learning framework developed by Meta AI, used an internal dependency called `torchtriton` for compiling nightly Linux builds. This was a specialized extension of the PyTorch Triton library, enabling models trained in PyTorch to leverage TensorRT inference accelerators. Critically, this package was hosted exclusively on PyTorch's private, dedicated package index and had **never been registered on public PyPI**.

**The Attack:** On Christmas Day 2022, an attacker operating under the guise of an ethical security researcher registered the exact name `torchtriton` on public PyPI with version `2.0.0+0d7e753227`. PyTorch's official nightly build documentation instructed users to use `--extra-index-url` pointing to their private index. Because pip merges both indices and picks the highest version, every nightly build and every developer following the official instructions silently pulled the malicious public package instead.

**Payload Mechanics:** The malicious package contained a compiled ELF (Executable and Linkable Format) binary named `triton` designed to execute upon installation, placing itself in `PYTHON_SITE_PACKAGES/triton/runtime/`. Once triggered, the binary:
- Harvested hostname, username, current working directory, and environment variables
- Read and copied `/etc/resolv.conf`, `/etc/hosts`, `/etc/passwd`, `.gitconfig`
- Exfiltrated up to 1,000 files from the user's `~/.ssh/` directory

To bypass network egress filters and DLP systems, the stolen data was encoded and exfiltrated via **DNS tunneling** -- encrypted DNS queries to the domain `.h4ck[.]cfd` using the DNS server `wheezy[.]io`. This technique avoids standard HTTP/HTTPS monitoring entirely.

**Aftermath:** The attack was discovered on December 30, 2022. PyTorch mitigated by renaming their internal package to `pytorch-triton` and registering a dummy placeholder on public PyPI to prevent future squatting. The `pytorch-triton` v0.0.1 on pypi.org today is that defensive placeholder -- not a usable package.

**Why benign samples are synthetic:** The real internal torchtriton only ever existed on PyTorch's private server, which is not publicly accessible. The synthetic `torchtriton-1.0.0.tar.gz` in `samples/benign/torchtriton/` represents what the private registry would have hosted, enabling the simulator to demonstrate the version-inflation attack.

**Further Reading:**
- [Malicious PyTorch dependency 'torchtriton' on PyPI — everything you need to know](https://www.wiz.io/blog/malicious-pytorch-dependency-torchtriton-on-pypi-everything-you-need-to-know) (Wiz Blog) — deep technical breakdown of the ELF binary and DNS tunneling payload
- [Compromised PyTorch-nightly dependency](https://pytorch.org/blog/compromised-nightly-dependency/) (PyTorch official blog) — Meta's own incident report and mitigation steps
- [PyTorch dependency 'torchtriton' Supply Chain Attack](https://www.sentinelone.com/blog/pytorch-dependency-torchtriton-supply-chain-attack/) (SentinelOne) — attacker attribution and timeline reconstruction

---

### 2. totallysafe

| Field | Value |
|---|---|
| **Attack Vector** | Dependency Confusion |
| **Malicious Version** | Unknown |
| **Infection Date** | 2015--2019 |
| **LKGR** | N/A |
| **Legitimate Target** | N/A (research artifact) |
| **Benign Sample** | `samples/benign/totallysafe/` (synthetic stub) |

**Backstory:** `totallysafe` is a foundational historical artifact from the Backstabber's Knife Collection (BKC), the academic dataset first presented by Ohm et al. at the DIMVA 2020 conference. Uploaded during the 2015--2019 window, it serves as an early proof-of-concept for hidden code execution within the Python packaging ecosystem.

Exact version metrics are obscured by its early removal from PyPI and subsequent academic archival. Its purpose in the BKC dataset is to demonstrate how malicious actors embed secondary payloads within standard Python setup scripts -- specifically, how `setup.py` can contain arbitrary code execution buried beneath layers of seemingly benign string manipulation and obfuscation.

**Role in PyPi-SCADA:** Used as a baseline control to test whether the diffing engine and SAST adapters can identify hidden arbitrary code execution, regardless of a package's specific version history. The synthetic benign stub provides the "before" state for the simulator.

**Further Reading:**
- [Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks](https://pmc.ncbi.nlm.nih.gov/articles/PMC7338168/) (Ohm et al., DIMVA 2020) — the original academic paper that catalogued totallysafe and defined the BKC dataset
- [Backstabber's Knife Collection dataset index](https://dasfreak.github.io/Backstabbers-Knife-Collection/) (GitHub Pages) — browsable archive of all collected malicious packages

---

### 3. num2words

| Field | Value |
|---|---|
| **Attack Vector** | Account Takeover (Fruit Poisoning) |
| **Malicious Version** | `0.5.15` (and `0.5.16`) |
| **Infection Date** | July 28, 2025 |
| **LKGR** | `0.5.14` (published December 17, 2024) |
| **Legitimate Target** | Same package (`num2words`) |
| **Benign Samples** | `samples/benign/num2words/` (15 versions, 0.5.0 through 0.5.14) |

**Backstory:** num2words is a highly popular, mature utility used to convert numerical digits into text words across multiple languages. It serves as a dependency for numerous text-to-speech and data processing applications, with a stable release history spanning over a decade.

**The Attack:** On July 28, 2025, the global Python security community was alerted to a severe supply chain compromise. Threat actors linked to the "Scavenger" group (also known as JuiceLedger in previous campaigns) executed a sophisticated **forward-proxy phishing attack** against PyPI maintainers.

The attackers scraped public GitHub repositories and package metadata to identify maintainer email addresses. They sent urgent emails requesting credential validation, linking to a deceptive domain equipped with an SSL certificate that **transparently proxied requests to the real pypi.org**. When maintainers clicked the link and logged in, the proxy server intercepted not only their usernames and passwords but also their **live MFA session tokens** -- completely bypassing Multi-Factor Authentication.

With full authenticated access, the attackers uploaded versions 0.5.15 and 0.5.16 directly to PyPI.

**Payload Mechanics:** The malware modified the package's core initialization script (`__init__.py`) to silently load and execute a malicious Dynamic Link Library (DLL) hidden within an obfuscated `_build.py` file. Because num2words was already implicitly trusted by the ecosystem, automated dependency management tools (Dependabot, Renovate) immediately detected the "update" and began opening pull requests to upgrade downstream enterprise projects, rapidly accelerating the infection.

**Correction of Historical Data:** Initial queries hypothesized that version 0.5.13 was the malicious release. Forensic analysis confirms that 0.5.13 was a legitimate benign release published on October 18, 2023, featuring standard bug fixes for Brazilian Portuguese and Norwegian language support. The LKGR is 0.5.14.

**Detection approach:** This is the ideal case for intra-package differential analysis. Diffing 0.5.14 against 0.5.15 would instantly reveal the anomalous inclusion of a binary DLL loader and arbitrary code execution in the initialization sequence. Furthermore, version 0.5.15 was published to PyPI without a corresponding tag or commit in the official GitHub repository -- a massive red flag.

**Further Reading:**
- [Supply Chain Security Alert: num2words PyPI Package Shows Signs of Compromise](https://www.stepsecurity.io/blog/supply-chain-security-alert-num2words-pypi-package-shows-signs-of-compromise) (StepSecurity) — first public disclosure with payload analysis
- [PyPI Phishing Attack: Incident Report](https://blog.pypi.org/posts/2025-07-31-incident-report-phishing-attack/) (PyPI official blog, July 31 2025) — PyPI's own account of the Scavenger/JuiceLedger MFA-bypass phishing campaign that enabled the compromise
- [Embedded Malicious Code in num2words — SNYK-PYTHON-NUM2WORDS-11172937](https://security.snyk.io/vuln/SNYK-PYTHON-NUM2WORDS-11172937) (Snyk) — CVE entry with technical indicators and affected version ranges

---

### 4. ultralytics

| Field | Value |
|---|---|
| **Attack Vector** | Account Takeover (CI/CD Pipeline Hijack) |
| **Malicious Version** | `8.3.41` (and `8.3.42`) |
| **Infection Date** | December 4, 2024 |
| **LKGR** | `8.3.40` (published December 2, 2024) |
| **Legitimate Target** | Same package (`ultralytics`) |
| **Benign Samples** | `samples/benign/ultralytics/` (465 versions, 0.0.13 through 8.3.40) |

**Backstory:** Ultralytics is a premier AI and computer vision library, famously maintaining the YOLO (You Only Look Once) object detection models. It boasts nearly 60 million global downloads and serves as a critical dependency in platforms like the ComfyUI Impact Pack.

**The Attack:** Uniquely, this attack was **not** the result of a stolen PyPI password or a phishing attack against a maintainer. Instead, the attackers compromised the project's automated **GitHub Actions CI/CD workflow**.

The attackers exploited a known script injection vulnerability related to the `pull_request_target` trigger in GitHub Actions. This trigger is inherently dangerous because it executes the workflow in the context of the **base repository** rather than the isolated fork, granting access to repository secrets including PyPI API publishing tokens (via PyPA's Trusted Publishing).

By submitting a maliciously crafted pull request from a suspicious account named `openimbot`, the threat actors executed arbitrary code directly within the GitHub build environment. This allowed them to **inject malware into the release artifacts during the compilation phase**, right before the artifacts were signed and pushed to PyPI.

**Payload Mechanics:** The malicious versions contained embedded downloader code that, upon installation, fetched and executed the **XMRig cryptocurrency miner** on the victim's hardware. The attack caused a measurable spike in global CPU usage as downstream AI applications automatically pulled the poisoned library.

**Why this attack is particularly terrifying:** The malicious code was injected during the ephemeral GitHub Actions build phase -- it never existed in the source repository's commit history. The source distribution and the built wheel on PyPI **differed fundamentally** from the public GitHub source code. A static differential analyzer cross-referencing the PyPI artifact against the linked source repository commit would immediately flag this cryptographic discrepancy.

**Correction of Historical Data:** Initial assumptions pointed to version 8.0.100 as the malicious release. Forensic analysis confirms the malicious code was in versions 8.3.41 and 8.3.42, published December 4, 2024.

**Further Reading:**
- [Ultralytics AI Library Hacked via GitHub for Cryptomining](https://www.wiz.io/blog/ultralytics-ai-library-hacked-via-github-for-cryptomining) (Wiz Blog) — detailed breakdown of the `pull_request_target` exploit and how the XMRig miner was injected at build time
- [Supply-chain attack analysis: Ultralytics](https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/) (PyPI official blog, December 11 2024) — PyPI's post-mortem including the cryptographic discrepancy between the published wheel and the GitHub source
- [The Ultralytics Supply Chain Attack: How It Happened, How to Prevent](https://www.legitsecurity.com/blog/the-ultralytics-supply-chain-attack-how-it-happened-how-to-prevent) (Legit Security) — attacker methodology and CI/CD hardening recommendations

---

### 6. sisaws

| Field | Value |
|---|---|
| **Attack Vector** | Multi-Stage Execution |
| **Malicious Version** | `2.1.6` |
| **Infection Date** | August 4, 2025 |
| **LKGR** | N/A (entirely malicious) |
| **Legitimate Target** | `sisa` (Sistema Integrado de Informacion Sanitaria Argentino) |
| **Benign Samples** | `samples/benign/sisa/` (14 versions, 0.2 through 0.922) |

**Backstory:** `sisaws` was the second package in the CondeTGAPIS campaign, uploaded the day after `secmeasure`. It used a different social engineering lure -- masquerading as a government API integration utility, specifically mimicking the legitimate `sisa` package.

`sisa` is a real Python package associated with Argentina's national health information system (Sistema Integrado de Informacion Sanitaria Argentino). By choosing a name that looks like a plausible AWS-integrated variant of `sisa`, the attacker created a convincing impersonation.

**Payload:** Identical to secmeasure -- the `sanitize_input` function, hex-encoded curl to GitHub Codespaces C2, SilentSync RAT download.

**Detection approach:** This is a hybrid case. The package both impersonates a legitimate target (`sisa`) *and* uses multi-stage execution. Detection can use:
1. **Name similarity** against the simulator index to identify the `sisa` connection
2. **Cross-package diffing** against `sisa`'s code to reveal injected malicious functions
3. **First-version SAST** to flag the obfuscated shell commands

**Further Reading:**
- [Malicious PyPI Packages Deliver SilentSync RAT](https://www.zscaler.com/blogs/security-research/malicious-pypi-packages-deliver-silentsync-rat) (Zscaler ThreatLabz) — covers sisaws alongside secmeasure; includes the deobfuscated `sanitize_input` function and C2 infrastructure details

---

### 7. termncolor

| Field | Value |
|---|---|
| **Attack Vector** | Multi-Stage Execution + Typosquatting |
| **Malicious Version** | `1.0.0` |
| **Infection Date** | September 18, 2025 |
| **LKGR** | N/A (entirely malicious) |
| **Legitimate Target** | `termcolor` (terminal text formatting library) |
| **Benign Samples** | `samples/benign/termcolor/` (20 versions, 0.1 through 3.3.0) |

**Backstory:** `termncolor` operated within the same multi-stage paradigm as the CondeTGAPIS campaign but combined it with typosquatting evasion. It masqueraded as `termcolor`, the highly popular text-formatting tool for terminal output. The name substitution is subtle -- an extra `n` that is easy to miss when reading quickly.

Published around September 18, 2025, the package was downloaded **nearly a thousand times** before detection.

**Payload Mechanics:** Unlike simpler malware, termncolor did not contain the final payload. Instead, upon execution, it was designed to quietly import a **secondary rogue package** called `colorinal`. This initiated a complex infection chain resulting in DLL side-loading -- loading a rogue DLL into a legitimate, trusted Windows process. The malware established deep persistence on the victim's machine and facilitated encrypted command-and-control communications, ultimately resulting in full remote code execution (RCE).

**Detection approach:** Dual detection path:
1. **Typosquatting detection**: Name similarity to `termcolor` triggers cross-package diff, revealing entirely different code and injected imports
2. **SAST analysis**: Flags the import of the unknown `colorinal` dependency and any encoded strings or shell commands

**Further Reading:**
- [Malicious PyPI Packages Deliver SilentSync RAT](https://www.zscaler.com/blogs/security-research/malicious-pypi-packages-deliver-silentsync-rat) (Zscaler ThreatLabz) — covers termncolor's DLL side-loading chain and the `colorinal` rogue package import
- [Malicious PyPI and npm Packages Discovered Exploiting Dependencies in Supply Chain Attacks](https://thehackernews.com/2025/08/malicious-pypi-and-npm-packages.html) (The Hacker News) — news coverage with download count and detection timeline

---

### 8. colourama

| Field | Value |
|---|---|
| **Attack Vector** | Typosquatting |
| **Malicious Version** | `0.1.6` |
| **Infection Date** | October 1, 2018 |
| **LKGR** | N/A (entirely malicious) |
| **Legitimate Target** | `colorama` (ANSI color styling, top-50 most downloaded) |
| **Benign Samples** | `samples/benign/colorama/` (46 versions, 0.1 through 0.4.6) |

**Backstory:** The `colorama` library is a cornerstone of the Python ecosystem, consistently ranking in the top 50 most downloaded packages globally. Developers use it to add ANSI color styling to terminal outputs. Taking advantage of the global spelling variation between American English ("color") and British English ("colour"), an attacker uploaded the package `colourama` (version 0.1.6) to PyPI around October 2018.

This is one of the **earliest documented and most cited** examples of a PyPI typosquatting attack, serving as a foundational case study in supply chain security research.

**Payload Mechanics:** Unlike modern multi-stage RATs that establish complex C2 persistence, `colourama` was a **direct financial exploit**. Upon installation, it:
1. Used Base64 encoding to obfuscate a payload that searched the local operating system for cryptocurrency wallets
2. Monitored the user's clipboard data in real-time
3. If the user copied a string matching the regex format of a cryptocurrency wallet address, the malware **replaced it with the attacker's address**
4. The next time the victim pasted the address to send a transaction, the funds went to the attacker

This clipboard-hijacking technique is elegant in its simplicity -- no C2 servers, no persistence mechanisms, just silent theft executed at the moment of transaction.

**Detection approach:** Cross-package diff between `colourama` and `colorama` would reveal that the typosquat copied much of colorama's legitimate code but injected the Base64-encoded clipboard monitoring payload -- a stark behavioral deviation from a library that should only format terminal text.

**Further Reading:**
- [Python's Colorama Typosquatting Meets 'Fade Stealer' Malware](https://www.imperva.com/blog/pythons-colorama-typosquatting-meets-fade-stealer-malware/) (Imperva) — analysis of the clipboard-hijacking payload and how it ties into the broader Fade Stealer info-stealer family
- [Backstabber's Knife Collection](https://arxiv.org/pdf/2005.09535) (Ohm et al., arXiv 2020) — the original academic paper that first formally documented colourama as a case study in PyPI typosquatting

---

### 9. nmap-python

| Field | Value |
|---|---|
| **Attack Vector** | Typosquatting (Combosquatting) |
| **Malicious Version** | `1.0.0` |
| **Infection Date** | 2015--2019 |
| **LKGR** | N/A (entirely malicious) |
| **Legitimate Target** | `python-nmap` (Python wrapper for the Nmap network scanner) |
| **Benign Samples** | `samples/benign/python-nmap/` (18 versions, 0.1.1 through 0.7.1) |

**Backstory:** The legitimate `python-nmap` is a widely used Python wrapper for the Nmap network security scanner. The attacker created `nmap-python` -- a classic example of **combosquatting**, where the words around the hyphen are simply reversed. This creates a highly plausible alternative name.

Developers typing from memory, relying on autocomplete scripts, or referencing outdated documentation are susceptible to running `pip install nmap-python`, immediately compromising their host machine with an embedded Trojan payload. The package is archived in the Backstabber's Knife Collection from the 2015--2019 era.

**Detection approach:** Name similarity analysis would flag `nmap-python` against `python-nmap` (identical tokens, reversed order). Cross-package diffing would then reveal the injected malicious code against python-nmap's legitimate network scanning wrapper.

**Further Reading:**
- [Backstabber's Knife Collection](https://arxiv.org/pdf/2005.09535) (Ohm et al., arXiv 2020) — formal documentation of nmap-python as a combosquatting case; includes analysis methodology
- [Beyond Typosquatting: An In-depth Look at Package Confusion](https://ldklab.github.io/assets/papers/usenix23-confusion.pdf) (De Carli, USENIX 2023) — academic treatment of word-reordering combosquatting and automated detection techniques

---

## Detection Strategy by Vector

| Attack Vector | Detection Method | Diff Type | Benign Samples Needed |
|---|---|---|---|
| **Account Takeover** | Intra-package diff (version N vs N+1) | Version-to-version | Yes -- full history of the same package |
| **Dependency Confusion** | Version anomaly + first-version SAST | None (metadata + SAST) | Synthetic stubs only |
| **Typosquatting** | Name similarity + cross-package diff | Cross-package | Yes -- history of the target package |
| **Multi-Stage Execution** | Cross-package diff (if typosquat) or first-version SAST | Varies | If a counterpart exists |

The current analyzer (`analyzer/main.py:59`) only implements intra-package diffing and skips packages with fewer than 2 versions. This handles account takeover well but is blind to the other three vectors.

---

## Directory Structure

```
samples/
    SAMPLES.md                        # this file
    samples_last_version.csv          # attack metadata table
    download_benign.py                # downloads real versions from PyPI
    create_synthetic.py               # builds synthetic dep-confusion stubs

    benign/                           # legitimate package versions
        colorama/                     # target of colourama (46 versions)
        python-nmap/                  # target of nmap-python (18 versions)
        termcolor/                    # target of termncolor (20 versions)
        sisa/                         # target of sisaws (14 versions)
        num2words/                    # account takeover, same pkg (15 versions)
        ultralytics/                  # account takeover, same pkg (465 versions)
        torchtriton/                  # synthetic stub for dep confusion
        totallysafe/                  # synthetic stub for dep confusion
        <each dir>/manifest.json      # chronological version list
        <each dir>/meta.json          # attack vector + detection strategy mapping

    malware_backstabbers_knife/       # malicious samples (password-protected zips)
        dependency_confusion/
            torchtriton.zip
            totallysafe.zip
        fruit_poisoning/
            num2words.zip
            ultralytics.zip
        multi_stage_execution/
            sisaws.zip
            termncolor.zip
        typosquating/
            colourama.zip
            nmap-python.zip
```

---

## Sources

1. Imperva -- "Python's Colorama Typosquatting Meets 'Fade Stealer' Malware"
2. Ohm et al. -- "Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks" (DIMVA 2020)
3. Wiz Blog -- "Malicious PyTorch dependency 'torchtriton' on PyPI"
4. Hacker News -- "Compromised PyTorch-nightly dependency chain between December 25th"
5. PyTorch Blog -- "Compromised PyTorch-nightly dependency"
6. StepSecurity -- "Supply Chain Security Alert: num2words PyPI Package Shows Signs of Compromise"
7. PyPI Blog -- "PyPI Phishing Attack: Incident Report" (July 31, 2025)
8. Snyk -- "Embedded Malicious Code in num2words" (SNYK-PYTHON-NUM2WORDS-11172937)
9. Wiz Blog -- "Ultralytics AI Library Hacked via GitHub for Cryptomining"
10. PyPI Blog -- "Supply-chain attack analysis: Ultralytics" (December 11, 2024)
11. Legit Security -- "The Ultralytics Supply Chain Attack: How It Happened, How to Prevent"
12. Zscaler ThreatLabz -- "Malicious PyPI Packages Deliver SilentSync RAT"
13. The Hacker News -- "Malicious PyPI and npm Packages Discovered Exploiting Dependencies in Supply Chain Attacks"
14. De Carli -- "Beyond Typosquatting: An In-depth Look at Package Confusion" (USENIX)
