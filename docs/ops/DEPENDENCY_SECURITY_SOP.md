# Standard Operating Procedure: PyPi-SCADA Dependency Security

This document defines the security standard for Python package management within the PyPi-SCADA project. It establishes defense-in-depth mechanisms against supply chain attacks affecting the project's own infrastructure.

## 1. Cryptographic Resolution
Package resolution requires strict cryptographic verification. Developers generate dependency lockfiles using `pip-tools`. The lockfile records the exact version and SHA-256 hash of every top-level package and sub-dependency. Installation executes exclusively via `pip install --require-hashes --no-deps`. This prevents upstream mutability from altering the local execution environment.

## 2. Continuous Composition Analysis
Lockfiles secure the supply chain at a specific timestamp. They do not protect against retroactive vulnerability disclosures or delayed malware detection. While the current active defense relies entirely on the strict enforcement of hashed lockfiles (generated via `pip-compile --generate-hashes`), the project plans to integrate `pip-audit` for continuous Software Composition Analysis as a future control. Once implemented, the pipeline will execute this audit against the active lockfile before initiating evaluation batches to abort execution if known CVEs or malicious package flags are detected.

## 3. Dependency Minimization
The attack surface scales linearly with dependency count. The architecture strictly limits third-party imports. Developers implement functionality using the Python Standard Library whenever possible. Convenience libraries and untested frameworks are prohibited from entering the `requirements/requirements.in` specification.

## 4. Execution Isolation
The system assumes eventual dependency compromise. Execution occurs strictly within the unprivileged `pypi-runner` environment. The iptables firewall configuration drops all outbound network requests from this user account. A compromised dependency cannot exfiltrate data, establish reverse shells, or download secondary payloads.

## 5. Breach Remediation
When a scanner flags an existing dependency as compromised, the operator halts the pipeline. The operator physically or logically isolates the VM from all host networks. The compromised lockfile hash is purged from the repository. The operator analyzes the malicious package using the project's own entry-point scanning tools before updating to a patched version or removing the dependency entirely.
