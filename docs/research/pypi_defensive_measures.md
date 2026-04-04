# static

# PyPI safeguards and observable detection or response methods (citable)

## 1) User and researcher malware reporting pipeline (intake mechanism)
PyPI provides an explicit malware reporting flow, including guidance to link directly to suspicious lines using inspector.pypi.io.
Source:
https://pypi.org/security/

## 2) Project-level quarantine (admin safety action, prevents easy installation)
PyPI administrators can quarantine a project marked potentially harmful, intended to reduce further harm while investigating.
Source:
https://blog.pypi.org/posts/2024-12-30-quarantine/

## 3) Project status markers, including “quarantined” semantics in API responses
PyPI documents “quarantined” as generally unsafe, due to malware, and indicates PyPI will not offer it for installation, installers are encouraged to warn.
Source:
https://blog.pypi.org/posts/2025-08-14-project-status-markers/

## 4) Yanked releases support (non-destructive removal signal to installers)
Defines yanking behavior in the Simple API, a control used to reduce harmful installs without breaking pinned environments.
Source:
https://peps.python.org/pep-0592/
Additional PyPI docs:
https://docs.pypi.org/project-management/yanking/

## 5) Account takeover mitigation, mandatory 2FA for PyPI users and maintainers
PyPI requires 2FA, framed as reducing account takeover risk for maintainers and the ecosystem.
Source:
https://discuss.python.org/t/announcement-2fa-now-required-for-pypi/42251
Background on critical-project 2FA rollout:
https://pypi.org/security-key-giveaway/

## 6) Domain-resurrection attack mitigation (expired domain monitoring, email unverification)
PyPI checks for expired domains and unverifies affected emails to block password-reset takeover paths.
Source:
https://blog.pypi.org/posts/2025-08-18-preventing-domain-resurrections/

## 7) Repository signing proposals for secure distribution (TUF based)
Defines the minimum security model for securing PyPI downloads using TUF metadata, this is about repository integrity, not malware scanning.
Source:
https://peps.python.org/pep-0458/

## 8) End-to-end signing proposal (compromise survivability)
Extends the above with end-to-end signing, again integrity oriented, relevant to supply chain threat mitigation claims.
Source:
https://peps.python.org/pep-0480/

## 9) Name retention and dispute policy (governance control to reduce namespace abuse)
Clarifies name ownership and transfer rules, useful when discussing typosquatting and abandoned-name risk.
Source:
https://peps.python.org/pep-0541/
PyPI docs:
https://docs.pypi.org/project-management/name-retention/

## 10) Public incident analyses showing response, quarantine, and removal actions
These posts document real incidents, and the operational response, including quarantine and removal statements.
Sources:
https://blog.pypi.org/posts/2024-11-25-aiocpa-attack-analysis/
https://blog.pypi.org/posts/2024-12-11-ultralytics-attack-analysis/

