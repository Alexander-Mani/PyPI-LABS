"""
heuristic_filter.py — Fast pre-filter that annotates a PackageInfo with
suspicious-pattern tags before passing it to the detection pipelines.

All checks are non-fatal: exceptions are logged and execution continues.
The filter mutates pkg.heuristic_flags in place and returns the same object.
See CONCERNS.md §5 for notes on the high false-positive rate of the
base64_or_hex check.
"""

from __future__ import annotations

import re
from pathlib import Path

from entry_extractor import PackageInfo
from src.utils.logger import get_logger

log = get_logger()

# ---------------------------------------------------------------------------
# Pattern constants
# ---------------------------------------------------------------------------

_B64_SUBSTRINGS = ("base64.b64decode", "bytes.fromhex", "binascii")
_B64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

_NETWORK_SUBSTRINGS = (
    "import urllib",
    "import socket",
    "import requests",
    "import httplib",
    "import http.client",
)

_SHELL_SUBSTRINGS = (
    "os.system",
    "subprocess.",
    "exec(",
    "eval(",
    "__import__",
)

_INSTALL_HOOKS = frozenset({"setup.py", "pyproject.toml"})


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------

class HeuristicFilter:

    def scan(self, pkg: PackageInfo) -> PackageInfo:
        """
        Run all four heuristic checks against *pkg* and append triggered tags
        to pkg.heuristic_flags. Returns the same (mutated) PackageInfo.
        """
        checks = [
            ("base64_or_hex",          self._check_base64_or_hex),
            ("network_in_install_hook", self._check_network_in_install_hook),
            ("shell_execution",         self._check_shell_execution),
            ("bundled_binary",          self._check_bundled_binary),
        ]
        for tag, fn in checks:
            try:
                if fn(pkg) and tag not in pkg.heuristic_flags:
                    pkg.heuristic_flags.append(tag)
                    log.debug(f"  [{pkg.name}] heuristic flag: {tag}")
            except Exception as exc:
                log.warning(f"  [{pkg.name}] heuristic check '{tag}' raised: {exc}")
        return pkg

    # ------------------------------------------------------------------
    # Individual checks
    # ------------------------------------------------------------------

    def _check_base64_or_hex(self, pkg: PackageInfo) -> bool:
        for content in pkg.files.values():
            for pattern in _B64_SUBSTRINGS:
                if pattern in content:
                    return True
            if _B64_RE.search(content):
                return True
        return False

    def _check_network_in_install_hook(self, pkg: PackageInfo) -> bool:
        for path, content in pkg.files.items():
            if Path(path).name not in _INSTALL_HOOKS:
                continue
            for pattern in _NETWORK_SUBSTRINGS:
                if pattern in content:
                    return True
        return False

    def _check_shell_execution(self, pkg: PackageInfo) -> bool:
        for content in pkg.files.values():
            for pattern in _SHELL_SUBSTRINGS:
                if pattern in content:
                    return True
        return False

    def _check_bundled_binary(self, pkg: PackageInfo) -> bool:
        for content in pkg.files.values():
            if "\x00" in content:
                return True
        return False
