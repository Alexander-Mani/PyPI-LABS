"""Test-only dependency shims for minimal system Python environments."""

from __future__ import annotations

import importlib.util
import sys
import types


class _FakeLogger:
    def remove(self):
        return None

    def add(self, *args, **kwargs):
        return None

    def info(self, *args, **kwargs):
        return None

    def warning(self, *args, **kwargs):
        return None

    def error(self, *args, **kwargs):
        return None

    def debug(self, *args, **kwargs):
        return None

    def bind(self, *args, **kwargs):
        return self


if importlib.util.find_spec("loguru") is None:
    sys.modules.setdefault("loguru", types.SimpleNamespace(logger=_FakeLogger()))

if importlib.util.find_spec("yaml") is None:
    def _missing_yaml(*args, **kwargs):
        raise RuntimeError("PyYAML is not installed in this minimal test environment")

    sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=_missing_yaml))
