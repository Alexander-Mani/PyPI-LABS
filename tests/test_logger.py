"""Regression tests for shared logging helpers."""

from __future__ import annotations

from src.utils import logger as logger_mod


def test_static_log_path_is_unchanged(tmp_path):
    configured = tmp_path / "upload_samples.log"
    resolved = logger_mod._resolve_log_path({"logging": {"file": str(configured)}})

    assert resolved == configured


def test_per_run_log_path_gets_timestamp_suffix(tmp_path):
    configured = tmp_path / "upload_samples.log"
    resolved = logger_mod._resolve_log_path(
        {"logging": {"file": str(configured), "per_run": True}}
    )

    assert resolved.parent == tmp_path
    assert resolved.suffix == ".log"
    assert resolved.name.startswith("upload_samples-")
    assert resolved != configured
