"""Tests for the masked identity alias validity probe."""

from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import EvalDetectionResult  # noqa: E402
from detection_controller import EvalController  # noqa: E402
from entry_extractor import PackageInfo  # noqa: E402
from identity_mask import mask_package_identity  # noqa: E402
from prompt_manager import PromptManager  # noqa: E402
from raw_experiment_log import RawExperimentLog  # noqa: E402
from scripts import check_identity_alias_leaks  # noqa: E402


class _FakePromptManager:
    def get_llm_strategy(self, name):
        assert name == "zero_shot"
        return "system", "Package: {package_name} Version: {version}\n{file_listing}"


class _FakeDB:
    def __init__(self):
        self.rows = []

    def insert_eval_result(self, **kwargs):
        self.rows.append(kwargs)
        return len(self.rows)


class _FakeHybridAdapter:
    _detector_name = "fake_llm"
    _experiment_mode = "hybrid"

    def __init__(self):
        self.seen_pkg = None

    def run(self, pkg, strategy, system_prompt, template_override, *, raw_log=None, trace_context=None):
        self.seen_pkg = pkg
        if raw_log is not None:
            user = template_override.format(
                package_name=pkg.name,
                version=pkg.version,
                file_listing="\n".join(f"{path}\n{content}" for path, content in pkg.files.items()),
                heuristic_flags="none",
            )
            raw_log.emit(
                "llm.request",
                **(trace_context or {}),
                payload={
                    "user_prompt_ref": raw_log.blob_text("llm_user_prompt", user, suffix=".txt"),
                    "request_json_ref": raw_log.blob_json(
                        "llm_request",
                        {"messages": [{"role": "user", "content": user}]},
                    ),
                },
            )
        return EvalDetectionResult(
            detector="fake_llm",
            experiment_mode="hybrid",
            verdict=True,
            confidence=0.9,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=10,
            api_cost_usd=0.001,
            input_tokens=10,
            output_tokens=5,
            details={"model": "fake-model"},
        )


def test_mask_package_identity_removes_names_but_preserves_behavior():
    pkg = PackageInfo(
        name="colourama",
        version="0.1.6",
        files={
            "colourama-0.1.6.dist-info/METADATA": "Name: colourama\nVersion: 0.1.6\n",
            "colourama/setup.py": (
                "from setuptools import setup\n"
                "import os, base64\n"
                "setup(name='colourama', version='0.1.6')\n"
                "os.system(base64.b64decode('ZWNobyB4').decode())\n"
            ),
        },
        files_raw={},
        heuristic_flags=["shell_execution"],
    )

    masked = mask_package_identity(pkg, alias_name="X001", alias_version="V001")
    combined = "\n".join([masked.package.name, masked.package.version, *masked.package.files.keys(), *masked.package.files.values()])

    assert masked.package.name == "X001"
    assert masked.package.version == "V001"
    assert "colourama" not in combined.lower()
    assert "0.1.6" not in combined
    assert "os.system" in combined
    assert "base64.b64decode" in combined
    assert masked.package.heuristic_flags == ["shell_execution"]


def test_alias_probe_keeps_db_identity_but_adapter_sees_alias(monkeypatch, tmp_path):
    monkeypatch.setattr(PromptManager, "instance", classmethod(lambda cls: _FakePromptManager()))
    adapter = _FakeHybridAdapter()
    db = _FakeDB()
    controller = EvalController.__new__(EvalController)
    controller._db = db
    controller._static = [object()]
    controller._llm = [adapter]
    controller._llm_raw = [object()]
    controller._agentic = [object()]
    trace = RawExperimentLog("alias-run", tmp_path / "logs")
    pkg = PackageInfo(
        name="X001",
        version="V001",
        files={"X001/setup.py": "from setuptools import setup\nsetup(name='X001', version='V001')\n"},
        files_raw={},
    )

    controller.run(
        run_id="alias-run",
        pkg=pkg,
        ground_truth=True,
        hybrid_zero_shot_only=True,
        artifact_filename="colourama-0.1.6.tar.gz",
        record_package_name="colourama",
        record_version="0.1.6",
        result_details_extra={
            "identity_mask": "alias",
            "alias_probe": True,
            "alias_name": "X001",
            "alias_version": "V001",
        },
        raw_log=trace,
        quiet_console=True,
    )

    assert adapter.seen_pkg is pkg
    assert db.rows[0]["package_name"] == "colourama"
    assert db.rows[0]["version"] == "0.1.6"
    assert db.rows[0]["details"]["identity_mask"] == "alias"
    assert db.rows[0]["details"]["alias_probe"] is True


def test_identity_alias_leak_checker_scans_model_facing_blobs(tmp_path):
    log_dir = tmp_path / "logs"
    trace = RawExperimentLog("alias-run", log_dir)
    trace.emit(
        "identity_alias.mask",
        package="colourama",
        version="0.1.6",
        artifact_filename="colourama-0.1.6.tar.gz",
        payload={
            "alias_name": "X001",
            "alias_version": "V001",
            "original_terms": ["colourama", "0.1.6"],
        },
    )
    request_ref = trace.blob_json(
        "llm_request",
        {"messages": [{"role": "user", "content": "Package: X001 Version: V001"}]},
    )
    trace.emit(
        "llm.request",
        package="colourama",
        version="0.1.6",
        artifact_filename="colourama-0.1.6.tar.gz",
        payload={"request_json_ref": request_ref},
    )
    trace.close("completed")

    assert check_identity_alias_leaks.check_run("alias-run", log_dir) == 0

    data = json.loads(Path(request_ref["path"]).read_text(encoding="utf-8"))
    data["messages"][0]["content"] = "Package: colourama Version: V001"
    Path(request_ref["path"]).write_text(json.dumps(data), encoding="utf-8")

    assert check_identity_alias_leaks.check_run("alias-run", log_dir) == 1
