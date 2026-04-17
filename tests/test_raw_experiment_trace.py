"""Trace integration tests for extractor and controller instrumentation."""

from __future__ import annotations

import io
import json
import sys
import tarfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from adapters import EvalDetectionResult  # noqa: E402
from detection_controller import EvalController  # noqa: E402
from entry_extractor import EntryPointExtractor, PackageInfo  # noqa: E402
from raw_experiment_log import RawExperimentLog  # noqa: E402


def _events(trace: RawExperimentLog) -> list[dict]:
    return [json.loads(line) for line in trace.path.read_text(encoding="utf-8").splitlines()]


def _make_targz(path: Path, members: dict[str, str]) -> Path:
    with tarfile.open(path, "w:gz") as tf:
        for rel, content in members.items():
            data = content.encode("utf-8")
            info = tarfile.TarInfo(name=f"demo-1.0.0/{rel}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return path


def test_extractor_emits_raw_member_and_selection_events(tmp_path):
    archive = _make_targz(
        tmp_path / "demo-1.0.0.tar.gz",
        {
            "setup.py": "import payload\n",
            "payload.py": "print('payload')\n",
            "README.md": "ignored\n",
        },
    )
    trace = RawExperimentLog("run-1", tmp_path / "logs")

    pkg = EntryPointExtractor().extract(
        archive,
        raw_log=trace,
        trace_context={"package": "demo", "version": "1.0.0", "artifact_filename": archive.name},
    )
    seen = _events(trace)

    assert "payload.py" in {Path(path).name for path in pkg.files}
    assert {event["event"] for event in seen} >= {
        "extract.archive.open",
        "extract.archive.members",
        "extract.archive.candidates",
        "extract.file.decoded",
        "extract.entrypoint.selection",
    }
    selection = next(event for event in seen if event["event"] == "extract.entrypoint.selection")
    assert "setup.py" in selection["payload"]["files"]
    assert any(edge["to"] == "payload.py" for edge in selection["payload"]["import_edges"])


class _FakeDB:
    def __init__(self):
        self.rows = []

    def insert_eval_result(self, **kwargs):
        self.rows.append(kwargs)
        return len(self.rows)


class _FakeAdapter:
    _tool = "fake_static"
    _experiment_mode = "static"

    def run(self, pkg, strategy, system_prompt, template_override, *, raw_log=None, trace_context=None):
        if raw_log is not None:
            raw_log.emit("fake.raw", **(trace_context or {}), payload={"files": sorted(pkg.files)})
        return EvalDetectionResult(
            detector="fake_static",
            experiment_mode="static",
            verdict=True,
            confidence=None,
            heuristic_flags=list(pkg.heuristic_flags),
            exec_time_ms=5,
            api_cost_usd=0.0,
            details={"raw": "ok"},
        )


def test_controller_emits_schedule_result_and_db_events(tmp_path):
    trace = RawExperimentLog("run-1", tmp_path / "logs")
    db = _FakeDB()
    controller = EvalController.__new__(EvalController)
    controller._db = db
    controller._static = [_FakeAdapter()]
    controller._llm = []
    controller._llm_raw = []
    controller._agentic = []
    pkg = PackageInfo(
        name="demo",
        version="1.0.0",
        files={"setup.py": "print('x')\n"},
        files_raw={"setup.py": "print('x')\n"},
    )

    controller.run(
        run_id="run-1",
        pkg=pkg,
        ground_truth=True,
        sast_only=True,
        artifact_filename="demo-1.0.0.tar.gz",
        artifact_url="http://127.0.0.1:8080/packages/demo/demo-1.0.0.tar.gz",
        source_index_url="http://127.0.0.1:8080/simple/demo/",
        raw_log=trace,
        quiet_console=True,
    )
    seen = _events(trace)

    assert [row["detector"] for row in db.rows] == ["fake_static"]
    assert {event["event"] for event in seen} >= {
        "detector.schedule",
        "fake.raw",
        "detector.result",
        "db.insert_eval_result",
    }
    db_event = next(event for event in seen if event["event"] == "db.insert_eval_result")
    assert db_event["payload"]["row_id"] == 1
    assert db_event["payload"]["fields"]["artifact_filename"] == "demo-1.0.0.tar.gz"
