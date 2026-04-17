"""Tests for the raw experiment flight recorder."""

from __future__ import annotations

import json
import threading

from src.analyzer.raw_experiment_log import RawExperimentLog


def _read_events(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_raw_experiment_log_writes_jsonl_and_blobs(tmp_path):
    trace = RawExperimentLog("run-1", tmp_path)
    blob = trace.blob_text("prompt", "hello world", suffix=".txt")
    trace.emit("llm.request", payload={"input_tokens": 12, "blob": blob})
    trace.close("completed", payload={"db_result_rows": 1})

    events = _read_events(trace.path)

    assert [event["seq"] for event in events] == [1, 2]
    assert events[0]["event"] == "llm.request"
    assert events[0]["payload"]["input_tokens"] == 12
    assert events[1]["event"] == "run.done"
    assert events[1]["payload"]["status"] == "completed"
    assert isinstance(events[1]["payload"]["blob_bytes"], int)
    assert blob["sha256"] in blob["path"]
    assert trace.blob_dir.joinpath(blob["path"].split("/")[-1]).read_text(encoding="utf-8") == "hello world"


def test_raw_experiment_log_redacts_secret_like_fields_but_not_token_counts(tmp_path):
    trace = RawExperimentLog("run-1", tmp_path)
    trace.emit(
        "event",
        payload={
            "Authorization": "Bearer secret",
            "OPENAI_API_KEY": "sk-secret",
            "input_tokens": 3,
            "output_tokens": 4,
            "message": "X_API_KEY=supersecret safe",
        },
    )

    event = _read_events(trace.path)[0]

    assert event["payload"]["Authorization"] == "<redacted>"
    assert event["payload"]["OPENAI_API_KEY"] == "<redacted>"
    assert event["payload"]["input_tokens"] == 3
    assert event["payload"]["output_tokens"] == 4
    assert "supersecret" not in event["payload"]["message"]


def test_raw_experiment_log_is_thread_safe(tmp_path):
    trace = RawExperimentLog("run-1", tmp_path)

    def worker(offset):
        for i in range(20):
            trace.emit("thread.event", payload={"value": offset + i})

    threads = [threading.Thread(target=worker, args=(i * 100,)) for i in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    events = _read_events(trace.path)

    assert len(events) == 80
    assert [event["seq"] for event in events] == list(range(1, 81))
