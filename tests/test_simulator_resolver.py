"""
Regression tests for simulator-backed artifact resolution.
"""

from __future__ import annotations

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "src" / "analyzer"))

from simulator_resolver import SimulatorResolver  # noqa: E402


class _FakeResponse:
    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self) -> bytes:
        return self._body


def test_resolver_uses_pep440_for_latest_labelled_version(monkeypatch, tmp_path):
    html = b"""
    <a href="/packages/pkg/pkg-0.1.2.tar.gz">pkg-0.1.2.tar.gz</a>
    <a href="/packages/pkg/pkg-0.1.10.tar.gz">pkg-0.1.10.tar.gz</a>
    <a href="/packages/pkg/pkg-1.0.0a1.tar.gz">pkg-1.0.0a1.tar.gz</a>
    """

    def fake_urlopen(url, timeout):
        assert url == "http://127.0.0.1:8080/simple/pkg/"
        assert timeout == 20
        return _FakeResponse(html)

    import simulator_resolver

    monkeypatch.setattr(simulator_resolver, "urlopen", fake_urlopen)
    resolver = SimulatorResolver("http://127.0.0.1:8080", tmp_path)

    artifacts = resolver.list_project_artifacts("pkg")
    selected = resolver.select_versions({a.version for a in artifacts})

    assert selected == ["0.1.10"]


def test_resolver_selects_pip_like_wheel_plus_sdist(tmp_path):
    resolver = SimulatorResolver("http://127.0.0.1:8080", tmp_path)
    artifacts = [
        resolver_artifact("pkg", "1.0.0", "pkg-1.0.0-cp310-cp310-manylinux_x86_64.whl", "wheel"),
        resolver_artifact("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl", "wheel"),
        resolver_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", "sdist"),
    ]

    assert [a.filename for a in resolver.select_artifacts(artifacts, policy="pip")] == [
        "pkg-1.0.0-py3-none-any.whl"
    ]
    assert [a.filename for a in resolver.select_artifacts(artifacts, policy="pip+sdist")] == [
        "pkg-1.0.0-py3-none-any.whl",
        "pkg-1.0.0.tar.gz",
    ]
    assert [a.filename for a in resolver.select_artifacts(artifacts, policy="sdist")] == [
        "pkg-1.0.0.tar.gz"
    ]


def test_resolver_selects_all_artifacts_for_canonical_policy(tmp_path):
    resolver = SimulatorResolver("http://127.0.0.1:8080", tmp_path)
    artifacts = [
        resolver_artifact("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl", "wheel"),
        resolver_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", "sdist"),
        resolver_artifact("pkg", "1.0.0", "pkg-1.0.0-cp311-cp311-linux.whl", "wheel"),
    ]

    assert [a.filename for a in resolver.select_artifacts(artifacts, policy="all")] == [
        "pkg-1.0.0.tar.gz",
        "pkg-1.0.0-cp311-cp311-linux.whl",
        "pkg-1.0.0-py3-none-any.whl",
    ]


def test_resolver_downloads_artifact_without_pip(monkeypatch, tmp_path):
    import simulator_resolver

    def fake_urlopen(url, timeout):
        assert url == "http://127.0.0.1:8080/packages/pkg/pkg-1.0.0.tar.gz"
        return _FakeResponse(b"archive-bytes")

    monkeypatch.setattr(simulator_resolver, "urlopen", fake_urlopen)
    resolver = SimulatorResolver("http://127.0.0.1:8080", tmp_path)
    artifact = resolver_artifact("pkg", "1.0.0", "pkg-1.0.0.tar.gz", "sdist")

    downloaded = resolver.download_artifact(artifact)

    assert downloaded == tmp_path / "pkg" / "1.0.0" / "pkg-1.0.0.tar.gz"
    assert downloaded.read_bytes() == b"archive-bytes"


def resolver_artifact(project: str, version: str, filename: str, kind: str):
    from simulator_resolver import IndexArtifact

    return IndexArtifact(
        project=project,
        version=version,
        filename=filename,
        url=f"http://127.0.0.1:8080/packages/{project}/{filename}",
        kind=kind,
    )
