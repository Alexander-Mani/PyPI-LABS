"""
simulator_resolver.py - Resolve and download bounded artifacts from the local
PyPI simulator without installing or executing packages.

The resolver treats the simulator's PEP 503 /simple/ index as the source of
truth for artifact bytes. It deliberately uses direct HTTP GETs instead of pip
so dependency resolution cannot escape the local, iptables-restricted VM.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urldefrag, urljoin, urlparse
from urllib.request import urlopen

from packaging.tags import sys_tags
from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from src.utils.logger import get_logger

log = get_logger()

DIST_SUFFIXES = (".whl", ".tar.gz", ".tar.bz2", ".tar.xz", ".zip")
SDIST_SUFFIX_PRIORITY = {".tar.gz": 0, ".zip": 1, ".tar.bz2": 2, ".tar.xz": 3}
STEM_RE = re.compile(r"^(.+?)-(\d[^-]*)(?:-.*)?$")


@dataclass(frozen=True)
class IndexArtifact:
    project: str
    version: str
    filename: str
    url: str
    kind: str  # "wheel" or "sdist"

    @property
    def is_sdist(self) -> bool:
        return self.kind == "sdist"


@dataclass(frozen=True)
class ResolvedSample:
    archive_path: Path
    package_name: str
    version: str
    ground_truth: bool
    artifact_filename: str
    artifact_url: str
    source_index_url: str
    sample_role: str
    attack_vector: str | None
    resolver_policy: str


class SimpleIndexError(RuntimeError):
    """Raised when the simulator index cannot be queried or parsed."""


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)


def normalize_project_name(name: str) -> str:
    return str(canonicalize_name(name))


def dist_suffix(filename: str) -> str | None:
    lower = filename.lower()
    for suffix in DIST_SUFFIXES:
        if lower.endswith(suffix):
            return suffix
    return None


def strip_dist_suffix(filename: str) -> str:
    suffix = dist_suffix(filename)
    if suffix:
        return filename[: -len(suffix)]
    return Path(filename).stem


def parse_archive_name_version(filename: str) -> tuple[str, str] | None:
    """Return normalized (project, version) for a wheel/sdist filename."""
    try:
        if filename.endswith(".whl"):
            name, version, *_ = parse_wheel_filename(filename)
        else:
            name, version = parse_sdist_filename(filename)
        return normalize_project_name(str(name)), str(version)
    except (InvalidSdistFilename, InvalidWheelFilename, ValueError):
        pass

    match = STEM_RE.match(strip_dist_suffix(filename))
    if match:
        return normalize_project_name(match.group(1)), match.group(2)
    return None


def _parsed_version(version: str) -> Version | None:
    try:
        return Version(version)
    except InvalidVersion:
        return None


def _sdist_sort_key(artifact: IndexArtifact) -> tuple[int, str]:
    suffix = dist_suffix(artifact.filename) or ""
    return SDIST_SUFFIX_PRIORITY.get(suffix, 99), artifact.filename


def _wheel_score(artifact: IndexArtifact) -> tuple[int, str]:
    """
    Lower is better. Prefer universal wheels, then wheels compatible with the
    current interpreter/platform, then deterministic filename order.
    """
    lower = artifact.filename.lower()
    if lower.endswith("-py3-none-any.whl") or lower.endswith("-py2.py3-none-any.whl"):
        return 0, artifact.filename

    try:
        _, _, _, wheel_tags = parse_wheel_filename(artifact.filename)
        if set(wheel_tags).intersection(sys_tags()):
            return 1, artifact.filename
    except (InvalidWheelFilename, ValueError):
        # Non-canonical wheel tags still appear in historical malware datasets.
        pass

    return 2, artifact.filename


class SimulatorResolver:
    """Resolve bounded package/version/artifact samples from the simulator."""

    def __init__(self, base_url: str, cache_dir: Path, timeout: int = 20, raw_log=None):
        self.base_url = base_url.rstrip("/")
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.raw_log = raw_log

    def project_index_url(self, project: str) -> str:
        return f"{self.base_url}/simple/{normalize_project_name(project)}/"

    def list_project_artifacts(self, project: str) -> list[IndexArtifact]:
        index_url = self.project_index_url(project)
        if self.raw_log is not None:
            self.raw_log.emit(
                "resolver.project_index.request",
                project=normalize_project_name(project),
                payload={"url": index_url, "timeout": self.timeout},
            )
        try:
            with urlopen(index_url, timeout=self.timeout) as resp:
                body = resp.read()
                status = getattr(resp, "status", None)
                headers = dict(getattr(resp, "headers", {}) or {})
                html = body.decode("utf-8", errors="replace")
        except HTTPError as exc:
            if self.raw_log is not None:
                self.raw_log.emit(
                    "resolver.project_index.error",
                    project=normalize_project_name(project),
                    payload={"url": index_url, "status": exc.code, "error": str(exc)},
                )
            if exc.code == 404:
                log.warning(f"Simulator project missing: {project} ({index_url})")
                return []
            raise SimpleIndexError(f"Could not query simulator index {index_url}: {exc}") from exc
        except URLError as exc:
            if self.raw_log is not None:
                self.raw_log.emit(
                    "resolver.project_index.error",
                    project=normalize_project_name(project),
                    payload={"url": index_url, "error": str(exc)},
                )
            raise SimpleIndexError(f"Could not query simulator index {index_url}: {exc}") from exc

        parser = _AnchorParser()
        parser.feed(html)
        if self.raw_log is not None:
            self.raw_log.emit(
                "resolver.project_index.response",
                project=normalize_project_name(project),
                payload={
                    "url": index_url,
                    "status": status,
                    "headers": headers,
                    "html_ref": self.raw_log.blob_text(
                        "simulator_simple_index_html", html, suffix=".html"
                    ),
                    "hrefs": list(parser.hrefs),
                },
            )

        artifacts: list[IndexArtifact] = []
        for href in parser.hrefs:
            clean_href, _ = urldefrag(href)
            artifact_url = urljoin(index_url, clean_href)
            filename = unquote(Path(urlparse(artifact_url).path).name)
            suffix = dist_suffix(filename)
            if suffix is None:
                continue
            parsed = parse_archive_name_version(filename)
            if parsed is None:
                log.warning(f"Skipping unparseable simulator artifact: {artifact_url}")
                continue
            parsed_name, version = parsed
            if parsed_name != normalize_project_name(project):
                log.debug(
                    f"Artifact name {parsed_name} differs from project {project}: {filename}"
                )
            artifacts.append(IndexArtifact(
                project=normalize_project_name(project),
                version=version,
                filename=filename,
                url=artifact_url,
                kind="wheel" if suffix == ".whl" else "sdist",
            ))

        return sorted(artifacts, key=lambda a: (a.version, a.kind, a.filename))

    def select_versions(
        self,
        versions: set[str],
        *,
        count: int = 1,
        extra_versions: set[str] | None = None,
    ) -> list[str]:
        """
        Select the latest stable PEP 440 version(s).
        Pre-releases are ignored unless no stable release exists.
        """
        parsed: list[tuple[Version, str]] = []
        invalid: list[str] = []
        for version in versions:
            parsed_version = _parsed_version(version)
            if parsed_version is None:
                invalid.append(version)
                continue
            parsed.append((parsed_version, version))

        if invalid:
            log.warning(f"Skipping invalid version(s): {sorted(invalid)}")
        if not parsed:
            return []

        stable = [(pv, raw) for pv, raw in parsed if not pv.is_prerelease]
        candidate_versions = stable if stable else parsed
        ordered = [raw for _, raw in sorted(candidate_versions, key=lambda item: item[0], reverse=True)]
        selected: list[str] = ordered[:count]

        for extra in sorted(extra_versions or set(), key=lambda v: _parsed_version(v) or Version("0"), reverse=True):
            if extra in versions and extra not in selected:
                selected.append(extra)

        return selected

    def select_artifacts(
        self,
        artifacts: list[IndexArtifact],
        *,
        policy: str = "all",
    ) -> list[IndexArtifact]:
        if not artifacts:
            return []

        if policy == "all":
            return sorted(artifacts, key=lambda a: (a.kind, a.filename))

        wheels = sorted((a for a in artifacts if a.kind == "wheel"), key=_wheel_score)
        sdists = sorted((a for a in artifacts if a.kind == "sdist"), key=_sdist_sort_key)

        if policy == "sdist":
            return sdists[:1] or wheels[:1]
        if policy == "pip":
            return (wheels[:1] or sdists[:1])
        if policy != "pip+sdist":
            raise ValueError(f"Unsupported artifact policy: {policy}")

        selected: list[IndexArtifact] = []
        selected.extend(wheels[:1] or sdists[:1])
        if sdists and all(item.filename != sdists[0].filename for item in selected):
            selected.append(sdists[0])
        return selected

    def download_artifact(self, artifact: IndexArtifact) -> Path:
        project_dir = self.cache_dir / artifact.project / artifact.version
        project_dir.mkdir(parents=True, exist_ok=True)
        dest = project_dir / artifact.filename
        if self.raw_log is not None:
            self.raw_log.emit(
                "artifact.download.request",
                package=artifact.project,
                version=artifact.version,
                artifact_filename=artifact.filename,
                payload={"url": artifact.url, "cache_path": dest, "timeout": self.timeout},
            )
        if dest.exists() and dest.stat().st_size > 0:
            data = dest.read_bytes()
            if self.raw_log is not None:
                self.raw_log.emit(
                    "artifact.download.response",
                    package=artifact.project,
                    version=artifact.version,
                    artifact_filename=artifact.filename,
                    payload={
                        "cache_hit": True,
                        "path": dest,
                        "bytes": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                )
            return dest

        try:
            with urlopen(artifact.url, timeout=self.timeout) as resp:
                data = resp.read()
                status = getattr(resp, "status", None)
                headers = dict(getattr(resp, "headers", {}) or {})
                dest.write_bytes(data)
        except (HTTPError, URLError) as exc:
            if self.raw_log is not None:
                self.raw_log.emit(
                    "artifact.download.error",
                    package=artifact.project,
                    version=artifact.version,
                    artifact_filename=artifact.filename,
                    payload={"url": artifact.url, "error": str(exc)},
                )
            raise SimpleIndexError(f"Could not download {artifact.url}: {exc}") from exc
        if self.raw_log is not None:
            self.raw_log.emit(
                "artifact.download.response",
                package=artifact.project,
                version=artifact.version,
                artifact_filename=artifact.filename,
                payload={
                    "cache_hit": False,
                    "url": artifact.url,
                    "status": status,
                    "headers": headers,
                    "path": dest,
                    "bytes": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                },
            )
        return dest
