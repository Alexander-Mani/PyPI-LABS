"""
diff.py — Diffing engine for consecutive package versions.

Extracts and unpacks consecutive package versions from the simulator,
computes static code diffs between previous and current versions,
normalises diffs to a consistent representation for downstream analysis,
and filters out unchanged files and non-code artifacts.
"""

import difflib
import io
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FileDiff:
    """Unified diff for a single file between two versions."""
    path: str
    status: str          # "added" | "modified" | "removed"
    unified_diff: str    # raw unified diff text (empty for added/removed)
    added_lines: list[str] = field(default_factory=list)
    removed_lines: list[str] = field(default_factory=list)


@dataclass
class PackageDiff:
    """Complete diff result between two consecutive package versions."""
    project: str
    version_before: str
    version_after: str
    file_diffs: list[FileDiff] = field(default_factory=list)

    @property
    def changed_files(self) -> list[FileDiff]:
        return [f for f in self.file_diffs if f.status != "unchanged"]


# ---------------------------------------------------------------------------
# PackageExtractor
# ---------------------------------------------------------------------------

_CODE_EXTENSIONS = {".py", ".pyx", ".pxd", ".pxi", ".cfg", ".toml", ".txt"}


class PackageExtractor:
    """
    Extracts source files from a .tar.gz or .whl distribution archive.
    Returns a dict mapping normalised file paths -> file content (bytes).
    """

    def extract(self, archive_path: Path) -> dict[str, bytes]:
        suffix = archive_path.suffix.lower()
        if suffix == ".gz" or archive_path.name.endswith(".tar.gz"):
            return self._extract_tar(archive_path)
        if suffix == ".whl":
            return self._extract_wheel(archive_path)
        raise ValueError(f"Unsupported archive format: {archive_path.name}")

    def _extract_tar(self, path: Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        with tarfile.open(str(path), "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                p = Path(member.name)
                if p.suffix not in _CODE_EXTENSIONS:
                    continue
                f = tar.extractfile(member)
                if f:
                    # Strip the top-level directory (e.g. "pkg-1.0.0/")
                    rel = "/".join(p.parts[1:]) if len(p.parts) > 1 else str(p)
                    files[rel] = f.read()
        return files

    def _extract_wheel(self, path: Path) -> dict[str, bytes]:
        files: dict[str, bytes] = {}
        with zipfile.ZipFile(str(path), "r") as zf:
            for name in zf.namelist():
                p = Path(name)
                if p.suffix not in _CODE_EXTENSIONS:
                    continue
                # Skip .dist-info metadata
                if ".dist-info" in name:
                    continue
                files[name] = zf.read(name)
        return files


# ---------------------------------------------------------------------------
# DiffParser
# ---------------------------------------------------------------------------

class DiffParser:
    """
    Computes a normalised FileDiff between two versions of the same file.
    """

    def diff(
        self,
        path: str,
        before: bytes | None,
        after: bytes | None,
    ) -> FileDiff:
        if before is None and after is not None:
            return FileDiff(
                path=path,
                status="added",
                unified_diff="",
                added_lines=after.decode(errors="replace").splitlines(),
            )
        if before is not None and after is None:
            return FileDiff(
                path=path,
                status="removed",
                unified_diff="",
                removed_lines=before.decode(errors="replace").splitlines(),
            )

        before_lines = before.decode(errors="replace").splitlines(keepends=True)
        after_lines = after.decode(errors="replace").splitlines(keepends=True)

        diff_lines = list(
            difflib.unified_diff(before_lines, after_lines, fromfile=path, tofile=path)
        )

        if not diff_lines:
            return FileDiff(path=path, status="unchanged", unified_diff="")

        added = [l[1:].rstrip("\n") for l in diff_lines if l.startswith("+") and not l.startswith("+++")]
        removed = [l[1:].rstrip("\n") for l in diff_lines if l.startswith("-") and not l.startswith("---")]

        return FileDiff(
            path=path,
            status="modified",
            unified_diff="".join(diff_lines),
            added_lines=added,
            removed_lines=removed,
        )


# ---------------------------------------------------------------------------
# DiffEngine
# ---------------------------------------------------------------------------

class DiffEngine:
    """
    Orchestrates extraction and diffing of two consecutive package versions.

    Usage::

        engine = DiffEngine()
        diff = engine.compute(project="requests",
                              path_before=Path("requests-2.31.0.tar.gz"),
                              path_after=Path("requests-2.32.0.tar.gz"),
                              version_before="2.31.0",
                              version_after="2.32.0")
    """

    def __init__(self):
        self._extractor = PackageExtractor()
        self._parser = DiffParser()

    def compute(
        self,
        project: str,
        path_before: Path,
        path_after: Path,
        version_before: str,
        version_after: str,
    ) -> PackageDiff:
        files_before = self._extractor.extract(path_before)
        files_after = self._extractor.extract(path_after)

        all_paths = set(files_before) | set(files_after)
        diffs: list[FileDiff] = []

        for p in sorted(all_paths):
            fd = self._parser.diff(
                path=p,
                before=files_before.get(p),
                after=files_after.get(p),
            )
            if fd.status != "unchanged":
                diffs.append(fd)

        return PackageDiff(
            project=project,
            version_before=version_before,
            version_after=version_after,
            file_diffs=diffs,
        )
