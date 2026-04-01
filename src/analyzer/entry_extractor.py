"""
entry_extractor.py — Unpack package archives and extract entry-point source files.

Supports .tar.gz, .whl, and .zip (password "infected" for malware archives).
Filters to setup.py, __init__.py, pyproject.toml, and any .py modules they
import directly (one level deep, within-package only).

Output is a PackageInfo dataclass consumed by HeuristicFilter and the detection
adapters in detection_controller.py.
"""

from __future__ import annotations

import ast
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from src.utils.logger import get_logger

log = get_logger()

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

_ENTRY_POINTS = frozenset({"setup.py", "__init__.py", "pyproject.toml"})

# Regex to pull name and version out of a canonical PyPI archive stem.
# Handles: pkg-1.0, pkg-name-1.0.0, pkg-1.0-py3-none-any (wheel)
_STEM_RE = re.compile(r"^(.+?)-(\d[^-]*)(?:-.*)?$")


@dataclass
class PackageInfo:
    name: str
    version: str
    files: dict[str, str]           # {relative_path: utf-8 content}
    heuristic_flags: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class EntryPointExtractor:

    def extract(self, archive_path: Path) -> PackageInfo:
        """
        Unpack *archive_path* and return a PackageInfo containing only the
        entry-point files and their 1-level-deep within-package imports.

        Never raises — on total failure returns a PackageInfo with empty files.
        """
        name, version = self._parse_name_version(archive_path)
        try:
            raw = self._read_archive(archive_path)
            files = self._filter_entry_points(raw)
            return PackageInfo(name=name, version=version, files=files)
        except Exception as exc:
            log.error(f"EntryPointExtractor: failed on {archive_path.name}: {exc}")
            return PackageInfo(name=name, version=version, files={})

    # ------------------------------------------------------------------
    # Name / version inference
    # ------------------------------------------------------------------

    def _parse_name_version(self, path: Path) -> tuple[str, str]:
        stem = path.name
        for suffix in (".tar.gz", ".tar.bz2", ".tar.xz"):
            if stem.endswith(suffix):
                stem = stem[: -len(suffix)]
                break
        else:
            stem = Path(stem).stem  # strips last extension (.whl, .zip)

        m = _STEM_RE.match(stem)
        if m:
            return m.group(1), m.group(2)
        # Fallback: treat whole stem as name, version unknown
        return stem, "unknown"

    # ------------------------------------------------------------------
    # Archive readers  →  dict[relative_path, bytes]
    # ------------------------------------------------------------------

    def _read_archive(self, path: Path) -> dict[str, bytes]:
        name = path.name
        if name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            return self._extract_tar(path)
        if name.endswith(".whl"):
            return self._extract_wheel(path)
        if name.endswith(".zip"):
            return self._extract_zip(path)
        raise ValueError(f"Unsupported archive format: {name}")

    def _extract_tar(self, path: Path) -> dict[str, bytes]:
        raw: dict[str, bytes] = {}
        with tarfile.open(path, "r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not member.name.endswith(".py"):
                    continue
                # Strip top-level directory prefix (e.g. "pkg-1.0/setup.py" → "setup.py")
                parts = Path(member.name).parts
                rel = str(Path(*parts[1:])) if len(parts) > 1 else member.name
                try:
                    f = tf.extractfile(member)
                    if f is not None:
                        raw[rel] = f.read()
                except Exception as exc:
                    log.warning(f"  skip {member.name}: {exc}")
        return raw

    def _extract_wheel(self, path: Path) -> dict[str, bytes]:
        raw: dict[str, bytes] = {}
        with zipfile.ZipFile(str(path), "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".py"):
                    continue
                if ".dist-info/" in name or ".data/" in name:
                    continue
                try:
                    raw[name] = zf.read(name)
                except Exception as exc:
                    log.warning(f"  skip {name}: {exc}")
        return raw

    def _extract_zip(self, path: Path) -> dict[str, bytes]:
        """
        Handles password-protected malware archives (password b"infected").
        Falls back to no-password open if the archive is not encrypted.
        """
        raw: dict[str, bytes] = {}
        try:
            zf = zipfile.ZipFile(str(path), "r")
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Bad zip file: {exc}") from exc

        with zf:
            zf.setpassword(b"infected")
            parts_list = zf.namelist()
            # Strip top-level dir if all members share one
            top_dirs = {p.split("/")[0] for p in parts_list if "/" in p}
            strip_prefix = top_dirs.pop() + "/" if len(top_dirs) == 1 else ""

            for name in parts_list:
                if not name.endswith(".py"):
                    continue
                rel = name[len(strip_prefix):] if strip_prefix and name.startswith(strip_prefix) else name
                try:
                    raw[rel] = zf.read(name)
                except RuntimeError as exc:
                    # Bad password or encryption error on this specific file
                    log.warning(f"  skip {name} (password/encryption error): {exc}")
                except Exception as exc:
                    log.warning(f"  skip {name}: {exc}")
        return raw

    # ------------------------------------------------------------------
    # Entry-point filtering + import resolution
    # ------------------------------------------------------------------

    def _filter_entry_points(self, raw: dict[str, bytes]) -> dict[str, str]:
        """
        From the full archive contents, keep only:
          - entry-point files (setup.py, __init__.py, pyproject.toml)
          - .py modules they import directly (1 level, within-package)
        Decode bytes to str; skip files that fail decoding.
        """
        decoded: dict[str, str] = {}
        for rel, content in raw.items():
            text = self._decode(rel, content)
            if text is not None:
                decoded[rel] = text

        # Candidates: entry-point filenames anywhere in the tree
        candidates: set[str] = {
            p for p in decoded if Path(p).name in _ENTRY_POINTS
        }

        # Resolve imports from .py candidates (skip pyproject.toml — it's TOML)
        included = set(candidates)
        for path in candidates:
            if path.endswith(".py"):
                included |= self._resolve_imports(decoded[path], decoded)

        return {p: decoded[p] for p in included if p in decoded}

    def _resolve_imports(self, source: str, all_files: dict[str, str]) -> set[str]:
        """
        Parse *source* with ast and return relative paths within *all_files*
        that correspond to top-level imports (one level deep).
        """
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return set()

        module_names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module:
                module_names.add(node.module.split(".")[0])

        found: set[str] = set()
        for mod in module_names:
            # Check for mod.py or mod/__init__.py anywhere in the archive
            for candidate in all_files:
                fname = Path(candidate).name
                parts = Path(candidate).parts
                if fname == f"{mod}.py":
                    found.add(candidate)
                elif len(parts) >= 2 and parts[-2] == mod and fname == "__init__.py":
                    found.add(candidate)
        return found

    def _decode(self, path: str, content: bytes) -> str | None:
        try:
            return content.decode("utf-8", errors="replace")
        except Exception as exc:
            log.warning(f"  decode failed for {path}: {exc}")
            return None
