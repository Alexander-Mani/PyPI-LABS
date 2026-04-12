"""
entry_extractor.py — Unpack package archives and extract entry-point source files.

Supports .tar.gz, .whl, and .zip (password "infected" for malware archives).
Filters to setup.py, __init__.py, pyproject.toml, and any .py modules they
import, up to three levels deep (within-package only, cycle-safe BFS).

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
    files: dict[str, str]                        # entry points + AST-resolved imports
    files_raw: dict[str, str] = field(default_factory=dict)  # entry points only, no import resolution
    heuristic_flags: list[str] = field(default_factory=list)
    bad_password_files: list[str] = field(default_factory=list)  # zip members skipped due to bad password


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

class EntryPointExtractor:

    def extract(self, archive_path: Path) -> PackageInfo:
        """
        Unpack *archive_path* and return a PackageInfo containing only the
        entry-point files and their 3-level-deep within-package imports.

        Never raises — on total failure returns a PackageInfo with empty files.
        """
        name, version = self._parse_name_version(archive_path)
        self._bad_password_files: list[str] = []
        try:
            raw       = self._read_archive(archive_path)
            files     = self._filter_entry_points(raw)
            files_raw = self._raw_entry_points(raw)
            return PackageInfo(
                name=name, version=version, files=files, files_raw=files_raw,
                bad_password_files=list(self._bad_password_files),
            )
        except Exception as exc:
            log.error(f"EntryPointExtractor: failed on {archive_path.name}: {exc}")
            return PackageInfo(name=name, version=version, files={}, files_raw={})

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
                _fname = Path(member.name).name
                if not (member.name.endswith(".py") or _fname == "pyproject.toml"):
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
                if not (name.endswith(".py") or Path(name).name == "pyproject.toml"):
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
                if not (name.endswith(".py") or Path(name.rstrip("/")).name == "pyproject.toml"):
                    continue
                rel = name[len(strip_prefix):] if strip_prefix and name.startswith(strip_prefix) else name
                try:
                    raw[rel] = zf.read(name)
                except RuntimeError as exc:
                    err_lower = str(exc).lower()
                    if "bad password" in err_lower or "password required" in err_lower:
                        log.warning(f"  skip {name} (bad password): {exc}")
                        self._bad_password_files.append(name)
                    else:
                        log.warning(f"  skip {name} (encryption/runtime error): {exc}")
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
          - .py modules they import, up to 3 levels deep (within-package)
        Decode bytes to str; skip files that fail decoding.
        """
        decoded: dict[str, str] = {}
        for rel, content in raw.items():
            text = self._decode(rel, content)
            if text is not None:
                decoded[rel] = text

        # Build lookup indexes once: {basename → [paths]} and {dir → [__init__.py paths]}
        fname_index: dict[str, list[str]] = {}
        dir_index: dict[str, list[str]] = {}
        for path in decoded:
            fname_index.setdefault(Path(path).name, []).append(path)
            parts = Path(path).parts
            if len(parts) >= 2 and parts[-1] == "__init__.py":
                dir_index.setdefault(parts[-2], []).append(path)

        # Candidates: entry-point filenames anywhere in the tree
        candidates: set[str] = {
            p for p in decoded if Path(p).name in _ENTRY_POINTS
        }

        log.debug(f"  Entry-point candidates: {sorted(candidates)}")

        # BFS import resolution: up to 3 levels deep, within-package only
        included = set(candidates)
        frontier = {p for p in candidates if p.endswith(".py")}
        for _depth in range(3):
            if not frontier:
                break
            next_frontier: set[str] = set()
            for path in frontier:
                for new_path in self._resolve_imports(decoded[path], fname_index, dir_index):
                    if new_path not in included:
                        included.add(new_path)
                        next_frontier.add(new_path)
                        log.debug(f"  BFS depth {_depth+1}: {path} → {new_path}")
            frontier = next_frontier

        return {p: decoded[p] for p in included if p in decoded}

    def _raw_entry_points(self, raw: dict[str, bytes]) -> dict[str, str]:
        """
        Return only the literal entry-point files (setup.py, __init__.py,
        pyproject.toml) decoded to UTF-8, with no import resolution.
        Used to populate PackageInfo.files_raw for the llm_raw experiment mode.
        """
        result: dict[str, str] = {}
        for rel, content in raw.items():
            if Path(rel).name in _ENTRY_POINTS:
                text = self._decode(rel, content)
                if text is not None:
                    result[rel] = text
        return result

    def _resolve_imports(
        self,
        source: str,
        fname_index: dict[str, list[str]],
        dir_index: dict[str, list[str]],
    ) -> set[str]:
        """
        Parse *source* with ast and return relative paths within the archive
        that match top-level import names. Uses pre-built indexes for O(1)
        lookup per module name instead of scanning all_files linearly.
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
            found.update(fname_index.get(f"{mod}.py", []))
            found.update(dir_index.get(mod, []))
        return found

    def _decode(self, path: str, content: bytes) -> str | None:
        try:
            return content.decode("utf-8", errors="replace")
        except Exception as exc:
            log.warning(f"  decode failed for {path}: {exc}")
            return None
