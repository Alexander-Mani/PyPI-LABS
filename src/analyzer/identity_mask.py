"""Identity masking helpers for LLM prior-knowledge controls."""

from __future__ import annotations

import re
from dataclasses import dataclass

from entry_extractor import PackageInfo


@dataclass(frozen=True)
class IdentityMaskResult:
    package: PackageInfo
    alias_name: str
    alias_version: str
    replacement_counts: dict[str, int]
    original_terms: list[str]

    def details(self) -> dict:
        return {
            "identity_mask": "alias",
            "alias_probe": True,
            "alias_name": self.alias_name,
            "alias_version": self.alias_version,
            "alias_probe_lane": "hybrid_zero_shot",
            "identity_mask_replacements": dict(self.replacement_counts),
        }


def identity_variants(package_name: str) -> list[str]:
    """Return package-name spellings likely to leak public identity."""
    name = package_name.strip()
    if not name:
        return []
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    variants = {
        name,
        name.lower(),
        normalized,
        normalized.replace("-", "_"),
        normalized.replace("-", "."),
    }
    return sorted((v for v in variants if v), key=len, reverse=True)


def _replace_terms(text: str, terms: list[str], replacement: str) -> tuple[str, int]:
    total = 0
    for term in terms:
        if not term:
            continue
        text, count = re.subn(re.escape(term), replacement, text, flags=re.IGNORECASE)
        total += count
    return text, total


def _replace_version_metadata(text: str, version: str, alias_version: str) -> tuple[str, int]:
    """Mask version values in common metadata declarations without rewriting all numbers."""
    if not version or version == "unknown":
        return text, 0
    escaped = re.escape(version)
    patterns = [
        rf"(?im)^(\s*Version:\s*){escaped}(\s*)$",
        rf"(?i)(\bversion\s*=\s*[\"']){escaped}([\"'])",
        rf"(?i)(\bversion\s*:\s*[\"']){escaped}([\"'])",
        rf"(?i)(__version__\s*=\s*[\"']){escaped}([\"'])",
    ]
    total = 0
    for pattern in patterns:
        text, count = re.subn(pattern, rf"\1{alias_version}\2", text)
        total += count
    return text, total


def _mask_file_map(
    files: dict[str, str],
    *,
    name_terms: list[str],
    version: str,
    alias_name: str,
    alias_version: str,
    counts: dict[str, int],
) -> dict[str, str]:
    masked: dict[str, str] = {}
    for path, content in files.items():
        masked_path, path_name_count = _replace_terms(path, name_terms, alias_name)
        counts["path_name"] += path_name_count
        if version and version != "unknown":
            masked_path, path_version_count = re.subn(
                re.escape(version), alias_version, masked_path, flags=re.IGNORECASE
            )
            counts["path_version"] += path_version_count

        masked_content, content_name_count = _replace_terms(content, name_terms, alias_name)
        counts["content_name"] += content_name_count
        masked_content, content_version_count = _replace_version_metadata(
            masked_content, version, alias_version
        )
        counts["content_version"] += content_version_count

        if masked_path in masked and masked[masked_path] != masked_content:
            suffix = 1
            candidate = f"{masked_path}.__alias_collision_{suffix}"
            while candidate in masked:
                suffix += 1
                candidate = f"{masked_path}.__alias_collision_{suffix}"
            masked_path = candidate
            counts["path_collisions"] += 1
        masked[masked_path] = masked_content
    return masked


def mask_package_identity(
    pkg: PackageInfo,
    *,
    alias_name: str,
    alias_version: str,
) -> IdentityMaskResult:
    """Return a PackageInfo copy whose model-visible identity is neutralized."""
    name_terms = identity_variants(pkg.name)
    counts = {
        "path_name": 0,
        "path_version": 0,
        "content_name": 0,
        "content_version": 0,
        "path_collisions": 0,
    }
    masked_files = _mask_file_map(
        pkg.files,
        name_terms=name_terms,
        version=pkg.version,
        alias_name=alias_name,
        alias_version=alias_version,
        counts=counts,
    )
    masked_files_raw = _mask_file_map(
        pkg.files_raw,
        name_terms=name_terms,
        version=pkg.version,
        alias_name=alias_name,
        alias_version=alias_version,
        counts=counts,
    )
    masked_pkg = PackageInfo(
        name=alias_name,
        version=alias_version,
        files=masked_files,
        files_raw=masked_files_raw,
        heuristic_flags=list(pkg.heuristic_flags),
        bad_password_files=list(pkg.bad_password_files),
    )
    original_terms = list(name_terms)
    if pkg.version and pkg.version != "unknown":
        original_terms.append(pkg.version)
    return IdentityMaskResult(
        package=masked_pkg,
        alias_name=alias_name,
        alias_version=alias_version,
        replacement_counts=counts,
        original_terms=original_terms,
    )
