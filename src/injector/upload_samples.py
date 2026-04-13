#!/usr/bin/env python3
"""
upload_samples.py — VM-targeted batch uploader for the PyPi-SCADA injector.

Scans a pre-extracted samples directory and uploads all distribution artifacts to the
local simulator via twine. Handles three archive categories:

  benign/   — per-package subdirs of .tar.gz / .whl files from PyPI
  controls/ — same layout; infrastructure packages used as FP baseline
              (benign/controls/ is also accepted as a legacy layout)
  malware_backstabbers_knife/ — extracted malicious bundle containing
                                package/version/.tar.gz or .whl archives;
                                legacy password-protected container zips are
                                also supported during transition

Older versions within a package are uploaded before newer ones so that
the simulator's list_versions() returns them in chronological order.

Usage:
    python upload_samples.py [--samples-dir PATH] [--simulator-url URL]
                             [--only {benign,controls,malicious,all}]
                             [--dry-run]
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Logging — reuse the shared loguru-based logger
# ---------------------------------------------------------------------------

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

# Minimal inline config so setup_logger has what it needs
_LOG_CONFIG = {
    "logging": {
        "file": str(Path(__file__).resolve().parent / "logs" / "upload_samples.log"),
        "level": "INFO",
        "console_output": True,
    }
}

from src.utils.logger import setup_logger, get_logger  # noqa: E402

setup_logger(_LOG_CONFIG)
log = get_logger()

try:
    from packaging.utils import (
        InvalidSdistFilename,
        InvalidWheelFilename,
        canonicalize_name,
        parse_sdist_filename,
        parse_wheel_filename,
    )
except ImportError:  # pragma: no cover - deployment dependency guard
    InvalidSdistFilename = InvalidWheelFilename = ValueError
    canonicalize_name = None
    parse_sdist_filename = parse_wheel_filename = None

# ---------------------------------------------------------------------------
# Version sorting
# ---------------------------------------------------------------------------

def _version_key(path: Path):
    """
    Sort key for archive filenames.  Parses the version segment from the
    filename stem using packaging.version.Version when available; falls back
    to a lexicographic sort so the script never hard-crashes on an
    unrecognised filename format.
    """
    try:
        from packaging.version import Version  # type: ignore
        # Filename formats:
        #   name-VERSION.tar.gz          →  stem = "name-VERSION"
        #   name-VERSION-py3-none-any.whl →  stem = "name-VERSION-py3-none-any"
        # Split on '-' and try each segment as a version string.
        stem = path.stem.replace(".tar", "")  # strip extra .tar from tar.gz stems
        for part in stem.split("-")[1:]:
            try:
                return Version(part)
            except Exception:
                continue
    except ImportError:
        pass
    return path.name  # fallback: lexicographic


# ---------------------------------------------------------------------------
# Twine upload
# ---------------------------------------------------------------------------

_NAME_VER_RE = re.compile(
    r"^([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)-(\d[^-]*)(?:-.*)?$"
)


def _strip_dist_suffix(name: str) -> str:
    for suffix in (".tar.gz", ".tar.bz2", ".tar.xz", ".zip"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return Path(name).stem


def _archive_name_version(archive: Path) -> tuple[str, str] | None:
    """Return normalized (project, version) from a wheel/sdist filename."""
    if parse_sdist_filename is None or parse_wheel_filename is None:
        log.error("Cannot parse archive metadata: packaging is not installed")
        return None

    try:
        if archive.name.endswith(".whl"):
            name, version, *_ = parse_wheel_filename(archive.name)
        else:
            name, version = parse_sdist_filename(archive.name)
        return str(canonicalize_name(str(name))), str(version)
    except (InvalidSdistFilename, InvalidWheelFilename, ValueError) as exc:
        log.warning(
            f"Non-canonical archive filename, trying fallback parse: "
            f"{archive.name} ({exc})"
        )

    match = _NAME_VER_RE.match(_strip_dist_suffix(archive.name))
    if match:
        return str(canonicalize_name(match.group(1))), match.group(2)

    log.error(f"Cannot parse archive name/version from {archive.name}")
    return None


def _simulator_has_artifact(simulator_url: str, name: str, version: str, filename: str) -> bool | None:
    """
    Return True/False if the simulator API can be queried, None if unavailable.
    Idempotency is artifact-level because a PyPI release may legitimately have
    both a wheel and an sdist for the same package version.
    """
    project = urllib.parse.quote(name)
    url = simulator_url.rstrip("/") + f"/api/files/{project}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        log.error(f"Could not query simulator files for {name}: {exc}")
        return None

    files = data.get("files", [])
    return any(
        str(item.get("version")) == version and str(item.get("filename")) == filename
        for item in files
        if isinstance(item, dict)
    )


def _supports_twine_skip_existing(repo_url: str) -> bool:
    return repo_url.startswith((
        "https://upload.pypi.org/legacy/",
        "https://test.pypi.org/legacy/",
    ))


def _twine_upload(archive: Path, simulator_url: str, dry_run: bool) -> str:
    """
    Upload a single archive to the simulator via twine.
    Returns "uploaded", "skipped", or "failed".
    Skips already-uploaded files when the target repository supports
    ``--skip-existing`` (e.g. PyPI/TestPyPI). Local simulator endpoints do not.
    """
    if dry_run:
        log.info(f"[dry-run] would upload {archive.name}")
        return "uploaded"

    repo_url = simulator_url.rstrip("/") + "/legacy/"
    if not _supports_twine_skip_existing(repo_url):
        parsed = _archive_name_version(archive)
        if parsed is None:
            return "failed"
        name, version = parsed

        exists = _simulator_has_artifact(simulator_url, name, version, archive.name)
        if exists is None:
            return "failed"
        if exists:
            log.info(f"Skipped existing: {name}=={version} {archive.name}")
            return "skipped"

    cmd = [
        sys.executable, "-m", "twine", "upload",
        "--repository-url", repo_url,
        "-u", "__token__",
        "-p", "sim-token",
        "--non-interactive",
        str(archive),
    ]

    # Twine rejects --skip-existing for custom repositories (including the local
    # simulator endpoint). Enable it only for Warehouse-hosted endpoints.
    if _supports_twine_skip_existing(repo_url):
        cmd.insert(-2, "--skip-existing")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        log.info(f"Uploaded: {archive.name}")
        return "uploaded"

    # twine may exit non-zero for "already exists" even with --skip-existing
    # on older versions; treat it as success if the message says so.
    combined = result.stdout + result.stderr
    if "already exists" in combined.lower() or "skipping" in combined.lower():
        log.info(f"Skipped (already exists): {archive.name}")
        return "skipped"

    # twine 4+ enforces strict PyPI metadata spec. Very old archives (pre-2012)
    # have metadata version 1.0 but use Classifier: fields from version 1.1.
    # These cannot be fixed without re-packaging; skip them rather than aborting.
    if "invaliddistribution" in combined.lower() or \
            "invalid distribution metadata" in combined.lower():
        log.warning(f"Skipped (invalid legacy metadata, unrecoverable): {archive.name}")
        return "skipped"

    log.error(f"Upload failed: {archive.name}")
    for line in combined.splitlines():
        if line.strip():
            log.error(f"  {line.strip()}")
    return "failed"


# ---------------------------------------------------------------------------
# Benign / controls pass
# ---------------------------------------------------------------------------

ARCHIVE_SUFFIXES = {".whl", ".gz"}  # .zip excluded — causes noisy twine failures
DIST_ARCHIVE_SUFFIXES = (".whl", ".tar.gz", ".tar.bz2", ".tar.xz", ".zip")


def _is_package_archive(path: Path) -> bool:
    return path.suffix in ARCHIVE_SUFFIXES and path.is_file()


def _is_dist_archive(path: Path) -> bool:
    return path.is_file() and path.name.endswith(DIST_ARCHIVE_SUFFIXES)


def _is_staged_malware_archive(path: Path, malware_dir: Path) -> bool:
    if not _is_dist_archive(path):
        return False
    # A top-level zip is treated as a legacy password-protected container, not a
    # direct package archive. Nested zip sdists from the extracted bundle are OK.
    return not (path.suffix == ".zip" and path.parent == malware_dir)


def _upload_flat_category(category_dir: Path, simulator_url: str, dry_run: bool) -> tuple[int, int, int]:
    """
    Walk category_dir/  (benign/ or controls/).
    Expected layout:
        category_dir/
          <package-name>/
            <archive-file>
            <archive-file>
            ...

    Archives within each package dir are sorted by version (oldest first)
    before uploading.

    Returns (uploaded_count, skipped_count, failure_count).
    """
    if not category_dir.exists():
        log.warning(f"Directory not found, skipping: {category_dir}")
        return 0, 0, 0

    uploaded = skipped = failure = 0

    package_dirs = sorted(p for p in category_dir.iterdir() if p.is_dir())
    log.info(f"Scanning {category_dir.name}/: {len(package_dirs)} package(s)")

    for pkg_dir in package_dirs:
        archives = sorted(
            (f for f in pkg_dir.iterdir() if _is_package_archive(f)),
            key=_version_key,
        )
        if not archives:
            log.debug(f"No archives in {pkg_dir.name}, skipping")
            continue

        log.info(f"  {pkg_dir.name}: {len(archives)} archive(s)")
        for archive in archives:
            result = _twine_upload(archive, simulator_url, dry_run)
            if result == "uploaded":
                uploaded += 1
            elif result == "skipped":
                skipped += 1
            else:
                failure += 1

    return uploaded, skipped, failure


# ---------------------------------------------------------------------------
# Malicious pass
# ---------------------------------------------------------------------------

_MALICIOUS_PASSWORD = b"infected"
_STAGING_ROOT = Path("/tmp/pypi-scada-staging")


def _extract_malicious_zip(zip_path: Path) -> Path | None:
    """
    Extract a password-protected malicious zip to a unique tmpfs staging dir.
    Returns the path to the first inner .tar.gz or .whl found, or None if
    no suitable archive is located.

    The caller is responsible for cleaning up the staging dir.
    """
    staging_dir = _STAGING_ROOT / str(uuid.uuid4())
    staging_dir.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(path=staging_dir, pwd=_MALICIOUS_PASSWORD)
    except zipfile.BadZipFile:
        log.error(f"BadZipFile: {zip_path.name} — not a valid zip archive")
        shutil.rmtree(staging_dir, ignore_errors=True)
        return None
    except RuntimeError as exc:
        log.error(f"Extraction failed for {zip_path.name}: {exc}")
        shutil.rmtree(staging_dir, ignore_errors=True)
        return None

    # Find the inner package archive (prefer .whl, then .tar.gz, then .zip)
    for suffix in (".whl", ".tar.gz", ".zip"):
        matches = list(staging_dir.rglob(f"*{suffix}"))
        if matches:
            return matches[0]

    log.warning(f"No inner package archive found in {zip_path.name}")
    shutil.rmtree(staging_dir, ignore_errors=True)
    return None


def _count_upload_result(result: str) -> tuple[int, int, int]:
    if result == "uploaded":
        return 1, 0, 0
    if result == "skipped":
        return 0, 1, 0
    return 0, 0, 1


def _upload_malicious_category(malicious_dir: Path, simulator_url: str, dry_run: bool) -> tuple[int, int, int]:
    """
    Upload malicious distribution artifacts staged under malware_backstabbers_knife/.
    The preferred deployment format is an extracted encrypted bundle containing
    package/version/*.whl or package/version/*.tar.gz files. Legacy individual
    password-protected container zips are still supported during transition.

    Returns (uploaded_count, skipped_count, failure_count).
    """
    if not malicious_dir.exists():
        log.warning(f"Directory not found, skipping: {malicious_dir}")
        return 0, 0, 0

    dist_archives = sorted(
        p for p in malicious_dir.rglob("*")
        if _is_staged_malware_archive(p, malicious_dir)
    )
    legacy_zips = sorted(p for p in malicious_dir.glob("*.zip") if p.is_file())
    log.info(
        f"Scanning malware_backstabbers_knife/: "
        f"{len(dist_archives)} distribution artifact(s), {len(legacy_zips)} legacy zip(s)"
    )

    uploaded = skipped = failure = 0

    for archive in dist_archives:
        log.info(f"  Uploading: {archive.relative_to(malicious_dir)}")
        if dry_run:
            log.info(f"  [dry-run] would upload {archive.name}")
            uploaded += 1
            continue

        result = _twine_upload(archive, simulator_url, dry_run)
        up, sk, fail = _count_upload_result(result)
        uploaded += up
        skipped += sk
        failure += fail

    for zip_path in legacy_zips:
        log.info(f"  Extracting: {zip_path.name}")

        if dry_run:
            log.info(f"  [dry-run] would extract and upload from {zip_path.name}")
            uploaded += 1
            continue

        inner = _extract_malicious_zip(zip_path)
        if inner is None:
            failure += 1
            continue

        staging_dir = inner.parent
        # Walk up to find the actual staging root we own
        while staging_dir.parent != _STAGING_ROOT and staging_dir != _STAGING_ROOT:
            staging_dir = staging_dir.parent

        result = _twine_upload(inner, simulator_url, dry_run)
        up, sk, fail = _count_upload_result(result)
        uploaded += up
        skipped += sk
        failure += fail

        shutil.rmtree(staging_dir, ignore_errors=True)

    return uploaded, skipped, failure


def _controls_dir(samples_dir: Path) -> Path:
    """
    Controls have existed in both samples/controls/ and samples/benign/controls/
    across dataset bundles. Prefer the top-level layout, but fall back to the
    nested layout when the top-level directory is absent or empty.
    """
    top_level = samples_dir / "controls"
    nested = samples_dir / "benign" / "controls"
    if top_level.exists() and any(top_level.iterdir()):
        return top_level
    if nested.exists():
        return nested
    return top_level


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Upload all samples from samples-extracted/ to the PyPi-SCADA simulator."
    )
    parser.add_argument(
        "--samples-dir",
        default="/home/pypi-runner/samples-extracted",
        metavar="PATH",
        help="Path to the extracted samples directory (default: %(default)s)",
    )
    parser.add_argument(
        "--simulator-url",
        default="http://127.0.0.1:8080",
        metavar="URL",
        help="Base URL of the simulator (default: %(default)s)",
    )
    parser.add_argument(
        "--only",
        choices=["benign", "controls", "malicious", "all"],
        default="all",
        help="Which category to upload (default: all)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be uploaded without calling twine",
    )
    args = parser.parse_args()

    samples_dir = Path(args.samples_dir).resolve()
    if not samples_dir.exists():
        log.error(f"samples-dir does not exist: {samples_dir}")
        sys.exit(1)

    mode = args.only
    simulator_url = args.simulator_url
    dry_run = args.dry_run

    if dry_run:
        log.info("Mode: dry-run — no uploads will be performed")

    total_uploaded = total_skipped = total_fail = 0

    if mode in ("benign", "all"):
        uploaded, skipped, fail = _upload_flat_category(samples_dir / "benign", simulator_url, dry_run)
        total_uploaded += uploaded
        total_skipped += skipped
        total_fail += fail

    if mode in ("controls", "all"):
        uploaded, skipped, fail = _upload_flat_category(_controls_dir(samples_dir), simulator_url, dry_run)
        total_uploaded += uploaded
        total_skipped += skipped
        total_fail += fail

    if mode in ("malicious", "all"):
        uploaded, skipped, fail = _upload_malicious_category(samples_dir / "malware_backstabbers_knife", simulator_url, dry_run)
        total_uploaded += uploaded
        total_skipped += skipped
        total_fail += fail

    log.info("─" * 50)
    log.info(f"Uploaded : {total_uploaded}")
    log.info(f"Skipped  : {total_skipped}")
    if total_fail:
        log.error(f"Failed   : {total_fail}")
        sys.exit(1)
    else:
        log.info("All uploads complete.")


if __name__ == "__main__":
    main()
