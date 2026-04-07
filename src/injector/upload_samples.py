#!/usr/bin/env python3
"""
upload_samples.py — VM-targeted batch uploader for the PyPi-SCADA injector.

Scans a pre-extracted samples directory and uploads all packages to the
local simulator via twine. Handles three archive categories:

  benign/   — per-package subdirs of .tar.gz / .whl files from PyPI
  controls/ — same layout; infrastructure packages used as FP baseline
  malware_backstabbers_knife/ — password-protected .zip containers
                                (password: "infected"); each contains an inner
                                .tar.gz or .whl to upload

Older versions within a package are uploaded before newer ones so that
the simulator's list_versions() returns them in chronological order.

Usage:
    python upload_samples.py [--samples-dir PATH] [--simulator-url URL]
                             [--only {benign,controls,malicious,all}]
                             [--dry-run]
"""

import argparse
import shutil
import subprocess
import sys
import tempfile
import uuid
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

def _twine_upload(archive: Path, simulator_url: str, dry_run: bool) -> bool:
    """
    Upload a single archive to the simulator via twine.
    Returns True on success, False on failure.
    Skips already-uploaded files when the target repository supports
    ``--skip-existing`` (e.g. PyPI/TestPyPI). Local simulator endpoints do not.
    """
    if dry_run:
        log.info(f"[dry-run] would upload {archive.name}")
        return True

    repo_url = simulator_url.rstrip("/") + "/legacy/"
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
    if repo_url.startswith(("https://upload.pypi.org/legacy/", "https://test.pypi.org/legacy/")):
        cmd.insert(-2, "--skip-existing")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        log.info(f"Uploaded: {archive.name}")
        return True

    # twine may exit non-zero for "already exists" even with --skip-existing
    # on older versions; treat it as success if the message says so.
    combined = result.stdout + result.stderr
    if "already exists" in combined.lower() or "skipping" in combined.lower():
        log.info(f"Skipped (already exists): {archive.name}")
        return True

    log.error(f"Upload failed: {archive.name}")
    for line in combined.splitlines():
        if line.strip():
            log.error(f"  {line.strip()}")
    return False


# ---------------------------------------------------------------------------
# Benign / controls pass
# ---------------------------------------------------------------------------

ARCHIVE_SUFFIXES = {".whl", ".gz"}  # .zip excluded — causes noisy twine failures


def _is_package_archive(path: Path) -> bool:
    return path.suffix in ARCHIVE_SUFFIXES and path.is_file()


def _upload_flat_category(category_dir: Path, simulator_url: str, dry_run: bool) -> tuple[int, int]:
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

    Returns (success_count, failure_count).
    """
    if not category_dir.exists():
        log.warning(f"Directory not found, skipping: {category_dir}")
        return 0, 0

    success = failure = 0

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
            ok = _twine_upload(archive, simulator_url, dry_run)
            if ok:
                success += 1
            else:
                failure += 1

    return success, failure


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


def _upload_malicious_category(malicious_dir: Path, simulator_url: str, dry_run: bool) -> tuple[int, int]:
    """
    Walk malware_backstabbers_knife/ for .zip files, extract each, upload
    inner archive.
    Staging dirs are cleaned up after each upload.

    Returns (success_count, failure_count).
    """
    if not malicious_dir.exists():
        log.warning(f"Directory not found, skipping: {malicious_dir}")
        return 0, 0

    zips = sorted(malicious_dir.glob("*.zip"))
    log.info(f"Scanning malware_backstabbers_knife/: {len(zips)} zip(s)")

    success = failure = 0

    for zip_path in zips:
        log.info(f"  Extracting: {zip_path.name}")

        if dry_run:
            log.info(f"  [dry-run] would extract and upload from {zip_path.name}")
            success += 1
            continue

        inner = _extract_malicious_zip(zip_path)
        if inner is None:
            failure += 1
            continue

        staging_dir = inner.parent
        # Walk up to find the actual staging root we own
        while staging_dir.parent != _STAGING_ROOT and staging_dir != _STAGING_ROOT:
            staging_dir = staging_dir.parent

        ok = _twine_upload(inner, simulator_url, dry_run)
        if ok:
            success += 1
        else:
            failure += 1

        shutil.rmtree(staging_dir, ignore_errors=True)

    return success, failure


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

    total_ok = total_fail = 0

    if mode in ("benign", "all"):
        ok, fail = _upload_flat_category(samples_dir / "benign", simulator_url, dry_run)
        total_ok += ok
        total_fail += fail

    if mode in ("controls", "all"):
        ok, fail = _upload_flat_category(samples_dir / "controls", simulator_url, dry_run)
        total_ok += ok
        total_fail += fail

    if mode in ("malicious", "all"):
        ok, fail = _upload_malicious_category(samples_dir / "malware_backstabbers_knife", simulator_url, dry_run)
        total_ok += ok
        total_fail += fail

    log.info("─" * 50)
    log.info(f"Uploaded : {total_ok}")
    if total_fail:
        log.error(f"Failed   : {total_fail}")
        sys.exit(1)
    else:
        log.info("All uploads complete.")


if __name__ == "__main__":
    main()
