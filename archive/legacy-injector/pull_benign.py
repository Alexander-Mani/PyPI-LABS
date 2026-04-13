#!/usr/bin/env python3
"""
pull_benign.py — Download benign sample pairs from PyPI.

Reads benign_samples.yaml and downloads each consecutive version pair
using pip. Archives land in the benign dataset directory defined in
config.yaml (dataset.benign_dir), ready for controller.sh to upload.

Upload ordering matters: v_before is downloaded first so that when
controller.sh globs and uploads alphabetically, v_before is always
uploaded before v_after — which is what DetectionAnalyzer.run_once()
relies on (it compares versions[-2] -> versions[-1]).

Usage:
    python pull_benign.py [--dry-run] [--category CATEGORY]
"""

import argparse
import subprocess
import sys
from pathlib import Path

import yaml


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _resolve_benign_dir(script_dir: Path, injector_cfg: dict) -> Path:
    relative = injector_cfg["dataset"]["benign_dir"]
    return (script_dir / relative).resolve()


# ---------------------------------------------------------------------------
# Download logic
# ---------------------------------------------------------------------------

def _find_existing(dest: Path, package: str, version: str) -> Path | None:
    """Return the first archive found for this package+version, or None."""
    # pip normalises hyphens to underscores and may capitalise the project name.
    candidates = [
        package,
        package.replace("-", "_"),
        package.replace("-", "_").capitalize(),
        package.capitalize(),
    ]
    for name in candidates:
        for ext in ("tar.gz", "whl", "zip"):
            matches = list(dest.glob(f"{name}-{version}*.{ext}"))
            if matches:
                return matches[0]
            # handle multi-part extensions like .tar.gz via stem trick
            matches = list(dest.glob(f"{name}-{version}*"))
            if matches:
                return matches[0]
    return None


def download_version(
    package: str,
    version: str,
    dest: Path,
    dry_run: bool,
) -> bool:
    """Download package==version into dest. Returns True on success."""
    spec = f"{package}=={version}"

    if dry_run:
        print(f"    [dry-run] would download {spec}")
        return True

    existing = _find_existing(dest, package, version)
    if existing:
        print(f"    [skip]   {spec}  ({existing.name})")
        return True

    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "download",
            "--no-deps",
            "--quiet",
            "-d", str(dest),
            spec,
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"    [ERROR]  {spec}")
        # Show the actual pip error (first non-empty line)
        for line in result.stderr.splitlines():
            if line.strip():
                print(f"             {line.strip()}")
                break
        return False

    downloaded = _find_existing(dest, package, version)
    if downloaded:
        print(f"    [ok]     {spec}  ->  {downloaded.name}")
        return True

    print(f"    [ERROR]  {spec}: file not found after download")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Download benign PyPI sample pairs for the control group."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be downloaded without actually downloading.",
    )
    parser.add_argument(
        "--category",
        metavar="NAME",
        help="Only download samples for this category (e.g. typosquatting).",
    )
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    injector_cfg = _load_yaml(script_dir / "config.yaml")
    samples_cfg = _load_yaml(script_dir / "benign_samples.yaml")

    dest = _resolve_benign_dir(script_dir, injector_cfg)
    if not args.dry_run:
        dest.mkdir(parents=True, exist_ok=True)

    print(f"Destination : {dest}")
    if args.dry_run:
        print("Mode        : dry-run (nothing will be downloaded)")
    print()

    categories: dict = samples_cfg["samples"]
    if args.category:
        if args.category not in categories:
            print(f"ERROR: unknown category '{args.category}'")
            print(f"Available  : {', '.join(categories)}")
            sys.exit(1)
        categories = {args.category: categories[args.category]}

    total = 0
    succeeded = 0
    failed: list[str] = []

    for category, entries in categories.items():
        print(f"[{category}]")
        for entry in entries:
            pkg = entry["package"]
            v_before, v_after = entry["versions"][0], entry["versions"][1]
            print(f"  {pkg}  {v_before} -> {v_after}")

            for ver in (v_before, v_after):
                total += 1
                ok = download_version(pkg, ver, dest, args.dry_run)
                if ok:
                    succeeded += 1
                else:
                    failed.append(f"{pkg}=={ver}")
        print()

    # Summary
    print("─" * 50)
    print(f"Downloaded : {succeeded}/{total}")
    if failed:
        print(f"Failed     : {len(failed)}")
        for f in failed:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("All samples ready.")


if __name__ == "__main__":
    main()
