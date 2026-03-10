"""
main.py — Detection Analyzer entry point.

Listens for packages on the PyPI Simulation server, performs diff-based
analysis using configured detectors (SAST + LLM), and stores results.
"""

import sys
import uuid
from pathlib import Path

import yaml
import requests

# Shared utilities
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils.logger import setup_logger, get_logger

from diff import DiffEngine
from detection_controller import DetectionController
from sql import SQL


# ---------------------------------------------------------------------------
# DetectionAnalyzer
# ---------------------------------------------------------------------------

class DetectionAnalyzer:
    """
    Orchestrates the full analysis pipeline:
      1. Poll the Simulator for known packages and their versions.
      2. For each new consecutive version pair, fetch archives and diff them.
      3. Pass the diff to DetectionController.
      4. Results are persisted to the results DB by the controller.
    """

    def __init__(self, config: dict):
        self._cfg = config
        self._db = SQL(config["storage"]["results_db"])
        self._engine = DiffEngine()
        self._controller = DetectionController(config, self._db)
        self._base_url = config["simulator"]["base_url"].rstrip("/")
        self._run_id = str(uuid.uuid4())
        self._db.create_run(self._run_id)
        get_logger().info(f"Analyzer started. run_id={self._run_id}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_once(self) -> None:
        """Fetch all projects from the simulator and analyse new version pairs."""
        log = get_logger()
        projects = self._list_projects()
        log.info(f"Found {len(projects)} project(s) on simulator")

        for project in projects:
            versions = self._list_versions(project)
            if len(versions) < 2:
                continue
            # Analyse the latest consecutive pair
            v_before, v_after = versions[-2], versions[-1]
            log.info(f"Analysing {project}: {v_before} -> {v_after}")
            self._analyse_pair(project, v_before, v_after)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _list_projects(self) -> list[str]:
        # Parse /simple/ root HTML to extract project links
        resp = requests.get(f"{self._base_url}/simple/", timeout=10)
        resp.raise_for_status()
        import re
        return re.findall(r'href="/simple/([^/]+)/"', resp.text)

    def _list_versions(self, project: str) -> list[str]:
        resp = requests.get(
            f"{self._base_url}/api/versions/{project}", timeout=10
        )
        resp.raise_for_status()
        return resp.json().get("versions", [])

    def _fetch_archive(self, project: str, filename: str) -> Path:
        url = f"{self._base_url}/packages/{project}/{filename}"
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        tmp = Path(f"/tmp/pypi_scada_{project}_{filename}")
        tmp.write_bytes(resp.content)
        return tmp

    def _guess_filename(self, project: str, version: str) -> str:
        """Best-effort: try .tar.gz first. Production: query /simple/<project>/."""
        return f"{project}-{version}.tar.gz"

    def _analyse_pair(self, project: str, v_before: str, v_after: str) -> None:
        log = get_logger()
        try:
            f_before = self._fetch_archive(
                project, self._guess_filename(project, v_before)
            )
            f_after = self._fetch_archive(
                project, self._guess_filename(project, v_after)
            )
            diff = self._engine.compute(project, f_before, f_after, v_before, v_after)
            results = self._controller.run(self._run_id, diff)
            for r in results:
                log.info(
                    f"  [{r.detector}] verdict={r.verdict} "
                    f"confidence={r.confidence}"
                )
        except Exception as exc:
            log.error(f"Failed to analyse {project} {v_before}->{v_after}: {exc}")
        finally:
            # Cleanup temp files
            for p in [f_before, f_after]:
                try:
                    p.unlink(missing_ok=True)
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    cfg = load_config()
    setup_logger(cfg)
    DetectionAnalyzer(cfg).run_once()
