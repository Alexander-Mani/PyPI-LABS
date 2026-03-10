"""
main.py — PyPI Simulator entry point.

Hosts a minimal PyPI-compatible HTTP service for controlled experiments.
Serves artifacts from the simulated index directory and exposes endpoints
used by pip (PEP 503) and by the Analyzer for metadata/version listing.
"""

import sys
from pathlib import Path

import yaml
from flask import Flask, request, abort, send_from_directory

# Shared utilities (one level up)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils.logger import setup_logger, get_logger

from simple import SimpleAPI, ProjectIndex
from metadata import MetadataStore


# ---------------------------------------------------------------------------
# PackageIndex
# ---------------------------------------------------------------------------

class PackageIndex:
    """
    Thin façade that coordinates ProjectIndex (file storage) and
    MetadataStore (SQLite), plus the /legacy/ upload endpoint logic.
    """

    def __init__(self, config: dict):
        self._cfg = config
        self._project_index = ProjectIndex(config["storage"]["index_dir"])
        self._metadata = MetadataStore(config["storage"]["metadata_db"])

    @property
    def project_index(self) -> ProjectIndex:
        return self._project_index

    def handle_upload(self, request) -> tuple[str, int]:
        """
        Process a twine multipart/form-data POST to /legacy/.
        Validates, stores the file, and records metadata.
        Returns (response_body, http_status).
        """
        log = get_logger()

        name = request.form.get("name")
        version = request.form.get("version")
        file_obj = request.files.get("content")

        if not (name and version and file_obj):
            log.warning("Upload rejected: missing name/version/content")
            return "Missing fields", 400

        sim_cfg = self._cfg.get("attack_simulation", {})

        # Credential takeover: enforce version bump
        if sim_cfg.get("enforce_version_bump", True):
            if self._metadata.version_exists(name, version):
                log.warning(f"Upload rejected: {name}=={version} already exists")
                return "Version already exists", 400

        # Store file
        filename = file_obj.filename
        data = file_obj.read()
        dest = self._project_index.store_file(name, filename, data)
        self._metadata.record(name, version, filename)

        log.info(f"Uploaded: {name}=={version} -> {dest}")
        return "OK", 200


# ---------------------------------------------------------------------------
# MetadataStore — SQLite metadata for uploaded packages
# (defined here; import target is simulator/metadata.py below)
# ---------------------------------------------------------------------------
# NOTE: MetadataStore lives in metadata.py (separate file for clarity).


# ---------------------------------------------------------------------------
# PyPISimulatorApp
# ---------------------------------------------------------------------------

class PyPISimulatorApp:
    """
    Composes all simulator sub-components and registers Flask routes.
    """

    def __init__(self, config: dict):
        self._cfg = config
        self._app = Flask(__name__)
        self._package_index = PackageIndex(config)
        self._simple_api = SimpleAPI(self._package_index.project_index)
        self._register_routes()

    def _register_routes(self):
        app = self._app

        # PEP 503 Simple API
        app.register_blueprint(self._simple_api.blueprint)

        # Static file serving — distributions
        index_dir = Path(self._cfg["storage"]["index_dir"]).resolve()

        @app.route("/packages/<project_name>/<filename>")
        def serve_package(project_name: str, filename: str):
            project_dir = index_dir / project_name
            if not project_dir.exists():
                abort(404)
            return send_from_directory(str(project_dir), filename)

        # twine upload endpoint (legacy API)
        @app.route("/legacy/", methods=["POST"])
        def legacy_upload():
            body, status = self._package_index.handle_upload(request)
            return body, status

        # Analyzer helper: list versions of a project
        @app.route("/api/versions/<project_name>")
        def api_versions(project_name: str):
            versions = self._package_index._metadata.list_versions(project_name)
            return {"project": project_name, "versions": versions}

    def run(self):
        srv = self._cfg["server"]
        get_logger().info(
            f"Starting PyPI Simulator on {srv['host']}:{srv['port']}"
        )
        self._app.run(host=srv["host"], port=srv["port"], debug=srv.get("debug", False))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


if __name__ == "__main__":
    cfg = load_config()
    setup_logger(cfg)
    PyPISimulatorApp(cfg).run()
