"""
simple.py — PEP 503 Simple Repository API endpoints.

Implements the /simple/ and /simple/<project>/ endpoints so that
standard `pip install` can discover and download packages from the
simulated index directory.
"""

from pathlib import Path
from flask import Blueprint, render_template_string, abort
from packaging.utils import canonicalize_name


# ---------------------------------------------------------------------------
# PEP 503 normalisation helper
# ---------------------------------------------------------------------------

def _normalize(name: str) -> str:
    """Normalise a package name per PEP 503 (lower-case, collapse runs of [-_.])."""
    return str(canonicalize_name(name.strip()))


# ---------------------------------------------------------------------------
# ProjectIndex
# ---------------------------------------------------------------------------

class ProjectIndex:
    """
    Manages the flat-file storage directory used as the package index.

    Directory layout::

        <index_dir>/
            <project-name>/
                <project-name>-<version>.tar.gz
                <project-name>-<version>-py3-none-any.whl
    """

    def __init__(self, index_dir: str | Path):
        self.root = Path(index_dir)
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Read helpers
    # ------------------------------------------------------------------

    def list_projects(self) -> list[str]:
        """Return all project names present in the index."""
        return sorted(p.name for p in self.root.iterdir() if p.is_dir())

    def list_files(self, project_name: str) -> list[Path]:
        """Return all distribution files for *project_name*."""
        project_dir = self.root / _normalize(project_name)
        if not project_dir.exists():
            return []
        return sorted(project_dir.iterdir())

    def get_project_dir(self, project_name: str) -> Path:
        """Return (and create) the storage directory for *project_name*."""
        d = self.root / _normalize(project_name)
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ------------------------------------------------------------------
    # Write helpers
    # ------------------------------------------------------------------

    def store_file(self, project_name: str, filename: str, data: bytes) -> Path:
        """Persist *data* as *filename* inside the project directory."""
        dest = self.get_project_dir(project_name) / filename
        dest.write_bytes(data)
        return dest


# ---------------------------------------------------------------------------
# SimpleIndexRenderer
# ---------------------------------------------------------------------------

_ROOT_TEMPLATE = """\
<!DOCTYPE html>
<html>
  <head><title>Simple Index</title></head>
  <body>
    <h1>Simple Index</h1>
    {% for name in projects %}
    <a href="/simple/{{ name }}/">{{ name }}</a><br>
    {% endfor %}
  </body>
</html>
"""

_PROJECT_TEMPLATE = """\
<!DOCTYPE html>
<html>
  <head><title>Links for {{ project }}</title></head>
  <body>
    <h1>Links for {{ project }}</h1>
    {% for filename in files %}
    <a href="/packages/{{ project }}/{{ filename }}">{{ filename }}</a><br>
    {% endfor %}
  </body>
</html>
"""


class SimpleIndexRenderer:
    """Renders PEP 503-compliant HTML index pages."""

    @staticmethod
    def root(projects: list[str]) -> str:
        """Render the /simple/ root page listing all projects."""
        return render_template_string(_ROOT_TEMPLATE, projects=projects)

    @staticmethod
    def project(project_name: str, files: list[str]) -> str:
        """Render the /simple/<project>/ page listing all distribution files."""
        return render_template_string(
            _PROJECT_TEMPLATE, project=project_name, files=files
        )


# ---------------------------------------------------------------------------
# SimpleAPI — Flask Blueprint
# ---------------------------------------------------------------------------

class SimpleAPI:
    """
    Wraps the PEP 503 Simple API as a Flask Blueprint.

    Usage::

        index = ProjectIndex("data/index")
        simple_api = SimpleAPI(index)
        app.register_blueprint(simple_api.blueprint)
    """

    def __init__(self, project_index: ProjectIndex):
        self._index = project_index
        self._renderer = SimpleIndexRenderer()
        self.blueprint = self._build_blueprint()

    def _build_blueprint(self) -> Blueprint:
        bp = Blueprint("simple", __name__)

        @bp.route("/simple/")
        def simple_root():
            projects = self._index.list_projects()
            html = self._renderer.root(projects)
            return html, 200, {"Content-Type": "text/html; charset=utf-8"}

        @bp.route("/simple/<project_name>/")
        def simple_project(project_name: str):
            files = self._index.list_files(project_name)
            if not files:
                abort(404)
            filenames = [f.name for f in files]
            html = self._renderer.project(project_name, filenames)
            return html, 200, {"Content-Type": "text/html; charset=utf-8"}

        return bp
