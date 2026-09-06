"""Every third-party module app/ imports must be DECLARED, not just installed.

FOUND THE HARD WAY: `ijson` was added to app/intel/library_import.py and pip-installed into the
dev venv, but never written into pyproject.toml / requirements.txt / requirements.lock. Locally
everything passed — 774 tests green — because the venv had it. The Docker image installs from
those manifests, so EVERY container (api, both workers, beat) would have died at import time:
library_import is imported during app startup.

That class of bug is structurally invisible to the rest of the suite, which runs in the very
environment where the package is already present. This test asks a different question: not "does
it import?" but "did anyone write it down?".

importlib.metadata.packages_distributions() maps an import name to its distribution name, so
this works for the cases a naive string match gets wrong: yaml -> PyYAML, jwt -> PyJWT,
sqlalchemy -> SQLAlchemy, dotenv -> python-dotenv.
"""
from __future__ import annotations

import ast
import pathlib
import re
import sys
import tomllib
from importlib.metadata import packages_distributions

_ROOT = pathlib.Path(__file__).resolve().parents[1]
_APP = _ROOT / "app"

#: Import names that are NOT third-party even though they are not in app/.
_FIRST_PARTY = {"app"}


def _stdlib_names() -> set[str]:
    names = set(getattr(sys, "stdlib_module_names", set()))
    return {n for n in names if not n.startswith("_")} | {"__future__"}


def _imported_top_level() -> set[str]:
    found: set[str] = set()
    for py in _APP.rglob("*.py"):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom):
                # level > 0 is a relative import — always first-party
                if not node.level and node.module:
                    found.add(node.module.split(".")[0])
    return found


def _declared_distributions(*, include_extras: bool = True) -> set[str]:
    """Distribution names in pyproject's [project].dependencies, PEP 503-normalised.

    tomllib, not a regex: `uvicorn[standard]>=0.52.1` contains a `]` that truncated a
    naive scan at the first bracket and silently reported a single dependency.
    """
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    deps = list(data.get("project", {}).get("dependencies", []))
    if include_extras:
        # app/ may legitimately import something provided by an extra (e.g. the `local`
        # embedding stack), so the import check considers extras declared. requirements.txt,
        # which is the RUNTIME install list, is compared against the base set only.
        for extra in (data.get("project", {}).get("optional-dependencies") or {}).values():
            deps += list(extra)
    out = set()
    for raw in deps:
        name = re.split(r"[<>=!\[;\s]", raw, maxsplit=1)[0]
        if name:
            out.add(re.sub(r"[-_.]+", "-", name).lower())
    return out


def test_every_third_party_import_in_app_is_declared():
    stdlib = _stdlib_names()
    mapping = packages_distributions()
    declared = _declared_distributions()

    undeclared = []
    for mod in sorted(_imported_top_level()):
        if mod in stdlib or mod in _FIRST_PARTY:
            continue
        dists = mapping.get(mod)
        if not dists:
            continue  # not an installed distribution (namespace pkg, or vendored) — nothing to declare
        norm = {re.sub(r"[-_.]+", "-", d).lower() for d in dists}
        if not (norm & declared):
            undeclared.append(f"{mod} (provides: {sorted(dists)})")

    assert not undeclared, (
        "app/ imports these but pyproject.toml does not declare them — they work locally only "
        "because the dev venv happens to have them, and the container will die at import:\n  "
        + "\n  ".join(undeclared))


def test_requirements_txt_agrees_with_pyproject():
    """The Docker image installs from requirements.txt, so a package declared in pyproject but
    missing here still never reaches the image."""
    req = (_ROOT / "requirements.txt").read_text(encoding="utf-8")
    listed = {re.sub(r"[-_.]+", "-", re.split(r"[<>=!\[;\s]", ln.strip(), maxsplit=1)[0]).lower()
              for ln in req.splitlines()
              if ln.strip() and not ln.strip().startswith(("#", "-"))}
    missing = sorted(_declared_distributions(include_extras=False) - listed)
    assert not missing, f"declared in pyproject.toml but absent from requirements.txt: {missing}"


def test_ijson_specifically_is_declared():
    """The exact package whose absence would have shipped a container that cannot start."""
    assert "ijson" in _declared_distributions()
    assert "ijson" in (_ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "ijson==" in (_ROOT / "requirements.lock").read_text(encoding="utf-8")
