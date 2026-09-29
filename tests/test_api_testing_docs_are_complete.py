"""The API_Testing documents are pinned to the code, so they cannot rot unnoticed.

WHY THIS FILE EXISTS. docs/API_Testing/ was written by reading the implementation, and a document
written that way is correct exactly once. tests/test_docs_track_the_schema.py already pins the two
OLDER guides — but it names them one by one, so anything added later is unpinned by default and
drifts silently. That is the same failure mode as the .env comment blocks, which were hand-edited
away from their generator and would have been silently reverted the next time anyone ran it.

The reference document claims to list EVERY route, and create_app() guarantees the registry in
route_audit.py is complete. That makes completeness mechanically checkable rather than a reviewer's
opinion, which is what this file does.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_DOCS = Path(__file__).resolve().parents[1] / "docs" / "API_Testing"
_REFERENCE = _DOCS / "API_Reference.md"
_GUIDE = _DOCS / "End_to_End_API_Testing_Guide.md"

_PLAN_BASE = "/v1/sessions/{session_id}/scenarios/{scenario_id}"


def _registry() -> set[tuple[str, str]]:
    from app.api import route_audit as ra
    return set(ra._ENTITY_SCOPED_ROUTES) | set(ra._EXEMPT_ROUTES)


def _documented_paths() -> set[str]:
    """Every path the reference spells out, plus the ones it abbreviates as `.../treatment-plan…`.

    The abbreviation is expanded rather than matched loosely: a substring check would pass for a
    route the document never mentions, which is the one thing this must not do."""
    text = _REFERENCE.read_text(encoding="utf-8")
    found = set(re.findall(r"`(/[A-Za-z0-9/_{}.-]*)`", text))
    for suffix in re.findall(r"`\.\.\.(/[A-Za-z0-9/_{}.-]*)`", text):
        found.add(_PLAN_BASE + suffix)
    # The session-scoped plan routes are introduced once with {sid}/{scid} shorthand.
    found.add(_PLAN_BASE + "/treatment-plan")
    return found


def test_both_documents_exist() -> None:
    assert _REFERENCE.is_file(), f"missing {_REFERENCE}"
    assert _GUIDE.is_file(), f"missing {_GUIDE}"


def test_the_reference_lists_every_route_the_app_serves() -> None:
    """The whole claim of API_Reference.md. create_app() refuses to boot on an unregistered route,
    so the registry is complete by construction — which makes a route present in the app and
    absent from the document a DEFECT IN THE DOCUMENT, detectable mechanically rather than by
    someone noticing."""
    documented = _documented_paths()
    missing = sorted({path for _method, path in _registry()} - documented)
    assert not missing, (
        "routes the app serves but docs/API_Testing/API_Reference.md does not list:\n  "
        + "\n  ".join(missing))


def test_the_reference_states_the_real_route_count() -> None:
    """The document opens with a count. A count that drifts is worse than no count — it reads as
    verified when it is not."""
    total = len(_registry())
    text = _REFERENCE.read_text(encoding="utf-8")
    assert f"{total} routes" in text, (
        f"the app serves {total} routes; API_Reference.md does not say so. Update its heading and "
        "the arithmetic under 'How the count is guaranteed'.")


@pytest.mark.parametrize("endpoint", [
    "/health",
    "/ready",
    "/v1/tsg/api-clients",
    "/v1/sessions",
    "/v1/remediation-plans",
    "/v1/tsg/threat-intel/library/pending",
])
def test_the_guide_covers_each_step_of_the_lifecycle(endpoint: str) -> None:
    """The end-to-end guide must walk the path it claims to. These six are the spine: a tester who
    cannot find one of them cannot get from an empty environment to a finished plan."""
    text = _GUIDE.read_text(encoding="utf-8")
    assert endpoint in text, f"{endpoint} is on the main path but the guide never mentions it"


def test_the_guide_documents_both_kinds_of_scenario() -> None:
    """One endpoint serves an AI scenario and a hand-written one. A guide showing only one would
    leave half the feature untested — and the manual half is exactly what the older HTML guidebook
    omits."""
    text = _GUIDE.read_text(encoding="utf-8")
    for token in ('"is_manual": true', '"is_manual": false', "Idempotency-Key"):
        assert token in text, f"the guide never shows {token}"
