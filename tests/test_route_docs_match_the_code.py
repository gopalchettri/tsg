"""The Swagger endpoint docs are pinned to the code, so prose drift fails HERE.

Why this exists. Every route now carries a hand-written `summary=`/`description=` aimed at an
API consumer. Hand-written prose asserting runtime behaviour is the same disease
`test_docs_track_the_schema.py` was built for: two renderings of one truth, with nothing that
fails when they diverge. When these descriptions were first written, an audit against the source
found 26 factual errors in 47 descriptions — a rate that guarantees recurrence if the only
safety net is somebody reading carefully.

Three of those 26 would have hung a caller who followed them (a poll loop with no terminal
condition), and one would have triggered an expensive full cache rebuild. So this is not a
tidiness test.

Prose cannot be fully verified. What CAN be pinned, and is:

  * every route publishes a consumer summary and description at all, and the description is not
    the maintainer docstring falling through (the state this replaced);
  * no description leaks maintainer vocabulary — index names, `module::function`, table names,
    review markers — which is what made the old docstrings unusable as public docs;
  * every identifier a description quotes in backticks still EXISTS in the source. This is the
    anti-drift half: rename `asset_busy`, drop a `ScenarioDecisionReason` member, or retire a
    progress value, and the description that promises it fails here instead of lying in Swagger.

The last check is deliberately one-directional. It cannot know whether a description's CLAIM is
true, only whether the things it names are real. That still catches the whole class of failure
this codebase actually hits: a rename lands, every test passes, and the docs quietly describe an
API that no longer exists.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

from app.main import create_app

_APP_DIR = Path(__file__).resolve().parents[1] / "app"
_HTTP_METHODS = ("get", "post", "put", "patch", "delete")

#: Vocabulary that belongs in a maintainer note and never in a public endpoint description.
#: Each entry cost a real readability failure in the docstrings this replaced.
_LEAKS = (
    "UX_",              # unique index names
    "::",               # module::function references
    "async def",        # Python runtime trivia
    "ponytail",         # in-repo review markers
    "REVIEW-FIX",
    "_scenario_select",  # private helpers
    "build_treatment_input",
    "Threat_Scenario_Control_Map",  # raw table names
    "Subsystem_Stage_State",
    "Risk_Treatment_Plan",
)

#: Backticked tokens that are prose or wire syntax, not identifiers to resolve in source.
_NOT_IDENTIFIERS = {
    "{}", "null", "true", "false", "202", "200", "201", "400", "403", "404", "409", "422",
    "503", "0.0", "1.0", "?include_plan=true", "?include_superseded=true",
    "?include_replaced=true", "?module=", "1-50", "1-100", "1-200",
}


def _operations() -> list[tuple[str, str, dict]]:
    spec = create_app().openapi()
    return [(m.upper(), path, op)
            for path, ops in spec["paths"].items()
            for m, op in ops.items() if m in _HTTP_METHODS]


@pytest.fixture(scope="module")
def operations() -> list[tuple[str, str, dict]]:
    return _operations()


@pytest.fixture(scope="module")
def known_symbols() -> set[str]:
    """The identity oracle: every name a description is allowed to quote.

    Built from real symbols, NOT from raw source text. The first version of this test grepped
    `app/**/*.py` for each quoted token and was completely vacuous, because the descriptions
    themselves live in that source — every token matched itself and no rename could ever fail
    it. Resolving against enum members, schema properties and declared parameters is what makes
    a rename actually break the build.
    """
    import enum as _enum

    from app.core import enums as enums_mod

    known: set[str] = set()

    for name in dir(enums_mod):
        obj = getattr(enums_mod, name)
        if isinstance(obj, type) and issubclass(obj, _enum.Enum):
            for member in obj:
                known.add(member.name)
                known.add(str(member.value))

    spec = create_app().openapi()
    for schema in spec.get("components", {}).get("schemas", {}).values():
        known.update(schema.get("properties", {}))
    for path_item in spec["paths"].values():
        for op in path_item.values():
            if not isinstance(op, dict):
                continue
            known.update(p["name"] for p in op.get("parameters", []) if "name" in p)

    # Values a Literal contributes (`ready`/`not_ready`) surface as JSON Schema enums.
    def _enums(node) -> None:
        if isinstance(node, dict):
            known.update(str(v) for v in node.get("enum", []) or [])
            for v in node.values():
                _enums(v)
        elif isinstance(node, list):
            for v in node:
                _enums(v)

    _enums(spec.get("components", {}).get("schemas", {}))

    # Plain string literals — error codes, and vocabularies like `env_pinned` or
    # `already_calibrated` that are written as literals rather than enum members.
    #
    # Every `description=`/`summary=` value is EXCLUDED. Without that exclusion the published
    # text becomes its own oracle and this whole check silently passes forever, which is exactly
    # how the first version of this test managed to prove nothing.
    for py in sorted(_APP_DIR.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8", errors="replace"), filename=str(py))
        doc_strings = {
            id(kw.value)
            for node in ast.walk(tree) if isinstance(node, ast.Call)
            for kw in node.keywords if kw.arg in ("description", "summary")
        }
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and id(node) not in doc_strings and len(node.value) < 60):
                known.add(node.value)

    return known


def test_every_route_has_a_consumer_summary(operations):
    """A route with no summary renders in Swagger as its title-cased function name — the state
    this replaced, where the sidebar read `Post Next Set Scenarios` and `Healthz`."""
    missing = [f"{m} {p}" for m, p, op in operations if not op.get("summary", "").strip()]
    assert not missing, "routes with no summary:\n  " + "\n  ".join(missing)


def test_every_route_has_a_consumer_description(operations):
    missing = [f"{m} {p}" for m, p, op in operations if not op.get("description", "").strip()]
    assert not missing, "routes with no description:\n  " + "\n  ".join(missing)


def test_no_description_leaks_maintainer_vocabulary(operations):
    """The docstrings still exist and still say these things — they are simply no longer the
    published text. If one starts falling through again, it shows up here."""
    offenders = [f"{m} {p}: {leak!r}"
                 for m, p, op in operations
                 for leak in _LEAKS if leak in op.get("description", "")]
    assert not offenders, (
        "endpoint descriptions are public API docs and must not carry maintainer vocabulary:\n  "
        + "\n  ".join(offenders))


def test_summaries_are_not_the_function_name(operations):
    """`Post Next Set Scenarios` is what FastAPI generates when nobody wrote a summary. A
    summary that still looks like one means a route was added without documenting it."""
    generated = [
        f"{m} {p}: {op['summary']!r}"
        for m, p, op in operations
        if re.fullmatch(r"(?:Get|Post|Put|Patch|Delete)(?: [A-Z][a-z]*)+", op.get("summary", ""))
    ]
    assert not generated, (
        "these summaries read like auto-generated function names:\n  " + "\n  ".join(generated))


def _quoted_identifiers(text: str) -> set[str]:
    """Backticked tokens that look like code identifiers rather than prose."""
    out = set()
    for tok in re.findall(r"`([^`]+)`", text):
        tok = tok.strip()
        if tok in _NOT_IDENTIFIERS or " " in tok:
            continue
        # snake_case / dotted paths / SCREAMING_CASE only; skip bare English words, which
        # carry no rename risk, and header names, which are hyphenated.
        if re.fullmatch(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+", tok):      # progress.overall
            out.add(tok.split(".")[-1])
        elif re.fullmatch(r"[a-z][a-z0-9]*_[a-z0-9_]*", tok):                 # asset_busy
            out.add(tok)
        elif re.fullmatch(r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+", tok):             # SCENARIOS_AWAITING_DECISION
            out.add(tok)
    return out


def test_every_identifier_a_description_quotes_still_exists(operations, known_symbols):
    """THE anti-drift check.

    Rename a gate reason, retire an enum member, or drop a response field, and every description
    promising it becomes a lie that no other test can see. Here it fails.

    One-directional by design: this proves the names are real, not that the surrounding claim is
    true. Claims still need a human, which is exactly why the names should not.
    """
    missing: list[str] = []
    for method, path, op in operations:
        for ident in sorted(_quoted_identifiers(op.get("description", ""))):
            if ident not in known_symbols:
                missing.append(
                    f"{method} {path}: `{ident}` is not an enum member, a schema property, "
                    f"a declared parameter, or an error code")
    assert not missing, (
        "endpoint descriptions name things that no longer exist in the code:\n  "
        + "\n  ".join(missing))


def test_the_documented_progress_values_are_the_real_ones():
    """The single most load-bearing sentence in these docs is 'read progress.overall', and it
    enumerates the values. If a member is added or renamed, that list silently goes stale."""
    from app.core.enums import SubsystemProgress

    spec = create_app().openapi()
    board = spec["paths"]["/v1/sessions/{session_id}"]["get"]["description"]
    for member in SubsystemProgress:
        assert f"`{member}`" in board, (
            f"GET /v1/sessions/{{session_id}} documents progress.overall but never mentions "
            f"`{member}` — a client switching on it has no idea the state exists")
