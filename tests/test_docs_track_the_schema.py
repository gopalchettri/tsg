"""The API guides are pinned to the schema, so a model change without a doc change fails HERE.

Why this exists: the treatment-plan response grew three fields over three changes, and the guides
kept describing the old contract — including a sentence telling readers they could omit the
now-required `plan_id`, and example responses missing `controls_unavailable`. Documentation drift
is the same disease as column-list drift (see dal.plan_presenter_columns): two hand-maintained
renderings of one truth, with nothing that fails when they diverge. This test is the thing that
fails.

Three pins:
  * every treatment example response in the Markdown smoke guide and the HTML guidebook has
    EXACTLY the wire fields of its Pydantic model (`model_fields` minus `exclude=True`);
  * every review REQUEST example carries every required field of TreatmentReviewBody;
  * the Word guidebook is a rendering of the HTML one, so for a few sentinel strings the two
    must agree on occurrence counts — that is what detects "HTML updated, Word not".

Placeholder values in the examples ("<plan_id>", 0, "2026-08-30T12:00:00") are fine: only KEY
SETS are compared, never values.
"""
from __future__ import annotations

import html
import json
import re
import zipfile
from pathlib import Path

import pytest

from app.api import schemas as S

_ROOT = Path(__file__).resolve().parents[1]
_MD = _ROOT / "docs" / "API_Smoke_Testing_Simple_Guide.md"
_HTML = _ROOT / "docs" / "tsg_full_api_guidebook.html"
_DOCX = _ROOT / "docs" / "TSG_API_Guidebook.docx"

_GET_PLAN = "GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan"
_REVIEW = "POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/review"
_BOARD = "GET /v1/sessions/{session_id}/treatment-plans"
_REGISTER = "GET /v1/entities/{entity_id}/treatment-plans"


def _wire(model) -> set[str]:
    """The keys a client actually receives: every field that is not exclude=True."""
    return {name for name, f in model.model_fields.items() if not f.exclude}


def _required(model) -> set[str]:
    return {name for name, f in model.model_fields.items() if f.is_required()}


# ───────────────────────────── Markdown smoke guide ─────────────────────────────

def _md_card(api_path: str) -> str:
    """The guide is one card per endpoint, each opening with a `| **API** | `...` |` row."""
    text = _MD.read_text(encoding="utf-8")
    start = text.index(f"| **API** | `{api_path}` |")
    nxt = text.find("| **API** |", start + 1)
    return text[start:nxt if nxt != -1 else len(text)]


def _md_output_json(api_path: str) -> dict:
    card = _md_card(api_path)
    m = re.search(r"\*\*Output \(complete response\)", card)  # label may carry a suffix
    assert m, f"no Output block in the {api_path} card"
    k = card.index("```json", m.start()) + len("```json")
    e = card.index("```", k)
    body = re.sub(r"^\s*\d{3}\s*", "", card[k:e].strip())  # "200 {…}" -> "{…}"
    return json.loads(body)


def _md_request_json(api_path: str) -> dict:
    """The worked curl's -d payload."""
    card = _md_card(api_path)
    m = re.search(r"-d '(\{.*?\})'", card, re.S)
    assert m, f"no curl -d payload in the {api_path} card"
    return json.loads(m.group(1))


def test_md_single_plan_example_has_exactly_the_wire_fields():
    assert set(_md_output_json(_GET_PLAN)) == _wire(S.TreatmentPlanStatus)


def test_md_board_example_has_exactly_the_wire_fields():
    board = _md_output_json(_BOARD)
    assert set(board) == _wire(S.TreatmentBoard)
    for row in board["plans"]:
        assert set(row) == _wire(S.TreatmentBoardRow), row.get("scenario_id")


def test_md_register_example_has_exactly_the_wire_fields():
    page = _md_output_json(_REGISTER)
    assert set(page) == _wire(S.TreatmentRegisterPage)
    for row in page["plans"]:
        assert set(row) == _wire(S.TreatmentRegisterRow), row.get("plan_id")


def test_md_review_request_carries_every_required_field():
    assert _required(S.TreatmentReviewBody) <= set(_md_request_json(_REVIEW))


def test_md_never_tells_the_reader_plan_id_is_optional():
    text = _MD.read_text(encoding="utf-8")
    assert "Omit plan_id" not in text and "omit (or pass the active version" not in text.lower()


# ───────────────────────────── HTML guidebook ─────────────────────────────

def _html_article(article_id: str) -> str:
    text = _HTML.read_text(encoding="utf-8")
    i = text.index(f'id="{article_id}"')
    return text[i:text.index("</article>", i)]


def _html_pre_json(article: str, heading: str) -> dict:
    i = article.index(f"<h3>{heading}")
    k = article.index("<pre>", i) + len("<pre>")
    e = article.index("</pre>", k)
    return json.loads(html.unescape(article[k:e]))


def test_html_single_plan_example_has_exactly_the_wire_fields():
    art = _html_article("get-v1-sessions-session-id-scenarios-scenario-id-treatment-plan")
    assert set(_html_pre_json(art, "Response")) == _wire(S.TreatmentPlanStatus)


def test_html_board_example_and_its_history_entries_have_exactly_the_wire_fields():
    art = _html_article("get-v1-sessions-session-id-treatment-plans")
    board = _html_pre_json(art, "Response")
    assert set(board) == _wire(S.TreatmentBoard)
    for row in board["plans"]:
        assert set(row) == _wire(S.TreatmentBoardRow), row.get("scenario_id")
        for entry in row.get("superseded") or []:
            assert set(entry) == _wire(S.TreatmentPlanStatus), entry.get("plan_id")


def test_html_register_example_has_exactly_the_wire_fields():
    art = _html_article("get-v1-entities-entity-id-treatment-plans")
    page = _html_pre_json(art, "Response")
    assert set(page) == _wire(S.TreatmentRegisterPage)
    for row in page["plans"]:
        assert set(row) == _wire(S.TreatmentRegisterRow), row.get("plan_id")


def test_html_review_request_carries_every_required_field():
    art = _html_article("post-v1-sessions-session-id-scenarios-scenario-id-treatment-plan-review")
    assert _required(S.TreatmentReviewBody) <= set(_html_pre_json(art, "Request"))


def test_html_never_tells_the_reader_plan_id_is_optional():
    assert "Omit plan_id" not in _HTML.read_text(encoding="utf-8")


# ───────────────────────────── Word guidebook = rendering of the HTML ─────────────────────────────

def _docx_text() -> str:
    with zipfile.ZipFile(_DOCX) as z:
        xml = z.read("word/document.xml").decode("utf-8", "ignore")
    return html.unescape("".join(re.findall(r"<w:t[^>]*>(.*?)</w:t>", xml, re.S)))


def _html_text() -> str:
    body = _HTML.read_text(encoding="utf-8")
    body = re.sub(r"<(style|script).*?</\1>", "", body, flags=re.S)
    return html.unescape(re.sub(r"<[^>]+>", "", body))


@pytest.mark.parametrize("sentinel", ["controls_unavailable", "Omit plan_id"])
def test_word_guidebook_agrees_with_the_html_on(sentinel):
    """The .docx is hand-exported from the HTML, so their texts must agree on these markers. A
    field added to the HTML examples but not the Word file shows up as a count mismatch; the
    stale 'omit plan_id' sentence must be gone from both."""
    h, d = _html_text().count(sentinel), _docx_text().count(sentinel)
    assert h == d, f"{sentinel!r}: HTML has {h}, Word has {d} — the Word guidebook is out of date"
    if sentinel == "Omit plan_id":
        assert h == 0, "the review section still says plan_id may be omitted"


# ---------------------------------------------------------------------------------------------
# The same pin, widened from four endpoints to EVERY endpoint.
#
# The four pins above cover treatment-plan responses only. The guide documents ~47 more, and
# until this test every one of those example responses was hand-typed with nothing checking it.
# That is not hypothetical: an audit of this guide found 34 defects, and six endpoints were added
# in one commit without the guide noticing at all. A doc that is only spot-checked drifts back.
#
# Compares KEY SETS, never values, and only complains about keys the model cannot produce —
# a missing key is often deliberate abbreviation in a long example, an INVENTED key never is.
# ---------------------------------------------------------------------------------------------

_API_ROW = re.compile(r"\|\s*\*\*APIs?\*\*\s*\|(.+?)\n", re.S)
_ENDPOINT = re.compile(r"`(GET|POST|PUT|PATCH|DELETE)\s+(/[^`\s?]+)")
_JSON_BLOCK = re.compile(r"```json\s*\n(?:(\d{3})\s+)?(.*?)```", re.S)


@pytest.fixture(scope="module")
def openapi_spec():
    """The spec with the risk module ON.

    It is flag-gated OFF by default, so without this the eleven treatment routes are simply
    absent and their cards would be skipped in silence — the failure mode this test exists to
    prevent, reproduced inside the test itself.
    """
    import os

    from app.core.config import get_settings
    from app.main import create_app

    previous = os.environ.get("TSG_RISK_MODULE_ENABLED")
    os.environ["TSG_RISK_MODULE_ENABLED"] = "true"
    get_settings.cache_clear()
    try:
        yield create_app().openapi()
    finally:
        if previous is None:
            os.environ.pop("TSG_RISK_MODULE_ENABLED", None)
        else:
            os.environ["TSG_RISK_MODULE_ENABLED"] = previous
        get_settings.cache_clear()


def _resolve(schema: dict, components: dict, depth: int = 0):
    if depth > 8 or not isinstance(schema, dict):
        return None
    if "$ref" in schema:
        return _resolve(components.get(schema["$ref"].rsplit("/", 1)[-1], {}), components, depth + 1)
    if schema.get("type") == "array":
        return _resolve(schema.get("items", {}), components, depth + 1)
    for key in ("anyOf", "oneOf", "allOf"):
        for alt in schema.get(key, []):
            if alt.get("type") == "null":
                continue
            got = _resolve(alt, components, depth + 1)
            if got:
                return got
    return schema if schema.get("properties") else None


_OPEN = object()   # this scope sets extra="allow" — undeclared keys are legitimate here


def _model_keys(schema: dict, components: dict, depth: int = 0) -> dict:
    """Key set at each nested path. `extra="allow"` scopes are marked _OPEN and never checked.

    ScenarioNarrative relies on that: scenario_title/scenario_statement/risk_statement are
    model-authored strings passed through undeclared on purpose, and the guide documents them
    correctly. Without honouring it, this test fails the guide for being right.
    """
    out: dict = {}
    obj = _resolve(schema, components)
    if not obj or depth > 4:
        return out
    props = obj.get("properties", {})
    out[""] = _OPEN if obj.get("additionalProperties") is True else set(props)
    for name, sub in props.items():
        for path, keys in _model_keys(sub, components, depth + 1).items():
            key = f"{name}.{path}".rstrip(".")
            if out.get(key) is _OPEN:
                continue
            out[key] = _OPEN if keys is _OPEN else (out.get(key) or set()) | keys
    return out


def _example_keys(value, prefix: str = "") -> dict:
    out: dict = {}
    if isinstance(value, dict):
        out.setdefault(prefix, set()).update(value)
        for k, v in value.items():
            for p, keys in _example_keys(v, f"{prefix}.{k}".lstrip(".")).items():
                out.setdefault(p, set()).update(keys)
    elif isinstance(value, list):
        for item in value:
            for p, keys in _example_keys(item, prefix).items():
                out.setdefault(p, set()).update(keys)
    return out


def test_every_documented_response_matches_its_model(openapi_spec):
    components = openapi_spec.get("components", {}).get("schemas", {})
    problems, checked = [], 0

    for card in re.split(r"^### Test ", _MD.read_text(encoding="utf-8"), flags=re.M)[1:]:
        title = card.split("\n", 1)[0].strip()[:52]
        row = _API_ROW.search(card)
        if not row:
            continue
        expected = None
        for method, path in _ENDPOINT.findall(row.group(1)):
            op = openapi_spec["paths"].get(path, {}).get(method.lower())
            if not op:
                continue
            for code in ("200", "201", "202"):
                body = op.get("responses", {}).get(code, {}).get("content", {}).get(
                    "application/json")
                if body and body.get("schema"):
                    keys = _model_keys(body["schema"], components)
                    if keys.get("") and keys.get("") is not _OPEN:
                        expected = keys
                    break
            if expected:
                break
        if not expected:
            continue                      # SSE streams and placeholder paths have no JSON model

        for status, raw in _JSON_BLOCK.findall(card):
            if status and status not in ("200", "201", "202"):
                continue
            try:
                payload = json.loads(raw.strip())
            except json.JSONDecodeError:
                continue
            if not isinstance(payload, (dict, list)):
                continue
            actual = _example_keys(payload)
            if not actual.get(""):
                continue
            checked += 1
            for scope, keys in sorted(actual.items()):
                known = expected.get(scope)
                if known is None or known is _OPEN:
                    continue
                invented = keys - known
                if invented:
                    problems.append(
                        f"Test {title} at {scope or '(top level)'}: {sorted(invented)}")

    assert checked >= 25, (
        f"only {checked} response examples were checked — the guide's card format probably "
        "changed and this test is now silently covering almost nothing")
    assert not problems, (
        "guide response examples contain keys their model cannot produce:\n  "
        + "\n  ".join(problems))
