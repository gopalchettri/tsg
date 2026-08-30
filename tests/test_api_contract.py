"""The PUBLISHED contract matches what the app actually does.

Each test pins a defect found by the 2026-08 API-design audit, and is written so the ORIGINAL bug
fails it:
  * the spec declared NO authentication at all — no `securitySchemes`, no `security`, and all five
    auth headers `required: false`, on admin routes too, so a generated client omitted the key;
  * 401/403/404/503 were returned but never declared;
  * `revoke` was typed `-> dict`, publishing an empty object schema;
  * the three scenario reads had no ORDER BY, so a POLLED endpoint could reshuffle between calls.

Route-count-agnostic on purpose: these walk the finished document, so a route (or a whole router)
added later is covered with nothing to remember — the reason main.py rewrites the schema centrally
instead of relying on a per-router kwarg somebody must remember.
"""
from __future__ import annotations

import json

import pytest
from pydantic import BaseModel

from app.api.sessions import _scenario_select
from app.main import create_app

_ERROR_REF = "#/components/schemas/ErrorResponse"
# The only genuinely unauthenticated routes: platform liveness/readiness probes, which carry no
# caller identity by design (app/api/route_audit.py maps both to `None`).
_PUBLIC = {("/health", "get"), ("/ready", "get")}


@pytest.fixture(scope="module")
def schema() -> dict:
    return create_app().openapi()


def _operations(schema: dict):
    for path, ops in schema["paths"].items():
        for method, op in ops.items():
            if isinstance(op, dict):  # skip "parameters"/"summary" siblings of the verb keys
                yield path, method, op


def test_security_schemes_are_declared(schema):
    declared = schema.get("components", {}).get("securitySchemes", {})
    assert set(declared) == {"ApiKeyAuth", "AdminKeyAuth"}, declared
    assert declared["ApiKeyAuth"]["name"] == "X-API-Key"
    assert declared["AdminKeyAuth"]["name"] == "X-Admin-Key"


def test_every_non_public_operation_requires_a_key(schema):
    """The whole point: a client generated from this spec must know to send the key. Anything not
    in _PUBLIC that carries no `security` is a route the spec describes as open."""
    unsecured = [(p, m) for p, m, op in _operations(schema)
                 if "security" not in op and (p, m) not in _PUBLIC]
    assert not unsecured, f"operations published as unauthenticated: {unsecured}"


def test_public_probes_are_not_given_a_key_requirement(schema):
    """The converse guard — blanket-securing everything would be just as wrong, and would break
    the orchestrator probes that must work without credentials."""
    wrong = [(p, m) for p, m, op in _operations(schema)
             if (p, m) in _PUBLIC and "security" in op]
    assert not wrong, f"health probes must stay unauthenticated: {wrong}"


def test_authenticated_routes_declare_401(schema):
    missing = [(p, m) for p, m, op in _operations(schema)
               if "security" in op and "401" not in op.get("responses", {})]
    assert not missing, f"can return 401 but never says so: {missing}"


def test_entity_scoped_routes_declare_403(schema):
    """403 is specific to the entity model — an authenticated caller reaching for an entity it is
    not entitled to. Admin-key routes cannot produce it, so this checks the client-key ones."""
    missing = [(p, m) for p, m, op in _operations(schema)
               if op.get("security") == [{"ApiKeyAuth": []}]
               and "403" not in op.get("responses", {})]
    assert not missing, f"entity-scoped but no 403 declared: {missing}"


def test_routes_naming_a_resource_declare_404(schema):
    missing = [(p, m) for p, m, op in _operations(schema)
               if "{" in p and "404" not in op.get("responses", {})]
    assert not missing, f"takes a resource id but never declares 404: {missing}"


def test_every_declared_error_uses_the_one_envelope(schema):
    """A second error shape is exactly what the error-handling audit removed from the wire; the
    document must not reintroduce one."""
    wrong = [
        (p, m, code)
        for p, m, op in _operations(schema)
        for code, resp in op.get("responses", {}).items()
        if code in {"401", "403", "404", "409", "422", "503"}
        for media in resp.get("content", {}).values()
        if media.get("schema", {}).get("$ref") != _ERROR_REF
    ]
    assert not wrong, f"error responses not using ErrorResponse: {wrong}"


def test_revoke_publishes_a_typed_body(schema):
    """`-> dict` publishes `{}` — a client generated from it has no idea what comes back."""
    media = schema["paths"]["/v1/tsg/api-clients/{client_id}/revoke"]["post"]["responses"]["200"]["content"]
    ref = media["application/json"]["schema"].get("$ref", "")
    assert ref.endswith("/ApiClientRevoked"), media
    assert set(schema["components"]["schemas"]["ApiClientRevoked"]["properties"]) == {
        "client_id", "status"}


def test_every_documented_example_validates_against_its_own_model():
    """A `json_schema_extra` example is a SEPARATE expression from the fields it illustrates, so a
    field rename leaves it silently wrong — /docs "Try it out", generated clients and Postman
    imports all then fail on the documented payload.

    This repo has already shipped exactly that: TreatmentPlanRegenerateBody advertised
    `{"user_note": "..."}` after the field was removed and `extra="forbid"` was added, so its own
    example was a 422. Nothing caught it because nothing validated examples.

    Request models are validated strictly. RESPONSE examples are checked for unknown keys only —
    they legitimately omit optional fields, and a partial example is a documentation choice, not a
    defect; a key that matches NO field is always a defect."""
    import app.api.schemas as s

    request_suffixes = ("Body",)
    stale: list[str] = []
    for name in dir(s):
        model = getattr(s, name)
        if not (isinstance(model, type) and issubclass(model, BaseModel)) or model is BaseModel:
            continue
        extra = (model.model_config or {}).get("json_schema_extra") or {}
        example = extra.get("example") if isinstance(extra, dict) else None
        if not isinstance(example, dict):
            continue
        if name.endswith(request_suffixes):
            try:
                model.model_validate(example)
            except Exception as exc:  # noqa: BLE001 - the message is the whole point of the report
                stale.append(f"{name}: documented example is REJECTED by its own model -> {exc}")
        elif (model.model_config or {}).get("extra") != "allow":
            # extra="allow" models (ScenarioNarrative) pass model-authored keys through on
            # purpose, so an undeclared key in their example is the documented behaviour, not drift.
            unknown = set(example) - set(model.model_fields) - {
                a for f in model.model_fields.values() if (a := f.alias)}
            if unknown:
                stale.append(f"{name}: example documents fields that do not exist -> {sorted(unknown)}")
    assert not stale, "stale documented examples:\n  " + "\n  ".join(stale)


def test_routes_that_can_be_unavailable_declare_503(schema):
    """503 is not derivable from the auth model or the path shape, so the ROUTE declares it via
    `responses=UNAVAILABLE_RESPONSES`. It used to be a central set of route PATHS in main.py, and
    the {output_id} -> {scenario_id} rename silently orphaned two of its six entries — no boot
    error, no failing test, those routes just stopped documenting 503.

    Attached to the decorator it cannot go stale: renaming a route moves the declaration with it.
    This asserts a representative route from EACH of the three causes, so deleting a fragment is
    caught even though the full list is not derivable."""
    must_declare = [
        ("/v1/sessions", "post"),                                   # capacity + broker refusal
        ("/v1/sessions/{session_id}/events", "get"),                # SSE stream ceiling
        ("/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan", "post"),
    ]
    missing = [(p, m) for p, m in must_declare
               if "503" not in schema["paths"][p][m].get("responses", {})]
    assert not missing, f"can answer 503 but no longer declares it: {missing}"


def test_a_naive_timestamp_serializes_as_utc():
    """Every datetime in this schema IS UTC — `dal.now()` returns aware UTC and `_utc_naive` strips
    tzinfo at the boundary because pyodbc drops it anyway. But an unlabelled datetime serializes
    with no offset, and a browser reads that as LOCAL time: 5.5 hours wrong for an IST client, on
    `accepted_at`, `reviewed_at` and every audit timestamp. The `Z` is the whole fix."""
    from datetime import UTC, datetime

    from app.api.schemas import ApiClientInfo

    naive = ApiClientInfo(client_id="c", name="n", module="tsg", active=True,
                          created_at=datetime(2026, 8, 30, 9, 0, 0))
    assert json.loads(naive.model_dump_json())["created_at"].endswith("Z"), "no timezone on the wire"

    # An already-aware value must be unchanged, and None must not be mangled into a string.
    aware = ApiClientInfo(client_id="c", name="n", module="tsg", active=True,
                          created_at=datetime(2026, 8, 30, 9, 0, 0, tzinfo=UTC))
    assert json.loads(aware.model_dump_json())["created_at"] == "2026-08-30T09:00:00Z"
    assert json.loads(naive.model_dump_json())["revoked_at"] is None


def test_every_timestamped_model_inherits_the_utc_base():
    """The base cannot be forgotten per-FIELD, but it can be forgotten per-MODEL. This is what
    stops the next `expires_at: datetime` from silently reintroducing the bug — the reason a base
    class was chosen over a per-field annotated type."""
    import app.api.schemas as s

    offenders = [
        name for name in dir(s)
        if isinstance(getattr(s, name), type)
        and issubclass(getattr(s, name), BaseModel)
        and getattr(s, name) not in (BaseModel, s.ApiModel)
        and any("datetime" in str(f.annotation) for f in getattr(s, name).model_fields.values())
        and not issubclass(getattr(s, name), s.ApiModel)
    ]
    assert not offenders, f"declare a datetime but skip ApiModel, so their timestamps lose UTC: {offenders}"


def test_scenario_reads_are_deterministically_ordered():
    """/results is POLLED while generation runs. With no ORDER BY, SQL Server may return rows in a
    different order on each call and a reviewer watches them reshuffle; /results.xlsx inherits it.
    Asserted on the shared select because all three scenario reads build on it — the one place
    that fixes every reader, including ones added later."""
    sql = str(_scenario_select())
    assert "ORDER BY" in sql, "scenario reads have no deterministic order"
    ordered = sql.split("ORDER BY", 1)[1]
    # ScenarioID is the tie-break that makes the order TOTAL: ScenarioNumber repeats across
    # regenerated versions of the same threat, so it cannot disambiguate on its own.
    assert "ScenarioID" in ordered, f"order is not total, ties stay undefined: {ordered.strip()!r}"
