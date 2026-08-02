"""Curator CRUD over the four threat-library master tables (app/api/library_crud.py).

The behaviours worth pinning are the ones a naive CRUD layer gets wrong:
  * a delete must be SOFT — library ids are referenced by completed sessions;
  * "who did this" must survive every verb, and a later edit must not rewrite who CREATED it;
  * the natural-key indexes are FILTERED, so a duplicate is a 409 but a soft-deleted name is
    genuinely free to reuse;
  * a rename must re-embed, or grounding keeps matching a name that no longer exists.
"""
from __future__ import annotations

import pytest
from sqlalchemy import insert, select

from app.core.config import get_settings
from app.db import models as m

_KEY = "test-admin-key"  # noqa: S105 — test fixture, not a credential
_BASE = "/v1/tsg/threat-library"
#: conftest.make_client overrides get_principal with a fixed sub — the identity comes from there,
#: not from an X-Dev-User header, so this is what CreatedBy/UpdatedBy must end up holding.
_USER = "u1"
#: Every CRUD-driven embedding job is dispatched non-strict. That is not cosmetic: the name is
#: read off a row this request just renamed or soft-deleted, so it is no longer an ACTIVE master
#: row — under the admin route's strict typo check a group that had never been embedded would
#: raise UnknownEmbeddingNames and report the curator's successful edit as a FAILED job.
_LENIENT = False


def _as_user(client, sub: str):
    """Re-point the client's principal override so a second curator can edit the first's row."""
    from app.api.deps import Principal, get_principal

    client.app.dependency_overrides[get_principal] = lambda: Principal(
        claims={"sub": sub}, entities={"5"})


@pytest.fixture()
def admin_client(engine, monkeypatch):
    from tests.conftest import make_client

    monkeypatch.setenv("TSG_ADMIN_API_KEY", _KEY)
    get_settings.cache_clear()
    yield make_client({"5"})
    get_settings.cache_clear()


@pytest.fixture()
def hdr():
    return {"X-Admin-Key": _KEY, "X-Dev-User": _USER}


@pytest.fixture(autouse=True)
def embed_calls(monkeypatch):
    """Embedding refreshes go through Celery; record the calls instead of needing a broker.
    Yields the (action, group, names) tuples every test's writes dispatched."""
    calls: list[tuple] = []

    class _Job:
        id = "job-1"

    monkeypatch.setattr("app.api.library_crud.admin_embedding_action_task",
                        type("T", (), {"delay": staticmethod(
                            lambda *a: (calls.append(a), _Job())[1])})())
    monkeypatch.setattr("app.api.library_crud.mark_admin_job", lambda *a, **k: None)
    return calls


@pytest.fixture()
def category(engine):
    """A live Threat_Category to hang types off — the curated seed isn't loaded in the test DB."""
    from app.db.engine import db_session

    with db_session() as s:
        s.execute(insert(m.Threat_Category).values(
            ThreatCategoryID=901, ThreatCategoryName="Spoofing", IsActive=True, IsDeleted=False))
        s.commit()
    return 901


def _post(client, hdr, resource, body):
    return client.post(f"{_BASE}/{resource}", headers=hdr, json=body)


def test_create_stamps_provenance_and_the_creating_user(admin_client, hdr, category):
    """Every column the request exists for: WHERE the row came from and WHO made it."""
    r = _post(admin_client, hdr, "threat-types",
              {"threat_type_name": "Credential Abuse", "threat_category_id": category})
    assert r.status_code == 201
    row = r.json()
    assert row["source"] == "manual"          # server-side; never read from the body
    assert row["created_by"] == _USER
    assert row["created_at"] is not None
    assert row["updated_by"] is None and row["updated_at"] is None  # nothing has edited it yet
    assert row["is_active"] is True and row["is_deleted"] is False


def test_source_cannot_be_forged_by_the_caller(admin_client, hdr, category):
    """Provenance a client can set records nothing — the body's attempt is ignored, not honoured."""
    r = _post(admin_client, hdr, "threat-types",
              {"threat_type_name": "Forged", "threat_category_id": category,
               "source": "functional_team_excel", "created_by": "someone-else"})
    assert r.status_code == 201
    assert r.json()["source"] == "manual" and r.json()["created_by"] == _USER


def test_update_stamps_the_editor_without_rewriting_the_creator(admin_client, hdr, category):
    """The two halves answer different questions and must not bleed into each other."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Before", "threat_category_id": category}).json()["threat_type_id"]
    _as_user(admin_client, "curator-2")
    r = admin_client.patch(f"{_BASE}/threat-types/{tid}", headers=hdr,
                           json={"threat_type_name": "After"})
    assert r.status_code == 200
    row = r.json()
    assert row["threat_type_name"] == "After"
    assert row["created_by"] == _USER          # unchanged by the edit
    assert row["updated_by"] == "curator-2" and row["updated_at"] is not None


def test_partial_update_leaves_unsent_fields_alone(admin_client, hdr, category):
    """exclude_unset, not "None means clear" — otherwise a one-field PATCH wipes the row."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Keeps", "description": "original text",
                 "threat_category_id": category}).json()["threat_type_id"]
    r = admin_client.patch(f"{_BASE}/threat-types/{tid}", headers=hdr,
                           json={"threat_type_name": "Renamed"})
    assert r.json()["description"] == "original text"
    assert r.json()["threat_category_id"] == category


def test_empty_update_body_is_rejected(admin_client, hdr, category):
    """Far likelier a mistake than a request to stamp UpdatedBy and change nothing."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Empty", "threat_category_id": category}).json()["threat_type_id"]
    assert admin_client.patch(f"{_BASE}/threat-types/{tid}", headers=hdr, json={}).status_code == 422


def test_delete_is_soft_and_records_who_deleted(admin_client, hdr, category):
    """A hard delete would orphan Identified_Threat rows in completed sessions. A delete IS an
    update, which is why UpdatedBy answers "who deleted this" and there is no DeletedBy column."""
    from app.db.engine import db_session

    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Doomed", "threat_category_id": category}).json()["threat_type_id"]
    r = admin_client.delete(f"{_BASE}/threat-types/{tid}", headers=hdr)
    assert r.status_code == 200
    assert r.json()["is_deleted"] is True and r.json()["updated_by"] == _USER

    with db_session() as s:  # the row still physically exists
        assert s.execute(select(m.Threat_Type).filter_by(ThreatTypeID=tid)).scalar_one().IsDeleted

    listed = [x["threat_type_id"] for x in admin_client.get(f"{_BASE}/threat-types", headers=hdr).json()]
    assert tid not in listed
    with_deleted = [x["threat_type_id"] for x in admin_client.get(
        f"{_BASE}/threat-types", headers=hdr, params={"include_deleted": True}).json()]
    assert tid in with_deleted


def test_deleted_rows_disappear_from_the_embedding_corpus(admin_client, hdr, category):
    """_active_names is what grounding embeds — a deleted threat type must stop being matchable."""
    from app.db.engine import db_session
    from app.pipeline.embeddings import _active_names

    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Vanishing", "threat_category_id": category}).json()["threat_type_id"]
    with db_session() as s:
        assert "Vanishing" in _active_names(s, m.Threat_Type, m.Threat_Type.ThreatTypeName)
    admin_client.delete(f"{_BASE}/threat-types/{tid}", headers=hdr)
    with db_session() as s:
        assert "Vanishing" not in _active_names(s, m.Threat_Type, m.Threat_Type.ThreatTypeName)


def test_duplicate_name_is_a_409_naming_the_existing_row(admin_client, hdr, category):
    """A 409 carrying the colliding id lets a client PATCH that row instead of retrying a
    create that can never succeed."""
    body = {"threat_type_name": "Only One", "threat_category_id": category}
    first = _post(admin_client, hdr, "threat-types", body).json()["threat_type_id"]
    r = _post(admin_client, hdr, "threat-types", body)
    assert r.status_code == 409
    assert r.json()["error_code"] == "library_conflict"
    assert r.json()["details"]["existing_id"] == first


def test_rename_onto_an_existing_name_is_a_409(admin_client, hdr, category):
    _post(admin_client, hdr, "threat-types", {"threat_type_name": "Taken", "threat_category_id": category})
    other = _post(admin_client, hdr, "threat-types",
                  {"threat_type_name": "Free", "threat_category_id": category}).json()["threat_type_id"]
    r = admin_client.patch(f"{_BASE}/threat-types/{other}", headers=hdr,
                           json={"threat_type_name": "Taken"})
    assert r.status_code == 409


def test_a_soft_deleted_name_can_be_reused(admin_client, hdr, category):
    """The unique indexes are FILTERED on IsActive=1 AND IsDeleted=0, so deleting genuinely
    frees the name — a create that 409'd yesterday can legitimately succeed today."""
    body = {"threat_type_name": "Recyclable", "threat_category_id": category}
    tid = _post(admin_client, hdr, "threat-types", body).json()["threat_type_id"]
    admin_client.delete(f"{_BASE}/threat-types/{tid}", headers=hdr)
    again = _post(admin_client, hdr, "threat-types", body)
    assert again.status_code == 201
    assert again.json()["threat_type_id"] != tid


def test_unknown_and_deleted_ids_both_404(admin_client, hdr, category):
    """A deleted row must 404 like a missing one, or DELETE becomes silently repeatable."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Gone", "threat_category_id": category}).json()["threat_type_id"]
    admin_client.delete(f"{_BASE}/threat-types/{tid}", headers=hdr)
    assert admin_client.delete(f"{_BASE}/threat-types/{tid}", headers=hdr).status_code == 404
    assert admin_client.patch(f"{_BASE}/threat-types/{tid}", headers=hdr,
                              json={"description": "x"}).status_code == 404
    assert admin_client.delete(f"{_BASE}/threat-types/999999", headers=hdr).status_code == 404


def test_parent_ids_must_resolve(admin_client, hdr, category):
    """These columns carry no DB foreign key, so an invented parent would otherwise create an
    orphan that stays invisible until grounding fails to resolve its family."""
    assert _post(admin_client, hdr, "threat-types",
                 {"threat_type_name": "Orphan", "threat_category_id": 999999}).status_code == 404
    assert _post(admin_client, hdr, "threat-catalogue",
                 {"threat_type_id": 999999, "threat_name": "Orphan"}).status_code == 404


def test_writes_refresh_the_embedding_index(admin_client, hdr, category, embed_calls):
    """A rename is delete-then-create: 'create' alone would add the new vector and leave the
    old name still matchable."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Old Name", "threat_category_id": category}).json()["threat_type_id"]
    assert embed_calls[-1] == ("create", "threat_type", ["Old Name"], _LENIENT)

    admin_client.patch(f"{_BASE}/threat-types/{tid}", headers=hdr, json={"threat_type_name": "New Name"})
    assert embed_calls[-2] == ("delete", "threat_type", ["Old Name"], _LENIENT)
    assert embed_calls[-1] == ("create", "threat_type", ["New Name"], _LENIENT)

    admin_client.delete(f"{_BASE}/threat-types/{tid}", headers=hdr)
    assert embed_calls[-1] == ("delete", "threat_type", ["New Name"], _LENIENT)


def test_non_name_edits_and_unembedded_tables_dispatch_nothing(admin_client, hdr, category, embed_calls):
    """Only the name is embedded, and actors/categories back no group at all — dispatching for
    them would queue pointless jobs on every edit."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Stable", "threat_category_id": category}).json()["threat_type_id"]
    before = len(embed_calls)
    r = admin_client.patch(f"{_BASE}/threat-types/{tid}", headers=hdr, json={"description": "new text"})
    assert len(embed_calls) == before and r.json()["embeddings_job_id"] is None

    r = _post(admin_client, hdr, "threat-actors", {"threat_actor_name": "Hacktivist"})
    assert r.status_code == 201 and len(embed_calls) == before


def test_embedding_dispatch_failure_does_not_fail_a_committed_write(admin_client, hdr, category, monkeypatch):
    """The row IS saved — reporting 5xx would invite a duplicate retry of work that succeeded."""
    def boom(*_a):
        raise RuntimeError("broker down")

    monkeypatch.setattr("app.api.library_crud.admin_embedding_action_task",
                        type("T", (), {"delay": staticmethod(boom)})())
    r = _post(admin_client, hdr, "threat-types",
              {"threat_type_name": "Survives", "threat_category_id": category})
    assert r.status_code == 201 and r.json()["embeddings_job_id"] is None


def test_every_resource_supports_the_full_cycle(admin_client, hdr, category):
    """One create/update/delete per table — the four share helpers, so this catches a field-map
    or PK-name typo on any of them."""
    tid = _post(admin_client, hdr, "threat-types",
                {"threat_type_name": "Parent", "threat_category_id": category}).json()["threat_type_id"]
    cases = [
        # NOT "Tampering" — that is a seeded STRIDE category, and UX_ThreatCategory_NaturalKey
        # (added 2026-07-30) now makes a duplicate live name a 409, same as its sibling masters.
        ("threat-categories", {"threat_category_id": 902, "threat_category_name": "Repudiation (crud-cycle)"},
         {"security_objective": "Integrity"}, "threat_category_id"),
        ("threat-catalogue", {"threat_type_id": tid, "threat_name": "Some exact threat"},
         {"description": "edited"}, "threat_catalogue_id"),
        ("threat-actors", {"threat_actor_name": "Nation State", "is_capable": 1},
         {"is_capable": 0}, "threat_actor_id"),
    ]
    for resource, create_body, patch_body, pk in cases:
        created = _post(admin_client, hdr, resource, create_body)
        assert created.status_code == 201, (resource, created.json())
        assert created.json()["created_by"] == _USER
        row_id = created.json()[pk]

        patched = admin_client.patch(f"{_BASE}/{resource}/{row_id}", headers=hdr, json=patch_body)
        assert patched.status_code == 200, (resource, patched.json())
        assert patched.json()["updated_by"] == _USER

        deleted = admin_client.delete(f"{_BASE}/{resource}/{row_id}", headers=hdr)
        assert deleted.status_code == 200 and deleted.json()["is_deleted"] is True


def test_category_create_requires_an_explicit_id(admin_client, hdr):
    """Threat_Category's PK is a plain int, not IDENTITY — deriving MAX+1 server-side would race."""
    assert _post(admin_client, hdr, "threat-categories",
                 {"threat_category_name": "No Id"}).status_code == 422


# ------------------------------------------------------------------ control library
_CBASE = "/v1/tsg/control-library"


def _control(admin_client, hdr, **over):
    body = {"control_code": "CII-CID-9001", "itot": "IT", "domain": "Identification",
            "control_name": "Phishing-Resistant MFA",
            "control_description": "Mechanisms exist to require FIDO2 for privileged accounts."}
    body.update(over)
    return admin_client.post(f"{_CBASE}/controls", headers=hdr, json=body)


def test_control_create_stamps_provenance_and_embeds(admin_client, hdr, embed_calls):
    """Controls are embedded on `name: description`, NOT the bare name — the create must queue a
    vector under the exact text embeddings._CONTROL_TEXT composes, or grounding never finds it."""
    r = _control(admin_client, hdr)
    assert r.status_code == 201
    row = r.json()
    assert row["source"] == "manual" and row["created_by"] == _USER and row["created_at"]
    assert embed_calls[-1] == ("create", "control_library", [
        "Phishing-Resistant MFA: Mechanisms exist to require FIDO2 for privileged accounts."], _LENIENT)


def test_editing_a_control_description_re_embeds_it(admin_client, hdr, embed_calls):
    """THE control-specific rule: the embedded text includes the description, so a
    description-only edit invalidates the vector. A name-only comparison would miss this and
    leave grounding matching the old wording forever."""
    cid = _control(admin_client, hdr).json()["control_library_id"]
    before = len(embed_calls)
    r = admin_client.patch(f"{_CBASE}/controls/{cid}", headers=hdr,
                           json={"control_description": "Rewritten control text."})
    assert r.status_code == 200 and r.json()["embeddings_job_id"] is not None
    assert embed_calls[before][0] == "delete"      # old text retired first
    assert embed_calls[-1] == ("create", "control_library",
                               ["Phishing-Resistant MFA: Rewritten control text."], _LENIENT)


def test_editing_a_non_embedded_control_field_does_not_re_embed(admin_client, hdr, embed_calls):
    """Domain/evidence/ITOT are not part of the embedded text — re-queueing for them would be
    pointless work on every edit."""
    cid = _control(admin_client, hdr).json()["control_library_id"]
    before = len(embed_calls)
    r = admin_client.patch(f"{_CBASE}/controls/{cid}", headers=hdr, json={"domain": "Network"})
    assert r.status_code == 200 and r.json()["embeddings_job_id"] is None
    assert len(embed_calls) == before


def test_control_code_is_the_natural_key_and_frees_on_delete(admin_client, hdr):
    """Unique on CODE, not name — two controls may share a name across domains. And the index is
    filtered now, so deleting genuinely frees the code (it was an unfiltered UNIQUE constraint,
    which would have reserved it forever)."""
    first = _control(admin_client, hdr).json()["control_library_id"]
    dup = _control(admin_client, hdr, control_name="A different name")
    assert dup.status_code == 409 and dup.json()["details"]["existing_id"] == first
    # same code, different name -> still a clash; same name, different code -> fine
    assert _control(admin_client, hdr, control_code="CII-CID-9002").status_code == 201

    admin_client.delete(f"{_CBASE}/controls/{first}", headers=hdr)
    assert _control(admin_client, hdr).status_code == 201


def test_control_standard_link_round_trip(admin_client, hdr):
    """The link is what fills `standards[]` on a scenario's mapped controls — without these two
    routes a hand-created control would report an empty list forever."""
    cid = _control(admin_client, hdr).json()["control_library_id"]
    sid = admin_client.post(f"{_CBASE}/standards", headers=hdr,
                            json={"standard_name": "ISO 27001:2022"}).json()["standard_id"]

    r = admin_client.post(f"{_CBASE}/controls/{cid}/standards/{sid}", headers=hdr)
    assert r.status_code == 201
    assert r.json()["standard_ids"] == [sid] and r.json()["standards"] == ["ISO 27001:2022"]

    # Idempotent: replaying the same attach is not an error, and does not duplicate the link.
    again = admin_client.post(f"{_CBASE}/controls/{cid}/standards/{sid}", headers=hdr)
    assert again.status_code == 201 and again.json()["standard_ids"] == [sid]

    assert admin_client.delete(f"{_CBASE}/controls/{cid}/standards/{sid}", headers=hdr).json()["standards"] == []
    # 404 on a second detach, so "removed it" is distinguishable from "nothing to remove".
    assert admin_client.delete(f"{_CBASE}/controls/{cid}/standards/{sid}", headers=hdr).status_code == 404


def test_linking_to_a_missing_control_or_standard_404s(admin_client, hdr):
    cid = _control(admin_client, hdr).json()["control_library_id"]
    assert admin_client.post(f"{_CBASE}/controls/{cid}/standards/999999", headers=hdr).status_code == 404
    assert admin_client.post(f"{_CBASE}/controls/999999/standards/1", headers=hdr).status_code == 404


def test_deleted_controls_leave_the_grounding_corpus(admin_client, hdr):
    """Same guarantee as the threat tables: a deleted control must stop being mappable."""
    from app.db.engine import db_session
    from app.pipeline.embeddings import _GROUPS, _active_names

    table, text_expr = _GROUPS["control_library"]
    cid = _control(admin_client, hdr).json()["control_library_id"]
    with db_session() as s:
        assert any("Phishing-Resistant MFA" in n for n in _active_names(s, table, text_expr))
    admin_client.delete(f"{_CBASE}/controls/{cid}", headers=hdr)
    with db_session() as s:
        assert not any("Phishing-Resistant MFA" in n for n in _active_names(s, table, text_expr))


def test_control_routes_require_the_admin_key(admin_client):
    no_key = {"X-Dev-User": _USER}
    for resource in ("controls", "standards"):
        assert admin_client.get(f"{_CBASE}/{resource}", headers=no_key).status_code == 401
        assert admin_client.post(f"{_CBASE}/{resource}", headers=no_key, json={}).status_code == 401
        assert admin_client.patch(f"{_CBASE}/{resource}/1", headers=no_key, json={}).status_code == 401
        assert admin_client.delete(f"{_CBASE}/{resource}/1", headers=no_key).status_code == 401
    assert admin_client.post(f"{_CBASE}/controls/1/standards/1", headers=no_key).status_code == 401
    assert admin_client.delete(f"{_CBASE}/controls/1/standards/1", headers=no_key).status_code == 401


def test_every_route_requires_the_admin_key(admin_client):
    """The library is shared cross-tenant, so the key is the authorization gate on all 16."""
    no_key = {"X-Dev-User": _USER}
    for resource in ("threat-categories", "threat-types", "threat-catalogue", "threat-actors"):
        assert admin_client.get(f"{_BASE}/{resource}", headers=no_key).status_code == 401
        assert admin_client.post(f"{_BASE}/{resource}", headers=no_key, json={}).status_code == 401
        assert admin_client.patch(f"{_BASE}/{resource}/1", headers=no_key, json={}).status_code == 401
        assert admin_client.delete(f"{_BASE}/{resource}/1", headers=no_key).status_code == 401


def test_duplicate_category_name_is_rejected_like_every_other_master(admin_client, hdr):
    """UX_ThreatCategory_NaturalKey (2026-07-30). Threat_Category was the only CRUD-writable
    master with no natural-key index, so the shared 409 handler — which fires purely on the
    IntegrityError that index raises — never triggered and duplicates were accepted silently.
    Two consumers then disagreed about which id a name means: grounding.find_category takes the
    LOWEST id, while the library importer builds its own name->id map."""
    first = _post(admin_client, hdr, "threat-categories",
                {"threat_category_id": 911, "threat_category_name": "Duplicate Probe"})
    assert first.status_code == 201

    clash = _post(admin_client, hdr, "threat-categories",
                {"threat_category_id": 912, "threat_category_name": "Duplicate Probe"})
    assert clash.status_code == 409                      # not a 500, and not a silent second row
    assert clash.json()["details"]["existing_id"] == 911

    # soft-delete frees the name, exactly like the filtered sibling indexes
    assert admin_client.delete(f"{_BASE}/threat-categories/911", headers=hdr).status_code == 200
    assert _post(admin_client, hdr, "threat-categories",
                {"threat_category_id": 913, "threat_category_name": "Duplicate Probe"}).status_code == 201


def test_duplicate_id_reports_an_id_clash_not_a_name_clash(admin_client, hdr):
    """Threat_Category's PK is caller-supplied (not IDENTITY), so re-sending an existing id
    collides on PK_Threat_Category while the NAME is free. Reporting that as "already matches this
    natural key" sends the curator to the wrong field — they'd rename, and hit the same 409."""
    assert _post(admin_client, hdr, "threat-categories",
                {"threat_category_id": 921, "threat_category_name": "Id Clash Probe"}).status_code == 201

    clash = _post(admin_client, hdr, "threat-categories",
                {"threat_category_id": 921, "threat_category_name": "A Completely Different Name"})
    assert clash.status_code == 409
    body = clash.json()
    assert "id already exists" in body["message"], body
    assert "natural key" not in body["message"]
    assert body["details"]["existing_id"] == 921

    # the name really was free — same name, a fresh id, succeeds
    assert _post(admin_client, hdr, "threat-categories",
                {"threat_category_id": 922,
                "threat_category_name": "A Completely Different Name"}).status_code == 201
