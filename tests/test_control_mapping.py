"""Step 4 — control library mapping (control_mapping.map_controls / grounding machinery /
sessions._controls_by_output). Runs on the shared SQLite fixture with StubLLM (rerank: 90 for
substring-style matches, 40 otherwise — brackets the min-score cutoff)."""
from __future__ import annotations

import json

from sqlalchemy import insert, select

from app.core.enums import ScenarioStatus, StageStatus, SubsystemLevel
from app.db import models as m
from app.db.dal import guid, now
from app.pipeline import grounding
from app.pipeline.control_mapping import itot_family, map_controls, _min_score, _resolve_itot
from app.pipeline.tasks import ASSET_UNIT_ID

SID = "11111111-1111-1111-1111-111111111111"
TASK = "22222222-2222-2222-2222-222222222222"  # ActiveTaskID is a GUID column


def _seed_controls(sess):
    sess.execute(insert(m.Control_Library), [
        {"ControlLibraryID": 1, "ControlCode": "CII-CID-001", "ITOT": "IT",
         "Domain": "Identification & Authentication", "ControlName": "Multi-Factor Authentication",
         "ControlDescription": "Mechanisms exist to require MFA for privileged accounts",
         "IsActive": True, "IsDeleted": False},
        {"ControlLibraryID": 2, "ControlCode": "CII-CID-002", "ITOT": "IT",
         "Domain": "Security Awareness", "ControlName": "Phishing Awareness Training",
         "ControlDescription": "Mechanisms exist to train personnel to recognize phishing",
         "IsActive": True, "IsDeleted": False},
        # OT-family control: must be excluded whenever the ITOT filter fires
        {"ControlLibraryID": 3, "ControlCode": "CII-CID-003", "ITOT": "OT",
         "Domain": "Network Security", "ControlName": "OT Network Segmentation",
         "ControlDescription": "Mechanisms exist to segment industrial control networks",
         "IsActive": True, "IsDeleted": False},
        # inactive: must never appear anywhere
        {"ControlLibraryID": 4, "ControlCode": "CII-CID-004", "ITOT": "IT",
         "Domain": "Cryptography", "ControlName": "Deprecated Control",
         "ControlDescription": "Retired", "IsActive": False, "IsDeleted": False},
    ])
    sess.execute(insert(m.Control_Standard), [
        {"StandardID": 1, "StandardName": "NIST SP 800-53 Rev. 5", "IsActive": True, "IsDeleted": False},
        {"StandardID": 2, "StandardName": "ISO 27001:2022", "IsActive": True, "IsDeleted": False},
    ])
    sess.execute(insert(m.Control_Library_Standard_Map), [
        {"ControlLibraryID": 1, "StandardID": 1}, {"ControlLibraryID": 1, "StandardID": 2},
        {"ControlLibraryID": 2, "StandardID": 1},
    ])
    sess.commit()


def _seed_stage_and_output(sess, scenario: dict, output_id: str | None = None):
    """A RUNNING SCENARIOS stage row (so dal.renew_lease's real fencing passes) plus one
    complete, active output carrying `scenario` as its ScenarioJSON."""
    if not sess.execute(select(m.Subsystem_Stage_State).filter_by(SessionID=SID)).first():
        sess.execute(insert(m.Subsystem_Stage_State), [{
            "StateID": guid(),
            "SessionID": SID, "SubsystemID": ASSET_UNIT_ID, "Level": SubsystemLevel.SCENARIOS,
            "Status": StageStatus.RUNNING, "GenerationEpoch": 1, "ActiveTaskID": TASK,
            "LeaseExpiresAt": None, "AttemptCount": 1, "UpdatedAt": now()}])
    oid = output_id or guid()
    sess.execute(insert(m.Threat_Scenario_Output), [{
        "OutputID": oid, "SessionID": SID, "TenantID": "t", "EntityID": "5", "SubsystemID": ASSET_UNIT_ID,
        "ScopedThreatID": guid(), "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario), "Accepted": 0, "Superseded": 0,
        "GenerationEpoch": 1, "CreatedAt": now()}])
    sess.commit()
    return oid


SESSION = {"SessionID": SID, "TenantID": "t", "EntityID": "5"}


def test_control_candidates_itot_filter_and_active_only(db):
    _seed_controls(db)
    it_rows = grounding.get_control_candidates(db, "IT")
    assert {r["ControlCode"] for r in it_rows} == {"CII-CID-001", "CII-CID-002"}  # no OT, no inactive
    all_rows = grounding.get_control_candidates(db, "SERVER")  # junk asset type → whole library
    assert {r["ControlCode"] for r in all_rows} == {"CII-CID-001", "CII-CID-002", "CII-CID-003"}
    assert all_rows[0]["text"].startswith("Multi-Factor Authentication: ")  # name+description concat


def test_map_controls_grounds_dedupes_and_is_idempotent(db, stub_llm):
    _seed_controls(db)
    oid = _seed_stage_and_output(db, {
        "scenario_title": "Credential theft against CAD", "scenario_statement": "S",
        # StubLLM reranks 90 only for substring-style matches, so the "why" fields stay empty
        # here — the query is then exactly the suggestion name, a prefix of the library text.
        "controls": [
            {"name": "Multi-Factor Authentication", "why": ""},
            {"name": "multi-factor authentication", "why": ""},  # dupe → same library row
            {"name": "Quantum Blockchain Firewall", "why": ""},  # no library counterpart → dropped
        ]})
    map_controls(db, SESSION, {"asset_type": "it"}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)
    db.commit()
    rows = db.execute(select(m.Threat_Scenario_Control_Map).filter_by(OutputID=oid)).scalars().all()
    assert [r.ControlLibraryID for r in rows] == [1]         # deduped; weak suggestion dropped (40 < 60)
    assert rows[0].MapRank == 1 and rows[0].Score >= 60
    assert rows[0].SuggestedControl == "Multi-Factor Authentication"
    map_controls(db, SESSION, {"asset_type": "it"}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)  # second run: NOT EXISTS guard
    db.commit()
    assert len(db.execute(select(m.Threat_Scenario_Control_Map).filter_by(OutputID=oid)).scalars().all()) == 1
    audit = db.execute(select(m.Scenario_Audit).filter_by(SessionID=SID)).scalars().all()
    assert len(audit) == 1 and audit[0].EventType == "controls_mapped"
    detail = json.loads(audit[0].DetailJSON)
    assert detail["itot_filter_applied"] is True and detail["itot"] == "IT" and detail["skipped"] == 0


def test_map_controls_no_audit_when_nothing_groundable(db, stub_llm):
    """An output with blank scenario text and no suggestions is skipped without emitting a
    misleading zero-count controls_mapped audit event (reviewer finding, 2026-07-26)."""
    _seed_controls(db)
    _seed_stage_and_output(db, {"scenario_title": "", "scenario_statement": ""})
    map_controls(db, SESSION, {"asset_type": "it"}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)
    db.commit()
    assert db.execute(select(m.Threat_Scenario_Control_Map)).scalars().all() == []
    assert db.execute(select(m.Scenario_Audit).filter_by(SessionID=SID)).scalars().all() == []


def test_map_controls_falls_back_to_scenario_text(db, stub_llm):
    _seed_controls(db)
    oid = _seed_stage_and_output(db, {  # pre-1.3 prompt shape: no `controls` key
        "scenario_title": "Phishing Awareness Training", "scenario_statement": ""})
    map_controls(db, SESSION, {"asset_type": ""}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)
    db.commit()
    rows = db.execute(select(m.Threat_Scenario_Control_Map).filter_by(OutputID=oid)).scalars().all()
    assert rows and rows[0].SuggestedControl is None  # fallback path stores no suggestion text


def test_controls_by_output_joins_standards_and_hides_inactive(db, stub_llm):
    from app.api.sessions import _controls_by_output

    _seed_controls(db)
    oid = guid()
    db.execute(insert(m.Threat_Scenario_Control_Map), [
        {"OutputID": oid, "ControlLibraryID": 1, "SessionID": SID, "MapRank": 1, "Score": 93.0,
         "SuggestedControl": "MFA", "CreatedAt": now()},
        # maps to the inactive control → must be filtered out of the payload
        {"OutputID": oid, "ControlLibraryID": 4, "SessionID": SID, "MapRank": 2, "Score": 80.0,
         "SuggestedControl": "old", "CreatedAt": now()},
    ])
    db.commit()
    by_output = _controls_by_output(db, [oid])
    controls = by_output[oid]
    assert [c.control_code for c in controls] == ["CII-CID-001"]
    assert controls[0].standards == ["ISO 27001:2022", "NIST SP 800-53 Rev. 5"]
    assert controls[0].domain == "Identification & Authentication" and controls[0].rank == 1
    assert _controls_by_output(db, []) == {}


def test_matrix_cache_reuses_and_invalidates(db, stub_llm):
    """Perf plan #1: same texts → the cached matrix object is reused; changed texts rebuild
    (digest tripwire); clear_cache drops it (re-embed tripwire)."""
    from app.pipeline import embeddings

    texts = ["Alpha control", "Beta control"]
    first = embeddings.get_matrix(stub_llm, texts, model_id="m", group="control_library")
    again = embeddings.get_matrix(stub_llm, texts, model_id="m", group="control_library")
    assert first is not None and again[0] is first[0]  # same cached object, no rebuild
    changed = embeddings.get_matrix(stub_llm, ["Alpha control", "Gamma control"],
                                    model_id="m", group="control_library")
    assert changed[0] is not first[0]  # library changed → digest changed → rebuilt
    embeddings.clear_cache("control_library")
    cleared = embeddings.get_matrix(stub_llm, texts, model_id="m", group="control_library")
    assert cleared[0] is not first[0]  # explicit invalidation (admin recreate path)


def test_ground_control_queries_matches_per_query_path(db, stub_llm):
    """Perf plan #2: the batched path must be score-identical to per-query find_closest_match."""
    from app.core.config import get_settings

    _seed_controls(db)
    s = get_settings()
    candidates = grounding.get_control_candidates(db, "IT")
    queries = ["Multi-Factor Authentication", "Phishing Awareness Training", "Quantum Blockchain Firewall"]
    batched = grounding.ground_control_queries(stub_llm, [(q, None) for q in queries], candidates, s)
    for q, got in zip(queries, batched):
        row, score = grounding.find_closest_match(stub_llm, q, candidates, "text", s, group="control_library")
        assert got is not None and got[0]["ControlLibraryID"] == row["ControlLibraryID"]
        assert got[1] == score


def test_rerank_many_local_is_one_dispatch(monkeypatch):
    """Local provider: ALL items' pairs flatten into ONE rerank_pairs call, re-sliced per item."""
    from app.core.config import get_settings
    from app.pipeline import local_models
    from app.pipeline.llm import LiteLLMClient

    calls = []

    def fake_pairs(pairs):
        calls.append(list(pairs))
        return [float(10 * i) for i in range(len(pairs))]

    monkeypatch.setattr(local_models, "rerank_pairs", fake_pairs)
    s = get_settings().model_copy(update={"reranker_provider": "local"})
    out = LiteLLMClient(s).rerank_many([("q1", ["a", "b"]), ("q2", ["c"])])
    assert len(calls) == 1 and calls[0] == [("q1", "a"), ("q1", "b"), ("q2", "c")]
    assert out == [[0.0, 10.0], [20.0]]  # re-sliced per item, order preserved


def test_rerank_many_remote_fails_open_per_item(monkeypatch):
    """Remote provider: one failing item → None for it (others survive); ALL failing → raises."""
    import pytest

    from app.core.config import get_settings
    from app.pipeline.llm import LiteLLMClient

    s = get_settings().model_copy(update={"reranker_provider": "litellm_proxy", "rerank_concurrency": 2})
    client = LiteLLMClient(s)

    def flaky(query, docs, *, model=None):
        if query == "bad":
            raise RuntimeError("boom")
        return [50.0] * len(docs)

    monkeypatch.setattr(client, "rerank", flaky)
    out = client.rerank_many([("ok", ["a"]), ("bad", ["b"]), ("ok2", ["c", "d"])])
    assert out == [[50.0], None, [50.0, 50.0]]
    monkeypatch.setattr(client, "rerank", lambda q, d, *, model=None: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(RuntimeError, match="all 2 rerank calls failed"):
        client.rerank_many([("x", ["a"]), ("y", ["b"])])


def test_controls_by_output_degrades_when_tables_missing(db):
    """Deploy-ordering guard: an environment where Control_library.sql hasn't run yet must get
    controls=[] on the core read endpoints, not a 500."""
    from sqlalchemy import text

    from app.api.sessions import _controls_by_output

    db.execute(text('DROP TABLE "Threat_Scenario_Control_Map"'))
    db.execute(text('DROP TABLE "Control_Library"'))
    db.commit()
    assert _controls_by_output(db, [guid()]) == {}
    # and the session is still usable for the caller's remaining reads
    assert db.execute(select(m.Scenario_Audit)).scalars().all() == []


def test_itot_family_recognizes_platform_vocabulary():
    """Fix #1: the filter must engage on the platform's REAL controlled vocabulary (the exact
    strings the seeded tech_gate rules match), not just bare IT/OT."""
    assert itot_family("Information Technology (IT)") == "IT"
    assert itot_family("Operational Technology (OT)") == "OT"
    assert itot_family("ot") == "OT" and itot_family("IT") == "IT"
    assert itot_family("Server") is None and itot_family("") is None and itot_family(None) is None
    # mixed signals → no filter; agreeing signals → filter; subsystem-only signal counts
    assert _resolve_itot({"asset_type": "Server"},
                         [{"asset_type": "Information Technology (IT)"}]) == "IT"
    assert _resolve_itot({"asset_type": "IT"}, [{"asset_type": "Operational Technology (OT)"}]) is None


def test_scenario_merge_replaces_raw_suggestions_and_recovers_why():
    """The API delivers ONE control list, nested: the grounded library matches replace the LLM's
    raw {name, why} suggestions inside `scenario`. `why` is never persisted (only `name[:500]`
    lands in SuggestedControl), so it has to be recovered from the raw list at read time —
    which is also what makes it work for sessions mapped before the field existed."""
    from app.api.schemas import MappedControl
    from app.api.sessions import _scenario_with_controls

    long_name = "L" * 600  # SuggestedControl is truncated to 500 — the lookup must still match
    scenario_json = json.dumps({
        "scenario_title": "T", "scenario_statement": "S", "risk_statement": "R",
        "controls": [{"name": "Multi-Factor Authentication", "why": "stops stolen passwords"},
                     {"name": long_name, "why": "long-name rationale"},
                     {"name": "Never Grounded", "why": "no library counterpart"}],
    })

    def mapped(suggested, rank):
        return MappedControl(control_library_id=rank, control_code=f"CII-CID-00{rank}",
                             domain="D", control_name="N", rank=rank, score=90.0,
                             suggested_control=suggested, standards=[])

    merged = _scenario_with_controls(scenario_json, [
        mapped("Multi-Factor Authentication", 1), mapped(long_name[:500], 2), mapped(None, 3)])

    assert merged["scenario_title"] == "T"  # the narrative itself is untouched
    controls = merged["controls"]
    # the raw {name, why} shape is gone; both halves resurface on the grounded entries
    assert all("name" not in c and c["control_code"] for c in controls)
    assert controls[0]["suggested_control"] == "Multi-Factor Authentication"
    assert controls[0]["suggested_why"] == "stops stolen passwords"
    assert controls[1]["suggested_why"] == "long-name rationale"  # matched past the truncation
    assert controls[2]["suggested_why"] is None  # scenario-text fallback carries no suggestion
    assert len(controls) == 3

    # ...and every raw suggestion survives under its own key, INCLUDING "Never Grounded", which has
    # no counterpart in `controls`. That difference is the library-gap signal: overwriting the raw
    # list outright made a suggestion the library couldn't satisfy vanish without trace.
    assert merged["suggested_controls"] == [
        {"name": "Multi-Factor Authentication", "why": "stops stolen passwords"},
        {"name": long_name, "why": "long-name rationale"},
        {"name": "Never Grounded", "why": "no library counterpart"}]
    assert "Never Grounded" not in {c["suggested_control"] for c in controls}

    # Nothing mapped yet (the ~4-min window before Step-4 runs): `controls` is empty, but the
    # model's suggestions are already there — blanking both is what made an in-progress read look
    # like the model had proposed nothing at all.
    in_progress = _scenario_with_controls(scenario_json, [])
    assert in_progress["controls"] == []
    assert [c["name"] for c in in_progress["suggested_controls"]] == [
        "Multi-Factor Authentication", long_name, "Never Grounded"]

    # a pre-v1.3 scenario has no `controls` key at all — empty, not a crash
    assert _scenario_with_controls(json.dumps({"scenario_title": "T"}), [])["suggested_controls"] == []
    # unusable entries (missing/blank name, non-dict) are dropped rather than emitted half-formed
    junk = json.dumps({"controls": [{"why": "no name"}, {"name": "   "}, "not even a dict"]})
    assert _scenario_with_controls(junk, [])["suggested_controls"] == []
    # a failed generation has no scenario at all, and must not become an empty dict
    assert _scenario_with_controls(None, []) is None

    # unmatched_suggestions precomputes the exact library-gap diff: "Never Grounded" is the only
    # raw suggestion with no counterpart naming it in a mapped control's suggested_control.
    assert merged["unmatched_suggestions"] == [{"name": "Never Grounded", "why": "no library counterpart"}]
    # gated on controls_mapped: mapping hasn't run yet -> null, not a misleading "everything unmatched"
    unmapped = _scenario_with_controls(scenario_json, [
        mapped("Multi-Factor Authentication", 1), mapped(long_name[:500], 2), mapped(None, 3)], False)
    assert unmapped["unmatched_suggestions"] is None


def test_a_non_object_scenario_json_degrades_to_null_not_a_500():
    """_safe_scenario_json's whole job is that ONE corrupted row never hides every other scenario
    in the session. It caught malformed text, but valid JSON that isn't an object parsed fine and
    then died in response validation — a 500 for the entire endpoint."""
    from app.api.sessions import _safe_scenario_json

    for not_a_scenario in ("[1,2]", "null", '"a bare string"', "42", "not json at all", "", None):
        assert _safe_scenario_json(not_a_scenario) is None, not_a_scenario
    assert _safe_scenario_json('{"scenario_title": "T"}') == {"scenario_title": "T"}


def test_controls_mapped_flag_mirrors_the_attempt_stamp():
    """`controls_mapped` is the ONLY thing separating "mapping ran, nothing in the library
    matched" from "mapping hasn't run yet" — both of which show an empty scenario.controls."""
    from app.api.sessions import _scenario_result

    row = {"OutputID": guid(), "ThreatID": guid(), "SubsystemID": ASSET_UNIT_ID, "ScenarioJSON": None,
           "Accepted": 0, "ValidationJSON": None, "GenerationEpoch": 1, "ScenarioNumber": 1,
           "ControlsMappedAt": None}
    assert _scenario_result(row).controls_mapped is False
    assert _scenario_result({**row, "ControlsMappedAt": now()}).controls_mapped is True


def test_min_score_follows_model_pair_unless_pinned():
    """Fix #2: pinned env value wins; otherwise the per-model-pair match threshold applies —
    the cutoff follows the models per environment instead of a one-size-fits-none constant."""
    from app.core.config import get_settings

    s = get_settings()
    pinned = s.model_copy(update={"control_map_min_score": 42.0})
    assert _min_score(None, None, pinned) == 42.0
    if "control_map_min_score" not in s.model_fields_set:
        assert _min_score(None, None, s) == grounding.resolve_thresholds(None, None, s)


def test_attempt_stamp_stops_rescan_even_with_zero_matches(db, stub_llm):
    """Fix #5: EVERY attempted output is stamped — including nothing-groundable ones — so no
    output is ever re-scanned on a later run."""
    _seed_controls(db)
    blank = _seed_stage_and_output(db, {"scenario_title": "", "scenario_statement": ""})
    map_controls(db, SESSION, {"asset_type": "it"}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)
    db.commit()
    out = db.execute(select(m.Threat_Scenario_Output).filter_by(OutputID=blank)).scalar_one()
    assert out.ControlsMappedAt is not None  # stamped despite zero map rows
    calls = []
    class CountingLLM:
        def embed(self, texts, **kw):
            calls.append(texts)
            return [[1.0]] * len(texts)
        rerank = None
    map_controls(db, SESSION, {"asset_type": "it"}, None, CountingLLM(), ASSET_UNIT_ID, TASK, 1)
    assert calls == []  # second run fetched nothing — no model work at all


def test_supersede_keeps_control_map_rows(db, stub_llm):
    """Superseding an output KEEPS its map rows (2026-07-30, replacing the former
    'superseded ⇒ no map rows' invariant).

    That invariant rested on "a superseded scenario is unreachable through the API, so its old
    map rows are pure dead weight". GET /results?include_replaced=true makes them reachable, so a
    reviewer comparing an old version against its replacement gets the controls it actually
    mapped to — and once deleted those are unrecoverable. This assertion is the point of the
    change: it fails against the old delete-on-supersede behaviour."""
    from app.db import dal

    _seed_controls(db)
    oid = _seed_stage_and_output(db, {"scenario_title": "T", "scenario_statement": "S",
                                      "controls": [{"name": "Multi-Factor Authentication", "why": ""}]})
    map_controls(db, SESSION, {"asset_type": "it"}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)
    db.commit()
    before = db.execute(select(m.Threat_Scenario_Control_Map).filter_by(OutputID=oid)).scalars().all()
    assert before
    dal.supersede(db, m.Threat_Scenario_Output, SID, ASSET_UNIT_ID)
    db.commit()
    after = db.execute(select(m.Threat_Scenario_Control_Map).filter_by(OutputID=oid)).scalars().all()
    assert len(after) == len(before)


def test_resolve_names_accepts_control_name_prefix():
    """Fix #7: admin per-name ops can address a control by its human ControlName even though
    the group's stored 'name' is the full name+description embed text."""
    from app.pipeline.embeddings import _resolve_names

    full = "Multi-Factor Authentication: Mechanisms exist to require MFA"
    resolved, unmatched = _resolve_names([full, "Phishing Awareness Training: trains people"],
                                         ["multi-factor authentication", "nope"])
    assert resolved == [full] and unmatched == ["nope"]


def test_moderation_covers_control_suggestions():
    """Fix #8: the moderation text includes the LLM's control suggestions, not just the
    narrative fields."""
    from app.pipeline import tasks

    seen = {}
    real = tasks.moderate

    def capture(text):
        seen["text"] = text
        return real("")

    try:
        tasks.moderate = capture
        tasks._moderation_report({"scenario_title": "T", "controls": [
            {"name": "MFA everywhere", "why": "stops stolen passwords"}]})
    finally:
        tasks.moderate = real
    assert "MFA everywhere" in seen["text"] and "stops stolen passwords" in seen["text"]


def test_map_controls_failure_leaves_session_usable(db, stub_llm, monkeypatch):
    """Reviewer finding (2026-07-26): a failure mid-write must roll back so the caller's
    finish_stage doesn't die on a poisoned session — enrichment failure never fails the stage."""
    from app.db import dal

    _seed_controls(db)
    _seed_stage_and_output(db, {"scenario_title": "T", "scenario_statement": "S",
                                "controls": [{"name": "Multi-Factor Authentication", "why": ""}]})
    monkeypatch.setattr(dal, "append_audit",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("db boom")))
    map_controls(db, SESSION, {"asset_type": "it"}, None, stub_llm, ASSET_UNIT_ID, TASK, 1)
    # never raises, and the session must be clean for the caller's next statement
    assert db.execute(select(m.Threat_Scenario_Output)).scalars().all() is not None
    # the failed attempt rolled back wholesale: no half-written map rows or stamps survive
    assert db.execute(select(m.Threat_Scenario_Control_Map)).scalars().all() == []
