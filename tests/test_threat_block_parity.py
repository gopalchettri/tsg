"""The 2026-08 next-set cross-check fixes, pinned (catalogue model).

  * ONE shared Identified_Threat column list (dal.scenario_threat_columns) feeds all three
    scenario reads — the drift where /accepted-scenarios answered null while /results
    carried the value can never come back; the list now carries ThreatCatalogueID and
    IsAIGenerated (ThemeID/AssetTypeID left with the register);
  * the SAME threat row produces the SAME _threat_block through both read paths;
  * _build_threat_records stamps the immutable IsAIGenerated provenance flag from
    gr.catalogue_id alone, whichever door the threat entered;
  * the treatment presenters coalesce the curator's wording exactly like /results;
  * the prompt-redaction net covers the pipeline dicts' own key spellings;
  * the calibration script no longer passes the deleted sector_ids kwarg;
  * promotion never touches the provenance flag.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import sessions as sessions_mod
from app.core.enums import GroundingStatus
from app.core.naming import display_threat_names
from app.db import dal
from app.db import models as m
from app.pipeline import grounding, prompts, tasks

_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.now(UTC)


def _threat_cols(sel) -> set[str]:
    it = m.Identified_Threat.__table__
    return {c.name for c in sel.selected_columns if getattr(c, "table", None) is it}


def test_all_scenario_reads_select_the_one_shared_threat_column_list():
    """The recurrence guard for the drift class itself: every scenario read carries exactly
    dal.scenario_threat_columns(). A fourth hand-maintained subset fails here immediately."""
    canonical = {c.name for c in dal.scenario_threat_columns()}
    assert _threat_cols(sessions_mod._scenario_select()) == canonical
    assert _threat_cols(dal._scenario_read_select()) == canonical
    # accepted_scenarios builds its select inline — pin at source that it unpacks the list.
    src = (_ROOT / "app" / "db" / "dal.py").read_text(encoding="utf-8")
    assert src.count("*scenario_threat_columns(),") == 2  # _scenario_read_select + accepted
    ssrc = (_ROOT / "app" / "api" / "sessions.py").read_text(encoding="utf-8")
    assert "*dal.scenario_threat_columns()," in ssrc
    # And the list carries the catalogue-model fields; the register-era columns are gone.
    assert {"ThreatCatalogueID", "ThreatCategoryID", "Description",
            "IsAIGenerated"} <= canonical
    assert not {"ThemeID", "AssetTypeID"} & canonical


def _gr(catalogue_id=None):
    return grounding.GroundingResult(
        status=GroundingStatus.verified if catalogue_id else GroundingStatus.unverified,
        type_id=7, catalogue_id=catalogue_id,
        library_type="Logic Manipulation" if catalogue_id else None,
        library_name="Unauthorised setpoint modification" if catalogue_id else None,
        score=95.0 if catalogue_id else 10.0, actors=["APT33"], actor_ids=[3],
        actors_validated=bool(catalogue_id), category_id=6,
        threshold_origin="env_pinned")


def _record(gr):
    row, summary = tasks._build_threat_records(
        str(uuid.uuid4()), str(uuid.uuid4()), "t", 0, "Tampering type", "Tampering",
        "Setpoint change", gr, "e", "u", generic_name="Setpoint change",
        description="An attacker alters setpoints.", category_id=6)
    return row, summary


def test_catalogue_verified_threat_is_not_ai_generated():
    """A generated proposal VERIFIED onto a live catalogue row is library provenance:
    IsAIGenerated False, and the row stores the catalogue id it verified onto."""
    row, summary = _record(_gr(catalogue_id=418))
    assert row["ThreatCatalogueID"] == 418
    assert row["IsAIGenerated"] is False and summary["is_ai_generated"] is False


def test_unverified_generated_threat_is_ai_generated():
    row, summary = _record(_gr())
    assert row["ThreatCatalogueID"] is None
    assert row["IsAIGenerated"] is True and summary["is_ai_generated"] is True


def test_retrieved_style_grounding_is_library_provenance():
    """_build_retrieved_records hand-builds gr with catalogue_id already set (identity
    match, no cutoff consulted) — the SAME catalogue_id-is-None rule must brand every
    retrieved threat as library, never AI."""
    row, summary = _record(_gr(catalogue_id=418))
    assert row["IsAIGenerated"] is False
    assert summary["catalogue_id"] == 418


def _seeded_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'parity.db'}")
    for tbl in (m.Scenario_Session, m.Identified_Threat, m.Scoped_Threat,
                m.Threat_Scenario):
        tbl.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    sid = str(uuid.uuid4())
    row, _summary = _record(_gr(catalogue_id=418))
    row["SessionID"] = sid
    scoped_id, scenario_id = str(uuid.uuid4()), str(uuid.uuid4())
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(
            SessionID=sid, TenantID="t", EntityID="e", UserID="u", AssetName="Asset",
            AssetID="1", SessionStatus="completed", CurrentStage="SCENARIO_GENERATION",
            StageStatus="COMPLETE", Mode="AUTO", SubsystemsJSON="[]", SectorIDsJSON="[]",
            CreatedAt=NOW, UpdatedAt=NOW))
        s.execute(m.Identified_Threat.__table__.insert().values(**row))
        s.execute(m.Scoped_Threat.__table__.insert().values(
            ScopedThreatID=scoped_id, SessionID=sid, TenantID="t", EntityID="e",
            SubsystemID=0, ThreatID=row["ThreatID"], Score=77.0, ScopeRank=1, Selected=1,
            Superseded=0, CreatedAt=NOW))
        s.execute(m.Threat_Scenario.__table__.insert().values(
            ScenarioID=scenario_id, SessionID=sid, TenantID="t", EntityID="e", SubsystemID=0,
            ScopedThreatID=scoped_id, Status="complete", ScenarioJSON="{}",
            Accepted=1, Superseded=0, ScenarioNumber=1, GenerationEpoch=1, CreatedAt=NOW,
            # accepted() implies the filtered index's WHOLE predicate: Accepted=1 AND
            # IdentityHash IS NOT NULL — a NULL hash row is invisible to it by design.
            IdentityHash="a" * 64, ScenarioSource="generated"))
        s.commit()
    return Session, sid


def test_both_read_paths_serve_the_identical_threat_block(tmp_path):
    """The wire-level bite for the original defect: /accepted-scenarios' row and /results'
    row build byte-identical threat blocks — ThreatCatalogueID and IsAIGenerated
    populated on BOTH, not just one."""
    Session, sid = _seeded_session(tmp_path)
    with Session() as s:
        accepted_row = dal.accepted_scenarios(s, sid)[0]
        results_row = dict(s.execute(
            sessions_mod._scenario_select().where(
                m.Threat_Scenario.SessionID == sid)).mappings().one())
    block_a = sessions_mod._threat_block(accepted_row, {"APT33": 3})
    block_r = sessions_mod._threat_block(results_row, {"APT33": 3})
    assert block_a == block_r
    assert block_a["threat_catalogue_id"] == 418
    assert block_a["is_threat_ai_generated"] is False
    assert block_a["actors"] == [{"actor_id": 3, "actor_name": "APT33"}]


def test_display_wording_coalesce_is_shared_and_prefers_the_curator():
    row = {"ThreatType": "model wording", "ThreatName": "model name",
           "LibraryThreatType": "Curated Type", "LibraryThreatName": "Curated Name"}
    assert display_threat_names(row) == ("Curated Type", "Curated Name")
    assert display_threat_names({"ThreatType": "model wording"}) == ("model wording", None)
    # The treatment presenters and plan selects actually use it — the wording parity fix.
    tsrc = (_ROOT / "app" / "api" / "treatment.py").read_text(encoding="utf-8")
    assert "display_threat_names(row)" in tsrc
    dsrc = (_ROOT / "app" / "db" / "dal.py").read_text(encoding="utf-8")
    # 1, not 2: the set-based active_plan_rows sibling was deleted with the Excel export it
    # existed to serve (2026-08) — active_plan_row is the only remaining plan select of this shape.
    assert dsrc.count("it.LibraryThreatType, it.LibraryThreatName)") == 1  # active_plan_row
    assert dsrc.count("it.LibraryThreatType, it.LibraryThreatName]") == 1  # entity_plan_rows
    ssrc = (_ROOT / "app" / "api" / "sessions.py").read_text(encoding="utf-8")
    assert "display_threat_names(threat_row)" in ssrc


def test_pipeline_dict_key_spellings_are_in_the_redaction_net():
    # catalogue_id/threat_catalogue_id are the live spellings; the register-era ones
    # stay in the net as defence-in-depth.
    for key in ("catalogue_id", "threat_catalogue_id", "register_id", "threat_code",
                "type_id", "category_id"):
        assert key in prompts._EXCLUDE_DB_KEY_TO_PROMPT, key


def test_calibration_script_no_longer_passes_the_deleted_sector_kwarg():
    src = (_ROOT / "scripts" / "calibrate_grounding.py").read_text(encoding="utf-8")
    assert "sector_ids" not in src


def test_promotion_never_touches_the_provenance_flag():
    """IsAIGenerated is immutable history — promote stamps ThreatCatalogueID but a
    promoted AI threat must keep answering True to 'was this invented by the AI?'."""
    src = (_ROOT / "app" / "pipeline" / "promote.py").read_text(encoding="utf-8")
    assert "IsAIGenerated" not in src
