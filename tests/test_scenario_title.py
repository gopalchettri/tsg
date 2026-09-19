"""Scenario titles name the impact only — never the asset, which is shown next to them.

It used to be the rule the other way round: the prompt asked for "the asset and the impact
against it" and validation flagged a title WITHOUT the asset, so every title read
"Power Generation System (PGS) — Disruption of control and monitoring functions". Now the prompt
asks for the impact only, a leading asset name the model adds anyway is cut before validation,
and one left anywhere else in the title is reported (never rewritten mid-sentence).
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.enums import StageStatus, SubsystemLevel
from app.db import models as m
from app.pipeline import tasks
from app.pipeline.validation import strip_asset_prefix, title_names_asset, validate_scenario

ASSET = "Power Generation System (PGS)"
NAMES_ASSET = f"scenario_title names the asset ({ASSET}); titles carry only the impact"


@pytest.mark.parametrize("title, expected", [
    ("Power Generation System (PGS) — Disruption of control and monitoring functions",
     "Disruption of control and monitoring functions"),
    ("Power Generation System (PGS) — unauthorized administrative access",
     "Unauthorized administrative access"),                                   # capitalised
    ("PGS — loss of telemetry", "Loss of telemetry"),                    # short form
    ("Power Generation System: spoofed dispatch", "Spoofed dispatch"),        # without the bracket
    ("power generation system (pgs) - data leak", "Data leak"),              # case, spaced hyphen
    ("PGS | forged commands", "Forged commands"),
    ("PGS \u2013 en dash", "En dash"),
    ("Disruption of control and monitoring functions",                        # already clean
     "Disruption of control and monitoring functions"),
    ("PGSX — something else", "PGSX — something else"),             # not a whole word
    ("PGS-related outage", "PGS-related outage"),                             # bare hyphen: a word
    ("Disruption of PGS control", "Disruption of PGS control"),               # mid-title: reported
    ("Power Generation System (PGS)", "Power Generation System (PGS)"),       # nothing else left
])
def test_a_leading_asset_name_is_cut(title, expected) -> None:
    assert strip_asset_prefix(title, ASSET) == expected


def test_the_model_is_told_to_leave_the_asset_out_of_the_title() -> None:
    """Both prompts that write scenarios — first run/regenerate/next-set and next-set variants."""
    from app.pipeline import prompts

    base = {"asset_name": ASSET, "critical_service": "Power generation"}
    for msgs in (prompts.scenario_prompt(base, "Spoofing", "Spoofing of dispatch identities",
                                         actors=[]),
                 prompts.variant_scenario_prompt(base, "Spoofing", "Spoofing of dispatch identities",
                                                 actors=[], existing=[(1, "an earlier scenario")])):
        system = msgs[0]["content"]
        assert "scenario_title: a short title naming the impact only" in system
        assert "Do NOT include the asset's name" in system
        assert "the asset and the impact against it" not in system


def test_no_asset_means_no_change() -> None:
    assert strip_asset_prefix("PGS — loss", None) == "PGS — loss"
    assert not title_names_asset("PGS — loss", "")


def _scenario(title: str) -> dict:
    return {"scenario_title": title,
            "scenario_statement": f"Spoofing disrupts the {ASSET}.",
            "risk_statement": f"The {ASSET} loses telemetry."}


def test_a_clean_title_is_not_flagged() -> None:
    """The old check flagged every title WITHOUT the asset; a clean title is now the norm."""
    report = validate_scenario(_scenario("Disruption of control functions"), "Spoofing",
                               "Spoofing", asset_name=ASSET)
    assert not any("scenario_title" in e for e in report["errors"]), report


@pytest.mark.parametrize("title", ["Disruption of PGS control", "PGS-related outage",
                                   "Loss of the Power Generation System"])
def test_a_title_that_still_names_the_asset_is_reported(title) -> None:
    report = validate_scenario(_scenario(title), "Spoofing", "Spoofing", asset_name=ASSET)
    assert NAMES_ASSET in report["errors"]


def test_ordinary_words_are_not_mistaken_for_the_asset() -> None:
    """Strict whole-name matching, not validation's loose word overlap: "power generation" alone
    is not the asset's name."""
    report = validate_scenario(_scenario("Disruption of power generation control"),
                               "Spoofing", "Spoofing", asset_name=ASSET)
    assert NAMES_ASSET not in report["errors"]


# --- through the real generation path ------------------------------------------------------------
SID, TASK_ID, TID = str(uuid.uuid4()), str(uuid.uuid4()), str(uuid.uuid4())
NOW = datetime.now(UTC)
THREAT = {"threat_id": TID, "grounding_status": "verified", "category": "Spoofing",
          "threat_type": "Spoofing", "threat_name": "Spoofing of dispatch identities",
          "library_threat_type": None, "library_threat_name": None,
          "threat_type_id": None, "catalogue_id": None, "actors": []}


class _LLM:
    """Scenario replies in order; a reply missing risk_statement makes the pipeline ask for a
    repair, and the next reply is that repair."""

    def __init__(self, *replies: dict):
        self.replies = list(replies)

    def chat(self, messages, temperature=None, expected_type=None):
        return json.dumps(self.replies.pop(0)), None

    def embed(self, texts, kind=None):
        return [[0.0] * 8 for _ in texts]


def _generate(monkeypatch, tmp_path, llm) -> tuple[dict, dict]:
    monkeypatch.setattr(tasks.bus, "publish", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_fetch_intel", lambda *a, **k: None)
    monkeypatch.setattr(tasks, "_finalize_scenario_batch", lambda *a, **k: None)
    engine = create_engine(f"sqlite:///{tmp_path / 'title.db'}")
    for tbl in (m.Scenario_Session, m.Subsystem_Stage_State, m.Identified_Threat,
                m.Scoped_Threat, m.Threat_Scenario, m.Threat_Scenario_Control_Map,
                m.Scenario_Audit, m.Prompt_Log):
        tbl.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    row = {"SessionID": SID, "TenantID": "t", "EntityID": "e", "UserID": "u", "AssetName": ASSET,
           "AssetID": "1", "SessionStatus": "active", "CurrentStage": "SCENARIO_GENERATION",
           "StageStatus": "RUNNING", "Mode": "AUTO",
           "SubsystemsJSON": json.dumps([{"id": 41, "name": "SCADA HMI", "asset_type": "OT"}]),
           "SectorIDsJSON": "[]", "CreatedAt": NOW, "UpdatedAt": NOW}
    with Session() as s:
        s.execute(m.Scenario_Session.__table__.insert().values(**row))
        for level in (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS, SubsystemLevel.LOCK):
            s.execute(m.Subsystem_Stage_State.__table__.insert().values(
                StateID=str(uuid.uuid4()), SessionID=SID, TenantID="t", EntityID="e",
                SubsystemID=0, Level=level, Status=StageStatus.IDLE, GenerationEpoch=1,
                LeaseExpiresAt=NOW + timedelta(minutes=30), UpdatedAt=NOW, CreatedAt=NOW))
        s.commit()
        tasks.write_scenarios(s, row, json.loads(row["SubsystemsJSON"]),
                              {"name": ASSET, "asset_type": "OT"}, [THREAT], llm, TASK_ID)
    with Session() as s:
        out = s.execute(m.Threat_Scenario.__table__.select()).mappings().one()
    return json.loads(out["ScenarioJSON"]), json.loads(out["ValidationJSON"])


def test_a_generated_title_is_saved_without_the_asset(monkeypatch, tmp_path) -> None:
    scenario, report = _generate(monkeypatch, tmp_path, _LLM(
        _scenario("Power Generation System (PGS) — impersonation of dispatch identities")))
    assert scenario["scenario_title"] == "Impersonation of dispatch identities"
    assert ASSET in scenario["scenario_statement"]          # the narrative still names it
    assert not any("scenario_title" in e for e in report["errors"]), report


def test_a_repair_cannot_bring_the_asset_back(monkeypatch, tmp_path) -> None:
    """The first reply is missing risk_statement, so the pipeline asks for a repair; the repair
    comes back with a prefixed title, and the merged result is what gets saved."""
    first = {k: v for k, v in _scenario("Impersonation of dispatch identities").items()
             if k != "risk_statement"}
    repair = {"risk_statement": f"The {ASSET} loses telemetry.",
              "scenario_title": "PGS — impersonation of dispatch identities"}
    scenario, report = _generate(monkeypatch, tmp_path, _LLM(first, repair))
    assert scenario["risk_statement"]                       # the repair was accepted
    assert scenario["scenario_title"] == "Impersonation of dispatch identities"
    assert not any("scenario_title" in e for e in report["errors"]), report
