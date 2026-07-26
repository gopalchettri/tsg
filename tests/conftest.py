"""Test harness — runs the slice on SQLite (partial unique indexes + rowcount CAS
behave like MSSQL for these tests). Integration/load tests that need real MSSQL
features are currently verified manually against dev TSG, not in CI (no CI is
configured in this repo yet) — this suite validates the logic only.
"""
from __future__ import annotations

import json
import string

import pytest
from sqlalchemy import insert, text

from app.pipeline.llm import Provenance

_ALPHA = string.ascii_lowercase


class StubLLM:
    """Deterministic, model-free client (SDD load-test 'fixed echo' idea)."""

    def chat(self, messages, *, model=None, temperature=None):
        sysc = messages[0]["content"].lower()
        if "json array" in sysc:
            out = [{"category": "Tampering", "type": "Firmware Tampering",
                    "name": "Bootloader implant", "actors": ["Hacker", "Nation-state"]}]
        else:
            out = {"scenario_title": "Bootloader implant on CAD", "scenario_statement": "S",
                   "business_impact": "B", "operational_impact": "O", "risk_statement": "R"}
        return json.dumps(out), Provenance(model="stub")

    def embed(self, texts, *, model=None, kind="query"):
        return [[t.lower().count(ch) for ch in _ALPHA] for t in texts]

    def rerank(self, query, docs, *, model=None):
        q = query.lower()
        return [90.0 if (q == d.lower() or q in d.lower() or d.lower() in q) else 40.0 for d in docs]


@pytest.fixture(autouse=True)
def _clear_embed_cache():
    from app.pipeline import embeddings

    embeddings.clear_cache()
    embeddings._breaker_open_until = 0.0  # a breaker-test failure shouldn't leak into later tests
    yield
    embeddings.clear_cache()


@pytest.fixture(autouse=True)
def _no_sse_publish(monkeypatch):
    # SSE is best-effort and not asserted here; skip the (failing) Redis publish so
    # tests don't wait on a non-running broker.
    monkeypatch.setattr("app.sse.bus.publish", lambda *a, **k: None)


@pytest.fixture()
def stub_llm():
    return StubLLM()


# DEFAULT_ASSET_CONTEXT (below) is a plain dict passed directly to
# find_threats/write_scenarios/prompts.threats_prompt in tests that call the pipeline
# functions directly, not through the HTTP API — unaffected by the ids-only body change
# below. It's also matched against the DB seed rows for tests that DO go through the API.
DEFAULT_ASSET_CONTEXT = {
    "cii_asset_description": "CAD design and drafting platform",
    "critical_service": ["Design Service"],
    "data_handled": "Engineering drawings and specs",
}
DEFAULT_SUPPORTING_SYSTEM_ID = [1019]


def session_body(asset_id=100, entity_id="5", **overrides):
    """A minimal, ids-only POST /v1/sessions body — descriptive context is resolved
    server-side from the DB seed rows below (gather_asset_details), not supplied here."""
    body = {"asset_id": asset_id, "entity_id": entity_id, "supporting_system_id": DEFAULT_SUPPORTING_SYSTEM_ID}
    body.update(overrides)
    return body


def _create_schema_and_seed(engine) -> None:
    from app.db import models as m

    m.metadata.create_all(engine)
    with engine.begin() as c:
        # Partial unique indexes (M4/M6/M8) — SQLite supports filtered indexes.
        c.execute(text('CREATE UNIQUE INDEX "UX_Session_ActiveAsset" ON "Scenario_Session"(EntityID, AssetID) WHERE SessionStatus = \'active\''))
        c.execute(text('CREATE UNIQUE INDEX "UX_Scenario_ActiveIdentity" ON "Threat_Scenario_Output"(SessionID, IdentityHash) WHERE Superseded = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_Session_IdempotencyKey" ON "Scenario_Session"(EntityID, IdempotencyKey) WHERE IdempotencyKey IS NOT NULL'))
        # M2 — master-library natural-key UNIQUE (safe concurrent promotion, no duplicate masters).
        # COALESCE makes SQLite match MSSQL's unique-index NULL semantics (MSSQL treats
        # NULL == NULL, SQLite treats NULLs as distinct) — without it, NULL-sector
        # upserts (threat-library import, R10 promotion) silently duplicate under test
        # while prod correctly rejects them.
        c.execute(text('CREATE UNIQUE INDEX "UX_ThreatType_NaturalKey" ON "Threat_Type"(ThreatTypeName, COALESCE(ThreatCategoryID, -1), COALESCE(SectorID, -1)) WHERE IsActive = 1 AND IsDeleted = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_ThreatCatalogue_NaturalKey" ON "Threat_Catalogue"(ThreatTypeID, ThreatName, COALESCE(SectorID, -1)) WHERE IsActive = 1 AND IsDeleted = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_ThreatActor_NaturalKey" ON "Threat_Actor"(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0'))
        # Scoping-rule natural key (migration 0027) — makes dal.upsert_threat_rule's
        # IntegrityError-on-duplicate path real under test, not vacuous.
        c.execute(text('CREATE UNIQUE INDEX "UX_ConfigThreatRule_NaturalKey" ON "Config_Threat_Rule"(ThreatTypeID, RuleType, RuleKey, RuleValue) WHERE IsActive = 1 AND IsDeleted = 0'))
        # Context: entity 5 owns asset 100/200 with supporting system 1019.
        c.execute(insert(m.onboarding_services).values(id=500, name="Design Service"))
        # No group_id on the asset — the live ctm_scan_entity has no such column. Entity
        # ownership and the critical_service label both come from ctm_scan_entity_bu below
        # (direct asset->entity/service link); tier1_critical_service_id is dead (unpopulated
        # on every real asset) and unused by any code path — kept here only as inert legacy data.
        c.execute(insert(m.ctm_scan_entity).values(
            id=100, name="CAD", type="app", criticality=1, tier1_critical_service_id=500,
            description="CAD design and drafting platform", data_handled="Engineering drawings and specs"))
        c.execute(insert(m.ctm_scan_entity).values(
            id=200, name="EPCR", type="app", criticality=1, tier1_critical_service_id=500,
            description="CAD design and drafting platform", data_handled="Engineering drawings and specs"))
        c.execute(insert(m.ctm_scan_entity_bu).values(id=100, ctm_scan_entity_id=100, group_id=5, service_id=500))
        c.execute(insert(m.ctm_scan_entity_bu).values(id=200, ctm_scan_entity_id=200, group_id=5, service_id=500))
        # option_value: option 1012 (Accessibility Channel) code 2 -> "Internal Network";
        # option 1015 (Hosting Environment) code 7 -> "Entity Data Centre".
        c.execute(insert(m.option).values(id=1012, option="Accessibility Channel"))
        c.execute(insert(m.option).values(id=1015, option="Hosting Environment"))
        c.execute(insert(m.option_value).values(id=1, name="Internal Network", value=2, option_id=1012))
        c.execute(insert(m.option_value).values(id=2, name="Entity Data Centre", value=7, option_id=1015))
        # ctm_scan_category: real live rows include id=1 "Physical infrastructure" (asset_type FK target).
        c.execute(insert(m.ctm_scan_category).values(id=1, name="Physical infrastructure"))
        c.execute(insert(m.onboarding_supporting_systems).values(
            id=1019, name="CAD System", asset_type=1, incident_description="None"))
        c.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=100, onboarding_supporting_system_id=1019))
        c.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=200, onboarding_supporting_system_id=1019))
        # Masters: category Tampering → types 10/11 → catalogue 20/21; actor Hacker on type 10.
        c.execute(insert(m.Threat_Category).values(ThreatCategoryID=2, ThreatCategoryName="Tampering", ThreatCategoryCode="TAM", IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Type).values(ThreatTypeID=10, ThreatTypeName="Firmware Tampering", ThreatCategoryID=2, IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Type).values(ThreatTypeID=11, ThreatTypeName="Config Tampering", ThreatCategoryID=2, IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Catalogue).values(ThreatCatalogueID=20, ThreatTypeID=10, ThreatName="Bootloader implant", IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Catalogue).values(ThreatCatalogueID=21, ThreatTypeID=11, ThreatName="OTA poisoning", IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Actor).values(ThreatActorID=1, ThreatActorName="Hacker", IsCapable=1, IsActive=True, IsDeleted=False))
        c.execute(insert(m.ThreatType_ThreatActor_Map).values(ThreatTypeID=10, ThreatActorID=1))


@pytest.fixture()
def engine(tmp_path, monkeypatch):
    dbfile = tmp_path / "test.db"
    monkeypatch.setenv("TSG_DB_DSN", f"sqlite:///{dbfile}")
    monkeypatch.setenv("EMBEDDING_PROVIDER", "litellm_proxy")  # tests use StubLLM, don't load torch
    monkeypatch.setenv("RERANKER_PROVIDER", "litellm_proxy")
    monkeypatch.setenv("EMBEDDING_STORE", "memory")  # tests don't touch Mongo
    from app.core.config import get_settings
    from app.db.engine import _sessionmaker, get_engine

    get_settings.cache_clear(); get_engine.cache_clear(); _sessionmaker.cache_clear()
    eng = get_engine()
    _create_schema_and_seed(eng)
    yield eng
    get_settings.cache_clear(); get_engine.cache_clear(); _sessionmaker.cache_clear()


@pytest.fixture()
def db(engine):
    from app.db.engine import db_session

    with db_session() as sess:
        yield sess


def make_client(entities: set[str]):
    from fastapi.testclient import TestClient

    from app.api.deps import Principal, get_principal
    from app.main import create_app

    app = create_app()
    app.dependency_overrides[get_principal] = lambda: Principal(claims={"sub": "u1"}, entities=entities)
    return TestClient(app)
