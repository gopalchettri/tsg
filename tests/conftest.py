"""Test harness — runs the slice on SQLite (partial unique indexes + rowcount CAS
behave like MSSQL for these tests). Integration/load tests that need real MSSQL
features run against dev TSG in CI; here we validate the logic.
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

    def chat(self, messages, *, model=None):
        sysc = messages[0]["content"].lower()
        if "supporting system" in sysc:
            out = {"subsystem_name": "CAD System", "summary": "Supports the asset."}
        elif "stride threats" in sysc:
            out = [{"category": "Tampering", "type": "Firmware Tampering",
                    "name": "Bootloader implant", "actors": ["Hacker", "Nation-state"]}]
        else:
            out = {"scenario_title": "Bootloader implant on CAD", "scenario_statement": "S",
                   "business_impact": "B", "operational_impact": "O"}
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


def _create_schema_and_seed(engine) -> None:
    from app.db import models as m

    m.metadata.create_all(engine)
    with engine.begin() as c:
        # Partial unique indexes (M4/M5/M6/M8) — SQLite supports filtered indexes.
        c.execute(text('CREATE UNIQUE INDEX "UX_Session_ActiveAsset" ON "Scenario_Session"(EntityID, AssetExternalID) WHERE SessionStatus = \'active\''))
        c.execute(text('CREATE UNIQUE INDEX "UX_Profile_Active" ON "Subsystem_Profile"(SessionID, SubsystemID) WHERE Superseded = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_Scenario_ActiveIdentity" ON "Threat_Scenario_Output"(SessionID, IdentityHash) WHERE Superseded = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_Session_IdempotencyKey" ON "Scenario_Session"(EntityID, IdempotencyKey) WHERE IdempotencyKey IS NOT NULL'))
        # M2 — master-library natural-key UNIQUE (safe concurrent promotion, no duplicate masters).
        c.execute(text('CREATE UNIQUE INDEX "UX_ThreatType_NaturalKey" ON "Threat_Type"(ThreatTypeName, PrimaryThreatCategoryID, SectorID) WHERE IsActive = 1 AND IsDeleted = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_ThreatCatalogue_NaturalKey" ON "Threat_Catalogue"(ThreatTypeID, ThreatName, SectorID) WHERE IsActive = 1 AND IsDeleted = 0'))
        c.execute(text('CREATE UNIQUE INDEX "UX_ThreatActor_NaturalKey" ON "Threat_Actor"(ThreatActorName) WHERE IsActive = 1 AND IsDeleted = 0'))
        # Context: entity 5 owns asset 100 with supporting system 1019.
        c.execute(insert(m.group_table).values(id=5, name="Org A", code="A"))
        c.execute(insert(m.group_table).values(id=6, name="Org B", code="B"))
        c.execute(insert(m.ctm_scan_entity).values(id=100, name="CAD", type="app", criticality=1, group_id=5, tier1_critical_service_id=500))
        c.execute(insert(m.ctm_scan_entity).values(id=200, name="EPCR", type="app", criticality=1, group_id=5, tier1_critical_service_id=500))
        c.execute(insert(m.onboarding_service_entity).values(service_id=500, group_id=5))  # asset→service→entity 5
        c.execute(insert(m.onboarding_supporting_systems).values(id=1019, name="CAD System", hosting_location="internal"))
        c.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=100, onboarding_supporting_system_id=1019))
        c.execute(insert(m.ctm_scan_entity_supporting_system).values(ctm_scan_entity_id=200, onboarding_supporting_system_id=1019))
        # Masters: category Tampering → types 10/11 → catalogue 20/21; actor Hacker on type 10.
        c.execute(insert(m.Threat_Category).values(ThreatCategoryID=2, ThreatCategoryName="Tampering", ThreatCategoryCode="TAM", IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Type).values(ThreatTypeID=10, ThreatTypeName="Firmware Tampering", PrimaryThreatCategoryID=2, IsActive=True, IsDeleted=False))
        c.execute(insert(m.Threat_Type).values(ThreatTypeID=11, ThreatTypeName="Config Tampering", PrimaryThreatCategoryID=2, IsActive=True, IsDeleted=False))
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
    monkeypatch.setenv("ASSET_ENTITY_BINDING", "service")  # pin: don't inherit the dev .env value
    # binding defaults to 'service' → uses the seeded onboarding_service_entity mapping
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
