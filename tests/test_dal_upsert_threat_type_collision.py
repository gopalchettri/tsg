"""dal.upsert_threat_type's IntegrityError recovery branch.

Mirrors test_promote_scenario_library.test_cross_type_name_collision_recovers_to_existing_row,
which exercises upsert_threat_catalogue's twin. upsert_threat_type's own collision recovery had
ZERO coverage anywhere: every fixture that calls it (accept, promote, admin CRUD) seeds
Threat_Type WITHOUT a live UX_ThreatType_NaturalKey, so the except-branch's SQL never actually
runs. Unlike the catalogue's TYPE-SCOPED dedup (which has a real blind spot the global index
does not share, letting a genuine collision arise from a single call), Threat_Type's app-owned
dedup and its unique index are BOTH keyed on name alone — so a real collision here can only come
from an actual race between two concurrent writers. This file simulates that race by making the
pre-check miss on a row that already exists live, forcing the INSERT to hit the real (filtered)
unique index exactly as a lost race would.
"""
from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import dal
from app.db import models as m


def _engine_with_live_index():
    engine = create_engine("sqlite://")
    m.Threat_Type.__table__.create(engine)
    with engine.begin() as conn:
        # The LIVE, FILTERED natural-key backstop — matches production's
        # UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName) WHERE IsActive=1 AND
        # IsDeleted=0 exactly (2. Threat_library.sql), so a soft-deleted same-name row is
        # correctly NOT a collision. Raw DDL so no Index object pollutes the shared table
        # metadata for other test files — same pattern as test_promote_scenario_library.py.
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName) "
            "WHERE IsActive = 1 AND IsDeleted = 0")
    return engine


def test_integrity_error_recovery_returns_the_existing_winner(monkeypatch):
    """Simulates the lost-race window: by the time this call's own pre-check ran, the winner's
    row was not yet visible/committed (monkeypatched to miss) — but by the time this call's
    INSERT executes, the winner has committed, so the real filtered index raises. The recovery
    must select by ThreatTypeName ALONE among ACTIVE rows and return that row's id — not raise,
    and never mint a second row."""
    engine = _engine_with_live_index()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        winner_id, created_first = dal.upsert_threat_type(s, "Supply Chain Compromise", None)
        s.commit()
    assert created_first is True

    monkeypatch.setattr(dal, "find_type_id_by_norm_name", lambda sess, name: None)
    with Session() as s:
        recovered_id, created = dal.upsert_threat_type(s, "Supply Chain Compromise", None)
        s.commit()
    assert created is False
    assert recovered_id == winner_id
    with Session() as s:
        assert s.query(m.Threat_Type).count() == 1, "the recovery minted a twin"


def test_soft_deleted_same_name_row_does_not_block_or_get_reused():
    """A retired type must not shadow a brand-new one with the same name: the filtered index
    permits the insert (no collision), and upsert_threat_type must mint a genuinely NEW active
    row rather than being fooled into 'recovering' the dead one."""
    engine = _engine_with_live_index()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.add(m.Threat_Type(ThreatTypeName="Retired Family", ThreatCategoryID=None,
                            IsActive=False, IsDeleted=True))
        s.commit()

    with Session() as s:
        new_id, created = dal.upsert_threat_type(s, "Retired Family", None)
        s.commit()
    assert created is True
    with Session() as s:
        rows = s.query(m.Threat_Type).all()
        assert len(rows) == 2, "the soft-deleted row blocked or absorbed the new insert"
        live = [r for r in rows if r.IsActive]
        assert len(live) == 1 and live[0].ThreatTypeID == new_id
