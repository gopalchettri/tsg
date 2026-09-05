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
        # UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName) WHERE IsDeleted=0 exactly
        # (2. Threat_library.sql, widened 2026-09-04 — see promote.py Change 3: a filtered index
        # scoped to IsActive=1 only restricts rows that themselves satisfy that predicate, so it
        # gave ZERO protection once inserts started IsActive=0). A hard-deleted same-name row is
        # correctly NOT a collision; a merely-pending (IsActive=0, IsDeleted=0) one now IS. Raw
        # DDL so no Index object pollutes the shared table metadata for other test files — same
        # pattern as test_promote_scenario_library.py.
        conn.exec_driver_sql(
            "CREATE UNIQUE INDEX UX_ThreatType_NaturalKey ON Threat_Type(ThreatTypeName) "
            "WHERE IsDeleted = 0")
    return engine


def test_integrity_error_recovery_returns_the_existing_winner(monkeypatch):
    """Simulates the lost-race window against an ALREADY-APPROVED type: by the time this call's
    own pre-check ran, the winner's row was not yet visible/committed (monkeypatched to miss) —
    but by the time this call's INSERT executes, the winner has committed, so the real filtered
    index (WHERE IsActive=1 AND IsDeleted=0) raises. The recovery must select by ThreatTypeName
    ALONE and return that row's id — not raise, and never mint a second row.

    The winner is seeded directly as IsActive=True (not via upsert_threat_type, which now always
    inserts PENDING/IsActive=False) to represent a name a curator already approved — the one case
    the filtered index still actually collides on. See
    test_two_pending_inserts_of_the_same_name_are_not_deduped_by_the_index below for the case
    this index no longer catches."""
    engine = _engine_with_live_index()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.add(m.Threat_Type(ThreatTypeName="Supply Chain Compromise", ThreatCategoryID=None,
                            IsActive=True, IsDeleted=False))
        s.commit()
        winner_id = s.query(m.Threat_Type.ThreatTypeID).scalar()

    monkeypatch.setattr(dal, "find_type_id_by_norm_name", lambda sess, name: None)
    with Session() as s:
        recovered_id, created = dal.upsert_threat_type(s, "Supply Chain Compromise", None)
        s.commit()
    assert created is False
    assert recovered_id == winner_id
    with Session() as s:
        assert s.query(m.Threat_Type).count() == 1, "the recovery minted a twin"


def test_two_pending_inserts_of_the_same_new_name_still_dedupe_via_widened_index(monkeypatch):
    """UX_ThreatType_NaturalKey was widened to WHERE IsDeleted=0 (2026-09-04) specifically because
    upsert_threat_type now inserts PENDING (IsActive=False, awaiting curator review): a filter
    scoped to IsActive=1 would never even see such an insert, giving zero duplicate protection.
    With the widened filter, two truly SIMULTANEOUS first-time promotions of the same brand-new
    name (dedup bypassed here to simulate the lost race) must still collide at the DB level and
    recover to one winner — exactly like the already-active case in
    test_integrity_error_recovery_returns_the_existing_winner, just for a pending row instead."""
    engine = _engine_with_live_index()
    Session = sessionmaker(bind=engine, future=True)

    monkeypatch.setattr(dal, "find_type_id_by_norm_name", lambda sess, name: None)
    with Session() as s:
        id_a, created_a = dal.upsert_threat_type(s, "Novel Attack Pattern", None)
        s.commit()
    with Session() as s:
        id_b, created_b = dal.upsert_threat_type(s, "Novel Attack Pattern", None)
        s.commit()

    assert created_a is True and created_b is False
    assert id_a == id_b
    with Session() as s:
        rows = s.query(m.Threat_Type).filter_by(ThreatTypeName="Novel Attack Pattern").all()
        assert len(rows) == 1 and not rows[0].IsActive


def test_soft_deleted_same_name_row_does_not_block_or_get_reused():
    """A retired (hard-deleted) type must not shadow a brand-new one with the same name: the
    filtered index permits the insert (no collision), and upsert_threat_type must mint a
    genuinely NEW row — PENDING (IsActive=False), not active, since that's the insert default
    now — rather than being fooled into 'recovering' the dead one."""
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
        pending = [r for r in rows if not r.IsDeleted]
        assert len(pending) == 1 and pending[0].ThreatTypeID == new_id and not pending[0].IsActive
