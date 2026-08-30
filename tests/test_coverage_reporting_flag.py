"""TSG_COVERAGE_REPORTING_ENABLED (default False): the read side, sessions.py::_coverage_verdict.
The write side (tasks.py::find_threats never computing/storing coverage while the flag is off) is
pinned in tests/test_library_first_identification.py; this file pins that the API-facing read
matches — None while off (even for a row that DOES carry a coverage block, e.g. one written before
a flag flip), the real verdict once on.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.api.sessions as sessions_mod
from app.core.config import get_settings
from app.core.enums import AuditEventType
from app.db import models as m

SESSION_ID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"


def _engine():
    engine = create_engine("sqlite://")
    m.Scenario_Audit.__table__.create(engine)
    return engine


def _seed_grounding_summary(s) -> None:
    s.execute(m.Scenario_Audit.__table__.insert().values(
        AuditID="a5c17c4a-6c0f-4a2a-9b8f-6b7e4a2f1c01", SessionID=SESSION_ID,
        EventType=str(AuditEventType.grounding_summary),
        CreatedAt=datetime.now(UTC),
        DetailJSON=json.dumps({
            "units": [0, 41, 42],
            "coverage": {"cells": 6, "covered": 5, "justified_na": 0, "unexplained": 1,
                        "gaps": [[42, "Tampering"]]},
        })))
    s.commit()


def test_coverage_verdict_is_none_while_the_flag_is_off_even_with_a_real_row():
    """A row carrying real coverage data (e.g. written before a flag flip, or by a test seed)
    must NOT leak through the read side while the flag is off — off means off, not "off unless
    something happens to be stored"."""
    assert get_settings().coverage_reporting_enabled is False
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_grounding_summary(s)
        assert sessions_mod._coverage_verdict(s, SESSION_ID) is None


def test_coverage_verdict_returns_the_real_shape_once_enabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "coverage_reporting_enabled", True)
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        _seed_grounding_summary(s)
        verdict = sessions_mod._coverage_verdict(s, SESSION_ID)
    assert verdict == {
        "cells": 6, "covered": 5, "justified_na": 0, "unexplained": 1, "complete": False,
        "units": [0, 41, 42],
        "gaps": [{"subsystem_id": 42, "category": "Tampering"}],
    }


def test_coverage_verdict_stays_none_with_no_row_regardless_of_the_flag(monkeypatch):
    """Unaffected baseline: "nobody has measured this yet" must still read as None on, exactly
    as it did before this flag existed."""
    monkeypatch.setattr(get_settings(), "coverage_reporting_enabled", True)
    Session = sessionmaker(bind=_engine(), future=True)
    with Session() as s:
        assert sessions_mod._coverage_verdict(s, SESSION_ID) is None
