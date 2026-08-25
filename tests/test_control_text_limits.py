"""One over-long control must not take control mapping down for everybody.

A control is embedded as `ControlName + ": " + ControlDescription` (embeddings._CONTROL_TEXT).
`llm.embed` REJECTS text above `max_embed_chars` rather than truncating it — deliberate, since a
silently truncated control changes meaning — and it embeds in BATCHES. So one oversized row raises
for the whole call, the entire control_library group fails to embed, and control mapping stops for
every asset and every session until somebody finds that row. `control_description` had
`min_length=1` and NO maximum.

Two halves, because either alone leaves the hole open:

  PREVENT  - the API caps both fields, sized to fit inside the default max_embed_chars.
  CONTAIN  - scripts/Seed_to_Control_library.sql writes rows with direct INSERT and never sees
             Pydantic, so _active_names skips any over-limit row loudly. One bad row then costs
             that ONE row its vector instead of the whole group.

Distinct from test_embedding_batching.py, which pins embed()'s OWN contract (per-request batch
cap, text at exactly the limit accepted). This file pins keeping the corpus inside that contract.

Nothing here asserts on the log line: structlog binds its stream at configure time, so pytest's
capture cannot see it (see test_tracing.py). Behaviour is asserted instead, which is the property
that matters anyway.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.api.schemas import ControlCreate, ControlUpdate
from app.core.config import (
    CONTROL_DESCRIPTION_MAX_CHARS,
    CONTROL_NAME_MAX_CHARS,
    get_settings,
)
from app.db import models as m
from app.pipeline import embeddings


def _row(**over):
    body = {"control_code": "CII-1", "itot": "OT", "domain": "Audit",
            "control_name": "n", "control_description": "d"}
    body.update(over)
    return body


def test_the_api_refuses_a_control_that_would_break_the_corpus():
    """Remove `max_length` from control_description and the reject case here passes an unbounded
    document straight into the embedding corpus."""
    ControlCreate(**_row(control_description="x" * CONTROL_DESCRIPTION_MAX_CHARS))   # the maximum
    ControlCreate(**_row(control_name="n" * CONTROL_NAME_MAX_CHARS))
    with pytest.raises(ValidationError):
        ControlCreate(**_row(control_description="x" * (CONTROL_DESCRIPTION_MAX_CHARS + 1)))
    with pytest.raises(ValidationError):
        ControlCreate(**_row(control_name="n" * (CONTROL_NAME_MAX_CHARS + 1)))
    # UPDATE is the same door. Capping only create leaves it wide open: edit an existing control
    # to a 50-page description and the corpus breaks in exactly the same way.
    ControlUpdate(control_description="x" * CONTROL_DESCRIPTION_MAX_CHARS)
    with pytest.raises(ValidationError):
        ControlUpdate(control_description="x" * (CONTROL_DESCRIPTION_MAX_CHARS + 1))


def test_a_maximum_length_control_still_fits_the_embed_limit():
    """The arithmetic, asserted against the REAL expression rather than a restated number.

    This is what the two constants are FOR: name + ": " + description must fit max_embed_chars.
    Raise either constant past that budget and this fails — the only check that the shipped caps
    still fit the shipped limit, since the boot validator that also asserted it was removed for
    imposing a floor on max_embed_chars (see the constants' comment in config.py).
    """
    engine = create_engine("sqlite://")
    m.Control_Library.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.execute(m.Control_Library.__table__.insert().values(
            ControlLibraryID=1, ControlCode="CII-1", ITOT="OT", Domain="Audit",
            ControlName="n" * CONTROL_NAME_MAX_CHARS,
            ControlDescription="x" * CONTROL_DESCRIPTION_MAX_CHARS,
            IsActive=True, IsDeleted=False))
        s.commit()
        composed = s.execute(select(embeddings._CONTROL_TEXT)).scalars().one()
    limit = get_settings().max_embed_chars
    assert len(composed) <= limit, (
        f"a maximum-length control composes {len(composed)} chars against a limit of {limit} — "
        "embed() would reject it and fail the whole group")


def test_one_oversized_row_costs_only_itself():
    """THE load-bearing test, and the half a schema cap cannot provide.

    The seed SQL inserts rows directly, bypassing Pydantic entirely, so a row CAN exceed the limit
    however tightly the API is capped. Revert the guard in _active_names and the oversized row is
    handed to llm.embed, which raises for the whole batch — every valid control loses its vector
    too, and that is the outage.
    """
    limit = get_settings().max_embed_chars
    engine = create_engine("sqlite://")
    m.Control_Library.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        for i, desc in enumerate(("short one", "x" * (limit + 500), "another short one"), start=1):
            s.execute(m.Control_Library.__table__.insert().values(
                ControlLibraryID=i, ControlCode=f"CII-{i}", ITOT="OT", Domain="Audit",
                ControlName=f"Control {i}", ControlDescription=desc,
                IsActive=True, IsDeleted=False))
        s.commit()
        names = embeddings._active_names(s, m.Control_Library, embeddings._CONTROL_TEXT)

    assert len(names) == 2, f"expected the 2 valid controls, got {len(names)}"
    assert all(len(n) <= limit for n in names), "an over-limit text reached the embed batch"
    assert any("Control 1" in n for n in names) and any("Control 3" in n for n in names), (
        "the valid controls must survive — skipping the bad row must not cost the good ones")

