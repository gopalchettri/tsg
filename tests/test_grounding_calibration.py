"""Calibration must survive an overlapping library, and must NOT run on the worker boot path.

Regression, both halves measured live on this checkout:

1. boundary_between demanded PERFECT separation (max(negatives) < min(positives)). The real
   catalogue holds one reciprocal near-synonym pair scoring 99.5 ('Mobile, QR or
   collaboration-channel compromise' ~ 'Removable media or portable device compromise'), so a
   single outlier vetoed all 300 measurements. Calibration logged
   `calibration_impossible_near_duplicate_library` on EVERY boot, stored nothing, and fell back
   to a static 75.0 that had been tuned for a different model pair. Because the fallback is
   deliberately never memoized, the next boot re-ran the same ~106s sweep for the same nothing.

2. That sweep ran inside `_init_worker`, which Celery fires BEFORE the consumer connects to the
   broker — so it was invisible to `inspect ping` for its whole duration. Worker boot measured
   ~115s warm and ~213s cold against start.ps1's 180s readiness budget, and cold starts failed.

So the guarantees under test are: overlap yields a cutoff instead of a veto, no-signal still
yields None rather than a fabricated number, and worker boot never reaches the expensive path.
"""
from __future__ import annotations

import inspect
import uuid
from contextlib import contextmanager
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine, insert
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from app.core.enums import CalibrationStatus
from app.db import dal
from app.db import models as m
from app.pipeline import celery_app as ca
from app.pipeline import grounding
from app.pipeline.grounding import boundary_between, separation_quality

# The shape that used to veto every calibration: 99 impostors well below the genuine matches,
# plus ONE near-duplicate riding above all of them.
_NEGATIVES = [60.0 + i * 0.25 for i in range(99)] + [99.5]
_POSITIVES = [88.0 + i * 0.1 for i in range(200)]


def test_separable_classes_still_get_the_gap_midpoint():
    """The soft margin must be a strict GENERALISATION — separable inputs are unchanged.

    If this drifts, every already-calibrated deployment silently moves its threshold on the next
    re-calibration, which is a behaviour change nobody asked for."""
    assert boundary_between([40.0], [60.0]) == 50.0
    # A sub-1-point gap must not collapse onto a measured score: the cutoff is applied as
    # `score >= th`, so landing on 71.2 would band that exact measured impostor as verified.
    tight = boundary_between([71.2], [71.4])
    assert tight is not None and 71.2 < tight <= 71.4


def test_one_near_duplicate_no_longer_vetoes_the_calibration():
    """THE regression. One outlier costs one sample's accuracy, not the whole run."""
    th = boundary_between(_NEGATIVES, _POSITIVES)
    assert th is not None, "a single near-duplicate must not veto 300 measurements"
    # It lands between the bulk of the impostors and the genuine matches, ignoring the outlier.
    assert 84.0 < th < 88.0, th
    # ...and it reports HOW well it did, so a cutoff scraped out of overlap is never mistaken for
    # a clean one: every positive kept, every impostor but the outlier excluded.
    assert separation_quality(_NEGATIVES, _POSITIVES, th) == 0.99


def test_no_signal_still_returns_none():
    """Tolerating overlap must not become inventing a cutoff for noise."""
    assert boundary_between([70.0], [65.0]) is None      # inverted
    assert boundary_between([70.0], [70.0]) is None      # identical
    assert boundary_between([], [10.0]) is None          # empty class
    assert boundary_between([10.0], []) is None
    # Fully interleaved classes carry no usable signal either.
    assert boundary_between([50.0, 60.0, 70.0], [50.0, 60.0, 70.0]) is None


def test_quality_is_1_only_for_a_clean_split():
    assert separation_quality([40.0], [60.0], 50.0) == 1.0
    assert separation_quality([60.0], [40.0], 50.0) == -1.0   # inverted
    assert separation_quality([50.0], [50.0], 50.0) == 0.0    # chance


def test_resolve_thresholds_cannot_calibrate():
    """STRUCTURAL, not textual: `resolve_thresholds` must have no switch that starts a sweep.

    The boot regression was not "someone called the wrong thing" — it was that ONE function did
    both a cheap read and a 10-15 minute measurement, chosen by a boolean any caller could set,
    and worker boot set it. Asserting on the SIGNATURE is what makes the fix durable: while no
    such parameter exists, no caller anywhere — boot, preflight, or a future one — can ask a
    reader to become a writer. An earlier version of this test grepped _init_worker's source for
    the flag name, which would pass happily on a renamed flag and fail on a comment mentioning
    it: it tested the prose, not the property."""
    params = inspect.signature(grounding.resolve_thresholds).parameters
    assert "allow_calibration" not in params, (
        "resolve_thresholds must stay READ-ONLY. worker_init runs BEFORE the broker consumer "
        "starts, so anything slow there is invisible to every readiness probe — that is what "
        "pushed cold boots past start.ps1's 180s budget. Measuring is grounding.calibrate(), "
        "reached only through POST /v1/tsg/grounding/calibrate.")
    assert set(params) == {"sess", "llm", "s"}, sorted(params)


def test_nothing_queues_a_calibration_automatically():
    """A sweep costs 10-15 minutes and ~100 billed LLM calls, so a process restart must never
    start one. The boot-time auto-queue helper is gone; this pins that it stays gone."""
    assert not hasattr(ca, "_queue_calibration_if_idle"), (
        "the boot-time auto-queue was removed deliberately — calibration is an explicit admin "
        "action. Re-adding it lets a rolling restart start billed sweeps unattended.")
    src = "\n".join(line.split("#", 1)[0]
                    for line in inspect.getsource(ca._init_worker).splitlines())
    assert ".delay(" not in src and "apply_async" not in src, (
        "worker boot must not enqueue ANY task; it reads the threshold and logs what it found.")


def test_calibration_task_is_registered_and_takes_force():
    """The operator route and the boot path both dispatch by this name."""
    assert "tsg.calibrate_grounding" in ca.celery_app.tasks
    params = inspect.signature(ca.calibrate_grounding_task.run).parameters
    assert "force" in params, "re-calibrating a curated library needs an overwrite switch"
    assert params["force"].default is False, "force must be opt-in — a sweep costs minutes"


# ---------------------------------------------------------------------------
# The ledger: Grounding_Calibration_Run is BOTH the audit trail and the threshold store.
# These pin the read rule the operator asked for, verbatim:
#   "1st check the database if found use it if not then default one. no mongodb."
# ---------------------------------------------------------------------------

def _ledger_engine():
    """In-memory SQLite with just the calibration table — the read path touches nothing else."""
    engine = create_engine("sqlite://")
    m.Grounding_Calibration_Run.__table__.create(engine)
    return engine


def _fake_db_session(Session):
    """A stand-in for app.db.engine.db_session with the SAME contract: commit on success,
    rollback on error, always close.

    A bare sessionmaker() will not do. Its __exit__ closes WITHOUT committing, so the record_*
    functions' writes would silently vanish and the assertions below would pass or fail on the
    harness rather than on the code — the failure mode a test exists to rule out."""
    @contextmanager
    def _cm():
        sess = Session()
        try:
            yield sess
            sess.commit()
        except Exception:
            sess.rollback()
            raise
        finally:
            sess.close()
    return _cm


def _settings(**over):
    """A Settings-shaped stub. An EMPTY `model_fields_set` means the operator did NOT pin the
    threshold in env, which is the branch every test below exercises — a pinned value
    short-circuits ahead of the database read."""
    base = {"embedding_model": "emb-A", "reranker_model": "rr-A",
            "grounding_match_threshold": 75.0, "model_fields_set": set(),
            "calibration_stale_after_seconds": 3600}
    base.update(over)
    return SimpleNamespace(**base)


def _row(sess, **over):
    vals = {"RunID": str(uuid.uuid4()), "Status": CalibrationStatus.success,
            "EmbeddingModel": "emb-A", "RerankerModel": "rr-A", "Forced": False,
            "StartedAt": dal.now(), "FinishedAt": dal.now(), "MatchTh": 86.25, "Quality": 0.99}
    vals.update(over)
    sess.execute(insert(m.Grounding_Calibration_Run).values(**vals))
    return vals["RunID"]


def test_a_recalibration_reaches_a_process_that_already_resolved():
    """THE reason there is no per-process memo.

    A module-level cache had no invalidation any other process could reach, so the FIRST resolve
    pinned that worker for its lifetime: an admin re-calibrating after curating the library would
    have left every already-warm worker serving the superseded cutoff, silently and indefinitely
    — while the API and the docs both promised "no restart needed". Two resolves in ONE process,
    with a newer run written between them, is exactly that scenario."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        _row(sess, MatchTh=75.0, StartedAt=dal.now() - timedelta(hours=1))
        sess.commit()
        assert grounding.resolve_thresholds(sess, None, _settings()).value == 75.0
        _row(sess, MatchTh=86.25, StartedAt=dal.now())   # the admin re-calibrates
        sess.commit()
        assert grounding.resolve_thresholds(sess, None, _settings()).value == 86.25, (
            "a re-calibration must reach a process that already resolved — no memo may pin it")


def test_threshold_comes_from_the_database_when_one_exists():
    """DB first. This is the operator's stated rule and the whole reason the ledger exists."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        _row(sess, MatchTh=86.25)
        sess.commit()
        th = grounding.resolve_thresholds(sess, None, _settings())
    assert th.value == 86.25
    assert th.origin == "calibrated", "a measured value must not report as the static default"


def test_threshold_falls_back_to_the_default_when_the_database_has_none():
    """...and if not, the default one. Never blocks, never raises: an uncalibrated deployment
    grounds on the static default and says so in its origin."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        th = grounding.resolve_thresholds(sess, None, _settings())
    assert th.value == 75.0
    assert th.origin == "static_default", (
        "origin is the ONLY thing separating this from a real measurement — they are the same "
        "float whenever a calibration happens to land on 75.0")


def test_only_this_model_pair_and_only_successes_count():
    """A calibration is valid ONLY for the models that produced it, and only when it actually
    measured something. A no_signal/failed/running row is not a threshold."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        _row(sess, EmbeddingModel="emb-OTHER", MatchTh=99.0)          # different pair
        _row(sess, Status=CalibrationStatus.no_signal, MatchTh=None)  # ran, found nothing
        _row(sess, Status=CalibrationStatus.failed, MatchTh=None)     # crashed
        _row(sess, Status=CalibrationStatus.running, MatchTh=None)    # in flight
        sess.commit()
        th = grounding.resolve_thresholds(sess, None, _settings())
    assert th.origin == "static_default", "none of those rows is a usable measurement"


def test_newest_successful_run_wins():
    """Re-calibrating APPENDS. History is preserved and the latest measurement is the one in
    force — which is what makes force=true, after curating the library, actually take effect."""
    engine = _ledger_engine()
    older, newer = dal.now() - timedelta(hours=2), dal.now()
    with sessionmaker(bind=engine, future=True)() as sess:
        _row(sess, MatchTh=70.0, StartedAt=older)
        _row(sess, MatchTh=88.0, StartedAt=newer)
        sess.commit()
        th = grounding.resolve_thresholds(sess, None, _settings())
    assert th.value == 88.0


def test_database_beats_the_env_value():
    """DB FIRST (flipped 2026-08, operator's direction): a paid, stored calibration can never be
    silently ignored by a forgotten env line — the exact trap the old env-first order created,
    where every sweep was billed, stored, and then discarded at runtime."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        _row(sess, MatchTh=86.25)
        sess.commit()
        th = grounding.resolve_thresholds(
            sess, None, _settings(grounding_match_threshold=90.0,
                                model_fields_set={"grounding_match_threshold"}))
    assert (th.value, th.origin) == (86.25, "calibrated")


def test_env_value_bootstraps_when_no_calibration_is_stored():
    """With an EMPTY ledger the env value governs (origin env_pinned) — the pre-calibration
    bootstrap — and, being deliberate, it reports as env_pinned rather than the
    provisional-and-warned static_default."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        th = grounding.resolve_thresholds(
            sess, None, _settings(grounding_match_threshold=90.0,
                                model_fields_set={"grounding_match_threshold"}))
    assert (th.value, th.origin) == (90.0, "env_pinned")


def test_no_session_degrades_to_the_default_rather_than_raising():
    """Callers without a session (one-off tooling, tests) must still get a usable threshold."""
    th = grounding.resolve_thresholds(None, None, _settings())
    assert (th.value, th.origin) == (75.0, "static_default")


def test_a_broken_ledger_read_degrades_instead_of_failing_grounding():
    """A grounding decision must never fail because the audit table is unreadable. The default
    exists precisely because it is always reachable."""
    engine = create_engine("sqlite://")  # table deliberately NOT created
    with sessionmaker(bind=engine, future=True)() as sess:
        th = grounding.resolve_thresholds(sess, None, _settings())
    assert (th.value, th.origin) == (75.0, "static_default")


def test_finishing_a_run_records_the_three_outcomes_distinctly():
    """success / no_signal / failed must stay distinguishable: they demand opposite responses —
    trust the number, curate the library, or fix the infrastructure."""
    engine = _ledger_engine()
    Session = sessionmaker(bind=engine, future=True)
    ok = grounding.CalibrationResult(86.25, 0.99, 100, 200, 99.5, 71.2, [])
    none = grounding.CalibrationResult(None, 0.0, 100, 0, 99.5, None, ["dupe @ 99.5"])
    cases = [(ok, None, CalibrationStatus.success, 86.25),
            (none, None, CalibrationStatus.no_signal, None),
            (None, "boom", CalibrationStatus.failed, None)]
    for result, error, want_status, want_th in cases:
        with Session() as sess:
            run_id = _row(sess, Status=CalibrationStatus.running, MatchTh=None, FinishedAt=None)
            sess.commit()
        with patch("app.db.engine.db_session", _fake_db_session(Session)):
            grounding.record_calibration_finished(run_id, result=result, error=error)
        with Session() as sess:
            row = sess.get(m.Grounding_Calibration_Run, run_id)
            assert row.Status == want_status, f"expected {want_status}, got {row.Status}"
            assert row.MatchTh == want_th
            assert (row.ErrorMessage is not None) == (error is not None)
            assert row.FinishedAt is not None, "a closed run must carry a finish time"


def test_an_abandoned_running_row_reads_as_failed_and_unblocks_the_next_run():
    """A sweep is minutes long, so `running` alone cannot mean "in progress". A worker killed
    mid-sweep leaves the row forever — and because the unique index counts it, an un-settled row
    would block EVERY future calibration, not merely report the old one wrongly."""
    engine = _ledger_engine()
    s = _settings()
    with sessionmaker(bind=engine, future=True)() as sess:
        stale = dal.now() - timedelta(seconds=s.calibration_stale_after_seconds + 60)
        run_id = _row(sess, Status=CalibrationStatus.running, MatchTh=None,
                    FinishedAt=None, StartedAt=stale)
        sess.commit()
        row = sess.get(m.Grounding_Calibration_Run, run_id)
        assert grounding.settled_status(row, s) == CalibrationStatus.failed
        assert "killed or hung" in (grounding.settled_error(row, s) or "")
        assert grounding.running_run(sess, ("emb-A", "rr-A")) is None, (
            "an abandoned row must not read as a live sweep, or the 409 becomes permanent")
        assert grounding.settle_abandoned_runs(sess, ("emb-A", "rr-A")) == 1
        sess.commit()
        assert sess.get(m.Grounding_Calibration_Run, run_id).Status == CalibrationStatus.failed


def test_a_live_running_row_is_left_alone():
    """The flip side: a genuinely in-flight sweep must NOT be settled away, or two concurrent
    10-15 minute billed sweeps become possible again."""
    engine = _ledger_engine()
    with sessionmaker(bind=engine, future=True)() as sess:
        _row(sess, Status=CalibrationStatus.running, MatchTh=None, FinishedAt=None,
            StartedAt=dal.now())
        sess.commit()
        assert grounding.running_run(sess, ("emb-A", "rr-A")) is not None
        assert grounding.settle_abandoned_runs(sess, ("emb-A", "rr-A")) == 0


def test_a_skipped_run_is_never_recorded_as_a_successful_calibration():
    """A non-forced request over an already-calibrated pair measures NOTHING. Recording that as
    `success` — as this once did, with a fabricated quality=0.0 and zero counts — puts a
    calibration that never happened into the audit trail, which is the one thing the ledger
    exists to prevent. It must still CLOSE the row, or it holds the unique index against the
    next real sweep until the stale window expires."""
    engine = _ledger_engine()
    Session = sessionmaker(bind=engine, future=True)
    with Session() as sess:
        run_id = _row(sess, Status=CalibrationStatus.running, MatchTh=None, FinishedAt=None,
                    Quality=None)
        sess.commit()
    with patch("app.db.engine.db_session", _fake_db_session(Session)):
        grounding.record_calibration_finished(run_id, skipped=86.25)
    with Session() as sess:
        row = sess.get(m.Grounding_Calibration_Run, run_id)
        assert row.Status == CalibrationStatus.skipped
        assert row.FinishedAt is not None, "the row must be closed or it blocks the next sweep"
        assert row.MatchTh == 86.25, "it still says what is in force"
        assert row.Quality is None and row.NegativesCount is None, (
            "nothing was measured — inventing zeros reads as a sweep that separated nothing")
        # ...and it must be invisible to the read path, so it can never pose as a measurement.
        assert grounding.latest_successful_run(sess, ("emb-A", "rr-A")) is None


def test_a_lost_success_write_raises_instead_of_reporting_a_stored_threshold():
    """On success this write IS the measurement, so swallowing a failure would report SUCCESS for
    a 10-15 minute, ~100-billed-call sweep whose number nobody stored — the exact
    "measured but not saved" state the single-table design exists to make unreachable.
    Bookkeeping-only outcomes keep swallowing, so a DB blip cannot mask a sweep's real error."""
    engine = create_engine("sqlite://")  # table absent => every write fails
    Session = sessionmaker(bind=engine, future=True)
    rid = str(uuid.uuid4())
    ok = grounding.CalibrationResult(86.25, 0.99, 100, 200, 99.5, 71.2, [])
    with patch("app.db.engine.db_session", _fake_db_session(Session)):
        with pytest.raises(OperationalError):
            grounding.record_calibration_finished(rid, result=ok)
        # failed / no_signal / skipped are notes about a finished job — they stay best-effort, so
        # a DB blip here can never mask the sweep's own error.
        grounding.record_calibration_finished(rid, error="boom")
        grounding.record_calibration_finished(rid, skipped=86.25)
        grounding.record_calibration_finished(
            rid, result=grounding.CalibrationResult(None, 0.0, 1, 0, None, None, []))
