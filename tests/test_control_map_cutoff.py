"""The control-relevance cutoff must be a MEASURED, STORED number — never a fabricated one.

WHY THESE PINS EXIST. Control mapping queries the library with a scenario PARAGRAPH; the grounding
threshold it used to borrow was measured on a short threat LABEL. The two score on different scales,
so the borrowed number was a guess — and a guess set too high drops every match, leaving each
scenario to publish `controls: []`, which this API documents in three places as a healthy library
gap. Nothing errors. Nothing logs. A reviewer concludes the library does not cover their asset.

So the failure mode this whole feature guards against is a number that LOOKS measured and is not.
Every pin below is aimed at exactly that:

  * the reader is keyed on the MODEL PAIR, so one measurement covers UAT and production while dev
    lands on its own row and cannot contaminate them;
  * the reader never raises — a broken audit table must degrade to "not measured", never take
    control mapping down;
  * the two readers over the one ledger cannot see each other's rows (the non-null column is the
    discriminator), so a threat-label threshold can never be served as a control cutoff;
  * a measurement with no answer stores NOTHING. Storing 0 would admit every control at every
    score, while claiming to have been measured;
  * the stricter alternative is RECORDED, never selected — that trade is the operator's;
  * the routes are in route_audit.py's registry, which create_app() refuses to boot without, and a
    caller with no admin key cannot reach them.
"""
from __future__ import annotations

import inspect
import uuid
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, insert, select
from sqlalchemy.orm import sessionmaker

from app.api import admin, route_audit
from app.api.deps import require_admin
from app.core.config import get_settings
from app.core.enums import CalibrationStatus, CeleryJobState
from app.db import dal
from app.db import models as m
from app.db.invariants import StartupInvariantError
from app.main import create_app
from app.pipeline import celery_app as ca
from app.pipeline import grounding

PAIR = ("emb-A", "rr-A")
CALIBRATE = "/v1/tsg/control-map/calibrate"
STATUS = "/v1/tsg/control-map/calibrate/status/{job_id}"


def _ledger_engine():
    """In-memory SQLite with just the calibration table — the read path touches nothing else."""
    engine = create_engine("sqlite://")
    m.Grounding_Calibration_Run.__table__.create(engine)
    return engine


def _row(sess, **over) -> str:
    """One ledger row. Defaults describe a SUCCESSFUL CONTROL-MAP run: ControlMapTh set, MatchTh
    NULL. That pairing is the discriminator, not decoration — see models.Grounding_Calibration_Run.
    """
    vals = {"RunID": str(uuid.uuid4()), "Status": CalibrationStatus.success,
            "EmbeddingModel": PAIR[0], "RerankerModel": PAIR[1], "Forced": False,
            "StartedAt": dal.now(), "FinishedAt": dal.now(),
            "MatchTh": None, "ControlMapTh": 55.0}
    vals.update(over)
    sess.execute(insert(m.Grounding_Calibration_Run).values(**vals))
    return vals["RunID"]


def _fake_db_session(Session):
    """A stand-in for app.db.engine.db_session with the SAME contract: commit on success, rollback
    on error, always close. A bare sessionmaker() will not do — its __exit__ closes WITHOUT
    committing, so the recorder's writes would vanish and these assertions would pass or fail on the
    harness rather than on the code, which is the one thing a test must rule out."""
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


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------

def test_the_newest_successful_measurement_for_this_pair_wins():
    """Re-measuring APPENDS, so history survives and the latest number is the one in force — which
    is what makes a re-measurement after curating the library actually take effect, with no
    redeploy and nothing pinned per environment."""
    with sessionmaker(bind=_ledger_engine(), future=True)() as sess:
        _row(sess, ControlMapTh=40.0, StartedAt=dal.now().replace(year=2025))
        _row(sess, ControlMapTh=55.0)
        sess.commit()
        assert grounding.latest_control_map_cutoff(sess, PAIR) == 55.0


def test_another_model_pair_can_never_leak_in():
    """THE property the model-pair key exists for. UAT and prod share models, so one measurement
    covers both; dev runs different models, so its row is invisible here. If this ever starts
    failing, a dev number can reach production."""
    with sessionmaker(bind=_ledger_engine(), future=True)() as sess:
        _row(sess, EmbeddingModel="emb-DEV", ControlMapTh=5.0)
        sess.commit()
        assert grounding.latest_control_map_cutoff(sess, PAIR) is None


@pytest.mark.parametrize("over", [
    {"Status": CalibrationStatus.no_signal},   # ran, measured nothing
    {"Status": CalibrationStatus.failed},      # crashed
    {"Status": CalibrationStatus.running},     # in flight
    {"ControlMapTh": None},                    # success, but nothing stored
])
def test_only_a_stored_success_counts_as_a_measurement(over):
    """A row is not a measurement. Every state below either never produced a number or is not
    finished producing one, and reading any of them as a cutoff is the fabrication this guards."""
    with sessionmaker(bind=_ledger_engine(), future=True)() as sess:
        _row(sess, **over)
        sess.commit()
        assert grounding.latest_control_map_cutoff(sess, PAIR) is None


def test_a_broken_read_degrades_instead_of_raising():
    """A control mapping pass must never fail because the audit table is unreadable. The fallback
    exists precisely because it is always reachable, so an unreadable ledger has to look EXACTLY
    like an unmeasured one — louder would mean a broken audit table can stop scenarios getting
    controls at all."""
    engine = create_engine("sqlite://")  # table deliberately NOT created
    with sessionmaker(bind=engine, future=True)() as sess:
        assert grounding.latest_control_map_cutoff(sess, PAIR) is None


def test_the_two_readers_over_one_ledger_cannot_see_each_other():
    """The non-null column IS the discriminator, which is why neither reader needs a `kind` column
    and why latest_successful_run's existing filter kept working untouched. Break this and a
    threat-LABEL threshold gets served as a control-PARAGRAPH cutoff: a plausible float measured
    for a different question."""
    with sessionmaker(bind=_ledger_engine(), future=True)() as sess:
        _row(sess, MatchTh=86.25, ControlMapTh=None)   # a grounding sweep
        _row(sess, MatchTh=None, ControlMapTh=55.0)    # a control-map run
        sess.commit()
        assert grounding.latest_control_map_cutoff(sess, PAIR) == 55.0
        assert grounding.latest_successful_run(sess, PAIR) == 86.25


# ---------------------------------------------------------------------------
# The measurement: what it refuses to invent
# ---------------------------------------------------------------------------

class _FakeLLM:
    def __init__(self, matches):
        self._matches = matches

    def embed(self, texts, kind):
        return [[0.0] for _ in texts]


def _settings():
    from app.core.config import get_settings
    return get_settings()


def _measure(monkeypatch, results):
    """Run the measurement with the rerank funnel stubbed — the funnel itself is
    ground_control_queries' own tested code, and what is under test here is what the measurement
    does with its OUTCOME."""
    monkeypatch.setattr(grounding, "ground_control_queries",
                        lambda llm, flat, candidates, s: results)
    candidates = [{"ControlLibraryID": 1, "text": "c1"}]
    queries = [(f"s{i}", f"query {i}") for i in range(len(results))]
    return grounding.measure_control_map_cutoff(_FakeLLM(results), candidates, queries, _settings())


def _matched(*scores):
    return grounding.ControlMatches([({"ControlLibraryID": 1}, sc) for sc in scores], True)


def test_a_cutoff_is_only_recommended_when_it_was_actually_measured(monkeypatch):
    """The happy path, so the guards below are not passing for want of a working case. `safe` is the
    HIGHEST swept value at which NO scenario loses all its controls — here the weaker scenario's
    best match is 84, so 80 is the last swept step both survive and 85 is the first that strands
    one."""
    out = _measure(monkeypatch, [_matched(91.0, 77.0), _matched(84.0, 62.0)])
    assert out.cutoff == 80.0, out
    assert out.scenarios == 2 and out.note is None


def test_an_unanswered_batch_never_becomes_a_cutoff(monkeypatch):
    """THE dangerous arithmetic. With nothing measured, the threshold sweep sees zero scenarios
    going empty at EVERY threshold, so the naive recommendation is the strictest value in the sweep
    — a 95 derived from no evidence whatsoever, which would drop every control in production. A
    failed rerank batch is a provider fault and must measure NOTHING."""
    unanswered = grounding.ControlMatches([], False)
    out = _measure(monkeypatch, [unanswered, unanswered])
    assert out.cutoff is None, "a cutoff from zero measurements is a fabrication, not a measurement"
    assert out.scenarios == 0
    assert "every rerank item failed" in (out.note or "")


def test_empty_shortlists_report_retrieval_rather_than_a_cutoff(monkeypatch):
    """`safe is None` is an ANSWER, not a value to coerce (see control_threshold's docstring): the
    shortlists were empty, so the fault is retrieval and no threshold fixes it. Coercing it to 0
    would admit every control at every score while claiming to be measured."""
    out = _measure(monkeypatch, [grounding.ControlMatches([], True)])
    assert out.cutoff is None
    assert "retrieval" in (out.note or "").lower()


def test_an_empty_library_or_no_scenarios_measures_nothing():
    """Measuring against an empty pool would 'prove' any cutoff — the one result that must never be
    stored, because it is the most confident-looking."""
    for candidates, queries in (([], [("s", "q")]), ([{"ControlLibraryID": 1}], [])):
        out = grounding.measure_control_map_cutoff(_FakeLLM([]), candidates, queries, _settings())
        assert out.cutoff is None and out.scenarios == 0
        assert "nothing to measure" in (out.note or "")


def test_the_stricter_alternative_is_reported_and_is_not_the_stored_value(monkeypatch):
    """It buys a cleaner tail by stranding a bounded, counted share of scenarios — they keep no match
    that CLEARS the cutoff, so production falls back to backfilling them with nearest matches, and
    the deepest-tail ones publish `controls: []`, a cost invisible in the response that lands on a
    human reviewer. That trade is the OPERATOR's, so the measurement offers it and the stored value
    stays `safe`.

    84 was the answer while the alternative was a percentile of the best-match scores taken with no
    reference to the sweep — a value that stranded NOBODY here and could equal the stored cutoff
    outright on a smaller sample. It is now read off the measured scores as the strictest cutoff that
    strands at most max(1, 5%) of them: with two scenarios the budget is one scenario, so the
    alternative is the second-lowest best match (91) and it costs the 84-scoring scenario."""
    out = _measure(monkeypatch, [_matched(91.0, 77.0), _matched(84.0, 62.0)])
    assert out.stricter_alternative == 91.0, out
    assert out.stricter_alternative > out.cutoff, (
        "the alternative must be genuinely STRICTER than the stored value — that is what makes "
        "accepting it a trade rather than a free improvement, and why nothing selects it for you")


# ---------------------------------------------------------------------------
# Storing it
# ---------------------------------------------------------------------------

def test_a_measured_cutoff_is_stored_with_its_provenance():
    """ONE write: the value is a column of the record of its own measurement, so "measured but not
    saved" is unreachable. The sample size and the stricter alternative ride along, because a cutoff
    measured over three scenarios and one measured over three hundred are the same float."""
    Session = sessionmaker(bind=_ledger_engine(), future=True)
    with Session() as sess:
        run_id = _row(sess, Status=CalibrationStatus.running, ControlMapTh=None, FinishedAt=None)
        sess.commit()
    measured = grounding.ControlMapMeasurement(55.0, 62.0, 47, 1288, None)
    with patch("app.db.engine.db_session", _fake_db_session(Session)):
        grounding.record_control_map_finished(run_id, measured)
    with Session() as sess:
        row = sess.execute(select(m.Grounding_Calibration_Run)).scalars().one()
    assert (row.Status, row.ControlMapTh) == (CalibrationStatus.success, 55.0)
    assert row.PositivesCount == 47, "the sample size must survive — see record_control_map_finished"
    assert row.LowestPositive == 62.0, "the stricter alternative is RECORDED, never applied"
    assert row.MatchTh is None, "a control-map run must stay invisible to the grounding reader"
    assert row.ErrorMessage is None


def test_a_measurement_with_no_answer_stores_no_cutoff_at_all():
    """THE pin the whole design turns on. `no_signal`, not `failed` (nothing crashed) and
    emphatically not `success` with a 0 — and ControlMapTh stays NULL, so the reader keeps reporting
    "not measured" and control mapping keeps its documented fallback."""
    Session = sessionmaker(bind=_ledger_engine(), future=True)
    with Session() as sess:
        run_id = _row(sess, Status=CalibrationStatus.running, ControlMapTh=None, FinishedAt=None)
        sess.commit()
    empty = grounding.ControlMapMeasurement(None, None, 0, 1288, "shortlists were empty")
    with patch("app.db.engine.db_session", _fake_db_session(Session)):
        grounding.record_control_map_finished(run_id, empty)
    with Session() as sess:
        row = sess.execute(select(m.Grounding_Calibration_Run)).scalars().one()
        assert row.Status == CalibrationStatus.no_signal
        assert row.ControlMapTh is None, "storing 0 would be a fabricated measurement"
        assert row.ErrorMessage == "shortlists were empty", "the reason must be readable afterwards"
        assert grounding.latest_control_map_cutoff(sess, PAIR) is None


def test_a_lost_success_write_raises_instead_of_reporting_a_stored_cutoff():
    """On success this write IS the measurement, so swallowing its failure would lose a multi-minute
    run while the job cheerfully reported a number nobody stored. Letting it out makes the task fail
    honestly and the measurement re-runnable. The no-cutoff path stays best-effort — there, the
    write is bookkeeping and must not mask the real outcome."""
    @contextmanager
    def _broken():
        raise RuntimeError("database gone")
        yield  # pragma: no cover — unreachable, keeps this a generator

    measured = grounding.ControlMapMeasurement(55.0, 62.0, 47, 1288, None)
    empty = grounding.ControlMapMeasurement(None, None, 0, 1288, "nothing measured")
    with patch("app.db.engine.db_session", _broken):
        with pytest.raises(RuntimeError):
            grounding.record_control_map_finished("r1", measured)
        grounding.record_control_map_finished("r1", empty)  # must NOT raise


# ---------------------------------------------------------------------------
# The job and the routes
# ---------------------------------------------------------------------------

def test_the_measurement_runs_as_a_job_and_requires_its_ledger_row():
    """It reranks every measured scenario against the whole active control library, so it must not
    run inline in a request handler. `run_id` has no default on purpose: the row is the concurrency
    guard, only the route can open it before the publish, and a task with no row has nowhere to
    store its answer."""
    assert "tsg.calibrate_control_map" in ca.celery_app.tasks
    params = inspect.signature(ca.calibrate_control_map_task.run).parameters
    assert params["run_id"].default is inspect.Parameter.empty
    assert "limit" in params, "the cost knob the operator needs — this reranks real scenarios"


def test_nothing_queues_the_measurement_by_itself():
    """A multi-minute rerank run must never start on a process restart. The only trigger is the
    admin route, which is what makes every run have an accountable caller."""
    src = inspect.getsource(ca)
    assert src.count("calibrate_control_map_task.apply_async") == 0, (
        "celery_app must not queue this itself — the admin route is the only trigger")
    assert "calibrate_control_map_task" in inspect.getsource(admin)


@pytest.mark.parametrize("method,path", [
    ("POST", CALIBRATE),
    ("GET", STATUS),
])
def test_each_new_route_is_triaged_in_the_registry(method, path):
    """create_app() refuses to boot on a route missing from route_audit.py, so this is not
    bookkeeping — it is the check that stops a forgotten auth dependency shipping as a silent IDOR.
    Admin-key gated, exactly like the grounding-threshold routes: the cutoff is a property of the
    deployment's model pair, shared by every entity, so there is no one entity to scope it to."""
    assert route_audit._EXEMPT_ROUTES[(method, path)] is require_admin


def test_removing_a_route_from_the_registry_fails_the_boot():
    """Drives the guard rather than trusting it. If this stops raising, the registry has become
    decorative and the next unregistered route ships unaudited."""
    live = dict(route_audit._EXEMPT_ROUTES)
    live.pop(("POST", CALIBRATE))
    with patch.object(route_audit, "_EXEMPT_ROUTES", live):
        with pytest.raises(StartupInvariantError, match="not classified"):
            create_app()


@pytest.mark.parametrize("call", [
    lambda c: c.post(CALIBRATE),
    lambda c: c.get(STATUS.format(job_id="anything")),
])
def test_a_caller_without_the_admin_key_is_refused(call):
    """The measurement is expensive and the stored value governs every tenant's control mapping, so
    neither starting one nor reading one is open. Refused at the ROUTER dependency, before any DB or
    broker work — which is why a missing key cannot even reach a 404."""
    resp = call(TestClient(create_app(), raise_server_exceptions=False))
    assert resp.status_code == 401, resp.text
    assert resp.json()["error_code"] == "unauthorized"


def _request():
    from types import SimpleNamespace
    return SimpleNamespace(client=None)


def _principal():
    from types import SimpleNamespace
    return SimpleNamespace(user_id="ops@example.com", client_id="client-7")


@contextmanager
def _nullsession():
    yield None


def test_starting_a_measurement_opens_the_ledger_row_before_it_queues_anything(monkeypatch):
    """THE ORDERING IS THE CONCURRENCY GUARD. The row must exist before the publish, because
    `UX_GroundingCalibration_Running` (unique, filtered on Status='running', keyed on the model
    pair) is what refuses a second one — a Python "is one running?" check has a window where two
    requests both read no, and queueing first moves the guard behind the broker, where the duplicate
    has already been promised a 202.

    This also drives the route BODY, which is what scripts/test_pipeline_guards.py requires of every
    write route: an authz test dies above the pipeline call and proves nothing about it."""
    order: list[str] = []
    monkeypatch.setattr(grounding, "record_calibration_started",
                        lambda key, **kw: (order.append("row"), "run-1")[1])
    monkeypatch.setattr(admin.calibrate_control_map_task, "apply_async",
                        lambda args, shadow: (order.append(f"queue{args}"),
                                            type("T", (), {"id": "job-1"})())[1])
    monkeypatch.setattr(admin, "_attach_job_id", lambda run_id, job_id: order.append("jobid"))
    out = admin.calibrate_control_map(_request(), limit=25, principal=_principal())
    assert (out.job_id, out.run_id) == ("job-1", "run-1")
    assert order == ["row", "queue('run-1', 25)", "jobid"], order


def test_a_second_concurrent_measurement_is_refused_by_the_database(monkeypatch):
    """The 409 comes from the unique index refusing the INSERT, never from a check-then-act, so it
    cannot be a false positive. It carries the in-flight run id so the caller polls that one rather
    than retrying blind into a second multi-minute rerank run."""
    from sqlalchemy.exc import IntegrityError

    def _refuse(key, **kw):
        raise IntegrityError("INSERT ...", {}, Exception("UX_GroundingCalibration_Running"))

    monkeypatch.setattr(grounding, "record_calibration_started", _refuse)
    monkeypatch.setattr(admin, "db_session", _nullsession)
    monkeypatch.setattr(grounding, "running_run",
                        lambda sess, key: type("R", (), {"RunID": "run-live"})())
    with pytest.raises(admin.CalibrationConflict) as caught:
        admin.calibrate_control_map(_request(), limit=50, principal=_principal())
    assert caught.value.run_id == "run-live"


def test_a_broker_that_refuses_the_publish_releases_the_ledger_row(monkeypatch):
    """The row is the lock and it was opened first, so a failed publish leaves nobody to close it.
    Without this unwind every call for the next stale window gets a 409 pointing at a run that never
    started — the lock outliving the thing it was locking."""
    closed: list[str] = []
    monkeypatch.setattr(grounding, "record_calibration_started", lambda key, **kw: "run-2")
    monkeypatch.setattr(grounding, "record_calibration_finished",
                        lambda run_id, **kw: closed.append(run_id))

    def _broker_down(args, shadow):
        raise OSError("broker unreachable")

    monkeypatch.setattr(admin.calibrate_control_map_task, "apply_async", _broker_down)
    with pytest.raises(OSError):
        admin.calibrate_control_map(_request(), limit=50, principal=_principal())
    assert closed == ["run-2"], "the row must be released, or the next caller is stuck behind a 409"


def test_the_status_route_answers_from_the_permanent_ledger():
    """No Celery result and no Redis marker, unlike its grounding sibling: the route opens the row
    before it queues anything, so the row is both the live state and the authorization check — and
    it never expires, which is exactly the question ("did last Tuesday's measurement pass?") the
    one-hour TTL could not answer."""
    class _Row:
        RunID, Status, ControlMapTh, LowestPositive, PositivesCount = "r1", CalibrationStatus.success, 55.0, 62.0, 47
        StartedBy, StartedAt, FinishedAt, ErrorMessage = "ops", None, None, None
        EmbeddingModel, RerankerModel = PAIR

    with patch.object(admin, "_calibration_row_by_job", lambda _job: _Row()):
        out = admin.get_control_map_calibration_status("job-1")
    assert (out.state, out.cutoff, out.scenarios) == (CeleryJobState.SUCCESS, 55.0, 47)
    assert out.stricter_alternative == 62.0


def test_the_status_route_refuses_to_present_a_grounding_sweep_as_a_control_cutoff():
    """Both measurements share one ledger, so the only state that could mislabel a NUMBER is a
    SUCCESSFUL row with no ControlMapTh — that is a grounding sweep, and its threat-label threshold
    is the answer to a different question."""
    class _GroundingRow:
        RunID, Status, ControlMapTh = "r2", CalibrationStatus.success, None
        MatchTh = 86.25

    from app.db.dal import NotFoundError
    with patch.object(admin, "_calibration_row_by_job", lambda _job: _GroundingRow()):
        with pytest.raises(NotFoundError):
            admin.get_control_map_calibration_status("job-2")


class _MeasuredRow:
    """A SUCCESSFUL control-map run that stored 55.0 — the measurement whose fate is in question."""
    RunID, Status, ControlMapTh, LowestPositive, PositivesCount = "r3", CalibrationStatus.success, 55.0, 62.0, 47
    StartedBy, StartedAt, FinishedAt, ErrorMessage = "ops", None, None, None
    EmbeddingModel, RerankerModel = PAIR


def test_the_status_route_reports_the_measurement_even_when_the_env_pins_a_cutoff(monkeypatch):
    """THE MEASUREMENT OUT-VOTES THE ENV FILE, and the route has to say so.

    INVERTED on 2026-09-25 by the owner's decision. This test asserted the OPPOSITE — that a pinned
    `TSG_CONTROL_MAP_MIN_SCORE` made every stored measurement inert — because that was what
    `control_mapping._min_score` did. The owner's words: "if .env file also have the value and
    database also have consider database. if no value in database then only consider .env value."
    The branch ORDER is the decision, so a test still pinning the old order would have left the suite
    asserting a rule the product no longer follows.

    The reasoning the order encodes: the env value is a GUESS made before anyone measured this
    deployment; the stored value is the answer from scoring real scenarios against the real library.
    So the route must report the measurement as the cutoff IN FORCE even on a deployment whose .env
    still pins a different number — because that is what control matching applies on its next pass,
    with no restart and no config edit.

    A REAL ENVIRONMENT VARIABLE, not a stubbed settings object, because `model_fields_set` is half
    the mechanism and pydantic populates it by reading the environment. Stub the settings and this
    passes while the thing it pins is broken."""
    monkeypatch.setenv("TSG_CONTROL_MAP_MIN_SCORE", "50")
    get_settings.cache_clear()
    try:
        with patch.object(admin, "_calibration_row_by_job", lambda _job: _MeasuredRow()):
            out = admin.get_control_map_calibration_status("job-3")
    finally:
        get_settings.cache_clear()   # drop the env-influenced cache for later tests
    assert out.cutoff == 55.0, "the measurement is reported — it was taken and stored"
    assert out.cutoff_origin == "calibrated_for_control_mapping"
    assert out.cutoff_in_force == out.cutoff == 55.0, (
        "the stored measurement is what control matching applies, so it is what the caller must be "
        "told is in force — NOT the 50 still sitting in the environment")


def test_the_status_route_falls_back_to_the_env_pin_when_the_run_stored_nothing(monkeypatch):
    """The `env_pinned` branch is still reachable, and this is the state that reaches it.

    The inversion demoted that branch, it did not delete it, so it still needs a pin — and what gets
    there is a run that MEASURED NOTHING: retrieval faulted, the run settled `no_signal`, and
    `ControlMapTh` was left NULL. Absence is NULL, never 0.0, which is exactly why the handler tests
    `is not None` rather than truthiness: a measured zero is an answer and must win, while this row
    has no answer at all and the bootstrap has to keep governing."""
    class _NoSignalRow(_MeasuredRow):
        Status = "no_signal"
        ControlMapTh = None
        ErrorMessage = "every shortlist came back empty"

    monkeypatch.setenv("TSG_CONTROL_MAP_MIN_SCORE", "50")
    get_settings.cache_clear()
    try:
        with patch.object(admin, "_calibration_row_by_job", lambda _job: _NoSignalRow()):
            out = admin.get_control_map_calibration_status("job-3b")
    finally:
        get_settings.cache_clear()
    assert out.cutoff is None, "nothing was measured, so nothing is reported as measured"
    assert out.cutoff_origin == "env_pinned"
    assert out.cutoff_in_force == 50.0, (
        "with no stored measurement the bootstrap governs — and a caller told to 're-run the "
        "measurement' rather than 'edit the variable' has to see which of the two they are looking at")


def test_the_status_route_reports_the_measurement_itself_when_nothing_is_pinned(monkeypatch):
    """The other branch, and the reason the one above cannot be satisfied by a constant. With no
    pin, `_min_score` reads the newest stored measurement for this model pair, so the measurement IS
    the cutoff in force and the uptake promise is true."""
    class _Unpinned:
        model_fields_set: set[str] = set()
        control_map_min_score = 60.0

    monkeypatch.setattr(admin, "get_settings", lambda: _Unpinned())
    with patch.object(admin, "_calibration_row_by_job", lambda _job: _MeasuredRow()):
        out = admin.get_control_map_calibration_status("job-4")
    assert out.cutoff_origin == "calibrated_for_control_mapping"
    assert out.cutoff_in_force == out.cutoff == 55.0
