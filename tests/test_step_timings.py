"""Per-step timings: threat identification, each scenario, control mapping.

Each test pins one way the numbers could silently start lying — the only failure mode that
matters here, because a wrong duration looks exactly like a right one.
"""
from __future__ import annotations

import ast
import inspect
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
import structlog

from app.api import sessions as api_sessions
from app.core import tracing
from app.core.config import get_settings
from app.db import dal
from app.pipeline import control_mapping, local_models, tasks

T0 = datetime(2026, 9, 5, 11, 4, 59)
_APP = Path(tasks.__file__).resolve().parents[1]


# ---------------------------------------------------------------------------------------------
# THE double-count. Worth a static guard because it is invisible at runtime: control mapping's
# ~600s would simply be added to the scenarios stage, and both numbers would still look sane.
# ---------------------------------------------------------------------------------------------
def test_scenarios_stage_is_settled_before_control_mapping_runs() -> None:
    """`write_scenarios` must call finish_stage BEFORE _finalize_scenario_batch.

    finish_stage stamps Subsystem_Stage_State.FinishedAt, and _finalize_scenario_batch IS control
    mapping (tasks._finalize_scenario_batch -> control_mapping.map_controls). Reverse the two and
    the scenarios span swallows the longest step in the pipeline — a real run spent 604s of 724s
    in control mapping — so progress.timings.scenarios would report ~600s instead of ~40s, and
    the same seconds would be counted again in progress.timings.controls.
    """
    fn = {n.name: n for n in ast.walk(ast.parse(inspect.getsource(tasks)))
          if isinstance(n, ast.FunctionDef)}["write_scenarios"]
    finish = [c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
              and isinstance(c.func, ast.Attribute) and c.func.attr == "finish_stage"]
    mapping = [c.lineno for c in ast.walk(fn) if isinstance(c, ast.Call)
               and isinstance(c.func, ast.Name) and c.func.id == "_finalize_scenario_batch"]
    assert finish, "write_scenarios no longer calls finish_stage — the scenarios span has no end"
    assert mapping, "write_scenarios no longer calls _finalize_scenario_batch"
    assert max(finish) < min(mapping), (
        f"finish_stage (line ~{max(finish)}) must run BEFORE _finalize_scenario_batch "
        f"(line ~{min(mapping)}). Control mapping is now inside the SCENARIOS span, so its "
        "~600s is counted twice: once in timings.scenarios and again in timings.controls.")


# ---------------------------------------------------------------------------------------------
# ONE subtraction behind every duration. Derived, never stored, and never negative.
# ---------------------------------------------------------------------------------------------
def test_span_seconds_is_the_one_subtraction() -> None:
    assert dal.span_seconds(T0, T0 + timedelta(seconds=18.432)) == 18.43


@pytest.mark.parametrize("start, end", [
    (None, T0), (T0, None), (None, None),
    (T0 + timedelta(hours=5), T0),          # the regen shape: finished-before-started
])
def test_span_seconds_is_null_not_zero_for_anything_that_is_not_a_duration(start, end) -> None:
    """0.0 would read as "took no time"; None reads as "not measured". A negative span is two
    stamps from different attempts or different clocks, and must never be published as a number."""
    assert dal.span_seconds(start, end) is None


# ---------------------------------------------------------------------------------------------
# The board: three spans, no summable total, never a negative.
# ---------------------------------------------------------------------------------------------
@pytest.fixture
def board(monkeypatch):
    """build_board with every unrelated DAL read stubbed, so only the timings are under test."""
    def _build(stage_rows, control_seconds):
        monkeypatch.setattr(api_sessions.dal, "stage_rows", lambda *a, **k: stage_rows)
        monkeypatch.setattr(api_sessions.dal, "has_undecided_scenarios", lambda *a, **k: False)
        monkeypatch.setattr(api_sessions.dal, "control_mapping_progress",
                            lambda *a, **k: "COMPLETE")
        monkeypatch.setattr(api_sessions.dal, "latest_next_set_outcome", lambda *a, **k: None)
        monkeypatch.setattr(api_sessions.dal, "latest_regen_outcome", lambda *a, **k: None)
        # build_board also asks whether the asset-unit LOCK is held, to decide whether the two
        # "what did my click do?" summaries are safe to publish yet. Irrelevant to timings, so
        # stub it like the rest — this fixture passes sess=None on purpose.
        monkeypatch.setattr(api_sessions.dal, "subsystem_lock_is_held", lambda *a, **k: False)
        session = {"SessionID": "ab14229c-0000-0000-0000-000000000000", "EntityID": "e1",
                   "AssetID": "7", "AssetName": "Widget Control System", "UserID": "u1",
                   "SessionStatus": "active", "CurrentStage": "SCENARIOS",
                   "StageStatus": "AWAITING_DECISION", "ControlMapSeconds": control_seconds}
        return api_sessions.build_board(None, session)["progress"]
    return _build


def _row(level, started, finished):
    return {"SubsystemID": 0, "Level": level, "Status": "COMPLETE", "ErrorMessage": None,
            "StartedAt": started, "FinishedAt": finished}


def test_board_reports_one_span_per_stage_plus_the_control_total(board) -> None:
    progress = board(
        [_row("THREATS", T0, T0 + timedelta(seconds=34.21)),
         _row("SCENARIOS", T0 + timedelta(seconds=34.3), T0 + timedelta(seconds=76.33))],
        604.12)
    assert progress["timings"] == {"threats": 34.21, "scenarios": 42.03, "controls": 604.12}


def test_board_omits_a_stage_that_has_not_finished(board) -> None:
    progress = board([_row("THREATS", T0, None), _row("SCENARIOS", None, None)], None)
    assert progress["timings"] is None


def test_board_never_publishes_a_negative_span(board) -> None:
    """The regenerate shape: the previous epoch's FinishedAt survived while a new attempt wrote
    StartedAt. claim_stage/reset_stage_for_regen now clear it; this is the last line of defence
    for a stale stamp or two workers' clocks — withheld and logged, never a number."""
    progress = board([_row("SCENARIOS", T0 + timedelta(hours=5), T0)], None)
    assert progress["timings"] is None


def test_board_publishes_no_summable_scenario_total(board) -> None:
    progress = board([_row("SCENARIOS", T0, T0 + timedelta(seconds=42))], 604.12)
    assert set(progress["timings"]) <= {"threats", "scenarios", "controls"}


# ---------------------------------------------------------------------------------------------
# Every stage-status writer keeps FinishedAt honest. finish_stage called itself "THE choke
# point"; it was not — the reaper and _record_failure ended stages without an end, and
# claim_stage started them without clearing the old one. This reads every UPDATE of the stage
# table in app/ so a fourth writer cannot regress it silently.
# ---------------------------------------------------------------------------------------------
_TERMINAL = {"ERROR", "COMPLETE", "AWAITING_DECISION", "CANCELLED"}
_OPEN = {"RUNNING", "IDLE"}
_KEEPS_FINISHED_AT = {"revive_errored_scenarios_to_review"}   # terminal -> terminal, in place
_KNOWN_WRITERS = {"claim_stage", "finish_stage", "reset_stage_for_regen", "_record_failure",
                  "clean_up_abandoned_sessions", "recover_session_now", "recover_abandoned_session"}


def _stage_state_values_calls():
    """(file, enclosing function, .values() Call) for every update(<stage table>)....values()."""
    for py in sorted(_APP.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"))
        aliases = {"Subsystem_Stage_State"} | {
            t.id for n in ast.walk(tree) if isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Attribute) and n.value.attr == "Subsystem_Stage_State"
            for t in n.targets if isinstance(t, ast.Name)}
        owner: dict = {}
        for fn in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)):
            for child in ast.walk(fn):
                owner.setdefault(child, fn.name)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "values"):
                continue
            root = node.func.value
            while isinstance(root, ast.Call) and isinstance(root.func, ast.Attribute):
                root = root.func.value                       # .values() <- .where() <- update()
            if not (isinstance(root, ast.Call) and isinstance(root.func, ast.Name)
                    and root.func.id == "update" and root.args):
                continue
            target = root.args[0]
            name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
            if name in aliases:
                yield py.name, owner.get(node, "<module>"), node


def _is_none(v) -> bool:
    return isinstance(v, ast.Constant) and v.value is None


def test_every_stage_status_writer_keeps_finished_at_honest() -> None:
    seen, offenders = set(), []
    for fname, fn, call in _stage_state_values_calls():
        kws = {k.arg: k.value for k in call.keywords if k.arg}
        if "Status" not in kws:
            continue                                     # lease/heartbeat renewals
        seen.add(fn)
        status = kws["Status"]
        member = status.attr if isinstance(status, ast.Attribute) else None   # None: a parameter
        names = {n.attr for n in ast.walk(call) if isinstance(n, ast.Attribute)}
        where = f"{fname}:{call.lineno} {fn}"
        if member in _OPEN:
            if "LOCK" in names:                          # _LOCK rows carry no span
                continue
            if not _is_none(kws.get("FinishedAt")):
                offenders.append(f"{where}: Status={member} must set FinishedAt=None")
            if member == "IDLE" and not _is_none(kws.get("StartedAt")):
                offenders.append(f"{where}: Status=IDLE must set StartedAt=None")
        elif member in _TERMINAL or member is None:
            if fn in _KEEPS_FINISHED_AT:
                continue
            if kws.get("FinishedAt") is None or _is_none(kws["FinishedAt"]):
                offenders.append(f"{where}: terminal Status without a FinishedAt stamp")
        else:
            offenders.append(f"{where}: Status={member!r} is not a stage status this test knows")
    assert not offenders, "stage-status writers that would corrupt progress.timings:\n  " + "\n  ".join(offenders)
    assert _KNOWN_WRITERS <= seen, f"parser missed known writers: {sorted(_KNOWN_WRITERS - seen)}"


# ---------------------------------------------------------------------------------------------
# A failed scenario is timed exactly like a successful one, and the span lives in columns.
# ---------------------------------------------------------------------------------------------
def test_a_failed_generation_still_reports_its_span(monkeypatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("model down")
    monkeypatch.setattr(tasks, "_generate_one_scenario", boom)
    sc = SimpleNamespace(threat_id="t1")
    out = tasks._generate_scenario_batch(None, {"SessionID": "s"}, {}, [(sc, "sc1", None)], {},
                                         None, "task", 1, {"sc1": {}}, None)
    ((scoped_id, result, exc, (started, finished)),) = out
    assert scoped_id == "sc1" and result is None and isinstance(exc, RuntimeError)
    assert started <= finished


def test_failure_and_success_rows_carry_the_span_in_columns_not_json() -> None:
    span = (T0, T0 + timedelta(seconds=7.5))
    ok = tasks._build_scenario_output_row("sc1", "s", "t", 0, {"scenario_statement": "x"},
                                          {"errors": []}, 1, "e", "u", {}, span=span)
    bad = tasks._build_error_output_row("sc1", "s", "t", 0, "boom", 1, "e", "u", {}, span=span)
    for row in (ok, bad):
        assert (row["GenStartedAt"], row["GenFinishedAt"]) == span
    assert "gen_started_at" not in ok["ValidationJSON"]


# ---------------------------------------------------------------------------------------------
# Control mapping and model paths: two more ways to lose a number silently.
# ---------------------------------------------------------------------------------------------
def test_map_controls_refuses_to_guess_durability() -> None:
    """A caller that omits durable= used to get a non-committing accumulate and lose its seconds."""
    p = inspect.signature(control_mapping.map_controls).parameters["durable"]
    assert p.kind is inspect.Parameter.KEYWORD_ONLY and p.default is inspect.Parameter.empty


def test_relative_model_paths_resolve_against_the_project_root(tmp_path) -> None:
    assert Path(local_models.resolve_model_path("models/e5")) == local_models._ROOT / "models" / "e5"
    absolute = str(tmp_path / "e5")
    assert local_models.resolve_model_path(absolute) == absolute


# ---------------------------------------------------------------------------------------------
# The contextvars fallback — the fix most likely to fail silently, because the file and console
# sinks never see contextvars at all and an unattributed record still looks well-formed.
# ---------------------------------------------------------------------------------------------
@pytest.fixture
def console_sink(monkeypatch):
    monkeypatch.setenv("TRACE_SINKS", "console")
    get_settings.cache_clear()
    structlog.contextvars.clear_contextvars()
    yield
    structlog.contextvars.clear_contextvars()
    get_settings.cache_clear()


def test_a_trace_with_no_sid_inherits_the_session_from_contextvars(console_sink, capsys) -> None:
    structlog.contextvars.bind_contextvars(session_id="ab14229c-3f21-4e0b")
    with tracing.trace_step("LLM CALL", None, model="gpt-4o"):
        pass
    assert "ab14229c" in capsys.readouterr().out


def test_an_explicit_sid_still_wins_over_the_contextvar(console_sink, capsys) -> None:
    structlog.contextvars.bind_contextvars(session_id="wrongone-dead-beef")
    with tracing.trace_step("STAGE CLAIM", "rightone-3f21", subsystem=0):
        pass
    out = capsys.readouterr().out
    assert "rightone" in out
    assert "wrongone" not in out


def test_the_fallback_stays_free_when_tracing_is_off(monkeypatch, capsys) -> None:
    monkeypatch.setenv("TRACE_SINKS", "")
    get_settings.cache_clear()
    seen: list[int] = []
    monkeypatch.setattr(tracing, "_contextvar_sid", lambda: seen.append(1) or "")
    with tracing.trace_step("LLM CALL", None) as t:
        t.result(ok=True)
    get_settings.cache_clear()
    assert seen == [], "trace_step resolved the session contextvar while every sink was off"
    assert capsys.readouterr().out == ""
