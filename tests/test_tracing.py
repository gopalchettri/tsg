"""app.core.tracing — the three sinks, the BEGIN/END guarantee, and the two fixes that would
otherwise fail SILENTLY in production.

Replaces test_trace_console.py, whose premise (a single console sink, paired IN/OUT calls) no
longer exists. Every assertion below pins something that has already been got wrong once:

  * the PID in the rotating filename — without it several processes share one file and rotation
    stops working with no error at all (on Windows the file just grows past its cap forever);
  * BEGIN/END pairing across an early return AND an exception — the failure mode the paired
    trace() calls had by construction;
  * LLMSlotUnavailable classified as expected, not an error — it is routine backpressure, and
    logging it at ERROR turns normal load-shedding into an error storm in Loki;
  * the json sink summarising while the txt sink stays whole — the split the file sinks exist for.
"""
from __future__ import annotations

import io
import json
import logging
import os
import sys
import threading
import time
import uuid

import pytest

from app.core import tracing
from app.core.config import get_settings
from app.core.logging import configure_logging


@pytest.fixture
def sinks(monkeypatch):
    """Enable sinks for one test. get_settings() is lru_cached — the same reason these settings
    are restart-only in a real process — so the cache must be cleared by hand here."""
    def _apply(value: str, tmp_dir=None):
        # The BARE spelling, not TSG_TRACE_SINKS: both are accepted, but config.py lists them as
        # AliasChoices("TRACE_SINKS", "TSG_TRACE_SINKS") and the FIRST match in a source wins.
        # Anything that puts the whole .env into os.environ therefore shadows the TSG_ spelling,
        # and this fixture silently stops overriding anything — which is how the file sink ended
        # up writing to the real logs/trace instead of tmp_dir.
        monkeypatch.setenv("TRACE_SINKS", value)
        if tmp_dir is not None:
            monkeypatch.setenv("TRACE_DIR", str(tmp_dir))
        get_settings.cache_clear()
        # File handlers are memoised per stem; drop them so a fresh tmp dir is honoured.
        for name in list(logging.root.manager.loggerDict):
            if name.startswith("tsg.tracefile."):
                logging.getLogger(name).handlers.clear()
    yield _apply
    get_settings.cache_clear()


def test_every_sink_off_by_default_costs_nothing(sinks, capsys):
    sinks("")
    assert tracing.active_sinks() == frozenset()
    with tracing.trace_step("HYBRID SEARCH", "sess1234", query="pumps") as t:
        t.result(matches=3)          # must stay callable on the null step
    assert capsys.readouterr().out == ""


def test_console_sink_emits_begin_and_end_with_duration(sinks, capsys):
    sinks("console")
    with tracing.trace_step("HYBRID SEARCH", "4b777191-24f0", corpus=4) as t:
        t.result(matches=2)
    out = capsys.readouterr().out
    assert "> HYBRID SEARCH" in out and "< HYBRID SEARCH" in out
    assert "[4b777191]" in out                    # session id truncated to 8
    assert "24f0" not in out
    assert "corpus" in out and "matches" in out
    assert "ms" in out                            # END carries the elapsed time
    assert "test_tracing.py:" in out              # the CALLER's file:line, not tracing.py's


def test_end_is_emitted_even_when_the_body_raises(sinks, capsys):
    """THE guarantee the paired trace(..., "IN"/"OUT") calls could not make: a raise used to
    leave a BEGIN with no END, so a failed step looked like one still running."""
    sinks("console")
    with pytest.raises(ValueError), tracing.trace_step("REGROUNDING", "sess1234", proposal="x"):
        raise ValueError("boom")
    out = capsys.readouterr().out
    assert out.count("> REGROUNDING") == 1
    assert out.count("< REGROUNDING") == 1
    assert "failed" in out and "ValueError: boom" in out


def test_end_is_emitted_on_an_early_return(sinks, capsys):
    """The other half of the same guarantee — threat_retrieval's `return []` on an empty library
    sits inside a traced block."""
    sinks("console")

    def work():
        with tracing.trace_step("METADATA FILTER", "sess1234", sector_ids=[]) as t:
            t.result(library_empty=True)
            return []
    assert work() == []
    out = capsys.readouterr().out
    assert out.count("< METADATA FILTER") == 1
    assert "ok" in out


def test_expected_exception_is_not_an_error(sinks, capsys):
    """LLMSlotUnavailable is backpressure — retried with max_retries=None and caught deliberately
    in cascade.py. Marking it `failed` would flood Loki with errors under normal load."""
    sinks("console")

    class LLMSlotUnavailable(Exception):
        pass

    with pytest.raises(LLMSlotUnavailable), tracing.trace_step("LLM CALL", "sess1234"):
        raise LLMSlotUnavailable("no slot")
    out = capsys.readouterr().out
    assert "expected" in out
    assert "failed" not in out


def test_file_sink_writes_both_forms_and_carries_the_pid(sinks, tmp_path):
    """PID-in-filename is the multi-process rotation fix: gunicorn -w 4 plus worker and beat all
    open these paths, and one shared file rotates wrongly (Linux) or never at all (Windows)."""
    sinks("file", tmp_path)
    big = "x" * 900
    with tracing.trace_step("BIG", "sess1234", prompt=big, items=list(range(30))) as t:
        t.result(ok=True)

    pid = os.getpid()
    jsonl = tmp_path / f"trace-{pid}.jsonl"
    txt = tmp_path / f"trace-{pid}.txt"
    assert jsonl.exists() and txt.exists(), sorted(p.name for p in tmp_path.iterdir())

    # Promtail requires EVERY line to parse on its own.
    records = [json.loads(line)
            for line in jsonl.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [r["phase"] for r in records] == ["BEGIN", "END"]
    assert records[1]["status"] == "ok" and "duration_ms" in records[1]

    # json SUMMARISES: the 900-char prompt is clipped and the 30-item list capped...
    assert len(records[0]["prompt"]) < 400
    assert "(+" in records[0]["prompt"]
    assert len(records[0]["items"]) == 11        # 10 items + the "...(+20 more)" marker
    # ...while the txt keeps the whole thing, which is what it is for.
    assert big in txt.read_text(encoding="utf-8")


def test_log_sink_routes_through_structlog(sinks):
    """The "show in logs / no logs" switch: with `log` on, a step becomes an ordinary structured
    log event and so reaches Loki alongside every other line.

    NOT capsys, and NOT capfd — both were tried and both see NOTHING. configure_logging reads
    `sys.stdout` at call time (app/core/logging.py) and hands it to PrintLoggerFactory, and
    `cache_logger_on_first_use=True` freezes that binding. The real process configures logging at
    startup, BEFORE pytest installs either capture layer, so the cached logger keeps writing to
    the original stream and the fixtures never observe it. Re-pointing stdout and reconfiguring is
    the only way to capture what this sink actually renders — and it is the better assertion
    anyway: this exercises the real processor chain and the real JSONRenderer, so it proves the
    line Promtail would ingest is genuinely parseable, not merely that an event was dispatched.
    """
    sinks("log")
    buf = io.StringIO()
    real_stdout = sys.stdout
    sys.stdout = buf
    configure_logging()
    try:
        with tracing.trace_step("COVERAGE", "sess1234", units=[0, 41]) as t:
            t.result(cells=24)
    finally:
        # Restore BEFORE reconfiguring, or structlog stays bound to this dead buffer and every
        # later test in the process logs into it.
        sys.stdout = real_stdout
        configure_logging()
    record = json.loads(buf.getvalue().strip().splitlines()[-1])
    assert record["event"] == "trace.step"
    assert record["step"] == "COVERAGE" and record["phase"] == "END"
    assert record["session_id"] == "sess1234"
    assert "duration_ms" in record


def test_summarise_keeps_structure_so_loki_json_filters_still_work():
    """Truncation must not flatten the record — `| json | session_id=...` in Loki depends on the
    small identifying fields surviving intact while only bulk payloads are cut."""
    out = tracing._summarise({"catalogue_id": 62, "score": 90.7, "name": "y" * 500,
                            "nested": {"kept": True}})
    assert out["catalogue_id"] == 62 and out["score"] == 90.7
    assert out["nested"] == {"kept": True}
    assert out["name"].endswith("chars)")


def test_render_full_is_ascii_safe():
    """A Windows console defaults to a codepage that cannot encode most model-authored text; an
    unencodable character must not kill the traced call site."""
    rendered = tracing._render_full({"t": "Unauthorised setpoint — SCADA", "e": "\U0001F6E1"})
    assert rendered.isascii()


def test_concurrent_first_use_attaches_exactly_one_handler(sinks, tmp_path, monkeypatch) -> None:
    """open_rotating_writer was a check-then-act with no lock. trace_step("SCENARIO") now fires
    from five greenlets at once and dal.claim_stage/finish_stage from concurrent API threads, so
    a cold stem got N handlers: every line written N times, and N rotations fighting over one
    file. A slow handler constructor widens the window so the race is deterministic: 8 before
    the lock, 1 with it."""
    sinks("file", tmp_path)
    real = tracing.RotatingFileHandler

    class _Slow(real):
        def __init__(self, *a, **k):
            time.sleep(0.3)                    # every thread passes the empty check meanwhile
            super().__init__(*a, **k)

    monkeypatch.setattr(tracing, "RotatingFileHandler", _Slow)
    stem = f"race-{uuid.uuid4().hex}-{{pid}}.txt"
    gate = threading.Barrier(8)

    def go():
        gate.wait()
        tracing.open_rotating_writer(stem)

    threads = [threading.Thread(target=go) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(logging.getLogger(f"tsg.tracefile.{stem}").handlers) == 1
