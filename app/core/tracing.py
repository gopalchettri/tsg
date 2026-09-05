"""Step tracing — one facility, three independently switchable sinks.

`TSG_TRACE_SINKS` is a comma list of `console`, `log` and `file`; empty (the default) means
tracing is off and every call site costs one cached settings read and nothing else.

    with trace_step("HYBRID SEARCH", sid, query=q, corpus=len(corpus)) as t:
        results = hybrid_search.hybrid_match(q, corpus, query_vec=qv)
        t.result(matches=results)

WHY A CONTEXT MANAGER rather than the paired trace(..., "IN") / trace(..., "OUT") calls this
replaces: the pairing is then guaranteed — an early return or a raise cannot leave a dangling
BEGIN with no END — the duration comes free (which is what makes the JSON sink worth querying in
Grafana), an exception marks the step failed instead of silently unterminated, and each call site
stays one line, which is what keeps the already-large pipeline modules from growing.

SINKS
  console  stdout, full dump. What you watch a run in.
  log      through structlog, so traces join the normal JSON stream and reach Loki with
           everything else. This is the "show in logs / no logs" switch.
  file     trace-<pid>.jsonl (SUMMARISED — large payloads truncated, so Loki ingestion stays
           affordable) and trace-<pid>.txt (FULL — for reading by eye). The txt is deliberately
           NOT Loki-shippable: a block spans many lines and Promtail would file each one as its
           own entry without a multiline stage.

This module must not import app.core.logging — logging.py imports open_rotating_writer from
HERE for its own file tee, and the dependency has to run one way. structlog is used directly.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import os
import pprint
import sys
import threading
import time
from itertools import count
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

import structlog

from app.core.config import get_settings

#: Project root — app/core/tracing.py -> app/core -> app -> <root>. Relative trace_dir values
#: resolve against THIS, never the CWD: start.ps1 opens three windows from different working
#: directories and would otherwise scatter a logs/ tree under each one.
_ROOT = Path(__file__).resolve().parents[2]

#: Ordering only. A single process-wide counter, not per-session: the session id already
#: disambiguates whose step it is, and a per-session dict would grow without bound in a worker
#: that never restarts. Numbers stay strictly increasing, which is all ordering needs.
_COUNTER = count(1)

#: Exceptions that are NORMAL control flow, matched by name to avoid an app.core -> app.pipeline
#: import inversion. LLMSlotUnavailable is backpressure: celery_app retries it with
#: max_retries=None and cascade.py catches it deliberately, so logging it at ERROR would turn
#: routine load-shedding into an error storm in Loki.
_EXPECTED_EXC = frozenset({"LLMSlotUnavailable"})

#: Caps for the SUMMARISED (json) rendering. The txt sink is never truncated.
_MAX_STR = 300
_MAX_ITEMS = 10

_RULE = "-" * 76


def active_sinks() -> frozenset[str]:
    """The enabled sink names. Empty frozenset = tracing off."""
    raw = get_settings().trace_sinks or ""
    return frozenset(part.strip().lower() for part in raw.split(",") if part.strip())


def trace_dir() -> Path:
    """The absolute directory the file sinks write into, created on demand."""
    configured = Path(get_settings().trace_dir)
    path = configured if configured.is_absolute() else _ROOT / configured
    path.mkdir(parents=True, exist_ok=True)
    return path


#: Guards handler CREATION in open_rotating_writer. Emitting through an existing handler is
#: already safe (RotatingFileHandler holds its own lock); attaching one is the check-then-act
#: that was not. gevent's cooperative lock in the worker; a real one in the FastAPI process,
#: whose sync routes run on OS threads.
_WRITER_LOCK = threading.Lock()


def open_rotating_writer(stem: str) -> logging.Logger:
    """A dedicated, non-propagating logger whose one handler rotates by size. `stem` is a
    filename template containing `{pid}`, e.g. "trace-{pid}.txt".

    THE PID IN THE FILENAME IS LOAD-BEARING, not cosmetic. gunicorn -w 4 plus the Celery worker
    and beat all import configure_logging, so several processes open the same path. Sharing one
    file breaks rotation silently on both platforms: on Linux the process that rolls unlinks the
    inode the others still hold, and their writes vanish into a deleted file; on Windows
    os.replace raises PermissionError against a file another process has open, logging's
    handleError swallows it, and the file simply grows past the cap forever — defeating the whole
    point of a size limit. One file per pid removes the contention; Promtail globs them.
    Budget disk as processes x max_bytes x backups.

    Reuses stdlib RotatingFileHandler rather than hand-rolling rotation: it already holds the
    per-instance lock that makes gevent greenlets and native threads safe.
    """
    logger = logging.getLogger(f"tsg.tracefile.{stem}")
    if logger.handlers:            # fast path, no lock: configure_logging is re-callable
        return logger
    # Double-checked: trace_step first fires from five greenlets at once (the scenario fan-out)
    # and from concurrent API threads, all on a cold stem. Without the lock every one passes the
    # empty check above and each attaches its own handler - every line written N times, and N
    # rotations fighting over one file (PermissionError on Windows, swallowed by
    # logging.handleError, so the file just grows past its cap). The section does no I/O:
    # delay=True defers the open to the first emit.
    with _WRITER_LOCK:
        if logger.handlers:        # the caller that lost the race to the first check
            return logger
        s = get_settings()
        handler = RotatingFileHandler(
            trace_dir() / stem.format(pid=os.getpid()),
            maxBytes=s.trace_max_bytes, backupCount=s.trace_backups, encoding="utf-8", delay=True)
        handler.setFormatter(logging.Formatter("%(message)s"))  # the line is already rendered
        logger.addHandler(handler)
        logger.propagate = False   # never re-enter the root handler; this is a raw file sink
        logger.setLevel(logging.INFO)
    return logger


def _render_full(value: Any) -> str:
    """Untruncated, human-readable. A dataclass renders by field name rather than as a bare
    repr; anything json cannot take falls back to pprint. Escaped to plain ASCII because a
    Windows console defaults to a codepage that cannot encode most model-authored text, and an
    unencodable character would otherwise kill the traced call site rather than the trace."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    try:
        text = json.dumps(value, indent=2, default=str)
    except TypeError:
        text = pprint.pformat(value, width=100)
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _summarise(value: Any, _depth: int = 0) -> Any:
    """Loki-affordable form: long strings clipped, long sequences cut to a head plus a count.
    Structure is preserved so `| json` filters still work on the fields that matter (ids,
    scores, counts); it is the bulk payloads (prompts, full candidate lists) that go."""
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        value = dataclasses.asdict(value)
    if isinstance(value, str):
        return value if len(value) <= _MAX_STR else f"{value[:_MAX_STR]}...(+{len(value) - _MAX_STR} chars)"
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        if _depth >= 4:
            return f"<dict of {len(value)}>"
        return {str(k): _summarise(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = list(value)
        if _depth >= 4:
            return f"<{type(value).__name__} of {len(items)}>"
        head = [_summarise(v, _depth + 1) for v in items[:_MAX_ITEMS]]
        extra = len(items) - _MAX_ITEMS
        return [*head, f"...(+{extra} more)"] if extra > 0 else head
    return _summarise(str(value), _depth)


class _NullStep:
    """What trace_step yields when every sink is off — result() must stay callable."""
    __slots__ = ()

    def result(self, **_fields: Any) -> None:
        return None


_NULL_STEP = _NullStep()


def _contextvar_sid() -> str:
    """The session id structlog already has bound, for trace sites that carry none themselves.

    celery_app's `task_prerun` binds `session_id` into structlog's contextvars for the whole
    task, so it is already available to any code the task reaches. Reading it HERE, in the shared
    helper, fixes every present and future trace site at once — and covers the `file` and
    `console` sinks, which never see contextvars at all (only the `log` sink does).

    Never raises: a trace is diagnostics, and diagnostics must not be able to fail the work they
    are observing.
    """
    try:
        return str(structlog.contextvars.get_contextvars().get("session_id") or "")
    except Exception:  # noqa: BLE001 - see docstring: a trace must never break its caller
        return ""


class trace_step:
    """Context manager emitting a BEGIN/END pair for one pipeline step. See module docstring."""

    __slots__ = ("_in", "_loc", "_n", "_out", "_sid", "_sinks", "_step", "_t0")

    def __init__(self, step: str, sid: str | None, **fields: Any) -> None:
        self._sinks = active_sinks()
        self._step = step
        self._in = fields
        self._out: dict[str, Any] = {}
        if not self._sinks:
            self._sid = ""
            return                                   # cheapest possible disabled path
        # `sid` is None at sites with no session in scope. "LLM CALL" (llm.py) is the one that
        # mattered: every LLM duration was recorded with an empty session_id and so could not be
        # joined to the scenario that made it. Falling back to the contextvar fixes that without
        # threading a sid parameter through llm.chat and all of its callers. Resolved AFTER the
        # disabled-path return above, so the no-op case stays as cheap as it was.
        self._sid = (sid or _contextvar_sid())[:8]
        frame = sys._getframe(1)                     # the CALLER, since __init__ runs there
        self._loc = f"{os.path.basename(frame.f_code.co_filename)}:{frame.f_lineno}"
        self._n = next(_COUNTER)

    def __enter__(self) -> Any:
        if not self._sinks:
            return _NULL_STEP
        self._t0 = time.monotonic()
        self._emit("BEGIN", self._in, status=None, duration_ms=None)
        return self

    def result(self, **fields: Any) -> None:
        """Record what the step produced. Merged into the END record."""
        self._out.update(fields)

    def __exit__(self, exc_type, exc, _tb) -> bool:
        if not self._sinks:
            return False
        ms = round((time.monotonic() - self._t0) * 1000, 1)
        if exc_type is None:
            self._emit("END", self._out, status="ok", duration_ms=ms)
        else:
            # An EXPECTED exception is not a failure of this step and must not be logged at
            # ERROR — see _EXPECTED_EXC for why that would flood Loki under normal load.
            expected = exc_type.__name__ in _EXPECTED_EXC
            self._emit("END", {**self._out, "error": f"{exc_type.__name__}: {exc}"},
                    status="expected" if expected else "failed", duration_ms=ms,
                    level="warning" if expected else "error")
        return False                                  # never swallow

    def _emit(self, phase: str, fields: dict[str, Any], *, status: str | None,
            duration_ms: float | None, level: str = "info") -> None:
        if "console" in self._sinks:
            sys.stdout.write(self._block(phase, fields, status, duration_ms))
        if "file" in self._sinks:
            open_rotating_writer("trace-{pid}.txt").info(
                self._block(phase, fields, status, duration_ms).rstrip("\n"))
            open_rotating_writer("trace-{pid}.jsonl").info(
                json.dumps(self._record(phase, fields, status, duration_ms), default=str))
        if "log" in self._sinks:
            getattr(structlog.get_logger().bind(logger="app.core.tracing"), level)(
                "trace.step", **self._record(phase, fields, status, duration_ms))

    def _record(self, phase: str, fields: dict[str, Any], status: str | None,
                duration_ms: float | None) -> dict[str, Any]:
        rec: dict[str, Any] = {"step": self._step, "phase": phase, "seq": self._n,
                            "session_id": self._sid, "loc": self._loc}
        if status is not None:
            rec["status"] = status
        if duration_ms is not None:
            rec["duration_ms"] = duration_ms
        rec.update({k: _summarise(v) for k, v in fields.items()})
        return rec

    def _block(self, phase: str, fields: dict[str, Any], status: str | None,
            duration_ms: float | None) -> str:
        """The human form. A rule above BEGIN and below END, a blank line after, and the step
        number plus elapsed time on the header — so where one step stops and the next starts is
        readable at a glance rather than inferred from indentation."""
        lines: list[str] = []
        if phase == "BEGIN":
            lines.append(f"{_RULE[:52]} [{self._sid}] step {self._n:03d}")
            lines.append(f"> {self._step}".ljust(56) + f"({self._loc})")
        else:
            tail = f"  {status}" + (f"  {duration_ms} ms" if duration_ms is not None else "")
            lines.append(f"< {self._step}{tail}")
        for name, value in fields.items():
            rendered = _render_full(value).splitlines() or [""]
            # A scalar goes inline ("corpus : 4"); only a genuinely multi-line value earns the
            # indented block. Giving every int three lines buried the structure it exists to show.
            if len(rendered) == 1:
                lines.append(f"    {name:<14}: {rendered[0]}")
            else:
                lines.append(f"    {name}:")
                lines.extend(f"      {ln}" for ln in rendered)
        if phase != "BEGIN":
            lines.append(_RULE)
            lines.append("")
        return "\n".join(lines) + "\n"
