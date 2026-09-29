"""The background writer behind every diagnostic row. One queue, one thread, batched inserts.

WHY THIS EXISTS AND WHY IT IS NOT A DIRECT INSERT. `record()` used to insert on the caller's
thread. That is survivable for exceptions, which are rare by definition, and NOT survivable for
ordinary log lines: one pipeline run emits hundreds, so a synchronous insert would put a database
round trip on every log call, inside whatever business transaction happens to be open, and make
the database a hard dependency of logging itself.

THE FOUR PROPERTIES THIS FILE EXISTS TO GUARANTEE. Each is a failure mode that has taken real
systems down, not a hypothetical:

  1. OFF THE HOT PATH. Callers append to an in-memory queue and return. No IO on the caller's
     thread, ever.
  2. BOUNDED AND LOSSY BY DESIGN. A full queue DROPS and counts. The alternative — blocking, or an
     unbounded queue — converts a slow database into a stalled pipeline or an out-of-memory kill.
     Losing diagnostics is a bad day; losing the worker is an outage. Dropping is the correct
     trade, and the dropped count is reported so the loss is never silent.
  3. ITS OWN CONNECTION. A separate engine with a SMALL pool, never `get_engine()`. Sharing the
     application pool would let a burst of logging starve the pipeline of the connections it needs
     to do actual work — the writer would compete with the thing it exists to observe.
  4. NEVER RAISES. Any failure falls back to stdout. The database being down is precisely when
     diagnostics matter most and precisely when writing them fails.

BATCHING IS THE IO OPTIMISATION. Rows are drained in groups and inserted with one executemany per
table per flush, so 500 log lines cost one round trip rather than 500. The flush fires on whichever
comes first — a full batch, or an idle interval — so a busy system batches hard and a quiet one
still persists promptly instead of holding rows until the batch fills.

ORDERING NOTE: rows are inserted in arrival order within a flush, but CreatedAt is stamped at
`submit()` time, not at insert time. That is deliberate — the timestamp an operator reads must be
when the event HAPPENED, not when the writer got round to it.
"""
from __future__ import annotations

import atexit
import queue
import threading
from typing import Any

from app.core.logging import get_logger

log = get_logger(__name__)

#: Rows per bulk insert. Large enough that a busy system amortises the round trip, small enough
#: that one statement stays well inside any sane packet/parameter limit.
_BATCH_SIZE = 200
#: Seconds the drain waits for more rows before flushing what it has. Bounds how long a row can
#: sit unwritten on a quiet system.
_FLUSH_INTERVAL = 1.0
#: Seconds to wait for the queue to drain at shutdown. Bounded: a hung database must not stop the
#: process from exiting.
_SHUTDOWN_TIMEOUT = 5.0


class _Writer:
    """Owns the queue, the thread and the engine. One instance per process (`WRITER` below)."""

    def __init__(self) -> None:
        self._queue: queue.Queue[tuple[str, dict[str, Any]] | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._engine: Any = None
        self._engine_dsn: str | None = None
        self._dropped = 0

    # -- caller side ---------------------------------------------------------------------------
    def submit(self, table: str, row: dict[str, Any], maxsize: int) -> None:
        """Queue one row. Returns immediately; never raises; drops when full."""
        if self._queue.qsize() >= maxsize:
            # DROP THE NEW ROW, not the oldest. Dropping the oldest would mean re-queuing under
            # contention, and during an incident the EARLIEST rows are the ones that explain it —
            # the later ones are usually the same failure repeating.
            self._dropped += 1
            if self._dropped in (1, 10, 100) or self._dropped % 1000 == 0:
                # Logged on a curve, not every time: a saturated queue must not become a second
                # flood of its own, and the FIRST drop is the one worth noticing.
                log.warning("diagnostic.queue_full", dropped=self._dropped, maxsize=maxsize,
                            note="diagnostics are being discarded; the database or the writer "
                                 "cannot keep up. Application behaviour is unaffected.")
            return
        self._ensure_thread()
        self._queue.put((table, row))

    def _ensure_thread(self) -> None:
        """Start the drain on first use. Lazy, so importing this module costs nothing and a
        process that never records a diagnostic never grows a thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._thread = threading.Thread(target=self._drain, name="tsg-diagnostics",
                                            daemon=True)
            self._thread.start()

    # -- writer side ---------------------------------------------------------------------------
    def _drain(self) -> None:
        """Pull rows, group them by table, and flush on a full batch or an idle interval."""
        pending: dict[str, list[dict[str, Any]]] = {}
        count = 0
        while True:
            try:
                item = self._queue.get(timeout=_FLUSH_INTERVAL)
            except queue.Empty:
                if pending:
                    self._flush(pending)
                    pending, count = {}, 0
                continue
            if item is None:                      # shutdown sentinel
                if pending:
                    self._flush(pending)
                return
            table, row = item
            pending.setdefault(table, []).append(row)
            count += 1
            if count >= _BATCH_SIZE:
                self._flush(pending)
                pending, count = {}, 0

    def _flush(self, pending: dict[str, list[dict[str, Any]]]) -> None:
        """One executemany per table. Never raises — see the module docstring."""
        try:
            from app.db import models as m

            tables = {"Diagnostic_Event": m.Diagnostic_Event, "Application_Log": m.Application_Log}
            engine = self._get_engine()
            with engine.begin() as conn:
                for name, rows in pending.items():
                    model = tables.get(name)
                    if model is not None and rows:
                        conn.execute(model.__table__.insert(), rows)
        except Exception as exc:  # noqa: BLE001 — stdout is the fallback; see the docstring
            total = sum(len(r) for r in pending.values())
            log.warning("diagnostic.flush_failed", rows_lost=total,
                        error=f"{type(exc).__name__}: {exc}"[:300])
            # The engine may be poisoned (a dead connection, a rotated credential). Drop it so the
            # next flush builds a fresh one rather than retrying the same broken handle forever.
            self._dispose()

    def _get_engine(self) -> Any:
        """A SMALL, SEPARATE pool. Never get_engine(): diagnostics must not compete for the
        connections the pipeline needs, and must not inherit its statement timeout either — a bulk
        insert of 200 rows is a different shape of statement from a pipeline query."""
        from app.core.config import get_settings

        dsn = get_settings().db_dsn
        # KEYED ON THE DSN, not merely cached. A cached engine outlives a configuration change, so
        # after the DSN moves the writer keeps writing to the OLD database — silently, because
        # every write here is best-effort. It surfaced as diagnostics landing in a real SQL Server
        # during a test run that had pointed everything else at a throwaway file. In production the
        # same shape appears on a credential rotation or a failover.
        if self._engine is not None and self._engine_dsn != dsn:
            self._dispose()
        if self._engine is None:
            from sqlalchemy import create_engine

            self._engine = create_engine(
                dsn, pool_size=1, max_overflow=1, pool_pre_ping=True, pool_recycle=1800,
                future=True)
            self._engine_dsn = dsn
        return self._engine

    def _dispose(self) -> None:
        engine, self._engine, self._engine_dsn = self._engine, None, None
        try:
            if engine is not None:
                engine.dispose()
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass

    # -- shutdown ------------------------------------------------------------------------------
    def close(self) -> None:
        """Flush what is queued, within a bounded wait.

        Without this the last rows before a worker stops are lost — and those are the ones written
        while whatever killed it was happening, which makes them the most valuable rows in the
        table. Bounded, because a hung database must never stop the process from exiting."""
        thread = self._thread
        if thread is None or not thread.is_alive():
            self._dispose()
            return
        try:
            self._queue.put_nowait(None)
            thread.join(timeout=_SHUTDOWN_TIMEOUT)
        except Exception:  # noqa: BLE001 — shutdown is best-effort like everything else here
            pass
        finally:
            self._thread = None
            self._dispose()

    def flush_now(self) -> None:
        """Block until the queue is drained. FOR TESTS ONLY — production never waits on IO."""
        self.close()

    @property
    def dropped(self) -> int:
        """Rows discarded because the queue was full. Surfaced by the admin config endpoint, so
        "am I losing diagnostics?" is answerable without reading logs."""
        return self._dropped


#: One writer per process. Module-level so the queue and thread are shared by every caller.
WRITER = _Writer()
atexit.register(WRITER.close)
