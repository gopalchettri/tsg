#!/usr/bin/env python
"""One-time backfill of the WHOLE AlienVault OTX subscription into Mongo `threat_intel`.

Run once per environment, by a developer:

    python scripts/backfill_otx.py

Why a script rather than a bigger Celery task: the subscription is ~8.9k pulses over ~178
offset-paginated pages that get slower with depth (1.8s at page 1, 35-46s past page 40),
so one pass takes roughly an hour — far past intel_refresh_feed_task's 600s soft_time_limit.
This just calls the ORDINARY refresh repeatedly. Each call walks pages for
`intel_otx_sync_seconds`, persists every page as it arrives, and records where it got to;
the next call resumes there. So this exercises exactly the code the scheduler runs, and can
be interrupted and re-run at any time without losing or duplicating work.

Afterwards the feed maintains itself: the daily refresh keeps walking the cycle (~9 days
end to end, inside the 30-day TTL) while always re-reading the head pages for new pulses.
Trigger one on demand with POST /v1/tsg/threat-intel/feeds/otx/refresh.

Exit codes: 0 = cycle completed · 1 = refresh failed or no store · 2 = no API key.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.config import get_settings  # noqa: E402
from app.core.logging import configure_logging  # noqa: E402
from app.intel import fetchers  # noqa: E402
from app.intel.otx import _read_cursor  # noqa: E402


def _stamp_legacy_published_at(col) -> int:
    """Docs cached before `published_at` existed have no ranking key and would sort below
    everything. Give them one (their sync time) — once, here, rather than on every read."""
    res = col.update_many({"published_at": {"$exists": False}},
                        [{"$set": {"published_at": "$fetched_at"}}])
    return res.modified_count


def main() -> int:
    configure_logging()
    s = get_settings()
    if not s.intel_otx_api_key:
        print("FAIL: no OTX API key configured. Add OTX_API_KEY=<key> to tsg/.env.")
        return 2

    col = fetchers._store_if_healthy()
    if col is None:
        print("FAIL: MongoDB unavailable — the backfill has nowhere to write.")
        return 1

    print(f"Backfilling OTX into {s.mongo_db}.threat_intel — "
          f"{s.intel_otx_sync_seconds}s per pass, resuming from page {_read_cursor(col)}.")
    started, passes = time.monotonic(), 0
    while True:
        passes += 1
        before_page = _read_cursor(col)
        t0 = time.monotonic()
        try:
            stored = fetchers.refresh_one("otx")
        except Exception as exc:  # noqa: BLE001 — report and stop; re-running resumes safely
            print(f"FAIL on pass {passes}: {type(exc).__name__}: {exc}")
            print(f"      progress is saved — re-run to resume from page {_read_cursor(col)}.")
            return 1
        after_page = _read_cursor(col)
        total = col.count_documents({"source": "otx"})
        print(f"  pass {passes:>2}: pages {before_page}->{after_page}  "
              f"stored {stored:>4}  total {total:>5}  ({time.monotonic() - t0:.0f}s)")
        if after_page == 1:          # the walk wrapped: a full cycle is done
            break

    stamped = _stamp_legacy_published_at(col)
    total = col.count_documents({"source": "otx"})
    print(f"\nDone in {(time.monotonic() - started) / 60:.1f} min over {passes} passes.")
    print(f"  otx documents: {total}")
    if stamped:
        print(f"  back-stamped published_at on {stamped} pre-existing doc(s)")
    print("  browse: GET /v1/tsg/threat-intel/items?source=otx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
