#!/usr/bin/env python
"""Standalone smoke test for the threat-library-import and threat-intel-refresh SSE routes
(GET .../imports/events/{job_id}, GET .../feeds/events/{job_id}).

Hits the REAL running local stack over HTTP — needs the API (uvicorn) and a Celery worker up,
same as scripts/test_otx_feed.py hits the real OTX API. Queues one dry-run import and one
single-feed refresh, streams each job's SSE endpoint, and asserts a matching *_job_update frame
arrives and the stream closes once the job reaches a terminal state (SUCCESS/FAILURE).

    python scripts/test_admin_job_sse.py --user-id you --api-key <api_client key>

X-Admin-Key comes from Settings.admin_api_key (local .env) — never hardcode it here. X-API-Key
must be a real api_client key from the local DB (docs/TSG_API_AUTHENTICATION_GUIDE.md); pass it
via --api-key or the TSG_TEST_API_KEY env var.

Exit codes: 0 = both streams reached a terminal state · 1 = HTTP/stream/assertion failure ·
2 = missing credentials.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

import requests

from app.core.config import get_settings
from app.intel.fetchers import enabled_feed_names
from app.pipeline.threat_library_import import URLS


def _read_sse(resp: requests.Response, expect_type: str, timeout_s: float) -> dict:
    """Reads one text/event-stream response until a terminal (SUCCESS/FAILURE) `expect_type`
    frame arrives; returns its parsed `data`. Raises AssertionError/TimeoutError otherwise."""
    deadline = time.monotonic() + timeout_s
    data_lines: list[str] = []
    seen_expected = False
    for raw_line in resp.iter_lines(decode_unicode=True):
        if time.monotonic() > deadline:
            raise TimeoutError(f"no terminal {expect_type} frame within {timeout_s}s")
        if raw_line == "":  # blank line = end of one SSE event
            if data_lines:
                payload = json.loads("\n".join(data_lines))
                data_lines = []
                if payload.get("type") == expect_type:
                    seen_expected = True
                    if payload.get("state") in ("SUCCESS", "FAILURE"):
                        return payload
            continue
        if raw_line.startswith("data:"):
            data_lines.append(raw_line[len("data:"):].strip())
    raise AssertionError(f"stream closed without a terminal {expect_type} frame "
                        f"(saw one at all: {seen_expected})")


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke-test the import/intel job SSE routes.")
    ap.add_argument("--base-url", default="http://127.0.0.1:8000")
    ap.add_argument("--user-id", required=True, help="X-User-Id — lands in Threat_Library_Import_Run.StartedBy")
    ap.add_argument("--api-key", default=os.environ.get("TSG_TEST_API_KEY", ""),
                    help="X-API-Key (real api_client key) — or set TSG_TEST_API_KEY")
    ap.add_argument("--source", default=None, help="threat-library source (default: first of URLS)")
    ap.add_argument("--feed", default=None, help="threat-intel feed (default: first enabled)")
    ap.add_argument("--timeout", type=float, default=120.0, help="per-stream seconds to wait for a terminal frame")
    args = ap.parse_args()

    admin_key = get_settings().admin_api_key
    if not admin_key:
        print("FAIL: Settings.admin_api_key is not configured (set it in .env).")
        return 2
    if not args.api_key:
        print("FAIL: no X-API-Key given. Pass --api-key or set TSG_TEST_API_KEY to a real "
            "api_client key from the local DB (docs/TSG_API_AUTHENTICATION_GUIDE.md).")
        return 2

    headers = {"X-Admin-Key": admin_key, "X-API-Key": args.api_key, "X-User-Id": args.user_id}
    source = args.source or sorted(URLS)[0]
    feed = args.feed or enabled_feed_names()[0]

    try:
        print(f"POST .../threat-library/sources/{source}/import (dry_run)")
        r = requests.post(f"{args.base_url}/v1/tsg/threat-library/sources/{source}/import",
                        json={"dry_run": True}, headers=headers, timeout=30)
        r.raise_for_status()
        import_job_id = r.json()["job_id"]
        print(f"  job_id={import_job_id} — streaming .../imports/events/{import_job_id}")
        with requests.get(f"{args.base_url}/v1/tsg/threat-library/imports/events/{import_job_id}",
                        headers=headers, stream=True, timeout=args.timeout) as resp:
            resp.raise_for_status()
            terminal = _read_sse(resp, "import_job_update", args.timeout)
        print(f"OK  import stream terminal state={terminal['state']}")

        print(f"POST .../threat-intel/feeds/{feed}/refresh")
        r = requests.post(f"{args.base_url}/v1/tsg/threat-intel/feeds/{feed}/refresh",
                        headers=headers, timeout=30)
        r.raise_for_status()
        intel_job_id = r.json()["jobs"][feed]
        print(f"  job_id={intel_job_id} — streaming .../feeds/events/{intel_job_id}")
        with requests.get(f"{args.base_url}/v1/tsg/threat-intel/feeds/events/{intel_job_id}",
                        headers=headers, stream=True, timeout=args.timeout) as resp:
            resp.raise_for_status()
            terminal = _read_sse(resp, "intel_job_update", args.timeout)
        print(f"OK  intel stream terminal state={terminal['state']}")
    except (requests.RequestException, AssertionError, TimeoutError, KeyError) as e:
        print(f"FAIL: {type(e).__name__}: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
