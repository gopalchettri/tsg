#!/usr/bin/env python
"""Standalone smoke test for the AlienVault OTX live intel feed.

Runs the REAL production fetch path (app.intel.fetchers.fetch_otx) against the live
OTX API — no Mongo, Celery, or FastAPI needed. Requires OTX_API_KEY in tsg/.env
(or TSG_INTEL_OTX_API_KEY in the environment).

    python scripts/test_otx_feed.py                      # fetch, list pulses, save scripts/otx_response.json
    python scripts/test_otx_feed.py --out C:/tmp/o.json  # save the JSON elsewhere

The saved file holds BOTH the full raw OTX response (every field, incl. indicators)
and the normalized docs TSG actually stores, so the output can be inspected offline.

Exit codes: 0 = fetched and parsed OK · 1 = HTTP/auth/parse failure · 2 = no key configured.
"""
import argparse
import json
import os
import sys
import urllib.error
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # make `app` importable

from app.core.config import get_settings  # noqa: E402
from app.intel import fetchers  # noqa: E402

DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "otx_response.json")


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke-test the OTX intel feed with the real fetch path.")
    ap.add_argument("--out", default=DEFAULT_OUT, help="where to save the response JSON (default: scripts/otx_response.json)")
    args = ap.parse_args()

    s = get_settings()
    if not s.intel_otx_api_key:
        print("FAIL: no OTX API key configured. Add OTX_API_KEY=<key> to tsg/.env "
              "(free key: https://otx.alienvault.com -> Settings -> OTX Key).")
        return 2

    print(f"GET {s.intel_otx_url}")
    try:
        docs = fetchers.fetch_otx(s)  # the production parse path
        raw = json.loads(fetchers._get(s.intel_otx_url, headers={"X-OTX-API-KEY": s.intel_otx_api_key}))
    except urllib.error.HTTPError as e:
        hint = " — key rejected, check OTX_API_KEY" if e.code in (401, 403) else ""
        print(f"FAIL: OTX returned HTTP {e.code} {e.reason}{hint}")
        return 1
    except Exception as e:  # noqa: BLE001 — smoke script: report anything (DNS, timeout, bad JSON) and exit 1
        print(f"FAIL: {type(e).__name__}: {e}")
        return 1

    print(f"OK  fetched and parsed {len(docs)} pulses (page 1 only — fetch_otx does not paginate)")
    for d in docs[:10]:
        print(f"    {d['external_id']}  tags={len(d['tags']):2d}  {d['title'][:70]}")
    if not docs:
        print("NOTE: 0 pulses is still a pass — subscribe to pulses/users on otx.alienvault.com "
              "for /pulses/subscribed to return results.")

    out = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "url": s.intel_otx_url,
        "pulse_count": len(docs),
        "raw_response": raw,          # everything OTX sent (indicators, references, adversary, ...)
        "normalized_docs": docs,      # the trimmed records TSG stores in Mongo threat_intel
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print(f"Saved full response -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
