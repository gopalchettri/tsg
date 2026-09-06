"""AlienVault OTX pulse retrieval — resumable, deadline-bounded pagination.

Its own module for the same reason app/intel/taxii_client.py is one: a source whose
retrieval is more than a single GET does not belong inline in fetchers.py.

Why it cannot be done in one run. `/pulses/subscribed` is offset-paginated at a hard 50
items per page (a larger `limit` is silently ignored) and slows down with depth —
measured 1.8s at page 1 against 35-46s past page 40 — so walking a full ~8.9k-pulse
subscription takes about an hour, against the 600s `soft_time_limit` on
intel_refresh_feed_task. So each run instead walks for `intel_otx_sync_seconds`, records
the page it reached on the feed's status doc, and the next run resumes from there;
reaching the end wraps the cursor back to 1. A full cycle at the daily cadence is ~9
days — comfortably inside the 30-day TTL that would otherwise purge anything the walk
failed to re-stamp.
"""
from __future__ import annotations

import json
import time
from collections.abc import Iterator
from typing import Any

from app.core.logging import get_logger
from app.intel.fetchers import _doc, _get, parse_dt, scope_keys

log = get_logger(__name__)

_FEED = "otx"
_STATUS_COLLECTION = "intel_feed_status"

# Attempts per page before it is skipped. Deliberately small: a failing page can cost up to
# the 120s socket timeout per try out of a budget the whole walk shares, and a skipped page
# comes back on the next cycle anyway.
_PAGE_ATTEMPTS = 2
# Pause before the second attempt. Measured 2026-09-06: a 502/504 asked again 40-150ms
# later is the same 502/504, so an instant retry never recovers anything.
_RETRY_DELAY_SECONDS = 5


def _names(items: Any, keys: tuple[str, ...] = ("display_name", "name", "id")) -> list[str]:
    """OTX list fields arrive as plain strings or as dicts depending on the endpoint version —
    normalize both to stripped strings, taking the first of `keys` a dict carries."""
    out: list[str] = []
    for x in items or []:
        if isinstance(x, dict):
            x = next((x[k] for k in keys if x.get(k)), "")
        x = str(x).strip()
        if x:
            out.append(x)
    return out


def pulse_doc(p: dict) -> dict:
    """One OTX pulse -> the shared intel doc shape.

    Keeps the structured fields a pulse already carries: `industries` and `targeted_countries`
    become `scope_tags` (so an Energy-sector asset matches an Energy-tagged campaign by
    structure, never by a word in the title), malware families and ATT&CK ids join the tags,
    and the attributed adversary gets an equality key for the reserved actor slot."""
    adv = (p.get("adversary") or "").strip()
    # Attribution reaches the prompt ONLY through the title (prompts._intel_block emits
    # id/title/url, title capped at 140 chars), so prepend it where truncation cannot reach.
    title = f"[{adv}] {p.get('name', '')}" if adv else p.get("name", "")
    industries = _names(p.get("industries"))
    countries = _names(p.get("targeted_countries"))
    malware = _names(p.get("malware_families"))
    attack_ids = _names(p.get("attack_ids"), keys=("id", "name"))   # the technique id, not its name
    tags = (([adv.lower()] if adv else [])
            + [t for t in (p.get("tags") or []) if t]
            + [m.lower() for m in malware]
            + [a.upper() for a in attack_ids])
    doc = _doc(_FEED, "pulse", p.get("id", ""), title,
            description=p.get("description", ""),
            url=f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
            tags=tags, raw=None,
            scope_tags=scope_keys(sectors=industries, countries=countries))
    if adv:
        # its own field for the /items API: community pulse names may legitimately start
        # with [brackets], so attribution is never re-parsed back out of the title
        doc["adversary"] = adv[:200]
        doc["adversary_key"] = adv.lower()[:200]       # fetchers.query_actor_pulses equality key
    if industries:
        doc["industries"] = industries[:20]
    if countries:
        doc["targeted_countries"] = countries[:20]
    if malware:
        doc["malware_families"] = malware[:20]
    if attack_ids:
        doc["attack_ids"] = attack_ids[:30]
    published = parse_dt(p.get("modified") or p.get("created"))
    if published:
        # the pulse's OWN date — query_intel ranks on it, so "top 5 matches" means the most
        # recently updated threats rather than whichever page happened to sync last
        doc["published_at"] = published
    return doc


def fetch_page(s, page: int) -> tuple[list[dict], bool]:
    """One page of subscribed pulses -> (docs, is_last_page).

    Raises once every attempt has failed, leaving skip-or-abort to the caller."""
    url = f"{s.intel_otx_url}?limit={s.intel_otx_page_size}&page={page}"
    for attempt in range(1, _PAGE_ATTEMPTS + 1):
        try:
            data = json.loads(_get(url, headers={"X-OTX-API-KEY": s.intel_otx_api_key}))
            results = data.get("results", [])
            # a short page is the tail; OTX also serves an empty page one past the end
            return [pulse_doc(p) for p in results], len(results) < s.intel_otx_page_size
        except Exception:
            if attempt == _PAGE_ATTEMPTS:
                raise
            log.warning("intel.otx_page_retry", page=page, attempt=attempt, exc_info=True)
            time.sleep(_RETRY_DELAY_SECONDS)
    raise RuntimeError(f"otx page {page}: attempts exhausted")  # unreachable; satisfies typing


def _read_cursor(col) -> int:
    """Page this feed resumes from — 1 when unknown, or when there is no store to read."""
    if col is None:
        return 1
    try:
        doc = col.database[_STATUS_COLLECTION].find_one({"feed": _FEED}) or {}
        return max(1, int(doc.get("sync_page") or 1))
    except Exception:
        log.warning("intel.otx_cursor_read_failed", exc_info=True)
        return 1


def _save_cursor(col, page: int) -> None:
    if col is None:
        return
    try:
        col.database[_STATUS_COLLECTION].update_one(
            {"feed": _FEED}, {"$set": {"sync_page": page}, "$setOnInsert": {"feed": _FEED}},
            upsert=True)
    except Exception:
        log.warning("intel.otx_cursor_save_failed", exc_info=True)


def _page_or_skip(s, page: int) -> tuple[list[dict], bool]:
    """fetch_page, except a page that fails every attempt is SKIPPED rather than aborting
    the walk — OTX intermittently 502/504s its deeper, slower pages, and one bad page
    must not cost the entire cycle."""
    try:
        return fetch_page(s, page)
    except Exception:
        log.warning("intel.otx_page_skipped", page=page, exc_info=True)
        return [], False


def walk(s, col, deadline: float) -> Iterator[list[dict]]:
    """Yield page-sized batches of pulse docs until `deadline` (a time.monotonic value),
    the last page, or intel_otx_max_pages.

    The first `intel_otx_fresh_pages` are re-read on EVERY run before the cursor resumes:
    the rolling cursor reaches page 1 only once per cycle, so without this a pulse
    published today would wait a whole cycle to be cached.

    The resume point is written in a `finally`, so a caller that stops consuming early
    still leaves the cycle where it actually got to."""
    head = max(0, s.intel_otx_fresh_pages)
    page = _read_cursor(col)
    try:
        for p in range(1, head + 1):
            if time.monotonic() >= deadline:
                return
            batch, is_last = _page_or_skip(s, p)
            if batch:
                yield batch
            if is_last:          # subscription smaller than the head sweep
                page = 1
                return
        while page <= s.intel_otx_max_pages:
            if time.monotonic() >= deadline:
                return
            if page <= head:     # already covered by the head sweep above
                page += 1
                continue
            batch, is_last = _page_or_skip(s, page)
            if batch:
                yield batch
            if is_last:
                page = 1         # cycle complete — the next run starts over
                return
            page += 1
        page = 1                 # hit the page cap: treat the cycle as complete
    finally:
        _save_cursor(col, page)
