"""Live threat-intel fetchers → Mongo `threat_intel` cache.

One small fetcher per open feed, all normalizing to the same doc shape:
    {source, kind, external_id, title, description, url, tags[], raw, fetched_at}

Refresh semantics: every run UPSERTS on (source, external_id) and stamps
`fetched_at`, so items still present in a feed never expire; the TTL index only
purges items a feed has dropped (or a whole decommissioned feed). Each fetcher is
fail-soft inside refresh_all — one dead feed never blocks the rest.

The store accessor mirrors embeddings._vector_store (same settings, same breaker
idea) but is its own handle: that one is @lru_cache'd onto the `embeddings`
collection and can't serve a second collection.

Scheduling: `tsg.intel_refresh` (celery_app.py beat, gated on TSG_INTEL_ENABLED).
Manual:     python -m app.intel.fetchers --once
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

_BREAKER_COOLDOWN_S = 30.0
_breaker_open_until = 0.0

# Only these kinds are ever injected into prompts (Phase C); IOC feeds are cached
# for analysts/future use but stay out of the LLM context.
PROMPT_KINDS = ("cve", "ics_advisory", "pulse")

# Every feed this module knows how to fetch, in report order. The status API reports ALL
# of them — not just the enabled ones — so "switched off" is visibly different from
# "enabled but never ran". Keep in step with _enabled_fetchers below.
ALL_FEEDS = ("cisa_kev", "cisa_ics", "otx", "urlhaus", "taxii")

# Feeds whose items can reach the LLM (they emit PROMPT_KINDS). urlhaus is the deliberate
# exception: cached for analysts, never prompted — raw IOCs are noise in a narrative scenario.
PROMPTED_FEEDS = ("cisa_kev", "cisa_ics", "otx", "taxii")


@lru_cache
def _intel_store():
    """`threat_intel` collection handle, memoized per process — indexes ensured once."""
    import pymongo

    s = get_settings()
    col = pymongo.MongoClient(
        s.mongo_url,
        serverSelectionTimeoutMS=s.mongo_connect_timeout_ms,
        connectTimeoutMS=s.mongo_connect_timeout_ms,
        socketTimeoutMS=max(s.mongo_connect_timeout_ms, 30000),  # bulk upserts of ~1k docs
    )[s.mongo_db]["threat_intel"]
    col.create_index([("source", 1), ("external_id", 1)], unique=True)
    # query_intel filters per kind and sorts newest-first — let each per-kind query walk
    # exactly its kind partition in sort order instead of scanning via the TTL index.
    col.create_index([("kind", 1), ("fetched_at", -1)])
    # list_intel's per-source page (filter source, sort fetched_at desc + external_id
    # tiebreak) — without this every /items call re-sorts in memory. The UNFILTERED
    # listing still sorts in memory: acceptable while TTL caps the collection at a few
    # thousand docs; add {fetched_at,external_id} if a feed ever grows past that.
    col.create_index([("source", 1), ("fetched_at", -1), ("external_id", 1)])
    ttl_seconds = s.intel_ttl_days * 86400
    try:
        col.create_index("fetched_at", expireAfterSeconds=ttl_seconds, name="ttl_fetched_at")
    except Exception:  # noqa: BLE001 — ttl changed since index creation: rebuild it
        col.drop_index("ttl_fetched_at")
        col.create_index("fetched_at", expireAfterSeconds=ttl_seconds, name="ttl_fetched_at")
    return col


def _store_if_healthy():
    """Same fixed-cooldown breaker contract as embeddings._store_if_healthy —
    a Mongo outage returns None instead of hammering reconnects."""
    global _breaker_open_until
    now = time.monotonic()
    if now < _breaker_open_until:
        return None
    try:
        col = _intel_store()
    except Exception:  # noqa: BLE001 — Mongo down → open breaker, caller degrades
        _breaker_open_until = now + _BREAKER_COOLDOWN_S
        log.warning("intel.mongo_breaker_open", cooldown_seconds=_BREAKER_COOLDOWN_S, exc_info=True)
        return None
    _breaker_open_until = 0.0
    return col


_MAX_FETCH_BYTES = 25 * 1024 * 1024  # generous vs the real feeds (KEV ≈ 2 MB, ICS pages ≪ 1 MB)


def _get(url: str, headers: dict[str, str] | None = None, timeout: int = 120) -> bytes:
    """Fetch one feed URL, bounded in BOTH directions.

    `timeout` is urllib's per-socket-operation timeout, not a deadline for the whole transfer: a
    server that trickles a byte before each timeout window never trips it, so an unbounded
    `resp.read()` could stream indefinitely into worker memory. Reading one byte past the cap and
    failing on it turns "hostile or broken upstream" into an ordinary feed error that
    `refresh_one` records against that one feed, rather than an OOM that takes the worker with it.
    The total-duration half of the bound is the task's `soft_time_limit` (see celery_app.py)."""
    req = urllib.request.Request(url, headers={"User-Agent": "TSG-intel/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — config-pinned https URLs
        body = resp.read(_MAX_FETCH_BYTES + 1)
    if len(body) > _MAX_FETCH_BYTES:
        raise ValueError(f"feed response exceeded {_MAX_FETCH_BYTES} bytes: {url}")
    return body


def _doc(source: str, kind: str, external_id: str, title: str, *, description: str = "",
        url: str = "", tags: list[str] | None = None, raw: Any = None) -> dict:
    return {
        "source": source, "kind": kind, "external_id": str(external_id)[:200],
        "title": (title or "")[:500], "description": (description or "")[:2000],
        "url": (url or "")[:500], "tags": tags or [], "raw": raw,
    }


# ---------------------------------------------------------------- fetchers
def fetch_kev(s) -> list[dict]:
    data = json.loads(_get(s.intel_kev_url))
    docs = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        tags = ["kev"]
        if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
            tags.append("ransomware")
        docs.append(_doc(
            "cisa_kev", "cve", cve,
            f"{cve} {v.get('vendorProject', '')} {v.get('product', '')} — {v.get('vulnerabilityName', '')}".strip(),
            description=v.get("shortDescription", ""),
            url=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            tags=tags, raw=v))
    return docs


def fetch_ics_advisories(s) -> list[dict]:
    """CISA ICS advisories via the official CSAF GitHub mirror (see config comment).
    changes.csv is newest-first `"path","iso-date"` rows; each path is a CSAF JSON
    advisory. Incremental: only advisories inside the TTL window and not already
    cached are fetched, so the daily run downloads a handful of small files."""
    import csv
    import io

    base = s.intel_ics_advisories_url.rsplit("/", 1)[0]
    rows = csv.reader(io.StringIO(_get(s.intel_ics_advisories_url).decode("utf-8")))
    cutoff = datetime.now(timezone.utc) - timedelta(days=s.intel_ttl_days)
    col = _store_if_healthy()
    known = ({d["external_id"] for d in col.find({"source": "cisa_ics"}, {"external_id": 1, "_id": 0})}
             if col is not None else set())
    docs: list[dict] = []  # _doc()'s own return type — mypy cannot infer it from an empty literal
    for row in rows:
        if len(row) != 2:
            continue
        path, date_s = row
        try:
            when = datetime.fromisoformat(date_s.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when < cutoff:
            break  # newest-first: everything below is older than the window
        code = path.rsplit("/", 1)[-1].removesuffix(".json").upper()
        if code in known or len(docs) >= 200:
            continue
        adv = json.loads(_get(f"{base}/{path}"))
        meta = adv.get("document", {})
        cves = [v.get("cve") for v in adv.get("vulnerabilities", []) if v.get("cve")]
        docs.append(_doc(
            "cisa_ics", "ics_advisory", code, f"{code} {meta.get('title', '')}".strip(),
            description=" ".join(cves)[:2000],
            url=f"https://www.cisa.gov/news-events/ics-advisories/{code.lower()}",
            tags=["ot", "ics"] + cves[:10], raw=None))
    return docs


def fetch_urlhaus(s) -> list[dict]:
    data = json.loads(_get(s.intel_urlhaus_url))
    entries = []
    if isinstance(data, dict):  # json_recent: {id: [entry, ...]}
        for v in data.values():
            entries.extend(v if isinstance(v, list) else [v])
    else:
        entries = data
    docs = []
    for e in entries[:500]:
        docs.append(_doc(
            "urlhaus", "ioc_url", e.get("urlhaus_reference") or e.get("url", ""),
            f"Malicious URL ({e.get('threat', 'unknown')})",
            description=e.get("url", ""), url=e.get("urlhaus_reference", ""),
            tags=[t for t in (e.get("tags") or []) if t], raw=None))
    return docs


def fetch_otx(s) -> list[dict]:
    data = json.loads(_get(s.intel_otx_url, headers={"X-OTX-API-KEY": s.intel_otx_api_key}))
    docs = []
    for p in data.get("results", []):
        # Attribution survives into the prompt only via the title (prompts._intel_block emits
        # id/title/url alone, title capped at 140 chars) — prepend so truncation can never drop
        # it. The tag makes actor-linked threats matchable (tasks._fetch_intel adds library
        # actors to query_intel's terms).
        adv = (p.get("adversary") or "").strip()
        title = f"[{adv}] {p.get('name', '')}" if adv else p.get("name", "")
        tags = ([adv.lower()] if adv else []) + [t for t in (p.get("tags") or [])]
        doc = _doc(
            "otx", "pulse", p.get("id", ""), title,
            description=p.get("description", ""),
            url=f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
            tags=tags[:20], raw=None)
        if adv:
            # stored as its own field for the /items API — community titles may legitimately
            # start with [brackets], so attribution is never re-parsed out of the title
            doc["adversary"] = adv[:200]
        docs.append(doc)
    return docs


def fetch_taxii(s) -> list[dict]:
    from app.intel.taxii_client import iter_objects  # lazy: optional dependency

    servers = json.loads(s.intel_taxii_servers) if s.intel_taxii_servers else []
    added_after = (datetime.now(timezone.utc) - timedelta(days=s.intel_ttl_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    docs = []
    for server in servers:
        label = server.get("label", server.get("url", "taxii"))
        for obj in iter_objects(server["url"], server["collection"], added_after=added_after):
            if obj.get("revoked"):
                continue
            docs.append(_doc(
                f"taxii:{label}", "stix", obj.get("id", ""), obj.get("name") or obj.get("id", ""),
                description=(obj.get("description") or "")[:2000],
                tags=[label, obj.get("type", "")], raw=None))
    return docs


# ---------------------------------------------------------------- refresh + query
def _enabled_fetchers(s) -> list[tuple[str, Any]]:
    out = []
    if s.intel_kev_enabled:
        out.append(("cisa_kev", fetch_kev))
    if s.intel_ics_advisories_enabled:
        out.append(("cisa_ics", fetch_ics_advisories))
    if s.intel_urlhaus_enabled:
        out.append(("urlhaus", fetch_urlhaus))
    if s.intel_otx_api_key:
        out.append(("otx", fetch_otx))
    if s.intel_taxii_servers:
        out.append(("taxii", fetch_taxii))
    return out


def enabled_feed_names() -> list[str]:
    """Names of the feeds switched on right now — the fan-out list the dispatcher task
    spawns one job per (celery_app.intel_refresh_task) and the status API reports on."""
    return [name for name, _ in _enabled_fetchers(get_settings())]


def _record_feed_status(col, feed: str, *, items: int | None = None, error: str | None = None) -> None:
    """One status doc per feed in `intel_feed_status`, so an outcome OUTLIVES the Celery
    result that reported it. Without this, a feed that failed at 03:00 is indistinguishable
    from one that was never switched on — the exact blind spot the status API exists to close.
    Best-effort: bookkeeping must never fail the refresh it is describing."""
    now = datetime.now(timezone.utc)
    update: dict[str, Any] = {"last_attempt_at": now, "last_error": error}
    if error is None:
        update["last_success_at"] = now
        update["item_count"] = items
    try:
        col.database["intel_feed_status"].update_one(
            {"feed": feed}, {"$set": update, "$setOnInsert": {"feed": feed}}, upsert=True)
    except Exception:  # noqa: BLE001 — status bookkeeping is never worth failing a refresh over
        log.warning("intel.status_record_failed", feed=feed, exc_info=True)


def refresh_one(feed: str) -> int:
    """Fetch ONE feed and upsert it into Mongo; returns the item count.

    The unit the per-feed Celery task wraps (celery_app.intel_refresh_feed_task), so one
    slow or broken feed can neither delay nor fail the others, and can be retried on its
    own instead of re-pulling everything. Raises on fetch/parse failure — the caller's
    retry policy decides what to do — but always records the outcome first.

    Note some feeds are deliberately INCREMENTAL (fetch_ics_advisories skips advisories
    already cached), so a count of 0 on an up-to-date cache is success, not a silent
    failure — read `last_success_at` from the status doc, not the count, to judge health."""
    from pymongo import ReplaceOne

    s = get_settings()
    fetcher = dict(_enabled_fetchers(s)).get(feed)
    if fetcher is None:
        raise ValueError(f"unknown or disabled intel feed: {feed!r}")
    col = _store_if_healthy()
    if col is None:
        raise RuntimeError("intel refresh skipped: Mongo unavailable")
    try:
        docs = fetcher(s)
        now = datetime.now(timezone.utc)
        for d in docs:
            d["fetched_at"] = now
        if docs:
            col.bulk_write([
                ReplaceOne({"source": d["source"], "external_id": d["external_id"]}, d, upsert=True)
                for d in docs
            ], ordered=False)
    except Exception as exc:  # noqa: BLE001 — record, then re-raise for the retry policy
        _record_feed_status(col, feed, error=f"{type(exc).__name__}: {exc}"[:500])
        log.warning("intel.feed_failed", feed=feed, exc_info=True)
        raise
    _record_feed_status(col, feed, items=len(docs))
    log.info("intel.feed_refreshed", feed=feed, items=len(docs))
    return len(docs)


def refresh_all() -> dict[str, int]:
    """Every enabled feed, in-process and sequential — the CLI/back-compat path.

    Production refreshes go through the fan-out instead (one Celery task per feed, see
    celery_app.intel_refresh_task), which gets parallelism, per-feed retry and per-feed
    isolation this loop cannot offer. Kept fail-soft (a dead feed reports -1 and the rest
    still run) so a direct caller kicking every feed by hand behaves as it always did."""
    col = _store_if_healthy()
    if col is None:
        log.warning("intel.refresh_skipped_mongo_down")
        return {}
    results: dict[str, int] = {}
    for name in enabled_feed_names():
        try:
            results[name] = refresh_one(name)
        except Exception:  # noqa: BLE001 — fail-soft: next feed still runs
            results[name] = -1
    return results


def feed_status() -> list[dict[str, Any]]:
    """Per-feed operational state for the status API: enabled flag, cached item count and
    freshness (aggregated from the intel docs themselves) merged with the last attempt /
    success / error recorded by `_record_feed_status`.

    Every KNOWN feed is reported, enabled or not, so "switched off", "never run" and "ran
    and failed" read as three different states instead of one indistinguishable silence."""
    enabled = set(enabled_feed_names())
    col = _store_if_healthy()
    by_source: dict[str, dict[str, Any]] = {}
    status_docs: dict[str, dict[str, Any]] = {}
    if col is not None:
        try:
            for r in col.aggregate([{"$group": {
                    "_id": {"s": "$source", "k": "$kind"},
                    "n": {"$sum": 1}, "last": {"$max": "$fetched_at"}}}]):
                cur = by_source.setdefault(r["_id"]["s"], {"item_count": 0, "kinds": {}, "last_fetched_at": None})
                cur["item_count"] += r["n"]
                cur["kinds"][r["_id"]["k"]] = r["n"]
                if r["last"] and (cur["last_fetched_at"] is None or r["last"] > cur["last_fetched_at"]):
                    cur["last_fetched_at"] = r["last"]
            status_docs = {d["feed"]: d for d in col.database["intel_feed_status"].find({}, {"_id": 0})}
        except Exception:  # noqa: BLE001 — reporting degrades, never raises
            log.warning("intel.status_read_failed", exc_info=True)
    out = []
    for feed in ALL_FEEDS:
        agg = by_source.get(feed, {})
        st = status_docs.get(feed, {})
        out.append({
            "feed": feed,
            "enabled": feed in enabled,
            "item_count": agg.get("item_count", 0),
            "kinds": agg.get("kinds", {}),
            "last_fetched_at": agg.get("last_fetched_at"),
            "last_attempt_at": st.get("last_attempt_at"),
            "last_success_at": st.get("last_success_at"),
            "last_error": st.get("last_error"),
            "prompted": feed in PROMPTED_FEEDS,
        })
    return out


def query_intel(terms: list[str], prefer_kinds: tuple[str, ...] = ("cve",), limit: int = 5) -> list[dict]:
    """Top current intel items whose title/tags match any term (case-insensitive).
    Fail-open: Mongo down or no matches → empty list. Only PROMPT_KINDS are
    returned — IOC feeds never reach the LLM context.

    `prefer_kinds` are drawn first and in order (e.g. ('ics_advisory','cve') for OT
    threats), then the remaining PROMPT_KINDS backfill. Drawing per-kind in the DB
    query — rather than post-sorting one recency-capped pool — is deliberate: a single
    refresh stamps every doc with the same `fetched_at`, so a recency-capped pool would
    be dominated by whichever source (e.g. KEV's ~1.6k CVEs) inserted first and could
    starve the preferred kind entirely."""
    col = _store_if_healthy()
    terms = [t for t in terms if t and len(t) >= 4]
    if col is None or not terms:
        return []
    try:
        rx = re.compile("|".join(re.escape(t) for t in terms), re.IGNORECASE)
        match = {"$or": [{"title": rx}, {"description": rx}, {"tags": rx}]}
        ordered_kinds = list(prefer_kinds) + [k for k in PROMPT_KINDS if k not in prefer_kinds]
        out: list[dict] = []
        for kind in ordered_kinds:
            if len(out) >= limit:
                break
            out.extend(col.find({**match, "kind": kind}, {"_id": 0, "raw": 0})
                       .sort("fetched_at", -1).limit(limit - len(out)))
        return out
    except Exception:  # noqa: BLE001 — enrichment is optional, never breaks generation
        log.warning("intel.query_failed", exc_info=True)
        return []


def list_intel(source: str | None = None, limit: int = 50, offset: int = 0) -> tuple[list[dict], int] | None:
    """Stored intel items for the admin /items API, newest first — or None when the store
    is unavailable, so the route can report 503 (an empty list must mean 'genuinely nothing').

    external_id tiebreak: one refresh stamps every doc with the SAME fetched_at, so a
    fetched_at-only sort leaves Mongo's order for ties unstable and pages could repeat or
    skip items between requests."""
    col = _store_if_healthy()
    if col is None:
        return None
    q = {"source": source} if source else {}
    try:
        items = list(col.find(q, {"_id": 0, "raw": 0})
                     .sort([("fetched_at", -1), ("external_id", 1)]).skip(offset).limit(limit))
        return items, col.count_documents(q)
    except Exception:  # noqa: BLE001 — a mid-query blip is the same "store unavailable"
        # as a breaker-open connection: the route's one 503 path must cover both, never
        # a raw 500 with a stack trace.
        log.warning("intel.list_failed", exc_info=True)
        return None


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Refresh all enabled threat-intel feeds once.")
    parser.add_argument("--once", action="store_true", help="run one refresh and exit (default behaviour)")
    parser.parse_args()
    from app.core.logging import configure_logging

    configure_logging()
    print(refresh_all())
