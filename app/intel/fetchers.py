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


def _get(url: str, headers: dict[str, str] | None = None, timeout: int = 120) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "TSG-intel/1.0", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — config-pinned https URLs
        return resp.read()


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
        docs.append(_doc(
            "otx", "pulse", p.get("id", ""), p.get("name", ""),
            description=p.get("description", ""),
            url=f"https://otx.alienvault.com/pulse/{p.get('id', '')}",
            tags=[t for t in (p.get("tags") or [])][:20], raw=None))
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


def refresh_all() -> dict[str, int]:
    """Fetch every enabled feed and upsert into Mongo. Fail-soft per feed:
    a dead feed logs and reports -1, the rest still complete."""
    from pymongo import ReplaceOne

    s = get_settings()
    col = _store_if_healthy()
    if col is None:
        log.warning("intel.refresh_skipped_mongo_down")
        return {}
    results: dict[str, int] = {}
    now = datetime.now(timezone.utc)
    for name, fetcher in _enabled_fetchers(s):
        try:
            docs = fetcher(s)
            for d in docs:
                d["fetched_at"] = now
            if docs:
                col.bulk_write([
                    ReplaceOne({"source": d["source"], "external_id": d["external_id"]}, d, upsert=True)
                    for d in docs
                ], ordered=False)
            results[name] = len(docs)
            log.info("intel.feed_refreshed", feed=name, items=len(docs))
        except Exception:  # noqa: BLE001 — fail-soft: next feed still runs
            results[name] = -1
            log.warning("intel.feed_failed", feed=name, exc_info=True)
    return results


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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Refresh all enabled threat-intel feeds once.")
    parser.add_argument("--once", action="store_true", help="run one refresh and exit (default behaviour)")
    parser.parse_args()
    from app.core.logging import configure_logging

    configure_logging()
    print(refresh_all())
