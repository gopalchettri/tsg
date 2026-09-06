"""Live threat-intel fetchers → Mongo `threat_intel` cache.

One small fetcher per open feed, all normalizing to the same doc shape:
    {source, kind, external_id, title, description, url, tags[], raw,
    fetched_at, published_at}

`fetched_at` is cache age (it drives the TTL); `published_at` is the item's own date at
the source and is what both read paths RANK on — see query_intel. Retrieval that needs
more than one request lives in its own module (otx.py, taxii_client.py).

Refresh semantics: every run UPSERTS on (source, external_id) and stamps
`fetched_at`, so items still present in a feed never expire; the TTL index only
purges items a feed has dropped (or a whole decommissioned feed). Each fetcher is
fail-soft inside refresh_all — one dead feed never blocks the rest.

The store accessor mirrors embeddings._vector_store (same settings, same breaker
idea) but is its own handle: that one is @lru_cache'd onto the `embeddings`
collection and can't serve a second collection.

Fetching is admin-triggered — POST /v1/tsg/threat-intel/feeds/refresh and
.../feeds/{feed}/refresh — or scheduled when TSG_INTEL_REFRESH_INTERVAL_SECONDS > 0; both go
through celery_app.dispatch_refresh, which fans out one `tsg.intel_refresh_feed` job per
enabled feed.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time
import urllib.parse
import urllib.request
from collections.abc import Iterable, Iterator
from datetime import UTC, date, datetime, timedelta
from functools import lru_cache
from typing import Any, NamedTuple

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

_BREAKER_COOLDOWN_S = 30.0
_breaker_open_until = 0.0

# Only these kinds are ever injected into prompts (Phase C); IOC feeds are cached
# for analysts/future use but stay out of the LLM context.
PROMPT_KINDS = ("cve", "ics_advisory", "pulse")

# How many intel items may enter one prompt lives in config (Settings.prompt_intel_limit,
# session-tunable via Config_Tuning). ONE site owns the cap — tasks._fetch_intel — and passes
# it explicitly as query_intel's `limit`; prompts._intel_block renders what it is given. No
# module constant: a def-time default froze the value at import, and a second slice in prompts
# silently min-capped any raised limit back to the old default.

# Every feed this module knows how to fetch, in report order. The status API reports ALL
# of them — not just the enabled ones — so "switched off" is visibly different from
# "enabled but never ran". Keep in step with _enabled_fetchers below.
ALL_FEEDS = ("cisa_kev", "cisa_ics", "otx", "urlhaus", "taxii")

# Feeds whose items can reach the LLM (they emit PROMPT_KINDS). urlhaus is the deliberate
# exception: cached for analysts, never prompted — raw IOCs are noise in a narrative scenario.
# taxii is excluded too: fetch_taxii emits kind="stix", which query_intel never draws, so
# listing it here would make the /feeds API misreport prompted:true for it.
PROMPTED_FEEDS = ("cisa_kev", "cisa_ics", "otx")


class IntelTerms(NamedTuple):
    """What one session searches the cache with — built by tasks._intel_vocabulary.

    `product`: vendor/technology/platform names; matched by regex against title+tags (a
    proper noun in a title IS evidence). `scope`: canonical keys from scope_keys() —
    'sector:energy', 'country:united arab emirates'; matched ONLY by equality against each
    item's structured `scope_tags`, never against a title, so the word "Energy" inside a
    vendor's name can no longer pull an unrelated advisory. `categories`: ctm_scan_category
    codes (IT/OT/...) — decides which kind is drawn first."""
    product: list[str]
    scope: list[str]
    categories: set[str]


# static synonym map; move to Config_Tuning if sectors churn. Keys are canonical
# sector names; values are how CISA (16 official sectors), OTX `industries`, and the asset
# context's sector/sub_sector/critical_service dropdowns spell them.
_SECTOR_SYNONYMS: dict[str, tuple[str, ...]] = {
    "energy": ("energy", "electricity", "power", "power generation", "power transmission",
            "power distribution", "utilities", "utility", "oil and gas", "oil & gas", "oil",
            "gas", "petroleum", "nuclear", "renewables", "smart grid"),
    "water": ("water", "water and wastewater", "water and wastewater systems", "wastewater",
            "desalination"),
    "healthcare": ("healthcare", "healthcare and public health", "health", "hospital", "hospitals",
                "medical", "pharmaceutical"),
    "financial": ("financial", "financial services", "finance", "banking", "banks", "insurance"),
    "government": ("government", "government facilities", "government services",
                "government services and facilities", "public sector", "defense",
                "defense industrial base", "defence", "military"),
    "transportation": ("transportation", "transportation systems", "transport", "aviation",
                    "airline", "airlines", "maritime", "rail", "railway", "logistics", "shipping"),
    "chemical": ("chemical", "chemicals"),
    "manufacturing": ("manufacturing", "critical manufacturing", "industrial", "automotive"),
    "communications": ("communications", "telecommunications", "telecom", "telecoms"),
    "information technology": ("information technology", "technology", "software", "it services"),
    "food": ("food and agriculture", "food", "agriculture"),
    "emergency services": ("emergency services",),
    "dams": ("dams",),
    "commercial facilities": ("commercial facilities", "retail", "hospitality"),
    "education": ("education", "academic", "universities"),
}
_SECTOR_RX = {key: re.compile(r"\b(?:" + "|".join(re.escape(a) for a in sorted(aliases, key=len, reverse=True))
                            + r")\b", re.I) for key, aliases in _SECTOR_SYNONYMS.items()}
# Countries with no discriminating power — an advisory "deployed Worldwide" says nothing.
_GLOBAL_COUNTRY_WORDS = frozenset({"worldwide", "global", "international", "multiple", "various"})


def _split_values(values: Any) -> list[str]:
    """Flatten a str / (nested) list / comma-or-semicolon-separated string into stripped parts."""
    out: list[str] = []
    for v in (values if isinstance(values, (list, tuple, set)) else [values]):
        if not v:
            continue
        if isinstance(v, (list, tuple, set)):
            out.extend(_split_values(v))
            continue
        for part in re.split(r"[,;/]", str(v)):
            part = part.strip()
            if part:
                out.append(part)
    return out


def sector_keys(values: Any) -> list[str]:
    """Canonical 'sector:<key>' tags for free-text sector labels from ANY side (a CISA note, an
    OTX `industries` list, or the asset's own sector/sub_sector/critical_service). Word-boundary
    alias match, so 'Nuclear Reactors, Materials, and Waste' → sector:energy and 'Power
    Transmission' → sector:energy, while 'Hitachi Energy' as a VENDOR never gets here — vendors
    go to tags, and only sector fields are passed in."""
    found: set[str] = set()
    for part in _split_values(values):
        for key, rx in _SECTOR_RX.items():
            if rx.search(part):
                found.add(f"sector:{key}")
    return sorted(found)


def country_keys(values: Any) -> list[str]:
    """Canonical 'country:<name>' tags; 'Worldwide'-style values carry no signal and are dropped."""
    found = {f"country:{p.casefold()}" for p in _split_values(values)
             if p.casefold() not in _GLOBAL_COUNTRY_WORDS}
    return sorted(found)


def scope_keys(*, sectors: Any = None, countries: Any = None) -> list[str]:
    return sector_keys(sectors) + country_keys(countries)


def parse_dt(value: Any) -> datetime | None:
    """ISO date/datetime string → aware UTC datetime; None when absent or unparseable.
    Source timestamps arrive naive ('2026-07-31T06:19:30.378000'), as dates ('2024-09-18'),
    or with a Z suffix — all read as UTC."""
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=UTC)
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


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
    # Both reads rank on `published_at` (the source's own date), NOT fetched_at: one sync
    # stamps thousands of docs with the same fetched_at, so ranking on it would pick an
    # arbitrary 5 out of every large match set.
    # The fetched_at-ranked pair these replace is dropped rather than left behind: an
    # unused index is write cost on every upsert forever, and an ops note to remove it by
    # hand would never reach the environments that already have it. Idempotent both ways —
    # a rollback recreates them.
    for superseded in ("kind_1_fetched_at_-1", "source_1_fetched_at_-1_external_id_1"):
        try:
            col.drop_index(superseded)
        except Exception:  # never created here, or already gone: the normal case
            log.debug("intel.superseded_index_drop_skipped", index=superseded, exc_info=True)
    col.create_index([("kind", 1), ("published_at", -1)])          # query_intel, per kind
    # list_intel's per-source page; the UNFILTERED listing still sorts in memory, which is
    # acceptable while the TTL caps the collection at low tens of thousands of docs.
    col.create_index([("source", 1), ("published_at", -1), ("external_id", 1)])
    # query_intel's scope tier ($in over an array of canonical keys) and the actor slot's
    # equality lookup — both multikey, both cheap.
    col.create_index([("scope_tags", 1)])
    col.create_index([("adversary_key", 1)])
    # One-time backfill for pulses cached before `adversary_key` existed: they already carry
    # `adversary`, so the actor slot covers the whole cache now instead of after the ~9-day OTX
    # cursor cycle. Idempotent (the filter excludes migrated docs) and cheap on the index above.
    # scope_tags cannot be backfilled the same way — industries were never stored.
    try:
        col.update_many({"kind": "pulse", "adversary": {"$exists": True}, "adversary_key": {"$exists": False}},
                        [{"$set": {"adversary_key": {"$toLower": "$adversary"}}}])
    except Exception:
        log.warning("intel.adversary_key_backfill_failed", exc_info=True)
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
    except Exception:
        _breaker_open_until = now + _BREAKER_COOLDOWN_S
        log.warning("intel.mongo_breaker_open", cooldown_seconds=_BREAKER_COOLDOWN_S, exc_info=True)
        return None
    _breaker_open_until = 0.0
    return col


_MAX_FETCH_BYTES = 25 * 1024 * 1024  # generous vs the real feeds (KEV ≈ 2 MB, ICS pages ≪ 1 MB)


# Known ceiling: if GitHub ever answers raw.githubusercontent.com with a redirect to a CDN host,
# the ICS fetch fails LOUDLY with "redirect refused" (recorded on the feed's status doc) — add
# that host here rather than loosening the policy.
_BUILTIN_FEED_HOSTS = frozenset({"www.cisa.gov", "raw.githubusercontent.com", "github.com"})


def allowed_feed_hosts() -> frozenset[str]:
    """Every host a feed fetch may talk to: the configured feed URLs' hosts plus the CISA/GitHub
    mirror pair. A redirect anywhere else is refused (see _RedirectPolicy)."""
    s = get_settings()
    urls = [s.intel_kev_url, s.intel_ics_advisories_url, s.intel_urlhaus_url, s.intel_otx_url]
    try:
        urls += [srv.get("url", "") for srv in (json.loads(s.intel_taxii_servers) if s.intel_taxii_servers else [])]
    except (ValueError, AttributeError):
        pass
    hosts = {urllib.parse.urlsplit(u).hostname or "" for u in urls if u}
    return frozenset(h for h in hosts if h) | _BUILTIN_FEED_HOSTS


def _is_ip_or_local(host: str) -> bool:
    if host in ("localhost", "") or host.endswith((".local", ".internal")):
        return True
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True                # ANY IP literal — link-local/metadata included
    except ValueError:
        return False


class _RedirectPolicy(urllib.request.HTTPRedirectHandler):
    """A hijacked upstream (or DNS/BGP interference) that answers 302 must not steer the worker
    to an arbitrary host with the OTX key still attached. Only https, only known feed hosts,
    never an IP literal; on a cross-host hop every header but User-Agent is dropped."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        host = target.hostname or ""
        if target.scheme != "https":
            raise ValueError(f"feed redirect refused: non-https target {newurl!r}")
        if _is_ip_or_local(host) or host not in allowed_feed_hosts():
            raise ValueError(f"feed redirect refused: host {host!r} not an allowed feed host")
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and (urllib.parse.urlsplit(req.full_url).hostname or "") != host:
            ua = req.get_header("User-agent")
            new = urllib.request.Request(newurl, headers={"User-Agent": ua} if ua else {})
        return new


@lru_cache
def _opener():
    return urllib.request.build_opener(_RedirectPolicy)


def _get(url: str, headers: dict[str, str] | None = None, timeout: int = 120) -> bytes:
    """Fetch one feed URL, bounded in BOTH directions and redirect-hardened (_RedirectPolicy).

    `timeout` is urllib's per-socket-operation timeout, not a deadline for the whole transfer: a
    server that trickles a byte before each timeout window never trips it, so an unbounded
    `resp.read()` could stream indefinitely into worker memory. Reading one byte past the cap and
    failing on it turns "hostile or broken upstream" into an ordinary feed error that
    `refresh_one` records against that one feed, rather than an OOM that takes the worker with it.
    The total-duration half of the bound is the task's `soft_time_limit` (see celery_app.py)."""
    req = urllib.request.Request(url, headers={"User-Agent": "TSG-intel/1.0", **(headers or {})})
    with _opener().open(req, timeout=timeout) as resp:
        body = resp.read(_MAX_FETCH_BYTES + 1)
    if len(body) > _MAX_FETCH_BYTES:
        raise ValueError(f"feed response exceeded {_MAX_FETCH_BYTES} bytes: {url}")
    return body


def _doc(source: str, kind: str, external_id: str, title: str, *, description: str = "",
        url: str = "", tags: list[str] | None = None, raw: Any = None,
        scope_tags: list[str] | None = None, summary: str = "",
        severity: float | None = None, cwes: list[str] | None = None) -> dict:
    """The one doc shape every feed normalizes to. `tags` are matched by regex (product tier),
    `scope_tags` by equality (scope tier) — see IntelTerms. `summary` is the SOURCE's own
    one-liner and is the only free text that reaches a prompt (CISA-authored kinds only)."""
    return {
        "source": source, "kind": kind, "external_id": str(external_id)[:200],
        "title": (title or "")[:500], "description": (description or "")[:2000],
        "url": (url or "")[:500], "tags": _dedup([t for t in (tags or []) if t])[:40], "raw": raw,
        "scope_tags": sorted(set(scope_tags or [])), "summary": (summary or "")[:300],
        "severity": severity, "cwes": list(cwes or [])[:20],
    }


def _dedup(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


# ---------------------------------------------------------------- fetchers
# Every fetcher takes (settings, meta): `meta` is a dict the fetcher may fill with
# `source_version` so refresh_one can record WHICH catalogue release it synced.

_PLACEHOLDER_PRODUCTS = frozenset({"multiple products", "multiple", "n/a", "various", "unknown"})


def kev_docs(data: dict) -> list[dict]:
    """Pure normalizer for the KEV catalogue JSON (testable without network).

    `published_at` is CISA's `dateAdded` — the day exploitation was confirmed — so "top 5"
    among CVE matches means the most recently exploited, not the arbitrary sync-time order
    every KEV doc used to share. Vendor and product become tags so a product term in the
    asset's inventory matches on structure, not only on the title's wording."""
    docs = []
    # dict = the whole catalogue (the pure-normalizer contract its tests rely on); anything
    # else = the streamed "vulnerabilities" entries. One body, both callers.
    vulns = data.get("vulnerabilities", []) if isinstance(data, dict) else data
    for v in vulns:
        cve = v.get("cveID", "")
        vendor = (v.get("vendorProject") or "").strip()
        product = (v.get("product") or "").strip()
        tags = ["kev"]
        if str(v.get("knownRansomwareCampaignUse", "")).lower() == "known":
            tags.append("ransomware")
        tags += [t.casefold() for t in (vendor, product) if t and t.casefold() not in _PLACEHOLDER_PRODUCTS]
        d = _doc(
            "cisa_kev", "cve", cve,
            f"{cve} {vendor} {product} — {v.get('vulnerabilityName', '')}".strip(),
            description=v.get("shortDescription", ""),
            url=f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "",
            tags=tags, raw=v, summary=v.get("shortDescription", ""),
            cwes=[c for c in (v.get("cwes") or []) if c])
        pub = parse_dt(v.get("dateAdded"))
        if pub:
            d["published_at"] = pub
        d["due_date"] = v.get("dueDate")
        docs.append(d)
    return docs


def fetch_kev(s, meta: dict | None = None) -> list[dict]:
    """Streamed: the catalogue is ~2 MB today and CISA adds to it every week, so it is read one
    vulnerability at a time rather than parsed whole. `catalogVersion`/`dateReleased` precede
    the array in CISA's layout and are picked off the same pass -- one download, both answers."""
    from app.intel.library_import import stream_json_array_capturing

    header: dict = {}
    docs = kev_docs(stream_json_array_capturing(
        s.intel_kev_url, "vulnerabilities.item", {"catalogVersion", "dateReleased"}, header))
    if meta is not None:
        meta["source_version"] = header.get("catalogVersion") or header.get("dateReleased")
    return docs


# changes.csv paths look like "2026/icsa-26-244-06.json" (or icsma- for medical advisories).
# The path steers the NEXT fetch, so it is validated before it is trusted — a poisoned mirror
# must not be able to point the worker at an arbitrary file.
_ICS_PATH_RE = re.compile(r"^\d{4}/ics[a-z]*-\d{2}-\d{3}-\d{2}[a-z0-9-]*\.json$", re.I)


def _note(notes: list[dict], *, title: str | None = None, category: str | None = None) -> str:
    for n in notes:
        if title is not None and (n.get("title") or "").strip().casefold() == title:
            return str(n.get("text") or "")
        if category is not None and n.get("category") == category:
            return str(n.get("text") or "")
    return ""


def ics_doc(adv: dict, code: str) -> dict:
    """Pure normalizer for one CSAF advisory (testable without network).

    Keeps what CISA already states in structure and the old fetcher threw away: the
    'Critical infrastructure sectors' and 'Countries/areas deployed' notes → `scope_tags`;
    vendor / product names from product_tree → tags; the 'Advisory Summary' note → `summary`
    (the one line a prompt can judge relevance with); max CVSS baseScore → `severity`; CWE ids;
    `published_at` = the advisory's own release date."""
    meta = adv.get("document") or {}
    notes = meta.get("notes") or []
    vendors: list[str] = []
    products: list[str] = []

    def walk(branches: Any) -> None:
        for b in branches or []:
            name = (b.get("name") or "").strip()
            if b.get("category") == "vendor" and name:
                vendors.append(name)
            elif b.get("category") == "product_name" and name:
                products.append(name)
            walk(b.get("branches"))

    walk((adv.get("product_tree") or {}).get("branches"))
    vulns = adv.get("vulnerabilities") or []
    cves = [v.get("cve") for v in vulns if v.get("cve")]
    cwes = sorted({(v.get("cwe") or {}).get("id") for v in vulns if (v.get("cwe") or {}).get("id")})
    severity: float | None = None
    for v in vulns:
        for sc in v.get("scores") or []:
            for key in ("cvss_v4", "cvss_v3"):
                base = (sc.get(key) or {}).get("baseScore")
                if base is not None:
                    severity = max(severity or 0.0, float(base))
    summary = _note(notes, category="summary")
    d = _doc(
        "cisa_ics", "ics_advisory", code, f"{code} {meta.get('title', '')}".strip(),
        description=summary or " ".join(cves),
        url=f"https://www.cisa.gov/news-events/ics-advisories/{code.lower()}",
        tags=["ot", "ics", *[x.casefold() for x in vendors], *[x.casefold() for x in products][:10], *cves[:10]],
        raw=None, summary=summary, severity=severity, cwes=cwes,
        scope_tags=scope_keys(sectors=_note(notes, title="critical infrastructure sectors"),
                              countries=_note(notes, title="countries/areas deployed")))
    d["cves"] = cves[:50]
    d["vendors"] = vendors[:10]
    tracking = meta.get("tracking") or {}
    pub = parse_dt(tracking.get("current_release_date") or tracking.get("initial_release_date"))
    if pub:
        d["published_at"] = pub
    return d


def fetch_ics_advisories(s, meta: dict | None = None) -> list[dict]:
    """CISA ICS advisories via the official CSAF GitHub mirror (see config comment).
    changes.csv is newest-first `"path","iso-date"` rows; each path is a CSAF JSON
    advisory. Incremental: only advisories inside the TTL window and not already
    cached are fetched, so the daily run downloads a handful of small files."""
    import csv
    import io

    base = s.intel_ics_advisories_url.rsplit("/", 1)[0]
    rows = csv.reader(io.StringIO(_get(s.intel_ics_advisories_url).decode("utf-8")))
    cutoff = datetime.now(UTC) - timedelta(days=s.intel_ttl_days)
    col = _store_if_healthy()
    # "Known" = already cached IN THE CURRENT SHAPE. A doc written before scope_tags existed is
    # re-fetched once so the cache self-migrates on the next refresh instead of waiting for the
    # TTL to expire it.
    known = ({d["external_id"] for d in col.find({"source": "cisa_ics", "scope_tags": {"$exists": True}},
                                                 {"external_id": 1, "_id": 0})}
            if col is not None else set())
    docs: list[dict] = []  # _doc()'s own return type — mypy cannot infer it from an empty literal
    for row in rows:
        if len(row) != 2:
            continue
        path, date_s = row
        try:
            when = datetime.fromisoformat(date_s)
        except ValueError:
            continue
        if meta is not None and "source_version" not in meta:
            meta["source_version"] = date_s          # newest row = the mirror's release level
        if when < cutoff:
            break  # newest-first: everything below is older than the window
        if not _ICS_PATH_RE.match(path):
            log.warning("intel.ics_path_rejected", path=path[:120])
            continue
        code = path.rsplit("/", 1)[-1].removesuffix(".json").upper()
        if code in known or len(docs) >= 200:
            continue
        docs.append(ics_doc(json.loads(_get(f"{base}/{path}")), code))
    return docs


def fetch_urlhaus(s, meta: dict | None = None) -> list[dict]:
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


def fetch_otx(s, meta: dict | None = None) -> Iterator[dict]:
    """The ONE fetcher that streams instead of returning a list: the subscription is ~8.9k
    pulses over ~178 increasingly slow pages (about an hour end to end), so it is walked
    across runs from a stored cursor — see app/intel/otx.py. Yielding lets refresh_one
    persist each page as it arrives, so a run cut short by the task's soft_time_limit keeps
    everything it already fetched."""
    from app.intel import otx  # lazy: same style as fetch_taxii, and breaks the import cycle

    deadline = time.monotonic() + s.intel_otx_sync_seconds
    for batch in otx.walk(s, _store_if_healthy(), deadline):
        yield from batch


def fetch_taxii(s, meta: dict | None = None) -> list[dict]:
    from app.intel.taxii_client import iter_objects  # lazy: optional dependency

    servers = json.loads(s.intel_taxii_servers) if s.intel_taxii_servers else []
    added_after = (datetime.now(UTC) - timedelta(days=s.intel_ttl_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
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
    # Annotated because the values are deliberately heterogeneous: a fetcher returns any
    # ITERABLE of docs — most build a list, otx yields page by page so refresh_one can
    # persist batches as they arrive instead of holding a whole corpus in memory.
    out: list[tuple[str, Any]] = []
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
    """Names of the feeds switched on right now — the fan-out list app/api/threat_intel.py::
    _dispatch spawns one job per and the status API reports on."""
    return [name for name, _ in _enabled_fetchers(get_settings())]


def _record_feed_status(col, feed: str, *, items: int | None = None, error: str | None = None,
                        source_version: str | None = None) -> None:
    """One status doc per feed in `intel_feed_status`, so an outcome OUTLIVES the Celery
    result that reported it. Without this, a feed that failed at 03:00 is indistinguishable
    from one that was never switched on — the exact blind spot the status API exists to close.
    Best-effort: bookkeeping must never fail the refresh it is describing."""
    now = datetime.now(UTC)
    update: dict[str, Any] = {"last_attempt_at": now, "last_error": error}
    if items is not None:
        # recorded on the FAILURE path too: writes are incremental, so a run that died
        # partway still stored real items and must not read as a total loss
        update["item_count"] = items
    if source_version:
        update["source_version"] = str(source_version)[:100]   # provenance: which release synced
    if error is None:
        update["last_success_at"] = now
    try:
        col.database["intel_feed_status"].update_one(
            {"feed": feed}, {"$set": update, "$setOnInsert": {"feed": feed}}, upsert=True)
    except Exception:
        log.warning("intel.status_record_failed", feed=feed, exc_info=True)


#: Docs per bulk_write. The point is not batch efficiency but DURABILITY: a feed that
#: streams for minutes (otx walks pages; cisa_ics issues up to 200 sequential requests)
#: used to write once at the very end, so a soft_time_limit kill or a dead worker threw
#: away everything already fetched. Now each batch is persisted as it is produced.
_WRITE_BATCH = 500


def _upsert_batch(col, docs: list[dict], now: datetime) -> None:
    """Stamp and upsert one batch on (source, external_id)."""
    from pymongo import ReplaceOne

    for d in docs:
        d["fetched_at"] = now                              # cache age — drives the TTL
        # One uniform ranking key across every feed: the source's own date where it has one
        # (OTX pulses), else sync time. query_intel/list_intel sort on this, so it must
        # never be missing or those docs would rank below everything.
        d["published_at"] = d.get("published_at") or now
    col.bulk_write([
        ReplaceOne({"source": d["source"], "external_id": d["external_id"]}, d, upsert=True)
        for d in docs
    ], ordered=False)


class RefreshAlreadyRunning(Exception):
    """Another refresh of this feed holds the per-feed lock (celery_app.intel_refresh_feed_task).
    Terminal, never retried: burning the retry budget waiting for a lock helps nobody."""


def refresh_one(feed: str) -> int:
    """Fetch ONE feed and upsert it into Mongo; returns the item count.

    The unit the per-feed Celery task wraps (celery_app.intel_refresh_feed_task), so one
    slow or broken feed can neither delay nor fail the others, and can be retried on its
    own instead of re-pulling everything. Raises on fetch/parse failure — the caller's
    retry policy decides what to do — but always records the outcome first.

    Note some feeds are deliberately INCREMENTAL (fetch_ics_advisories skips advisories
    already cached), so a count of 0 on an up-to-date cache is success, not a silent
    failure — read `last_success_at` from the status doc, not the count, to judge health."""
    s = get_settings()
    fetcher = dict(_enabled_fetchers(s)).get(feed)
    if fetcher is None:
        raise ValueError(f"unknown or disabled intel feed: {feed!r}")
    col = _store_if_healthy()
    if col is None:
        raise RuntimeError("intel refresh skipped: Mongo unavailable")
    now = datetime.now(UTC)
    stored, batch = 0, []
    meta: dict[str, Any] = {}      # the fetcher may report the source release it synced
    try:
        for doc in fetcher(s, meta):        # list or generator — both iterate
            batch.append(doc)
            if len(batch) >= _WRITE_BATCH:
                _upsert_batch(col, batch, now)
                stored += len(batch)
                batch = []
        if batch:
            _upsert_batch(col, batch, now)
            stored += len(batch)
    except Exception as exc:
        _record_feed_status(col, feed, items=stored, error=f"{type(exc).__name__}: {exc}"[:500],
                            source_version=meta.get("source_version"))
        log.warning("intel.feed_failed", feed=feed, items_stored=stored, exc_info=True)
        raise
    _record_feed_status(col, feed, items=stored, source_version=meta.get("source_version"))
    log.info("intel.feed_refreshed", feed=feed, items=stored, source_version=meta.get("source_version"))
    return stored


def refresh_all() -> dict[str, int]:
    """Every enabled feed, in-process and sequential — the CLI/back-compat path.

    Production refreshes go through the fan-out instead (one Celery task per feed, see
    app/api/threat_intel.py::_dispatch), which gets parallelism, per-feed retry and per-feed
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
    s = get_settings()
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
        except Exception:
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
            "source_version": st.get("source_version"),
            # SDD SOURCE_STALE: an ENABLED feed with no success inside the window. Disabled
            # feeds are never stale — there is nothing they were supposed to do.
            "stale": feed in enabled and is_stale(st.get("last_success_at"), s.intel_stale_after_seconds),
            "prompted": feed in PROMPTED_FEEDS,
        })
    return out


def is_stale(last_success_at: datetime | None, stale_after_seconds: int) -> bool:
    """No success ever, or the last one older than the window. Mongo hands back naive UTC
    datetimes; compare in the same frame."""
    if last_success_at is None:
        return True
    last = last_success_at.replace(tzinfo=None) if last_success_at.tzinfo else last_success_at
    return datetime.now(UTC).replace(tzinfo=None) - last > timedelta(seconds=stale_after_seconds)


def query_intel(terms: IntelTerms, prefer_kinds: tuple[str, ...] = ("cve",),
                limit: int | None = None, backfill: bool = True) -> list[dict]:
    """Top current intel items for one session's terms. Fail-open: Mongo down or nothing
    matches → empty list. Only PROMPT_KINDS are returned — IOC feeds never reach the LLM.

    TWO TIERS per kind, drawn in order:
      product — `terms.product` (vendor / technology / platform names) as a case-insensitive
                regex over title+tags. A proper noun in a title IS evidence.
      scope   — `terms.scope` ('sector:energy', 'country:...') by EQUALITY against the item's
                structured `scope_tags`. Never against a title: the word "Energy" inside the
                vendor "Hitachi Energy" used to pull an unrelated advisory into every grid
                prompt. KEV has no scope_tags, so a CVE only enters through a real product hit.
    `description` is DELIBERATELY not searched (narrative prose mentions every sector in
    passing; measured 5% on-topic vs 75% for title/tags).

    Ranked by `published_at` — the item's OWN date (KEV dateAdded, CSAF release date, pulse
    modified), so "top 5" means the most recent threats, not an arbitrary five from one sync.

    Draw order is TIER-major, then ROUND-ROBIN across kinds: every product hit (the stronger
    evidence — a named product in the asset's own inventory) is taken before any scope hit,
    and within a tier one item is taken per kind in `prefer_kinds` order, cycling until the
    limit. Round-robin is what keeps the block mixed: a sector with 14 fresh advisories would
    otherwise fill every slot with the preferred kind and the campaign report never appears.
    `prefer_kinds` then the remaining PROMPT_KINDS (`backfill=False` draws only prefer_kinds);
    drawing per kind in the DB query stops the largest source (KEV, ~1.7k CVEs) from starving
    the rest. Each returned doc carries `matched_via` ('product' | 'scope').

    `limit=None` resolves from config AT CALL TIME (never a def-time default, which would
    freeze the value at import and ignore any session-tuned override the caller carries).

    Known ceiling: product terms match as WHOLE phrases — "Windows Server 2019" in the inventory
    will not match a KEV title "Microsoft Windows". Splitting terms into tokens would bring
    back the noise ("Server" hits everything); accept the lower recall."""
    s = get_settings()
    if limit is None:
        limit = s.prompt_intel_limit
    col = _store_if_healthy()
    product = [t for t in terms.product if t and len(t) >= s.intel_min_term_length]
    scope = [k for k in terms.scope if k]
    if col is None or limit <= 0 or (not product and not scope):
        return []
    tiers: list[tuple[str, dict]] = []
    if product:
        rx = re.compile("|".join(re.escape(t) for t in product), re.IGNORECASE)
        tiers.append(("product", {"$or": [{"title": rx}, {"tags": rx}]}))
    if scope:
        tiers.append(("scope", {"scope_tags": {"$in": scope}}))
    ordered_kinds = list(prefer_kinds)
    if backfill:
        ordered_kinds += [k for k in PROMPT_KINDS if k not in prefer_kinds]
    try:
        out: list[dict] = []
        seen: set[tuple[str, str]] = set()
        for via, match in tiers:
            # newest `limit` candidates per kind, then interleave in prefer order
            queues = [list(col.find({**match, "kind": kind}, {"_id": 0, "raw": 0})
                           .sort("published_at", -1).limit(limit)) for kind in ordered_kinds]
            while len(out) < limit and any(queues):
                for q in queues:
                    while q:
                        d = q.pop(0)
                        key = (d.get("source", ""), d.get("external_id", ""))
                        if key not in seen:
                            seen.add(key)
                            d["matched_via"] = via
                            out.append(d)
                            break
                    if len(out) >= limit:
                        break
        return out
    except Exception:
        log.warning("intel.query_failed", exc_info=True)
        return []


def query_actor_pulses(actors: list[str], limit: int = 1) -> list[dict]:
    """The reserved actor slot: the newest OTX pulse whose ATTRIBUTED ADVERSARY equals one of
    the threat's actor names (casefolded). Equality on `adversary_key`, never a regex over
    titles — the old regex let the role label "Cybercriminal" pull a pulse about stolen AI
    compute because the word appeared in its name. Generic roles ("Malicious user", "External
    attacker") match no adversary and get nothing; a named group matches its own reports.
    Fail-open like query_intel."""
    col = _store_if_healthy()
    keys = _dedup(a.strip().lower() for a in actors if a and a.strip())
    if col is None or not keys or limit <= 0:
        return []
    try:
        docs = list(col.find({"kind": "pulse", "adversary_key": {"$in": keys}}, {"_id": 0, "raw": 0})
                    .sort("published_at", -1).limit(limit))
        for d in docs:
            d["matched_via"] = "actor"
        return docs
    except Exception:
        log.warning("intel.actor_query_failed", exc_info=True)
        return []


def list_intel(source: str | None = None, limit: int = 50, offset: int = 0) -> tuple[list[dict], int] | None:
    """Stored intel items for the admin /items API, newest threat first — or None when the
    store is unavailable, so the route can report 503 (an empty list must mean 'genuinely
    nothing').

    Ordered by `published_at` (the source's own date), with an external_id tiebreak: docs
    from one sync share a timestamp, and an unstable order for ties lets pages repeat or
    skip items between requests."""
    col = _store_if_healthy()
    if col is None:
        return None
    q = {"source": source} if source else {}
    try:
        items = list(col.find(q, {"_id": 0, "raw": 0})
                    .sort([("published_at", -1), ("external_id", 1)]).skip(offset).limit(limit))
        return items, col.count_documents(q)
    except Exception:
        # as a breaker-open connection: the route's one 503 path must cover both, never
        # a raw 500 with a stack trace.
        log.warning("intel.list_failed", exc_info=True)
        return None
