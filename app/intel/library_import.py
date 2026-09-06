"""Import open-source threat libraries into the Threat_* master tables.

Front door: POST /v1/tsg/threat-intel/library/import/{source} -> the
tsg.import_threat_library Celery task -> run_import below. Each source is adapted to
normalized records {type_name, threat_name, categories[]} and upserted through the same
race-safe DAL functions the promotion path uses.

Validation failures raise ThreatLibraryImportError -- NEVER SystemExit: SystemExit is a
BaseException, and Celery treats an uncaught SystemExit inside task code as a
worker-termination signal (the SIGTERM shutdown mechanism), so a merely-invalid request
could crash the whole worker and every other in-flight pipeline task on it.

VISIBILITY: grounding.get_possible_types, get_possible_names and
embeddings._catalogue_texts all filter IsActive == True, so a row inserted PENDING is one
retrieval can never return. dal.upsert_threat_type / upsert_threat_catalogue used to hardcode
IsActive=False -- correct for their AI-promotion caller, wrong for a curated import -- which
forced this module into an INSERT-then-UPDATE dance. The policy is now a caller-declared
`is_active` argument, so a curated import states its intent AT THE INSERT and the row is never
briefly invisible. That also removes the ordering hazard: with no separate activation step
there is no window in which an embedding refresh could run against pending rows and silently
skip them.

An EXISTING row keeps its own IsActive -- the upserts are first-writer, so a re-import never
flips a row a curator has deliberately deactivated.
"""
from __future__ import annotations

import collections
import contextlib
import itertools
import json
import re
from collections.abc import Iterator
from typing import Any

import ijson
import yaml
from sqlalchemy import func, select

from app.core.logging import get_logger
from app.core.naming import normalize_name
from app.core.stride import STRIDE_ORDER
from app.db import dal
from app.db import models as m

log = get_logger(__name__)

# The canonical six, from THE single definition (app/core/stride.py) rather than a private
# copy that could drift from the seeded Threat_Category rows.
SPOOF, TAMPER, REPUD, INFO, DOS, ELEV = STRIDE_ORDER

_ATLAS_V6_PATH_RE = re.compile(r"^v6/ATLAS-[\w.]+\.yaml$")

#: Cap on the sample/skipped lists carried in the job result -- this dict travels through the
#: Celery result backend into an API response, and a big source can skip hundreds of rows.
RESULT_LIST_CAP = 50

#: Per-request download ceiling for WHOLE-BODY reads, mirroring fetchers._MAX_FETCH_BYTES.
#: This one is a memory bound: _get holds the entire body, then the caller parses it into an
#: object tree several times that size. Keep it tight.
_MAX_FETCH_BYTES = 25 * 1024 * 1024

#: Ceilings for STREAMED reads. Memory no longer scales with the file here -- only one record is
#: ever live -- so these are transfer/abuse bounds, not memory bounds, and are deliberately far
#: larger. MITRE's ATT&CK Enterprise bundle is 51 MB today and grows with every release; a tight
#: ceiling on this path is exactly the bug that made /techniques/rebuild fail 100% of the time.
_MAX_STREAM_BYTES = 512 * 1024 * 1024
_MAX_STREAM_ITEMS = 1_000_000


#: Lock key + TTL for serializing imports of one source. The heartbeat in core.joblock renews
#: this, so it only has to outlive one heartbeat interval, not the whole import -- a plain
#: constant rather than a setting nobody would tune. Promote it to Settings if that changes.
LOCK_TTL_SECONDS = 300


def lock_key(source: str) -> str:
    """THE key for both the worker's acquire and the route's advisory probe -- one definition, so
    the two can never disagree about what is being locked."""
    return f"tsg:library-import:{source}"


class ThreatLibraryImportError(Exception):
    """A structurally-valid but business-rule-invalid import request (unknown source,
    unparseable/mismatched content, unseeded STRIDE categories) -> 422, same envelope shape as
    every other domain error (registered in app/api/errors.py)."""


class ImportAlreadyRunning(ThreatLibraryImportError):
    """Another import of this same source holds the lock.

    A ThreatLibraryImportError subclass on purpose: the handling is identical (terminal, never
    retried -- burning the retry budget waiting for a lock helps nobody), while remaining
    distinguishable for a caller that wants to say "busy" rather than "invalid"."""


URLS = {
    "pytm": "https://raw.githubusercontent.com/OWASP/pytm/master/pytm/threatlib/threats.json",
    "emb3d": "https://raw.githubusercontent.com/mitre/emb3d/main/_data/threats.json",
    "atlas": "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/manifest.yaml",
    "misp_actors": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
}
SOURCES = tuple(sorted(URLS))
YAML_SOURCES = {"atlas"}
SOURCE_TAGS = {  # Threat_Type.Source / Threat_Catalogue.Source provenance values
    "pytm": "pytm", "emb3d": "mitre_emb3d",
    "atlas": "mitre_atlas", "misp_actors": "misp_galaxy",
}
#: Which embedding group each source's rows land in -- drives the chained refresh.
ACTOR_SOURCES = {"misp_actors"}

# ---------------------------------------------------------------- STRIDE maps
# pytm SID prefix -> (Threat_Type name, STRIDE categories)
PYTM_PREFIXES = {
    "AA": ("Authentication Abuse", [SPOOF]),
    "AC": ("Access Control Abuse", [ELEV]),
    "API": ("API Abuse", [ELEV, TAMPER]),
    "CR": ("Credential & Session Attacks", [SPOOF, INFO]),
    "DE": ("Data Interception", [INFO]),
    "DO": ("Denial of Service", [DOS]),
    "DR": ("Sensitive Data Exposure", [INFO]),
    "DS": ("Data Excavation", [INFO]),
    "HA": ("Path & File Attacks", [ELEV, TAMPER]),
    "INP": ("Input Manipulation", [TAMPER]),
    "LB": ("API Manipulation", [TAMPER]),
    "LLM": ("AI / LLM Threats", [TAMPER, INFO]),
    "SC": ("Client-side Script Attacks", [TAMPER]),
}

# EMB3D top-level category -> STRIDE (coarse; unknown categories are skipped, not guessed)
EMB3D_CATEGORY_STRIDE = {
    "hardware": [TAMPER, INFO],
    "system software": [TAMPER, ELEV],
    "application software": [TAMPER, ELEV],
    "networking": [SPOOF, INFO, DOS],
}

# ATLAS tactic id (kill-chain phase) -> nearest STRIDE category. Defensible, not exact --
# ATLAS's kill-chain phases and STRIDE's security-property categories aren't the same taxonomy.
# A technique whose tactics are ALL absent here is skipped, same as any unmappable input.
ATLAS_TACTIC_STRIDE = {
    "AML.TA0002": INFO,    # Reconnaissance
    "AML.TA0003": TAMPER,  # Resource Development
    "AML.TA0004": SPOOF,   # Initial Access
    "AML.TA0000": ELEV,    # AI Model Access
    "AML.TA0005": TAMPER,  # Execution
    "AML.TA0006": ELEV,    # Persistence
    "AML.TA0012": ELEV,    # Privilege Escalation
    "AML.TA0007": REPUD,   # Defense Evasion
    "AML.TA0013": SPOOF,   # Credential Access
    "AML.TA0008": INFO,    # Discovery
    "AML.TA0015": ELEV,    # Lateral Movement
    "AML.TA0009": INFO,    # Collection
    "AML.TA0001": TAMPER,  # AI Attack Staging
    "AML.TA0014": TAMPER,  # Command and Control
    "AML.TA0010": INFO,    # Exfiltration
    "AML.TA0011": DOS,     # Impact
}

# MISP actor relevance filter for CII (keeps Threat_Actor -- and the actor hints built from it --
# focused instead of 700+ rows)
CII_KEYWORDS = ("critical infrastructure", "energy", "ics", "scada", "industrial",
                "utilities", "banking", "financial", "government", "telecom", "water")

# Per-source top-level shape -- the cheap pre-parse sniff run before dispatching to an adapter
# (valid JSON of the WRONG shape would otherwise crash deep inside one with a meaningless
# AttributeError). (predicate, human-readable expectation).
EXPECTED_SHAPES: dict[str, tuple] = {
    "pytm": (lambda d: isinstance(d, list), "a JSON list of pytm threat objects"),
    "emb3d": (lambda d: isinstance(d, (dict, list)), 'a JSON object with a "threats" list (or a bare list)'),
    "misp_actors": (lambda d: isinstance(d, dict) and "values" in d, 'a MISP galaxy object with a "values" list'),
    "atlas": (lambda d: isinstance(d, dict) and isinstance(d.get("techniques"), dict) and bool(d["techniques"]),
              'a YAML object with a non-empty "techniques" mapping (ATLAS format v6)'),
}


# ---------------------------------------------------------------- adapters
# Each returns (records, skipped) where a record is
# {type_name, threat_name, categories} and a skipped entry is {reason, item}.
# misp_actors returns actor NAMES instead of records.

def adapt_pytm(data) -> tuple[list[dict], list[dict]]:
    records, skipped = [], []
    for t in data:
        sid = t.get("SID", "")
        prefix = re.match(r"[A-Z]+", sid)
        entry = PYTM_PREFIXES.get(prefix.group()) if prefix else None
        if not entry:
            skipped.append({"reason": f"unknown SID prefix: {sid}", "item": t.get("description")})
            continue
        type_name, cats = entry
        records.append({
            "type_name": type_name,
            "threat_name": f"{sid} {t.get('description', '')}".strip(),
            "categories": cats,
        })
    return records, skipped


def adapt_emb3d(data) -> tuple[list[dict], list[dict]]:
    threats = data.get("threats", data) if isinstance(data, dict) else data
    records, skipped = [], []
    for t in threats:
        category = (t.get("category") or "").replace("_", " ").lower()
        cats = EMB3D_CATEGORY_STRIDE.get(category)
        if not cats:
            skipped.append({"reason": f"unknown EMB3D category: {category}", "item": t.get("text")})
            continue
        records.append({
            "type_name": f"Embedded Device - {category.title()}",
            "threat_name": f"{t.get('id')} {t.get('text')}".strip(),
            "categories": cats,
        })
    return records, skipped


def adapt_atlas(data) -> tuple[list[dict], list[dict]]:
    """MITRE ATLAS (AI/ML attack techniques), format v6. Unlike the other sources ATLAS is a
    two-level hierarchy: a top-level technique becomes the Threat_Type, and either its
    sub-techniques (if any) or the technique itself (if it has none) become one Threat_Catalogue
    row each -- so grounding.get_possible_names always has >=1 name under every imported type.

    v6 moved both technique->tactic and sub-technique->parent out of the technique object into
    the top-level `relationships` map (keyed by technique id): an `achieves` entry's target is a
    tactic id, a `specializes` entry's target is the parent technique id. `techniques` and
    `relationships` are dicts keyed by id, not lists, in v6."""
    techniques: dict[str, dict] = data["techniques"]
    relationships: dict[str, dict] = data.get("relationships") or {}

    sub_by_parent: dict[str, list[str]] = collections.defaultdict(list)
    is_subtechnique: set[str] = set()
    for _tech_id, rels in relationships.items():
        for rel in rels.get("specializes", []):
            sub_by_parent[rel["target"]].append(rel["source"])
            is_subtechnique.add(rel["source"])

    records, skipped = [], []
    for tech_id, tech in techniques.items():
        if tech_id in is_subtechnique:
            continue  # visited as a child of its parent
        tactic_ids = [r["target"] for r in relationships.get(tech_id, {}).get("achieves", [])]
        cats = sorted({ATLAS_TACTIC_STRIDE[t] for t in tactic_ids if t in ATLAS_TACTIC_STRIDE})
        if not cats:
            skipped.append({"reason": f"unmapped tactic(s): {tactic_ids}",
                            "item": f"{tech_id} {tech.get('name')}"})
            continue
        for entry_id in sub_by_parent.get(tech_id) or [tech_id]:
            entry = techniques.get(entry_id)
            if entry is None:  # a relationship naming a technique the map does not carry
                skipped.append({"reason": "sub-technique missing from techniques map",
                                "item": entry_id})
                continue
            records.append({
                "type_name": tech["name"],
                "threat_name": f"{entry_id} {entry.get('name')}".strip(),
                "categories": cats,
            })
    return records, skipped


def adapt_misp_actors(values, max_actors: int) -> tuple[list[str], list[dict]]:
    """Accepts EITHER the whole MISP galaxy (`{"values": [...]}`) or the entries on their own.

    Production streams the entries, so the document is never in memory; the unit tests hand over
    a whole galaxy, which is the natural way to write them. One line supports both.

    The early `break` on max_actors matters more now than it reads: against a stream it stops
    pulling the download the moment the cap is met, instead of parsing every remaining actor.
    """
    if isinstance(values, dict):
        values = values.get("values", [])
    actors, skipped = [], []
    for v in values:
        blob = json.dumps(v, ensure_ascii=False).lower()
        if not any(k in blob for k in CII_KEYWORDS):
            continue
        name = (v.get("value") or "").strip()
        if not name:  # a CII-matching entry with no "value" key -- data, not a crash
            skipped.append({"reason": "entry has no 'value' name", "item": None})
            continue
        actors.append(name)
        if len(actors) >= max_actors:
            skipped.append({"reason": f"max_actors cap ({max_actors}) reached; remaining "
                                      "CII-relevant actors not imported",
                            "item": "raise max_actors to import more"})
            break
    return actors, skipped


ADAPTERS = {"pytm": adapt_pytm, "emb3d": adapt_emb3d, "atlas": adapt_atlas}


# ---------------------------------------------------------------- IO
def _resolve_atlas_dataset_url(manifest) -> str:
    """URLS["atlas"] points at dist/manifest.yaml; this picks the current v6 dataset path out of
    it and returns that file's URL. The path is checked against a fixed pattern before being used
    to build a URL: the manifest is remote third-party content, and this is a place where its
    contents steer an outgoing fetch."""
    for release in manifest:
        for version in release.get("versions", []):
            path = version.get("path", "")
            if str(version.get("format-version", "")).startswith("6.") and _ATLAS_V6_PATH_RE.match(path):
                return f"https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/{path}"
    raise ThreatLibraryImportError(
        "could not find a v6 release in dist/manifest.yaml -- MITRE ATLAS's release index "
        "format may have changed")


#: Every import fetch goes through _open(). Kept as ONE door because the streaming work added
#: two more download sites without the guard, and a fourth will be added one day too.
_FETCH_TIMEOUT_S = 180


def _open(url: str, *, timeout: int = _FETCH_TIMEOUT_S):
    """THE single outbound connection for every import fetch, scheme/host/redirect checked.

    Import source URLs are configuration, and configuration steering an outgoing fetch is a trust
    boundary: a typo or a tampered env could otherwise point a worker at 169.254.169.254 (cloud
    metadata) or an internal service. urllib also follows redirects blindly, so even a pinned
    https URL can be walked somewhere else by a hijacked upstream answering 302.

    Reuses app.intel.fetchers' policy rather than restating it -- one allowlist, one redirect
    handler, no second copy to drift. Note this checks the INITIAL url as well, which
    fetchers._get does not: there only redirect targets are policed.

    Imported lazily so this module does not pull fetchers (and pymongo with it) at import time.
    """
    import urllib.parse

    from app.intel.fetchers import _is_ip_or_local, _opener, allowed_feed_hosts

    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme != "https":
        raise ThreatLibraryImportError(f"refusing a non-https source URL: {url!r}")
    if _is_ip_or_local(host):
        raise ThreatLibraryImportError(
            f"refusing an IP-literal or loopback source host: {host!r}")
    if host not in allowed_feed_hosts():
        raise ThreatLibraryImportError(
            f"source host {host!r} is not an allowed feed host -- add it to the allowlist "
            "(fetchers._BUILTIN_FEED_HOSTS) rather than loosening this check")
    req = urllib.request.Request(url, headers={"User-Agent": "TSG-library-import/1.0"})
    return _opener().open(req, timeout=timeout)


def _get(url: str, *, max_bytes: int = _MAX_FETCH_BYTES) -> bytes:
    """Download `url`, refusing anything past `max_bytes`.

    The ceiling is a PARAMETER because one global value cannot fit sources whose legitimate
    sizes differ by an order of magnitude. The 25 MB default is right for these WHOLE-BODY
    feeds (atlas, emb3d). The streamed sources do not use this function at all -- they go
    through stream_json_array and inherit _MAX_STREAM_BYTES, which is far larger because
    memory there is O(one record) rather than O(file). Before streaming existed,
    /techniques/rebuild failed 100% of the time on "source content exceeds the 25 MB
    ceiling" against a 51 MB bundle -- a brand-new endpoint that could never succeed.
    """
    log.info("library_import.downloading", url=url, max_bytes=max_bytes)
    with _open(url) as resp:
        body = resp.read(max_bytes + 1)
    if len(body) > max_bytes:
        raise ThreatLibraryImportError(
            f"source content exceeds the {max_bytes // (1024 * 1024)} MB ceiling")
    return body


class _CountingReader:
    """File-like wrapper that refuses to hand out more than `max_bytes`.

    The ceiling has to be enforced DURING the stream, not by measuring a body we already hold --
    holding it is the thing we are trying to stop. ijson pulls through .read(), so counting here
    covers every byte it sees.
    """

    def __init__(self, fp, max_bytes: int, url: str) -> None:
        self._fp, self._max, self._url, self._seen = fp, max_bytes, url, 0

    def read(self, size: int = -1) -> bytes:
        chunk = self._fp.read(size)
        self._seen += len(chunk)
        if self._seen > self._max:
            raise ThreatLibraryImportError(
                f"source content exceeds the {self._max // (1024 * 1024)} MB streaming ceiling")
        return chunk


def stream_json_array(url: str, path: str, *, max_bytes: int = _MAX_STREAM_BYTES,
                      max_items: int = _MAX_STREAM_ITEMS,
                      found: dict | None = None) -> Iterator[Any]:
    """Yield records from a remote JSON array WITHOUT materialising the document.

    Peak memory is one record -- a few KB -- whether the file is 51 MB or 5 GB. The whole-body
    alternative (`json.loads(_get(url))`) costs the file size in bytes PLUS several times that
    again as a Python object tree, which is why a 51 MB ATT&CK bundle needed ~1 GB to produce
    647 records of six short fields.

    `path` is an ijson path: "item" for a bare top-level array, "objects.item" for
    {"objects": [...]}, "values.item" for {"values": [...]}.

    Both guards survive the change to streaming: bytes are capped by _CountingReader as they
    arrive, and `max_items` bounds a file that is small but pathologically deep in records.
    """
    container = path[: -len(".item")] if path.endswith(".item") else ""

    def _tee(events):
        for prefix, event, value in events:
            if found is not None and event == "start_array" and prefix == container:
                # The array ITSELF was located. Lets a caller tell "this document is the wrong
                # shape" (never seen) from "the array is genuinely empty" (seen, yielded none) --
                # a distinction json.loads gave for free and streaming otherwise destroys.
                found["container"] = True
            yield prefix, event, value

    log.info("library_import.streaming", url=url, path=path, max_bytes=max_bytes)
    with _open(url) as resp:
        # ijson.items accepts an EVENT STREAM as well as a file, which is what lets _tee sit
        # between parse and item-building. (ijson.common.items does the same but is deprecated.)
        events = ijson.parse(_CountingReader(resp, max_bytes, url))
        seen = 0
        for item in ijson.items(_tee(events), path):
            seen += 1
            if seen > max_items:
                raise ThreatLibraryImportError(
                    f"source yielded more than {max_items} records at {path!r}")
            yield item


def stream_json_array_capturing(url: str, path: str, capture: set[str], into: dict, *,
                                max_bytes: int = _MAX_STREAM_BYTES,
                                max_items: int = _MAX_STREAM_ITEMS) -> Iterator[Any]:
    """Stream an array AND collect named top-level scalars, in ONE pass.

    CISA's KEV needs both its `vulnerabilities` array and the `catalogVersion` scalar that
    stamps the feed's source_version. Fetching twice to get them is the obvious wrong answer,
    and parsing the document whole is what this module exists to avoid -- so the parse events
    are teed: scalars are picked off as they go past, and the same event stream builds the
    array records. Works because those scalars precede the array in the document; a scalar
    positioned AFTER it would simply not be captured, which is why `into` is read only for keys
    the caller knows come first.
    """
    def _tee(events):
        for prefix, event, value in events:
            if prefix in capture and event in ("string", "number", "boolean", "null"):
                into[prefix] = value
            yield prefix, event, value

    log.info("library_import.streaming", url=url, path=path, capture=sorted(capture))
    with _open(url) as resp:
        events = ijson.parse(_CountingReader(resp, max_bytes, url))
        seen = 0
        for item in ijson.items(_tee(events), path):
            seen += 1
            if seen > max_items:
                raise ThreatLibraryImportError(
                    f"source yielded more than {max_items} records at {path!r}")
            yield item


#: JSON sources read one record at a time, and the ijson path to their records.
#: NOT here, and deliberately:
#:   * atlas  -- YAML, which ijson cannot parse (and 6 KB).
#:   * emb3d  -- its top level is EITHER {"threats": [...]} OR a bare list, so there is no single
#:               path to stream; resolving it would need a second fetch or a buffered peek, both
#:               of which cost more than they save on a 40 KB file. Left on the whole-body read.
STREAM_PATHS = {"pytm": "item", "misp_actors": "values.item"}


def _streamed_records(source: str) -> Iterator[Any]:
    """Stream one source, preserving the shape error `check_source_shape` used to raise.

    Whole-document validation is impossible on a stream, so the same guarantee is kept two ways:
    a path that matches NOTHING means the content is not the shape we expect, and the FIRST
    record is checked before the rest are consumed. Same message either way, so the API's
    failure text is unchanged.
    """
    expected = EXPECTED_SHAPES[source][1]
    found: dict = {}
    it = stream_json_array(URLS[source], STREAM_PATHS[source], found=found)
    first = next(it, None)
    if first is None:
        if found.get("container"):
            # The array exists and is EMPTY. That is a data condition, not a malformed source:
            # run_import turns zero records into its "0 usable records" warning, deliberately,
            # so that zero does not read as success. Raising here instead made an upstream
            # publishing [] a hard job failure -- a regression this streaming rewrite introduced.
            return iter(())
        raise ThreatLibraryImportError(
            f"content does not match the {source!r} format -- expected {expected}")
    if not isinstance(first, dict):
        raise ThreatLibraryImportError(
            f"content does not match the {source!r} format -- expected {expected}")
    return itertools.chain([first], it)


def check_source_shape(source: str, data) -> None:
    """Raise ThreatLibraryImportError unless `data`'s top-level shape matches what `source`'s
    adapter expects, so a mismatched download fails with a clean message instead of an opaque
    AttributeError deep inside an adapter."""
    predicate, expected = EXPECTED_SHAPES[source]
    if not predicate(data):
        raise ThreatLibraryImportError(
            f"content does not match the {source!r} format -- expected {expected}")


def load(source: str):
    """Download one source, as records where possible and as a whole document where not.

    Sources in STREAM_PATHS come back as an ITERATOR of records -- nothing holds the document,
    so memory does not scale with the file. The rest (atlas, emb3d) come back parsed whole, for
    the reasons noted on STREAM_PATHS. Both kinds are handed to adapters that already iterate,
    so the adapters do not care which they got.

    ATLAS costs two hops: the pinned URL is its release manifest, not the dataset."""
    if source in STREAM_PATHS:
        return _streamed_records(source)
    is_yaml = source in YAML_SOURCES
    raw = _get(URLS[source])
    try:
        data = yaml.safe_load(raw) if is_yaml else json.loads(raw)
    except (ValueError, yaml.YAMLError) as exc:
        fmt = "YAML" if is_yaml else "JSON"
        raise ThreatLibraryImportError(f"source content is not valid {fmt}: {exc}") from exc
    if source == "atlas":
        try:
            data = yaml.safe_load(_get(_resolve_atlas_dataset_url(data)))
        except (ValueError, yaml.YAMLError) as exc:
            raise ThreatLibraryImportError(f"ATLAS dataset is not valid YAML: {exc}") from exc
    check_source_shape(source, data)
    return data


# ---------------------------------------------------------------- write helpers
def group_by_type(records: list[dict]) -> dict[str, list[dict]]:
    """{type_name: [record, ...]} -- one Threat_Type per key."""
    out: dict[str, list[dict]] = collections.defaultdict(list)
    for r in records:
        out[r["type_name"]].append(r)
    return out


def modal_category(recs: list[dict]) -> str:
    """A Threat_Type's default category = the commonest STRIDE among its own threats."""
    return collections.Counter(c for r in recs for c in r["categories"]).most_common(1)[0][0]


def category_ids(sess) -> dict[str, int]:
    """{category name: id} for live Threat_Category rows -- ONE query, read once per import."""
    return {name: cid for name, cid in sess.execute(
        select(m.Threat_Category.ThreatCategoryName, m.Threat_Category.ThreatCategoryID)
        .where(m.Threat_Category.IsActive == True,
               m.Threat_Category.IsDeleted == False))}


def source_count(sess, tag: str) -> int:
    return sess.execute(select(func.count()).select_from(m.Threat_Catalogue)
                        .where(m.Threat_Catalogue.Source == tag)).scalar() or 0


def _existing_type_ids(sess) -> dict[str, int | None]:
    """{normalized type name: id} for every live Threat_Type, read ONCE.

    IO: dal.upsert_threat_type calls _find_active_id_by_norm_name per name, which reads the whole
    table and folds in Python (its docstring's "27 types" assumption is long stale). Pre-loading
    lets a RE-RUN skip that call entirely for names already present. A normalized name shared by
    two rows maps to None so the caller falls through to the DAL, preserving its documented
    never-guess contract."""
    out: dict[str, int | None] = {}
    for tid, name in sess.execute(
            select(m.Threat_Type.ThreatTypeID, m.Threat_Type.ThreatTypeName)
            .where(m.Threat_Type.IsDeleted == False)):
        key = normalize_name(name or "")
        if not key:
            continue
        out[key] = None if key in out else tid
    return out


def _existing_catalogue_ids(sess) -> dict[tuple[int, str], int | None]:
    """{(type_id, normalized name): id} for live Threat_Catalogue rows, read ONCE.

    upsert_threat_catalogue deliberately does NOT dedup -- its docstring states the caller runs
    find_catalogue_id_by_norm_name first and "this function only mints". Honouring that here is
    also the IO fix for re-runs: without it EVERY imported row hits an INSERT, raises
    IntegrityError against UX_ThreatCatalogue_NaturalKey and recovers through the except branch --
    correct, but one savepoint rollback per row, and it silently depends on that index existing.
    Doing the dedup in one query keeps a re-import to zero failed inserts.

    Ambiguity maps to None so the caller falls through to the DAL, preserving its never-guess
    contract (mirrors _existing_type_ids)."""
    out: dict[tuple[int, str], int | None] = {}
    for cid, tid, name in sess.execute(
            select(m.Threat_Catalogue.ThreatCatalogueID, m.Threat_Catalogue.ThreatTypeID,
                m.Threat_Catalogue.ThreatName)
            .where(m.Threat_Catalogue.IsDeleted == False)):
        key = (tid, normalize_name(name or ""))
        if not key[1]:
            continue
        out[key] = None if key in out else cid
    return out


def import_records(sess, records: list[dict], tag: str, created_by: str | None,
                is_active: bool) -> dict:
    """Upsert every record into Threat_Type / Threat_Catalogue (+ category links).

    `is_active` is passed straight to the upserts, so created rows are born with the right
    visibility (see the module docstring). Rows that already existed keep their original
    provenance AND their own IsActive: the upserts are first-writer, so a re-import never
    rewrites who added something, nor un-hides what a curator hid."""
    cat_ids = category_ids(sess)
    missing = sorted({c for r in records for c in r["categories"]} - set(cat_ids))
    if missing:
        raise ThreatLibraryImportError(
            f"STRIDE categories missing from Threat_Category: {missing} -- seed them first")

    known_types = _existing_type_ids(sess)
    known_threats = _existing_catalogue_ids(sess)
    created_types: list[int] = []
    created_threats: list[int] = []
    new_links = 0

    for type_name, recs in group_by_type(records).items():
        bounded = type_name[:300]  # match ThreatTypeName's column width before the lookup
        hit = known_types.get(normalize_name(bounded))
        if hit is not None:
            type_id = hit  # re-run fast path: skips a whole-table read inside the DAL
        else:
            type_id, was_new = dal.upsert_threat_type(
                sess, bounded, cat_ids[modal_category(recs)], source=tag,
                created_by=created_by, is_active=is_active)
            if was_new:
                created_types.append(type_id)
            known_types[normalize_name(bounded)] = type_id

        for r in recs:
            bounded_name = r["threat_name"][:500]  # ThreatName's column width, before the lookup
            key = (type_id, normalize_name(bounded_name))
            hit = known_threats.get(key) if key[1] else None
            if hit is not None:
                cid = hit  # re-run fast path: no INSERT, so no IntegrityError to recover from
            else:
                cid, was_new = dal.upsert_threat_catalogue(
                    sess, bounded_name, type_id, source=tag, created_by=created_by,
                    is_active=is_active)
                if was_new:
                    created_threats.append(cid)
                if key[1]:
                    known_threats[key] = cid
            for c in r["categories"]:
                new_links += dal.link_catalogue_category(sess, cid, cat_ids[c])

    return {"types": len(group_by_type(records)), "threats": len(records),
            "new_category_links": new_links,
            "types_created": len(created_types), "threats_created": len(created_threats)}


def run_import(sess, source: str, *, dry_run: bool = False, activate: bool = True,
               max_actors: int = 40, started_by: str | None = None) -> dict:
    """The one entry point behind the import API and its Celery task.

    Returns, for every source: {source, dry_run, skipped_count, skipped, sample}. Catalogue-shaped
    sources add {types, threats, types_created, threats_created, new_category_links,
    before_count, after_count, activate}; misp_actors adds {actors_found, actors_upserted}. A technically-valid
    source yielding zero usable records adds a `warning` -- zero results must not read like
    success. Raises ThreatLibraryImportError on any validation failure, never SystemExit."""
    if source not in URLS:
        raise ThreatLibraryImportError(f"unknown source {source!r} -- valid: {list(SOURCES)}")
    data = load(source)
    tag = SOURCE_TAGS[source]
    created_by = started_by or f"auto:{tag}"
    result: dict[str, Any] = {"source": source, "dry_run": dry_run}

    try:
        # closing(): adapt_misp_actors BREAKS once max_actors is met, which leaves a streamed
        # generator suspended inside its `with urllib.request.urlopen(...)` and the socket open
        # until GC finalises it. Fine in a script, a slow descriptor leak in a long-lived worker.
        with contextlib.closing(data) if hasattr(data, "close") else contextlib.nullcontext():
            if source == "misp_actors":
                actors, skipped = adapt_misp_actors(data, max_actors)
            else:
                records, skipped = ADAPTERS[source](data)
    except ThreatLibraryImportError:
        raise
    except Exception as exc:
        # The shape sniff catches top-level mismatches; this is the containment net for anything
        # deeper. Capture, don't swallow: full traceback server-side, bounded message to the
        # caller -- never a raw traceback string on the job status.
        log.exception("library_import.adapt_failed", source=source)
        raise ThreatLibraryImportError(
            f"could not parse content as {source!r} data -- check it matches the expected format"
        ) from exc

    if source == "misp_actors":
        result["actors_found"] = len(actors)
        result["actors_upserted"] = 0 if dry_run else len(actors)
        result["sample"] = actors[:RESULT_LIST_CAP]
        if not actors:
            result["warning"] = (f"0 usable actors found for source {source!r} -- check the "
                                 "content matches the selected source")
        elif not dry_run:
            for a in actors:
                dal.upsert_threat_actor(sess, a, source=tag, created_by=created_by)
    else:
        result.update({"types": len(group_by_type(records)), "threats": len(records),
                       "new_category_links": None, "before_count": source_count(sess, tag),
                       "after_count": None, "types_created": 0, "threats_created": 0,
                       "activate": activate, "sample": records[:RESULT_LIST_CAP]})
        if not records:
            result["warning"] = (f"0 usable threats found for source {source!r} -- check the "
                                 "content matches the selected source")
            result["after_count"] = result["before_count"]
        elif dry_run:
            # after_count == before_count and new_category_links stays None: link newness is
            # unknowable without writing, and must not be guessed at.
            result["after_count"] = result["before_count"]
        else:
            result.update(import_records(sess, records, tag, created_by, is_active=activate))
            result["after_count"] = source_count(sess, tag)

    result["skipped_count"] = len(skipped)
    result["skipped"] = skipped[:RESULT_LIST_CAP]
    return result
