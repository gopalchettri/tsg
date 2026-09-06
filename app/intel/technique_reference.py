"""ATT&CK / CAPEC technique reference -- published attack techniques the scenario writer can
consult, keyed by THE THREAT rather than by the asset.

Why this is its own channel. TSG already has two:
  * the threat library  -- asset-keyed via retrieval, and name-only since
    Threat_Catalogue.Description was dropped, so a technique's whole value (its description)
    would be discarded by it;
  * the intel feed      -- asset-keyed too: fetchers.query_intel admits a document through a
    PRODUCT tier (the asset's vendor/technology names, matched over title+tags) or a SCOPE tier
    ('sector:energy', equality on scope_tags). An ATT&CK technique carries neither, so it would
    sit in that collection and match nothing, for any asset, forever.
Nothing about an asset's inventory says whether "Phishing" is relevant; the threat being written
about does. Hence a third channel, queried by threat text.

Storage is a SEPARATE Mongo collection with NO TTL index -- the intel collection expires its
documents by design, and this corpus must not. It is rebuilt on demand
(POST /v1/tsg/threat-intel/techniques/rebuild), staged then renamed, so a killed rebuild can
never leave a half-populated corpus live.
"""
from __future__ import annotations

import itertools
import time
from typing import Any

import ijson

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.stride import STRIDE_ORDER
from app.intel.library_import import ThreatLibraryImportError, stream_json_array

log = get_logger(__name__)

SPOOF, TAMPER, REPUD, INFO, DOS, ELEV = STRIDE_ORDER

COLLECTION = "technique_reference"
_STAGING = "technique_reference__staging"

_BREAKER_COOLDOWN_S = 30.0
_breaker_open_until = 0.0

URLS = {
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "attack_ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "capec": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
}
SOURCES = tuple(sorted(URLS))

SOURCE_TAGS = {"attack": "mitre_attack", "attack_ics": "mitre_attack_ics", "capec": "capec"}

#: Enterprise techniques describe IT tradecraft, ICS describes plant tradecraft. CAPEC is
#: application-layer and applies to both. Used as a soft preference, never a hard exclusion --
#: lookup() falls back to the unmasked pool rather than returning nothing.
APPLIES_TO = {"attack": ["IT"], "attack_ics": ["OT"], "capec": ["IT", "OT"]}

#: Longest description kept in the corpus. The prompt truncates far shorter still (see
#: prompts._technique_block); this bound is about document size, not prompt size.
MAX_DESCRIPTION = 600

# ATT&CK tactic (kill_chain phase_name) -> STRIDE. Enterprise + ICS-only tactics.
# 'resource-development' is deliberately absent: attacker infrastructure prep is not a system
# threat, so those techniques are skipped rather than mapped to something plausible-looking.
TACTIC_STRIDE = {
    "reconnaissance": [INFO],
    "initial-access": [SPOOF, ELEV],
    "execution": [TAMPER, ELEV],
    "persistence": [ELEV],
    "privilege-escalation": [ELEV],
    "defense-evasion": [REPUD],
    "stealth": [REPUD],              # ATT&CK v18 successor of defense-evasion
    "defense-impairment": [TAMPER],  # ATT&CK v18: disabling/altering defensive controls
    "credential-access": [INFO, SPOOF],
    "discovery": [INFO],
    "lateral-movement": [ELEV],
    "collection": [INFO],
    "command-and-control": [TAMPER],
    "exfiltration": [INFO],
    "impact": [TAMPER, DOS],
    # ICS-only
    "impair-process-control": [TAMPER],
    "inhibit-response-function": [DOS],
    "evasion": [REPUD],
}

# CAPEC x_capec_consequences scope -> STRIDE
CAPEC_SCOPE_STRIDE = {
    "confidentiality": INFO, "integrity": TAMPER, "availability": DOS,
    "authentication": SPOOF, "authorization": ELEV, "access_control": ELEV,
    "accountability": REPUD, "non-repudiation": REPUD,
}

_KILL_CHAIN = {"attack": "mitre-attack", "attack_ics": "mitre-ics-attack"}


# ---------------------------------------------------------------- STIX helpers
def _stix_patterns(objects):
    """Yield live (non-revoked, non-deprecated) attack-pattern objects.

    Accepts EITHER a parsed STIX bundle (`{"objects": [...]}`) or the "objects" entries on their
    own. Production streams the entries, so the document is never in memory; the builders' unit
    tests hand over a whole bundle, which is the natural way to write them and a contract worth
    keeping. Both builders funnel through here, so supporting both costs one line, once.
    """
    if isinstance(objects, dict):
        objects = objects.get("objects", [])
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        yield obj


def _stix_ext_id(obj, source_names) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in source_names and ref.get("external_id"):
            return ref["external_id"]
    return None


def _clean(text: str | None, limit: int = MAX_DESCRIPTION) -> str:
    """Collapse whitespace and bound the length. Fence delimiters are stripped HERE, at build
    time, so no document in the corpus can ever forge a prompt-block boundary -- checked again by
    assert_fence_safe below, and defanged a third time at render. Belt and braces, because this
    text reaches a model prompt."""
    return " ".join((text or "").split())[:limit].replace("<<<", "").replace(">>>", "")


# ---------------------------------------------------------------- builders
def build_attack(data, source: str) -> tuple[list[dict], list[dict]]:
    """ATT&CK Enterprise or ICS -> corpus entries. Sub-techniques are kept: unlike the library
    import (where they would fork Threat_Types), here every entry is a flat reference row and a
    sub-technique is often the most specific, most useful description."""
    kill_chain = _KILL_CHAIN[source]
    entries, skipped = [], []
    for obj in _stix_patterns(data):
        ext_id = _stix_ext_id(obj, {"mitre-attack"})
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == kill_chain]
        stride = sorted({c for t in tactics for c in TACTIC_STRIDE.get(t, [])})
        if not (ext_id and stride):
            # ONE entry per skip. The retired module appended this twice, inflating every
            # unmapped-tactic count by 2x in the reported totals.
            skipped.append({"reason": f"unmapped tactic(s): {tactics}" if ext_id
                            else "no mitre-attack external id",
                            "item": f"{ext_id or '?'} {obj.get('name')}".strip()})
            continue
        entries.append({
            "id": ext_id,
            "name": _clean(obj.get("name"), 200),
            "description": _clean(obj.get("description")),
            "source": SOURCE_TAGS[source],
            "stride": stride,
            "applies_to": list(APPLIES_TO[source]),
        })
    return entries, skipped


def build_capec(data, source: str = "capec") -> tuple[list[dict], list[dict]]:
    """CAPEC attack patterns -> corpus entries. Meta/Standard abstractions only: Detailed ones
    are variants of a Standard parent and would flood the corpus with near-duplicates."""
    entries, skipped = [], []
    for obj in _stix_patterns(data):
        if obj.get("x_capec_abstraction") not in ("Meta", "Standard"):
            continue
        if obj.get("x_capec_status") in ("Deprecated", "Obsolete"):
            continue
        ext_id = _stix_ext_id(obj, {"capec"})
        scopes = [s.lower() for s in (obj.get("x_capec_consequences") or {})]
        stride = sorted({CAPEC_SCOPE_STRIDE[s] for s in scopes if s in CAPEC_SCOPE_STRIDE})
        if not (ext_id and stride):
            skipped.append({"reason": f"no mappable consequences: {scopes}" if ext_id
                            else "no capec external id",
                            "item": f"{ext_id or '?'} {obj.get('name')}".strip()})
            continue
        entries.append({
            "id": ext_id,
            "name": _clean(obj.get("name"), 200),
            "description": _clean(obj.get("description")),
            "source": SOURCE_TAGS[source],
            "stride": stride,
            "applies_to": list(APPLIES_TO[source]),
        })
    return entries, skipped


BUILDERS = {"attack": build_attack, "attack_ics": build_attack, "capec": build_capec}


def assert_fence_safe(entries: list[dict]) -> None:
    """No corpus document may contain a prompt-fence delimiter. Enforced at BUILD time so the
    guarantee holds for every reader of the collection, not only the one render path that also
    defangs. A violation is a bug in _clean, not bad input to tolerate."""
    for e in entries:
        for field in ("id", "name", "description"):
            if "<<<" in str(e.get(field, "")) or ">>>" in str(e.get(field, "")):
                raise ThreatLibraryImportError(
                    f"technique {e.get('id')!r} carries a fence delimiter in {field!r} "
                    "after cleaning -- refusing to publish it")


def _streamed_objects(source: str):
    """Stream a STIX bundle's "objects" entries, preserving the old shape error.

    The whole-document check this replaces (`isinstance(data, dict) and "objects" in data`) is
    impossible on a stream, so the same guarantee is kept by outcome: a document that is not a
    STIX bundle yields NOTHING at "objects.item", and that is raised with the identical message.
    Checked on the first record, before the rest are consumed, so a wrong source fails fast
    instead of after a 51 MB download has been walked.
    """
    shape_error = ThreatLibraryImportError(
        f"content does not match the {source!r} format -- expected a STIX bundle object "
        'with an "objects" list')
    def _wrapped(stream):
        """Translate ijson errors for EVERY record, not just the first.

        A bundle that goes malformed 40 MB in would otherwise surface a raw ijson exception from
        inside the builder loop, long after the friendly message was possible -- the whole-body
        version could not have that problem because json.loads validated everything up front.
        """
        try:
            yield from stream
        except ijson.JSONError as exc:
            raise ThreatLibraryImportError(
                f"{source!r} content is not valid JSON: {exc}") from exc

    try:
        it = _wrapped(stream_json_array(URLS[source], "objects.item"))
        first = next(it, None)
    except ijson.JSONError as exc:
        raise ThreatLibraryImportError(
            f"{source!r} content is not valid JSON: {exc}") from exc
    if first is None:
        raise shape_error
    return itertools.chain([first], it)


def build_entries(sources: list[str]) -> tuple[list[dict], list[dict]]:
    """Download and normalize every requested source. Entries are sorted by id so the corpus --
    and therefore the embedding text list, and therefore embeddings.get_matrix's digest -- is
    byte-stable across rebuilds that fetched identical upstream data."""

    entries: list[dict] = []
    skipped: list[dict] = []
    for source in sources:
        if source not in URLS:
            raise ThreatLibraryImportError(
                f"unknown technique source {source!r} -- valid: {list(SOURCES)}")
        got, skip = BUILDERS[source](_streamed_objects(source), source)
        entries.extend(got)
        skipped.extend(skip)
    # An id can appear in more than one requested source; first source wins, deterministically.
    deduped: dict[str, dict] = {}
    for e in entries:
        deduped.setdefault(e["id"], e)
    out = sorted(deduped.values(), key=lambda e: e["id"])
    assert_fence_safe(out)
    return out, skipped


# ---------------------------------------------------------------- storage
def _store(name: str = COLLECTION):
    """Collection handle. Deliberately NO TTL index -- fetchers._intel_store expires its docs on
    `fetched_at` by design, and this corpus must survive indefinitely; it changes only when MITRE
    ships a release. `id` is unique so a rebuild cannot publish duplicates."""
    import pymongo

    s = get_settings()
    col = pymongo.MongoClient(
        s.mongo_url,
        serverSelectionTimeoutMS=s.mongo_connect_timeout_ms,
        connectTimeoutMS=s.mongo_connect_timeout_ms,
        socketTimeoutMS=max(s.mongo_connect_timeout_ms, 30000),
    )[s.mongo_db][name]
    col.create_index("id", unique=True)
    return col


def _store_if_healthy(name: str = COLLECTION):
    """Same fixed-cooldown breaker contract as fetchers._store_if_healthy -- a Mongo outage
    returns None instead of hammering reconnects. Every read path treats None as 'no corpus',
    which degrades the prompt rather than failing the scenario."""
    global _breaker_open_until
    now = time.monotonic()
    if now < _breaker_open_until:
        return None
    try:
        col = _store(name)
    except Exception:
        _breaker_open_until = now + _BREAKER_COOLDOWN_S
        log.warning("technique_reference.mongo_breaker_open",
                    cooldown_seconds=_BREAKER_COOLDOWN_S, exc_info=True)
        return None
    _breaker_open_until = 0.0
    return col


def publish(entries: list[dict], built_at) -> int:
    """Replace the live corpus with `entries`, ATOMICALLY.

    Written to a staging collection and renamed over the live one, so a worker killed mid-rebuild
    leaves the previous corpus completely intact -- never a half-populated one, which would
    silently degrade every scenario until someone noticed. Returns the document count."""
    if not entries:
        raise ThreatLibraryImportError("refusing to publish an empty technique corpus")
    staging = _store(_STAGING)
    staging.drop()
    staging = _store(_STAGING)
    docs = [dict(e, built_at=built_at) for e in entries]
    staging.insert_many(docs, ordered=False)
    # dropTarget replaces the live collection in one metadata operation; readers see either the
    # old corpus or the new one, never a mixture.
    staging.rename(COLLECTION, dropTarget=True)
    _invalidate_cache()
    return len(docs)


def stats() -> dict[str, Any]:
    """What the corpus currently holds -- the health check behind GET .../techniques.
    `total: 0` means scenarios are running WITHOUT the reference block: nothing breaks (the
    prompt is byte-identical to the pre-feature one) but quality is lower, and this is how an
    operator sees that rather than guessing."""
    col = _store_if_healthy()
    if col is None:
        return {"total": 0, "by_source": {}, "by_stride": {}, "built_at": None,
                "available": False, "sample": []}
    by_source: dict[str, int] = {}
    by_stride: dict[str, int] = {}
    built_at = None
    total = 0
    for doc in col.find({}, {"_id": 0, "source": 1, "stride": 1, "built_at": 1}):
        total += 1
        by_source[doc.get("source", "?")] = by_source.get(doc.get("source", "?"), 0) + 1
        for c in doc.get("stride") or ():
            by_stride[c] = by_stride.get(c, 0) + 1
        built_at = built_at or doc.get("built_at")
    sample = list(col.find({}, {"_id": 0, "id": 1, "name": 1, "stride": 1, "applies_to": 1})
                .sort("id", 1).limit(3))
    return {"total": total, "by_source": by_source, "by_stride": by_stride,
            "built_at": built_at, "available": True, "sample": sample}


# ---------------------------------------------------------------- lookup
#: Cached corpus per process: (built_at, entries, passage texts). Loading ~800 docs on every
#: scenario would be pure waste -- the corpus changes only on an explicit rebuild.
_CACHE: tuple[Any, list[dict], list[str]] | None = None
_CACHE_CHECKED_AT = 0.0
#: How long a cached corpus is trusted before its `built_at` is re-checked. One tiny find_one,
#: not a reload, so a rebuild on another pod propagates within this window instead of requiring
#: a restart -- the reason this corpus is in Mongo rather than a file.
_REVALIDATE_S = 60.0


def _invalidate_cache() -> None:
    global _CACHE, _CACHE_CHECKED_AT
    _CACHE, _CACHE_CHECKED_AT = None, 0.0


def passage_text(entry: dict, limit: int) -> str:
    """THE embedded text for one technique -- id, name and description.

    Unlike embeddings.catalogue_passage_text (name-only since Threat_Catalogue.Description was
    dropped) this KEEPS the description: carrying it is the entire reason this channel exists.
    Shape mirrors embeddings._CONTROL_TEXT (`name + ": " + description`)."""
    return f"{entry['id']} {entry['name']}: {entry['description']}".strip()[:limit]


def _corpus() -> tuple[list[dict], list[str]]:
    """(entries, passage texts) for the WHOLE corpus, ordered by id.

    Order is stable and the full set is always returned, because embeddings.get_matrix memoizes
    on sha256 of the joined text list: returning a filtered subset would mint a new digest per
    filter combination and thrash that cache (see lookup)."""
    global _CACHE, _CACHE_CHECKED_AT
    now = time.monotonic()
    if _CACHE is not None and now - _CACHE_CHECKED_AT < _REVALIDATE_S:
        return _CACHE[1], _CACHE[2]

    col = _store_if_healthy()
    if col is None:
        return [], []
    try:
        head = col.find_one({}, {"_id": 0, "built_at": 1}, sort=[("id", 1)])
    except Exception:
        log.warning("technique_reference.revalidate_failed", exc_info=True)
        return (_CACHE[1], _CACHE[2]) if _CACHE else ([], [])
    _CACHE_CHECKED_AT = now
    built_at = head.get("built_at") if head else None
    if _CACHE is not None and _CACHE[0] == built_at:
        return _CACHE[1], _CACHE[2]
    if head is None:
        # Empty corpus is a valid state (nobody has run a rebuild yet). Log once per
        # revalidation window, never per scenario -- fail open, but never fail silent.
        log.warning("technique_reference.corpus_empty",
                    hint="POST /v1/tsg/threat-intel/techniques/rebuild")
        _CACHE = (None, [], [])
        return [], []

    limit = get_settings().max_embed_chars
    entries = list(col.find({}, {"_id": 0}).sort("id", 1))
    texts = [passage_text(e, limit) for e in entries]
    _CACHE = (built_at, entries, texts)
    log.info("technique_reference.corpus_loaded", total=len(entries), built_at=str(built_at))
    return entries, texts


def corpus_vocabulary() -> set[str]:
    """The DISTINCT applies_to labels the live corpus actually carries.

    Read from the data, never a constant: when a future rebuild tags entries with labels beyond
    IT/OT, grounding.resolve_asset_labels widens to them with no code change here -- the same
    "nothing is hardcoded" property grounding.control_itot_vocabulary gives the control filter."""
    entries, _ = _corpus()
    return {label for e in entries for label in (e.get("applies_to") or ())}


def lookup(llm, query: str, *, stride: str | None = None,
        asset_labels: list[str] | set[str] | None = None,
        k: int = 4) -> list[dict]:
    """The `k` techniques closest to `query`, preferring this threat's STRIDE and asset type.

    Fail-open everywhere: no corpus, no numpy, an embedding failure or nothing above zero all
    return [] and the caller emits no block, leaving the prompt byte-identical to the
    pre-feature one.

    `asset_labels` is a SET, resolved through grounding.resolve_asset_labels: an asset is rarely
    one thing, and a single label could not express OT+IT. None means "no asset preference" --
    which that resolver returns whenever any of the session's categories is absent from the
    corpus vocabulary, so an asset whose nature is only partly representable is never silently
    narrowed. That failure mode is a documented past defect, not a hypothetical.

    MASK, NEVER PRE-FILTER -- the load-bearing performance decision. embeddings.get_matrix
    memoizes on (model_id, group, kind) -> sha256 of the joined texts, keeping only
    _MATRIX_SHAPES digests per key. Handing it a STRIDE/asset-filtered subset would produce up
    to 6x2 distinct text lists, so the digests would evict one another and the ~800-row matrix
    would be rebuilt over and over. Scoring the full corpus and zeroing the rows that fail the
    predicate keeps it to ONE digest and ONE matrix per process, for one extra dot product over
    rows that are discarded anyway."""
    from app.pipeline import embeddings

    if not (query or "").strip():
        return []
    entries, texts = _corpus()
    if not entries:
        return []
    s = get_settings()
    try:
        got = embeddings.get_matrix(llm, texts, model_id=s.embedding_model,
                                    group=COLLECTION, kind="passage")
        if got is None:  # numpy missing, or no usable vectors
            return []
        mat, row_idx = got
        # Through get_vectors, not llm.embed directly, so the SAME threat asked again -- a
        # scenario variant, a retried stage -- hits L1/L2 instead of paying for a second embed.
        qv = embeddings.get_vectors(llm, [query], model_id=s.embedding_model,
                                    group=COLLECTION, kind="query")[query]
    except Exception:
        log.warning("technique_reference.lookup_failed", exc_info=True)
        return []

    import numpy as np

    q = np.asarray(qv, dtype=np.float32)
    if q.shape[0] != mat.shape[1]:
        log.warning("technique_reference.query_dimension_mismatch",
                    query_dim=int(q.shape[0]), corpus_dim=int(mat.shape[1]))
        return []
    norm = float(np.linalg.norm(q)) or 1.0
    scores = mat @ (q / norm)

    wanted = set(asset_labels or ())

    def _ranked(masked: bool) -> list[int]:
        out = []
        for i, ri in enumerate(row_idx):
            if masked:
                e = entries[ri]
                if stride and stride not in (e.get("stride") or ()):
                    continue
                # UNION, not equality: an OT+IT asset legitimately wants both families.
                if wanted and not (wanted & set(e.get("applies_to") or ())):
                    continue
            if scores[i] > 0:
                out.append(i)
        # -score first, then row index: a deterministic tie-break, so a fixed corpus and a fixed
        # query always yield the same block (the G-14 determinism contract).
        return sorted(out, key=lambda i: (-float(scores[i]), i))[:k]

    picked = _ranked(masked=True)
    if not picked:
        # Same [R6] fallback grounding.get_possible_types takes: a filter that empties the pool
        # must widen, not return nothing.
        picked = _ranked(masked=False)
    return [entries[row_idx[i]] for i in picked]
