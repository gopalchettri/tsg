"""Shared core for importing open-source threat libraries — the logic that used to live
inside scripts/import_threat_libraries.py, moved here so BOTH front doors (the CLI script
and the tsg.import_threat_library Celery task behind POST /v1/tsg/threat-library/import)
drive the exact same code. Each source is adapted to normalized records
{type_name, threat_name, description, stride_categories[]} and upserted through the same
race-safe DAL functions the R10 promotion path uses; OT-flavored sources additionally
auto-write boost-only Config_Threat_Rule rows (apply_ot_rules below).

Validation failures raise ThreatLibraryImportError — NEVER SystemExit: SystemExit is a
BaseException, and Celery treats an uncaught SystemExit inside task code as a
worker-termination signal (the SIGTERM shutdown mechanism), so a merely-invalid request
could crash the whole worker and every other in-flight pipeline task on it.
"""
from __future__ import annotations

import collections
import json
import re
import urllib.request

from sqlalchemy import func, select

from app.core.enums import ThreatRuleType
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m

log = get_logger(__name__)


class ThreatLibraryImportError(Exception):
    """A structurally-valid but business-rule-invalid import request (unknown source,
    bad via_taxii combo, unparseable/mismatched file content, unseeded STRIDE
    categories) -> 422, same envelope shape as every other domain error
    (registered in app/api/errors.py, mirrored on AdminValidationError)."""


# Canonical STRIDE names — must match the seeded Threat_Category rows.
SPOOF, TAMPER, REPUD, INFO, DOS, ELEV = (
    "Spoofing", "Tampering", "Repudiation", "Information Disclosure",
    "Denial of Service", "Elevation of Privilege",
)

URLS = {
    "pytm": "https://raw.githubusercontent.com/OWASP/pytm/master/pytm/threatlib/threats.json",
    "threat_composer": "https://raw.githubusercontent.com/awslabs/threat-composer/main/packages/threat-composer/src/data/threatPacks/generated/GenAIChatbot.json",
    "capec": "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "attack_ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
    "emb3d": "https://raw.githubusercontent.com/mitre/emb3d/main/_data/threats.json",
    "misp_actors": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
}
OT_SOURCES = {"attack_ics", "emb3d"}
SOURCE_TAGS = {  # Threat_Type.Source / Threat_Catalogue.Source provenance values
    "pytm": "pytm", "threat_composer": "aws_threat_composer", "capec": "capec",
    "attack": "mitre_attack", "attack_ics": "mitre_attack_ics", "emb3d": "mitre_emb3d",
    "misp_actors": "misp_galaxy",
}

# Weight for the auto-written OT relevance rules — matches scoping._DEFAULT_RULE_WEIGHT,
# kept explicit here so the persisted Metadata is self-documenting.
_AUTO_OT_RELEVANCE_WEIGHT = 10.0

# The result dict caps the skipped list it carries (full counts always reported) — a big
# STIX bundle can skip hundreds of rows, and this dict travels through the Celery result
# backend to an API response.
_SKIPPED_CAP = 50

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

# ATT&CK tactic (kill_chain phase_name) -> STRIDE. Enterprise + ICS-only tactics.
# 'resource-development' is deliberately absent: attacker infra prep is not a
# system threat — those techniques go to the skipped report.
TACTIC_STRIDE = {
    "reconnaissance": [INFO],
    "initial-access": [SPOOF, ELEV],
    "execution": [TAMPER, ELEV],
    "persistence": [ELEV],
    "privilege-escalation": [ELEV],
    "defense-evasion": [REPUD],
    "stealth": [REPUD],              # ATT&CK v18 successor of defense-evasion (hiding traces)
    "defense-impairment": [TAMPER],  # ATT&CK v18: disabling/altering defensive controls
    "credential-access": [INFO, SPOOF],
    "discovery": [INFO],
    "lateral-movement": [ELEV],
    "collection": [INFO],
    "command-and-control": [TAMPER],
    "exfiltration": [INFO],
    "impact": [TAMPER, DOS],
    # ICS-only tactics
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

# EMB3D top-level category -> STRIDE (coarse; unknown categories are skipped, not guessed)
EMB3D_CATEGORY_STRIDE = {
    "hardware": [TAMPER, INFO],
    "system software": [TAMPER, ELEV],
    "application software": [TAMPER, ELEV],
    "networking": [SPOOF, INFO, DOS],
}

# Threat Composer impactedGoal -> STRIDE
TC_GOAL_STRIDE = {"confidentiality": INFO, "integrity": TAMPER, "availability": DOS}

# MISP actor relevance filter for CII (keeps the Threat_Actor table — and the
# threats_prompt actor hint built from it — focused instead of 700+ rows)
CII_KEYWORDS = ("critical infrastructure", "energy", "ics", "scada", "industrial",
                "utilities", "banking", "financial", "government", "telecom", "water")


def _tidy(phase: str) -> str:
    return phase.replace("-", " ").title()


# ---------------------------------------------------------------- adapters
# Each returns (records, skipped) where records are
# {type_name, threat_name, description, categories} and skipped are
# {reason, item} entries for the report. misp_actors returns actor names instead.

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
            "threat_name": f"{sid} {t['description']}".strip(),
            "description": (t.get("details") or "")[:1000] or None,
            "categories": cats,
        })
    return records, skipped


def adapt_threat_composer(data) -> tuple[list[dict], list[dict]]:
    pack_name = data.get("name") or "Threat Composer Pack"
    records, skipped = [], []
    for t in data.get("threats", []):
        stmt = t.get("statement") or ""
        goals = [g.lower() for g in (t.get("impactedGoal") or [])]
        cats = sorted({TC_GOAL_STRIDE[g] for g in goals if g in TC_GOAL_STRIDE})
        if not cats:
            skipped.append({"reason": "no mappable impactedGoal", "item": stmt[:120]})
            continue
        name = (t.get("threatAction") or stmt[:120]).strip()
        records.append({
            "type_name": pack_name,
            "threat_name": name,
            "description": stmt[:1000] or None,
            "categories": cats,
        })
    return records, skipped


def _stix_patterns(data):
    """Yield live (non-revoked, non-deprecated) attack-pattern objects."""
    for obj in data.get("objects", []):
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


def _adapt_attack(data, kill_chain_name: str, type_prefix: str):
    records, skipped = [], []
    for obj in _stix_patterns(data):
        if obj.get("x_mitre_is_subtechnique"):
            continue
        ext_id = _stix_ext_id(obj, {"mitre-attack"})
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == kill_chain_name]
        cats = sorted({c for t in tactics for c in TACTIC_STRIDE.get(t, [])})
        if not cats:
            skipped.append({"reason": f"unmapped tactic(s): {tactics}", "item": f"{ext_id} {obj.get('name')}"})
            continue
        # one Threat_Type per tactic family; techniques spanning tactics file under the first
        type_name = f"{type_prefix} – {_tidy(tactics[0])}"
        records.append({
            "type_name": type_name,
            "threat_name": f"{ext_id} {obj.get('name')}".strip(),
            "description": (obj.get("description") or "")[:1000] or None,
            "categories": cats,
        })
    return records, skipped


def adapt_attack(data):
    return _adapt_attack(data, "mitre-attack", "ATT&CK")


def adapt_attack_ics(data):
    return _adapt_attack(data, "mitre-ics-attack", "ICS ATT&CK")


def adapt_capec(data) -> tuple[list[dict], list[dict]]:
    records, skipped = [], []
    for obj in _stix_patterns(data):
        if obj.get("x_capec_abstraction") not in ("Meta", "Standard"):
            continue
        if obj.get("x_capec_status") in ("Deprecated", "Obsolete"):
            continue
        ext_id = _stix_ext_id(obj, {"capec"})
        scopes = [s.lower() for s in (obj.get("x_capec_consequences") or {}).keys()]
        cats = sorted({CAPEC_SCOPE_STRIDE[s] for s in scopes if s in CAPEC_SCOPE_STRIDE})
        if not cats:
            skipped.append({"reason": f"no mappable consequences: {scopes}", "item": f"{ext_id} {obj.get('name')}"})
            continue
        domain = (obj.get("x_capec_domains") or ["General"])[0]
        records.append({
            "type_name": f"CAPEC – {domain}",
            "threat_name": f"{ext_id} {obj.get('name')}".strip(),
            "description": (obj.get("description") or "")[:1000] or None,
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
            skipped.append({"reason": f"unknown EMB3D category: {category}", "item": f"{t.get('id')} {t.get('text')}"})
            continue
        records.append({
            "type_name": f"Embedded Device – {category.title()}",
            "threat_name": f"{t.get('id')} {t.get('text')}".strip(),
            "description": None,  # EMB3D threats.json carries name + category only
            "categories": cats,
        })
    return records, skipped


def adapt_misp_actors(data, max_actors: int) -> tuple[list[str], list[dict]]:
    actors, skipped = [], []
    for v in data.get("values", []):
        blob = json.dumps(v, ensure_ascii=False).lower()
        if not any(k in blob for k in CII_KEYWORDS):
            continue
        actors.append(v["value"])
        if len(actors) >= max_actors:
            skipped.append({"reason": f"max_actors cap ({max_actors}) reached; remaining CII-relevant actors not imported",
                            "item": "raise max_actors to import more"})
            break
    return actors, skipped


ADAPTERS = {
    "pytm": adapt_pytm,
    "threat_composer": adapt_threat_composer,
    "capec": adapt_capec,
    "attack": adapt_attack,
    "attack_ics": adapt_attack_ics,
    "emb3d": adapt_emb3d,
}

# Per-source-family top-level JSON shape — the cheap pre-parse sniff the API handler runs
# before dispatching (valid JSON of the WRONG shape would otherwise crash deep inside an
# adapter with a meaningless AttributeError). (predicate, human-readable expectation).
EXPECTED_SHAPES: dict[str, tuple] = {
    "pytm": (lambda d: isinstance(d, list), "a JSON list of pytm threat objects"),
    "threat_composer": (lambda d: isinstance(d, dict) and "threats" in d, 'a JSON object with a "threats" list'),
    "capec": (lambda d: isinstance(d, dict) and "objects" in d, 'a STIX bundle object with an "objects" list'),
    "attack": (lambda d: isinstance(d, dict) and "objects" in d, 'a STIX bundle object with an "objects" list'),
    "attack_ics": (lambda d: isinstance(d, dict) and "objects" in d, 'a STIX bundle object with an "objects" list'),
    "emb3d": (lambda d: isinstance(d, (dict, list)), 'a JSON object with a "threats" list (or a bare list)'),
    "misp_actors": (lambda d: isinstance(d, dict) and "values" in d, 'a MISP galaxy object with a "values" list'),
}


def check_source_shape(source: str, data) -> None:
    """Raise ThreatLibraryImportError unless `data`'s top-level shape matches what
    `source`'s adapter expects. Shared by the API handler (pre-dispatch, so a mismatched
    upload never reaches the queue) and load() below (so the CLI/task path gets the same
    clean error instead of an adapter crash)."""
    predicate, expected = EXPECTED_SHAPES[source]
    if not predicate(data):
        raise ThreatLibraryImportError(
            f"content does not match the {source!r} format — expected {expected}")


# ---------------------------------------------------------------- IO + import
def load(source: str, file_content: str | None, via_taxii: bool):
    """Resolve the raw data for one import: in-memory content (API upload or CLI --file,
    already read into a string) > TAXII > pinned https download. Every failure mode a
    caller can cause raises ThreatLibraryImportError (see module docstring for why never
    SystemExit)."""
    if file_content is not None and via_taxii:
        raise ThreatLibraryImportError("provide file content OR via_taxii, not both")
    if file_content is not None:
        try:
            data = json.loads(file_content)
        except ValueError as exc:
            raise ThreatLibraryImportError(f"file content is not valid JSON: {exc}") from exc
    elif via_taxii:
        if source not in ("attack", "attack_ics"):
            raise ThreatLibraryImportError("via_taxii is only supported for attack / attack_ics")
        from app.intel.taxii_client import fetch_collection_bundle  # lazy: Phase B module
        data = fetch_collection_bundle(source)
    else:
        url = URLS[source]
        log.info("threat_library_import.downloading", source=source, url=url)
        with urllib.request.urlopen(url, timeout=180) as resp:  # noqa: S310 — pinned https URLs above
            data = json.load(resp)
    check_source_shape(source, data)
    return data


def category_ids(sess) -> dict[str, int]:
    rows = sess.execute(
        select(m.Threat_Category.ThreatCategoryName, m.Threat_Category.ThreatCategoryID)
        .where(m.Threat_Category.IsActive == True, m.Threat_Category.IsDeleted == False)  # noqa: E712
    ).all()
    return {name: cid for name, cid in rows}


def source_count(sess, tag: str) -> int:
    return sess.execute(
        select(func.count()).select_from(m.Threat_Catalogue).where(m.Threat_Catalogue.Source == tag)
    ).scalar() or 0


def import_records(sess, records: list[dict], tag: str) -> dict:
    """Upsert every record into Threat_Type/Threat_Catalogue (+ category links). Returns
    stats INCLUDING type_ids (type_name -> ThreatTypeID) so apply_ot_rules can key its
    rules without re-querying."""
    cat_ids = category_ids(sess)
    missing = sorted({c for r in records for c in r["categories"]} - set(cat_ids))
    if missing:
        raise ThreatLibraryImportError(
            f"STRIDE categories missing from Threat_Category: {missing} — seed them first")

    # type default category = most common category among the type's threats
    by_type: dict[str, list[dict]] = collections.defaultdict(list)
    for r in records:
        by_type[r["type_name"]].append(r)

    new_links = 0
    type_ids: dict[str, int] = {}
    for type_name, recs in by_type.items():
        counts = collections.Counter(c for r in recs for c in r["categories"])
        default_cat = cat_ids[counts.most_common(1)[0][0]]
        type_id = dal.upsert_threat_type(sess, type_name, default_cat, None, source=tag)
        type_ids[type_name] = type_id
        for r in recs:
            cat_id_ = dal.upsert_threat_catalogue(sess, r["threat_name"], type_id, None,
                                                  description=r["description"], source=tag)
            for c in r["categories"]:
                new_links += dal.link_catalogue_category(sess, cat_id_, cat_ids[c])
    return {"types": len(by_type), "threats": len(records), "new_category_links": new_links,
            "type_ids": type_ids}


def apply_ot_rules(sess, records: list[dict], type_ids: dict[str, int], tag: str,
                   dry_run: bool) -> list[dict]:
    """Auto-write one BOOST-ONLY scoping rule per imported OT threat type: relevance_flag
    on asset_type='OT' (deliberately never tech_gate — a wrong auto-rule may only nudge
    ranking, never silently hide a threat). Replaces the old print-only suggest_ot_rules.
    Returns the rules written (or previewed, on dry_run) for the job's visible result."""
    rules = []
    for type_name in sorted({r["type_name"] for r in records}):
        entry = {"threat_type_id": type_ids.get(type_name), "threat_type_name": type_name,
                 "rule_key": "asset_type"}
        if not dry_run:
            entry["threat_rule_id"] = dal.upsert_threat_rule(
                sess, type_ids[type_name], str(ThreatRuleType.relevance_flag), "asset_type",
                "OT", _AUTO_OT_RELEVANCE_WEIGHT, source=f"auto:{tag}")
        rules.append(entry)
    return rules


def run_import(sess, source: str, *, file_content: str | None = None, via_taxii: bool = False,
               max_actors: int = 40, dry_run: bool = False) -> dict:
    """The one entry point both front doors (CLI script, Celery task) call.

    Returns, for every source: {source, dry_run, skipped_count, skipped (first
    _SKIPPED_CAP entries)}. Catalogue-shaped sources add {types, threats,
    new_category_links (None on dry_run — link newness is unknowable without writing),
    before_count, after_count, ot_rules} — ot_rules is [] for non-OT sources. misp_actors
    adds {actors_upserted} instead. A technically-valid file yielding zero usable records
    adds a "warning" (zero-results must not read like success). Raises
    ThreatLibraryImportError on any validation failure — never SystemExit."""
    if source not in URLS:
        raise ThreatLibraryImportError(f"unknown source {source!r} — valid: {sorted(URLS)}")
    data = load(source, file_content, via_taxii)
    tag = SOURCE_TAGS[source]
    result: dict = {"source": source, "dry_run": dry_run}

    if source == "misp_actors":
        try:
            actors, skipped = adapt_misp_actors(data, max_actors)
        except Exception as exc:  # noqa: BLE001 — same containment net as ADAPTERS below
            # This branch sat OUTSIDE the try/except that wraps every other source, so an
            # item-level malformation (a values[] entry with CII keywords but no "value" key)
            # escaped as a raw KeyError — a 500-class traceback string on the job status
            # instead of the bounded 422-class message every sibling source produces.
            log.exception("threat_library_import.adapt_failed", source=source)
            raise ThreatLibraryImportError(
                f"could not parse content as {source!r} data — check it matches the "
                "expected format") from exc
        if not dry_run:
            for a in actors:
                dal.upsert_threat_actor(sess, a)
        # actors_upserted must not claim writes a dry run never made, and zero usable records
        # has to read as a problem here exactly as it does for every other source.
        result["actors_upserted"] = 0 if dry_run else len(actors)
        result["actors_found"] = len(actors)
        if not actors:
            result["warning"] = (f"0 usable actors found for source {source!r} — check the "
                                "content matches the selected source")
    else:
        try:
            records, skipped = ADAPTERS[source](data)
        except Exception as exc:
            # The shape sniff catches top-level mismatches; this is the containment net for
            # anything deeper (capture, don't swallow: full traceback server-side, bounded
            # message to the caller — never a raw traceback string on the job status).
            log.exception("threat_library_import.adapt_failed", source=source)
            raise ThreatLibraryImportError(
                f"could not parse content as {source!r} data — check it matches the "
                "expected format") from exc
        result.update({"types": len({r["type_name"] for r in records}), "threats": len(records),
                       "new_category_links": None, "before_count": source_count(sess, tag),
                       "after_count": None, "ot_rules": []})
        if not records:
            result["warning"] = (f"0 usable threats found for source {source!r} — check the "
                                 "content matches the selected source")
        elif dry_run:
            if source in OT_SOURCES:
                result["ot_rules"] = apply_ot_rules(sess, records, {}, tag, dry_run=True)
            result["after_count"] = result["before_count"]
        else:
            stats = import_records(sess, records, tag)
            type_ids = stats.pop("type_ids")
            result.update(stats)
            if source in OT_SOURCES:
                result["ot_rules"] = apply_ot_rules(sess, records, type_ids, tag, dry_run=False)
            result["after_count"] = source_count(sess, tag)

    result["skipped_count"] = len(skipped)
    result["skipped"] = skipped[:_SKIPPED_CAP]
    return result
