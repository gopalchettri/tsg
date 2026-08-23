from __future__ import annotations

import difflib
import json
import math
import re
from collections.abc import Callable
from typing import Any, NamedTuple, overload

from sqlalchemy import func, insert, update
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import (
    AuditEventType,
    DuplicateReason,
    ScenarioStatus,
    ScopingRejection,
    SelectionReason,
    SessionStatus,
    SSEEventType,
    StageStatus,
    SubsystemLevel,
    WorkflowStage,
)
from app.core.logging import get_logger
from app.core.security import _redact_value, is_placeholder
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, guid, now
from app.pipeline import control_mapping, grounding, prompts, scoping, validation
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, Provenance, moderate
from app.sse import bus

log = get_logger(__name__)

_EPOCH = 1
_WORK_LEVELS = (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS)
_SCENARIO_TEXT_FIELDS = ("scenario_title", "scenario_statement", "risk_statement")
ASSET_UNIT_ID = 0

#: Prepositions that can appear right before an asset name (e.g. "of X", "from X").
#: Used by both cleanup steps in asset_agnostic_name so they can't drift out of sync —
#: they used to be two separate lists that disagreed, which left leftover words like
#: "from" dangling after the asset name was removed.
_ASSET_PREPOSITIONS = "of|from|to|in|on|for|against|at"

#: Subsystem fields used to build intel search terms (technology names, vendors, platforms).
#: Subsystem asset_type is deliberately excluded — it's just an IT/OT label, not a product
#: name, and is only used to decide is_ot. The asset-level asset_type (free text like
#: "Power Plant") IS included below.
_INTEL_TECH_FIELDS = ("technology_used", "vendor_name", "database_platforms",
                    "saas_platform_list", "public_cloud_platforms")

#: Placeholder values the model sends when it has no real name. Compared after stripping
#: brackets/quotes/punctuation and lowercasing, so "N/A", '["N/A"]', "(none)", "NULL" etc.
#: all match something here. Add new placeholders to this list only.
_JUNK_NAME_TOKENS = frozenset({
    "", "na", "n a", "none", "null", "nil", "tbd", "unknown", "not applicable",
    "not available", "no name", "no threat", "empty", "NA", "N/A", "N A", "None", "NULL",
    "Nil", "TBD", "Unknown", "Not Applicable", "[]","{}", "['']", '[""]', "['N/A']", 
    '["N/A"]', "['None']", '["None"]', "['NULL']", '["NULL"]',
})

#: Max length for one proposal's text before it's embedded, now Settings.max_proposal_chars
#: (default unchanged: 3500). Kept <= Settings.max_embed_chars by config.py's own boot-time
#: validator (_validate_proposal_below_embed_cap) — embed() errors instead of truncating over
#: that limit, which would lose every threat in the batch, not just the long one.

class RegenTarget(NamedTuple):
    output_id: str
    threat_id: str
    scoped_threat_id: str
    scenario_number: int
    identity_hash: str | None

class _ScenarioFold(NamedTuple):
    rows: list
    siblings_by_hash: dict
    cross_pairs: list
    frozen_by_hash: dict


class _ScenarioBatch(NamedTuple):
    base_ctx: dict
    enriched: dict
    deduped: int
    pairs: list
    scoped_count: int
    fold: _ScenarioFold
    entry_vocab: dict
    intel_terms: list
    intel_ot: bool

class _Coverage(NamedTuple):
    vocab: dict
    frozen: list | None
    others: list | None
    # Intel search terms from _intel_vocabulary. Defaults to None/False so old callers that
    # don't pass this still work — missing terms just mean "no intel block", not a crash.
    intel_terms: list | None = None
    intel_ot: bool = False

def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", s)).strip().casefold()

def _flag_sibling_similarity(report: dict, scenario: dict, sibling_texts: list[tuple[int, str]],
                            ratio: float) -> None:
    statement = str(scenario.get("scenario_statement") or "")
    if not statement.strip():
        return
    for number, sibling_statement in sibling_texts:
        if not sibling_statement.strip():
            continue
        if difflib.SequenceMatcher(None, statement, sibling_statement).ratio() >= ratio:
            report["errors"] = list(report.get("errors") or [])
            report["errors"].append(
                f"scenario is very similar to this threat's other scenario (scenario #{number})")
            report["validation_status"] = "warning"
            return


def threat_label(t: dict) -> str:
    return (t.get("library_threat_name") or t.get("threat_name")
            or t.get("library_threat_type") or t.get("threat_type") or "")


def _semantic_duplicates(llm: LLMClient, sid: str, ss: int,
                        threats: list[dict],
                        priors: list[dict] | None = None,
                        asset_name: str = "",
                        threshold: float | None = None) -> dict[str, dict]:
    """Find threat IDs that mean the same thing as a higher-ranked threat already in this
    batch or already active on the session. The caller removes these before inserting.

    Returns {threat_id: {"reason": DuplicateReason, "score": float,
    "duplicate_of_threat_id": str | None}} — the id it matched is only known when the match is a
    THIS-BATCH sibling or a prior threat carrying its own threat_id; still None otherwise (a
    prior entry with no id available), same "best-effort" contract as _duplicate_row's caller.

    Why: exact-match dedup (dal.identity_hash) misses paraphrases — "Data leakage from X"
    and "Unauthorised disclosure of X" would both get inserted as separate threats. This
    catches those by comparing embeddings of the asset-stripped threat label.

    First-wins: each threat is only compared against threats that survived so far, never
    against ones already dropped. Similarity isn't transitive (A~B and B~C doesn't mean
    A~C), so comparing against a dropped item could wrongly chain-drop something. This
    only works because threats always arrive in a stable, deterministic order."""
    # Labels are compared with the asset name stripped out first (same as grounding does).
    # Every label ends in "... of <asset name>", so leaving it in mostly just confirms
    # "same asset" rather than "same threat" — stripping it raised the median similarity
    # score from 0.814 to 0.899 in testing.
    #
    # The drop decision is CATEGORY-BLIND. A shared STRIDE category is a ~1-in-6 coincidence
    # that says nothing about two threats meaning the same thing, and an earlier design that
    # judged same-category pairs at a lower bar merged distinct threats that merely share
    # vocabulary (one real asset run collapsed to 6 survivors, all reasoned
    # semantic_same_category). Category affects NEITHER the decision NOR the record now:
    # every semantic drop is written as DuplicateReason.semantic_similarity — the old
    # same/cross-category reasons survive only as historical row values (enums.py).
    def _cat(t: dict) -> str:
        return str(t.get("category") or "").strip().casefold()

    def _key(t: dict) -> str:
        return asset_agnostic_name(threat_label(t), asset_name) or ""

    raw_entries = [(t.get("threat_id"), _key(t), _cat(t)) for t in threats]
    # Separate name for the filtered list so the `if tid and lbl` guard is reflected in the
    # annotation: rebinding the same name keeps the pre-filter `str | None`, and every downstream
    # use (dupes[tid], tid_of[lbl]) then reads as a possible None key.
    entries: list[tuple[str, str, Any]] = [(tid, lbl, c) for tid, lbl, c in raw_entries if tid and lbl]
    prior_entries = [(t.get("threat_id"), _key(t), _cat(t)) for t in (priors or [])]
    prior_entries = [(tid, lbl, c) for tid, lbl, c in prior_entries if lbl]
    if not entries or not (prior_entries or len(entries) > 1):
        return {}
    labels = [lbl for _tid, lbl, _c in entries]
    prior = [lbl for _tid, lbl, _c in prior_entries]
    # The label-clash map resolves to the FIRST holder — the SURVIVOR. On a label clash the
    # survivor is the prior-round threat, or the first of two identical-label proposals; the
    # later holder is the one that gets dropped as its duplicate. Last-writer-wins here
    # corrupted the audit trail: an identical-label duplicate's DuplicateOfThreatID pointed at
    # ITSELF (a threat never inserted) — the map must name the SURVIVING threat's id, not
    # whichever entry happened to write the label last.
    tid_of: dict[str, str] = {}
    for tid, lbl, _c in prior_entries + entries:
        if tid and lbl not in tid_of:
            tid_of[lbl] = tid
    if threshold is None:  # use the caller's session-tuned value if given, otherwise fall back to config
        threshold = get_settings().semantic_near_duplicate_threshold
    # ONE bar for every pair, whatever the categories: real near-duplicates can score LOWER
    # than two genuinely different threats ("Unauthorized disclosure of X" vs "Unauthorized
    # modification of X" measured 0.969 — two REAL threats one word apart), so the bar must sit
    # above that trap for ALL pairs, not just cross-category ones. The session-tuned threshold
    # can only RAISE it (set it to 1.0 to disable the gate without a deploy), never lower it
    # below the config base.
    drop_threshold = max(get_settings().semantic_cross_category_threshold, threshold)
    try:
        # `texts` is just the unique strings to embed, so we don't pay to embed the same
        # label twice. It is NOT a count of how many threats there are — several threats can
        # share one label. (An earlier version bailed out early whenever there were fewer than
        # 2 unique texts, which skipped the exact case it was meant to catch: many threats
        # sharing one label.) The real "nothing to compare" check already happened above;
        # this just guards against an empty list.
        texts = list(dict.fromkeys([lbl for lbl in labels if lbl] + prior))
        if not texts:
            return {}

        vectors = dict(zip(texts, llm.embed(texts, kind="query")))

        norms = {t: math.sqrt(sum(x * x for x in v)) or 1.0 for t, v in vectors.items()}
    except Exception:
        # If the similarity check itself fails, don't block threat generation for it — just
        # act as if no duplicates were found. Raising here would lose every threat in the round.
        log.warning("threats.semantic_scan_failed", session_id=sid, subsystem=ss, exc_info=True)
        return {}
    dupes: dict[str, dict] = {}
    kept: list[str] = []  # survivors only — see the first-wins note in the docstring
    for tid, label, cat in entries:
        qv = vectors.get(label)
        if qv is None:
            kept.append(label)
            continue
        for other in prior + kept:
            ov = vectors.get(other)
            # No check to skip comparing an entry to itself — it isn't needed. `kept` only
            # gets an entry added after it's confirmed unique, and `prior` was read before
            # this batch existed, so self-comparison can't happen. (A previous version DID
            # guard against this by comparing label text, which accidentally also skipped two
            # genuinely different threats that happened to share identical labels — the
            # strongest possible duplicate signal, silently ignored.)
            if ov is None or len(ov) != len(qv):
                continue
            score = sum(x * y for x, y in zip(qv, ov)) / (norms[label] * norms[other])
            if score >= drop_threshold:
                dupes[tid] = {"reason": DuplicateReason.semantic_similarity, "score": score,
                            "duplicate_of_threat_id": tid_of.get(other)}
                log.info("threats.semantic_near_duplicate", session_id=sid, subsystem=ss,
                        proposed=label, matched=other, category=cat or None,
                        cosine=round(score, 4), threshold=drop_threshold)
                break
        else:
            kept.append(label)
    return dupes


def _statement_of(scenario_json: str | None) -> str:

    try:
        return str((json.loads(scenario_json or "{}") or {}).get("scenario_statement") or "")
    except (TypeError, ValueError):
        return ""

# Turn a session's scenario rows into a structure used to check for similar scenarios and
# to find each identity hash's primary scenario (the one with the lowest scenario number).
def _fold_scenario_rows(rows: list) -> _ScenarioFold:    
    siblings: dict[str, list[tuple[str, int, str]]] = {}
    cross: list[tuple[str, str]] = []
    frozen: dict[str, list[int]] = {}
    primary_number: dict[str, int] = {}
    for r in rows:
        if r.Status != ScenarioStatus.complete:
            continue
        statement = _statement_of(r.ScenarioJSON)
        siblings.setdefault(r.IdentityHash, []).append((r.OutputID, r.ScenarioNumber, statement))
        if statement.strip():
            cross.append((r.IdentityHash, statement))
        if r.ScenarioNumber < primary_number.get(r.IdentityHash, 1 << 30):
            primary_number[r.IdentityHash] = r.ScenarioNumber
            ids = dal._entry_ids(r.ScenarioJSON, "plausible_entry_point_ids")
            if ids:
                frozen[r.IdentityHash] = ids
            else:
                frozen.pop(r.IdentityHash, None)
    return _ScenarioFold(rows, siblings, cross, frozen)


def _flag_cross_threat_similarity(report: dict, scenario: dict, other_texts: list[str],
                                ratio: float) -> None:
    statement = str(scenario.get("scenario_statement") or "")
    if not statement.strip():
        return
    for other in other_texts:
        if not other.strip():
            continue
        if difflib.SequenceMatcher(None, statement, other).ratio() >= ratio:
            report["errors"] = list(report.get("errors") or [])
            report["errors"].append(
                "scenario is very similar to an active scenario of ANOTHER threat in this session")
            report["validation_status"] = "warning"
            return


def _ask_ai(sess: Session, llm: LLMClient, messages: list[dict], *, scenario_session: dict,
            subsystem_id: int, stage: str, level: SubsystemLevel | None = None,
            epoch: int | None = None, task_id: str | None = None,
            correlation_id: str | None = None,
            expected_type: type, temperature: float | None = None) -> tuple[Any, Provenance | None]:
    
    sid = scenario_session["SessionID"]
    if level is not None and epoch is not None and task_id is not None:
        # All three travel together: renew_lease needs every one of them, so guarding on
        # `level` alone would hand it None for epoch/task_id on any caller that omitted them.
        if not dal.renew_lease(sess, sid, subsystem_id, level, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid,
                        subsystem=subsystem_id, level=str(level))
        if not dal.renew_lock_lease(sess, sid, subsystem_id, task_id):
            log.debug("lock.lease_renewal_skipped", session_id=sid, subsystem=subsystem_id)
    sess.commit()
    # expected_type controls the LLM provider's JSON mode. Getting this wrong breaks things:
    # "json_object" mode forces a top-level object, so the threats stage (which expects a
    # list) would fail every call once JSON mode is on. This parameter is the single source
    # of truth for which shape is expected.
    text, prov = llm.chat(messages, temperature=temperature, expected_type=expected_type)
    if prov is not None:
        prov.prompt_version = prompts.PROMPT_VERSION
    row = {
        "LogID": guid(), "SessionID": scenario_session["SessionID"], "TenantID": scenario_session["TenantID"],
        "EntityID": scenario_session["EntityID"], "UserID": scenario_session.get("UserID"),
        "SubsystemID": subsystem_id, "Stage": stage, "PromptVersion": prompts.PROMPT_VERSION,
        "Messages": json.dumps(messages),
        "Prompt": "\n\n".join(f"[{msg['role']}]\n{msg.get('content') or ''}" for msg in messages),
        "ResponseText": text,
        "Model": prov.model if prov else None, "ModelVersion": prov.model_version if prov else None,
        "CreatedAt": now(),
        # Links this log row to one specific item (e.g. a plan ID) so audits can find the
        # exact attempt without guessing by timestamp. Left as None for stage-level callers.
        "CorrelationID": correlation_id,
    }
    try:
        parsed = validation.parse_json(text, stage=stage, expected_type=expected_type)
    except validation.LLMResponseParseError:
        sess.rollback()
        dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": False})
        sess.commit()
        log.warning("llm_response.parse_failed", session_id=scenario_session["SessionID"],
                    subsystem=subsystem_id, stage=stage)
        raise
    dal.insert_row(sess, m.Prompt_Log, {**row, "ParseSucceeded": True})    
    sess.commit()
    return parsed, prov


def _summarize_ai_call(p: Provenance | None) -> dict | None:
    return None if p is None else {"model": p.model, "version": p.model_version,
                                "params": p.params, "prompt_version": p.prompt_version}


def _send_live_update(session_id: str, sse_type: SSEEventType, subsystem_id: int,
        level: SubsystemLevel, status: StageStatus, epoch: int = _EPOCH) -> None:
    bus.publish(session_id, {
        "type": str(sse_type), "session_id": session_id, "subsystem_id": subsystem_id,
        "stage": str(level), "status": str(status), "generation_epoch": epoch,
        "ts": now().isoformat(),
    })


def set_up_progress_tracking(sess: Session, session_id: str, tenant_id: str, entity_id: str) -> None:
    rows = [{
        "StateID": guid(), "SessionID": session_id, "TenantID": tenant_id, "EntityID": str(entity_id),
        "SubsystemID": ASSET_UNIT_ID, "Level": level, "Status": StageStatus.IDLE,
        "GenerationEpoch": _EPOCH, "UpdatedAt": now(), "CreatedAt": now(),
    } for level in (*_WORK_LEVELS, SubsystemLevel.LOCK)]
    sess.execute(insert(m.Subsystem_Stage_State), rows)


@overload
def _safe_text(v: Any, default: str) -> str: ...
@overload
def _safe_text(v: Any, default: None) -> str | None: ...
def _safe_text(v: Any, default: str | None) -> str | None:
    """Overloaded so a non-None `default` is typed as returning `str`: callers slice the
    result immediately (`[:300]`), which a `str | None` return would make a type error at
    every call site rather than here, where the guarantee actually lives."""
    if default is None:
        return v if isinstance(v, str) else None
    return grounding.ensure_text(v, default)


def _build_threat_records(tid: str, sid: str, tenant: str, ss: int, ptype: str | None, pcat: str | None,
                        pname: str | None, gr: grounding.GroundingResult, entity_id: str | None,
                        user_id: str | None, generic_name: str | None = None) -> tuple[dict, dict]:
    row = {
        "ThreatID": tid, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ThreatCategory": pcat, "ThreatType": ptype,
        "ThreatName": pname,
        # A generic (library-ready) version of ThreatName, saved so that later triage (when
        # this threat is accepted, maybe days later) uses the AI's own wording instead of a
        # rough text-stripping fallback. Cut to fit the column, so one overly long AI value
        # can't fail the whole batch insert and lose every threat in the round.
        "GenericName": generic_name[:500] if generic_name else None,
        "ThreatActorsJSON": json.dumps({"actors": gr.actors, "validated": gr.actors_validated}),
        "LibraryThreatType": gr.library_type, "LibraryThreatName": gr.library_name,
        "ThreatTypeID": gr.type_id, "ThreatCatalogueID": gr.catalogue_id,
        "GroundingStatus": gr.status, "GroundingScore": gr.score,
        "Superseded": 0, "CreatedAt": now(),
    }
    summary = {
        "threat_id": tid, "grounding_status": str(gr.status),
        # STRIDE category (Spoofing/Tampering/etc.), kept so the near-duplicate scan can
        # compare threats only within the same category — needed because two genuinely
        # different threats can still score higher on text similarity than real paraphrases
        # do (see _semantic_duplicates). Same key name used by dal.active_threats.
        "category": pcat,
        "threat_type": ptype, "threat_name": pname,
        "library_threat_type": gr.library_type, "library_threat_name": gr.library_name,
        "threat_type_id": gr.type_id,
        "catalogue_id": gr.catalogue_id,
        "actors": gr.actors,
    }
    return row, summary


def _duplicate_row(row: dict, reason: DuplicateReason, *,
                    duplicate_of: str | None = None, score: float | None = None) -> dict:
    """An Identified_Threat row, reshaped for Identified_Duplicate_Threat — same proposed
    content, minus the library-grounding/scoring columns that table doesn't have, plus why it
    was dropped and (when known) what it matched. Audit-only; never read by the pipeline."""
    return {
        "DuplicateThreatID": row["ThreatID"], "SessionID": row["SessionID"],
        "TenantID": row["TenantID"], "EntityID": row["EntityID"], "UserID": row["UserID"],
        "SubsystemID": row["SubsystemID"],
        "ThreatCategory": row["ThreatCategory"], "ThreatType": row["ThreatType"],
        "ThreatName": row["ThreatName"], "GenericName": row["GenericName"],
        "ThreatActorsJSON": row["ThreatActorsJSON"],
        "DuplicateOfThreatID": duplicate_of, "DuplicateReason": str(reason),
        "SimilarityScore": score, "CreatedAt": row["CreatedAt"],
    }


def _asset_boundary_pattern(asset_name: str) -> re.Pattern | None:
    """Build one regex pattern for matching/removing an asset name from text, used everywhere
    this needs to happen. Uses lookarounds instead of \\b word boundaries because asset names
    can start or end with non-word characters (like "(PGS)"). A plain substring match would
    also match INSIDE unrelated words — asset name "CIS" once matched inside "decision",
    corrupting text to "Loss of de ion integrity" and poisoning grounding, GenericName, and
    triage downstream."""
    # Handles three cases a plain literal match would miss — each one a real way the asset
    # name used to leak through into GenericName and the shared library:
    #   * trailing punctuation on the name ("ACME Corp.") not matching "ACME Corp systems"
    #   * extra/missing whitespace ("Power  Plant" vs "Power Plant")
    #   * a possessive right after the match ("Citizen Portal's credentials") leaving a
    #     dangling "'s"
    a = (asset_name or "").strip().rstrip(".,;:!")
    if not a:
        return None
    body = r"\s+".join(re.escape(tok) for tok in a.split())
    return re.compile(r"(?<!\w)" + body + r"(?:'s)?(?!\w)", re.IGNORECASE)

def asset_agnostic_name(name: str | None, asset_name: str) -> str | None:
    """Remove the asset name from a threat label. Returns None (never the original text) if
    nothing but the asset name is left — returning the original would let an asset-specific
    name slip through into the shared, cross-tenant threat library. Every caller already
    handles None safely."""
    if not name or not asset_name:
        return name
    pat = _asset_boundary_pattern(asset_name)
    if pat:
        # Also remove a preposition right before the asset name, so removing the name from
        # the middle of a sentence doesn't leave it dangling: "Compromise of X leading to
        # outage" used to become "Compromise of leading to outage" (the cleanup below only
        # fixes trailing prepositions, not ones in the middle).
        combined = re.compile(rf"(?:\b(?:{_ASSET_PREPOSITIONS})\s+)?" + pat.pattern, pat.flags)
        stripped = combined.sub(" ", name)
    else:
        stripped = name
    stripped = re.sub(r"\s+", " ", stripped).strip(" ,;:-.'")
    stripped = re.sub(rf"\s+({_ASSET_PREPOSITIONS})$", "", stripped, flags=re.IGNORECASE)
    return stripped or None


def clean_library_name(name: str | None) -> str | None:
    """Clean up a name so it's fit to enter the shared library, or return None if it isn't.
    Rejects empty values, bracket/quote junk ('N/A', ['NA'], [], '"None"'), known filler
    words, and anything without at least two real words. This matters because meaningless
    text embeds far from anything in the library, making it the MOST likely junk to sneak
    past auto-approval — the one path a human curator never reviews. Checked both when a
    threat is first saved and again at auto-approve time, as a second safety net."""
    if not name:
        return None
    core = re.sub(r"""[\[\]{}()<>'"`,;:._\-/\\]+""", " ", name)
    core = re.sub(r"\s+", " ", core).strip()
    if core.casefold() in _JUNK_NAME_TOKENS:
        return None
    if len([w for w in core.split() if any(ch.isalpha() for ch in w)]) < 2:
        return None
    # Return the name with only its wrapping junk removed, not the raw input as-is. It used
    # to validate the cleaned-up `core` text but then return the untouched original, so
    # '"Data exfiltration"' passed validation but got stored WITH the quotes — becoming the
    # literal library entry text. Punctuation inside the name (like "e-mail" or "command &
    # control") is left alone; only the outer wrapping is stripped.
    display = re.sub(r"""^[\s\[\]{}()<>'"`]+|[\s\[\]{}()<>'"`]+$""", "", name)
    display = display.strip(" ,;:.-")
    return display or None

def _generic_name_of(p: dict, asset_name: str) -> str | None:
    """Get the library-ready name for a Stage-1 proposal. Prefers the AI's own
    "generic_name" field, but only if it passes clean_library_name and doesn't contain the
    asset name — we don't trust the prompt alone to enforce that. Falls back to stripping
    the asset name out of the regular "name" field, which is also used by the near-duplicate
    scan, so both stay consistent about what counts as asset-agnostic."""
    pat = _asset_boundary_pattern(asset_name)
    g = clean_library_name(_safe_text(p.get("generic_name"), None))
    if g and pat and pat.search(g):
        log.warning("threats.generic_name_leaks_asset", generic_name=g)
        g = None
    return g or asset_agnostic_name(_safe_text(p.get("name"), None), asset_name)

# Builds a dedup key for a threat: prefers catalogue ID, then type ID + name, then falls
# back to normalized type/name text. Used to catch duplicate threats both within a batch
# and against threats already active in the session.
def _dedup_key(info: dict) -> str:

    key_type = _normalize(info.get("threat_type") or "")
    key_name = _normalize(info.get("threat_name") or "")
    catalogue_id = info.get("catalogue_id")
    if catalogue_id is not None:
        return f"cat:{catalogue_id}"
    type_id = info.get("threat_type_id")
    if type_id is not None:
        return f"type:{type_id}|{key_name}" if key_name else f"type:{type_id}"
    if not key_type and not key_name:
        return "txt:tid:" + str(info.get("threat_id"))
    return "txt:" + key_type + "|" + key_name


def _usable_proposal(p: object) -> bool:
    """Is this one item from the LLM's JSON list safe to save?

    We only checked that the response is a list overall — each item inside could still be
    junk. This filters out three kinds of junk before they cause damage further downstream:

    * Not a dict -> later code calling `.get()` on it crashes with the wrong kind of error,
      which cancels the whole session instead of failing gracefully.
    * Missing type/name -> there's nothing to match, score, or de-duplicate against, and it
      would keep failing the same way on every retry with no way to fix it.
    * Too long -> generating its embedding fails and takes down all the other threats found
      in that same batch with it.
    """
    if not isinstance(p, dict):
        return False
    ptype = _safe_text(p.get("type"), "") or ""
    pname = _safe_text(p.get("name"), "") or ""
    return bool(ptype) and bool(pname) and len(ptype) + len(pname) <= get_settings().max_proposal_chars


def find_threats(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, categories: list[str] | None = None,
                actor_examples: list[str] | None = None,
                supersede: bool = True, exclude: list[str] | None = None,
                prior_threats: list[dict] | None = None,
                max_threats: int | None = None) -> tuple[list[dict], Provenance | None]:
    # `exclude` is label text used to steer the prompt away from repeats. `prior_threats` is
    # those same threats as full rows (with category), needed for the near-duplicate scan.
    # The caller already has both, so passing them in costs no extra query.
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
    tn = tuning.from_session(scenario_session)  # tuning settings frozen at session start, not live config
    # `max_threats` override lets a caller (run_next_set's additive top-up) ask for exactly the
    # shortfall it needs instead of the full per-asset cap — every other caller leaves this None
    # and gets the original tn.max_threats_per_asset ceiling, unchanged.
    if max_threats is None:
        max_threats = tn.max_threats_per_asset
    proposals, prov = _ask_ai(sess, llm, prompts.threats_prompt(
                                scenario_session["AssetName"], asset_context, subsystems,
                                max_threats=max_threats,
                                categories=categories if categories is not None else dal.active_category_names(sess),
                                actor_examples=actor_examples if actor_examples is not None else dal.active_actor_names(sess),
                                exclude=exclude),
                                scenario_session=scenario_session, subsystem_id=ss, stage="threats",
                                level=SubsystemLevel.THREATS, epoch=epoch, task_id=task_id, expected_type=list,
                                temperature=get_settings().threat_identification_temperature)
    # Filter untrusted LLM output once here (see _usable_proposal) rather than in every place
    # that reads it below — that's both the smallest fix and the only one that covers every
    # reader, including grounding.prime_query_embeddings.
    usable = [p for p in proposals if _usable_proposal(p)]
    if len(usable) != len(proposals):
        log.warning("threats.proposals_dropped", session_id=sid,
                    dropped=len(proposals) - len(usable), received=len(proposals))
    proposals = usable
    if supersede:
        dal.supersede(sess, m.Identified_Threat, sid, ss)
    existing_identities = dal.active_identified_threat_identities(sess, sid, ss) if not supersede else {}
    threats: list[dict] = []
    rows: list[dict] = []
    duplicates = 0
    dup_rows: list[dict] = []  # Identified_Duplicate_Threat rows — audit-only, see _duplicate_row
    sector_ids = json.loads(scenario_session["SectorIDsJSON"]) if scenario_session.get("SectorIDsJSON") else []
    grounding_cache: dict = {}
    # Grounding and the identity fingerprint both run on the library-ready name: the AI's
    # own generic_name if valid, otherwise a stripped-down fallback name (_generic_name_of).
    to_ground = [{**p, "name": _generic_name_of(p, scenario_session["AssetName"])}
                for p in proposals]  # safe: _usable_proposal already guaranteed these are all dicts
    grounding.prime_query_embeddings(llm, to_ground, grounding_cache)
    for p, gp in zip(proposals, to_ground):
        if len(rows) >= max_threats:            
            log.warning("threats.over_proposed", session_id=sid,
                        proposed=len(proposals), cap=max_threats)
            break
        
        if not dal.renew_lease(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid, subsystem=ss, level=str(SubsystemLevel.THREATS))
        sess.commit()
        # Clip these values to fit their DB columns right here, not later when building the
        # row: an over-long AI value would otherwise fail the whole batch insert (losing every
        # threat in the round), and clipping afterward would make the stored value disagree
        # with the identity hash computed from these same variables.
        ptype = _safe_text(p.get("type"), "")[:300]
        pcat = _safe_text(p.get("category"), "")[:200]
        pname = _safe_text(p.get("name"), None)
        if pname:
            pname = pname[:500]
        gr = grounding.find_threat_in_library(sess, llm, gp, sector_ids=sector_ids, cache=grounding_cache)
        tid = guid()
        row, summary = _build_threat_records(tid, sid, tenant, ss, ptype, pcat, pname, gr,
                                        scenario_session["EntityID"], scenario_session.get("UserID"),
                                        generic_name=gp.get("name") if isinstance(gp, dict) else None)
        identity = dal.identity_hash(sid, ss, summary)
        if identity in existing_identities:
            duplicates += 1
            dup_rows.append(_duplicate_row(row, DuplicateReason.identity,
                                        duplicate_of=existing_identities.get(identity)))
            continue
        existing_identities[identity] = tid
        rows.append(row)
        threats.append(summary)
    # Run the near-duplicate check BEFORE inserting, so it can actually block bad rows — the
    # exact-match check above only catches identical wording, so two threats phrased
    # differently would both slip through and get generated (and billed) separately. Can be
    # switched off without a deploy by setting semantic_near_duplicate_threshold to 1.0.
    dupe_info = _semantic_duplicates(llm, sid, ss, threats, prior_threats,
                                    scenario_session["AssetName"],
                                    threshold=tn.semantic_near_duplicate_threshold)
    near_dupes = len(dupe_info)
    if dupe_info:
        by_id = {r["ThreatID"]: r for r in rows}
        dup_rows.extend(
            _duplicate_row(by_id[tid], info["reason"],
                        duplicate_of=info["duplicate_of_threat_id"], score=info["score"])
            for tid, info in dupe_info.items() if tid in by_id
        )
        rows = [r for r in rows if r["ThreatID"] not in dupe_info]
        threats = [t for t in threats if t["threat_id"] not in dupe_info]
        log.info("threats.semantic_duplicates_dropped", session_id=sid, subsystem=ss,
                dropped=near_dupes)
    if rows:
        sess.execute(insert(m.Identified_Threat), rows)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch, task_id):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="THREATS", epoch=epoch)
        return [], None
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.THREAT_IDENTIFICATION, SubsystemID=ss,
                    EventType=AuditEventType.grounding_summary,
                    DetailJSON=json.dumps({"count": len(threats),
                                        "identity_duplicates": duplicates,
                                        "semantic_near_duplicates": near_dupes}))
    sess.commit()
    if dup_rows:
        # Deliberately OUTSIDE the transaction above, in its own try/except: this is an
        # audit-only table, and it must never be able to roll back or block the real threats
        # just committed — e.g. a deployment that hasn't re-run TSG_Core.sql yet would
        # otherwise lose an entire round's worth of legitimate threats over a missing table.
        try:
            sess.execute(insert(m.Identified_Duplicate_Threat), dup_rows)
            sess.commit()
        except Exception:
            sess.rollback()
            log.warning("threats.duplicate_audit_insert_failed", session_id=sid, subsystem=ss,
                        exc_info=True)
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="THREATS", count=len(threats))
    return threats, prov

# Runs the moderation check on a scenario's text and controls together.
# Returns {"checked": ok?, "flagged": found something?, "categories": [...], "error": str|None}.
def _moderation_report(scenario: dict) -> dict:  
    text = " ".join(str(scenario.get(f) or "") for f in _SCENARIO_TEXT_FIELDS)
    text = " ".join([text] + [f"{c.get('name') or ''} {c.get('why') or ''}".strip()
                            for c in (scenario.get("controls") or []) if isinstance(c, dict)])
    r = moderate(text)
    return {"checked": r.checked, "flagged": r.flagged, "categories": r.categories, "error": r.error}


def _intel_vocabulary(subsystems: list[dict], asset_context: dict) -> tuple[list[str], bool]:
    """Build search terms for threat-intel lookups from the asset's tech inventory and
    classification fields — never from the threat's own wording.

    Why not threat wording: threat names use generic business language ("failure",
    "maintenance", "system"), which happens to match everyday IT advisories. That's how a
    power plant search once pulled up Cisco/Fortinet/SharePoint CVEs while the relevant ICS
    advisories were ignored. Product names ("Siemens", "SCADA", "Windows Server") match what
    advisories actually talk about, so we use those instead.

    Sector, sub-sector, and critical-service are added too, because they use the same fixed
    vocabulary that OTX and CISA ICS advisories tag themselves with. They also save assets
    whose whole tech inventory is just "Custom Application" / "NA" from producing zero terms.

    Terms come from whatever fields the context layer already has — the same ones sent to the
    LLM — with placeholders like "NA" or "Unknown" dropped via is_placeholder.

    Returns (terms, is_ot). is_ot is true if ANY subsystem or the asset itself looks like OT
    (via control_mapping.itot_family), a deliberately loose check — one OT component is enough,
    so a plant with a single IT historian still gets flagged for ICS advisories. If no terms
    are found, the caller skips sending intel at all rather than sending a noisy, useless block."""
    terms: list[str] = []
    seen: set[str] = set()

    def _add(value: Any) -> None:
        for v in value if isinstance(value, (list, tuple)) else [value]:
            text = str(v).strip() if v is not None else ""
            if text and not is_placeholder(text) and text.casefold() not in seen:
                seen.add(text.casefold())
                terms.append(text)

    for sub in subsystems or []:
        for fld in _INTEL_TECH_FIELDS:
            _add(sub.get(fld))
    # These come from fixed dropdown values ("Energy", "Power Generation"), not free text —
    # matching the exact wording OTX and CISA ICS advisories use to tag themselves. Without
    # this, an asset with a generic tech inventory like "Custom Application" would match
    # nothing and silently get no intel block at all.
    for fld in ("asset_type", "sector", "sub_sector", "critical_service"):
        _add(asset_context.get(fld))
    is_ot = any(control_mapping.itot_family(s.get("asset_type")) == "OT"
                for s in subsystems or [])
    is_ot = is_ot or control_mapping.itot_family(asset_context.get("asset_type")) == "OT"
    return terms, is_ot


def _fetch_intel(terms: list[str] | None, is_ot: bool,
                actors: list[str] | None = None, limit: int | None = None) -> list[dict] | None:
    """Fetches threat-intel items to inject into the prompt; prompts._intel_block just
    renders whatever this returns. If `terms` (from _intel_vocabulary) is empty, no intel
    block is sent at all."""
    s = get_settings()
    if not s.intel_enabled or not terms:
        return None
    if limit is None:
        limit = s.prompt_intel_limit
    try:
        from app.intel.fetchers import query_intel

        prefer = ("ics_advisory", "cve") if is_ot else ("cve",)
        actor_terms = [a for a in (actors or []) if a]
        items = query_intel(terms + actor_terms, prefer_kinds=prefer, limit=limit)
        if actor_terms:
            pulses = query_intel(actor_terms, prefer_kinds=("pulse",), limit=1, backfill=False)
            if pulses:
                seen = {(p["source"], p["external_id"]) for p in pulses}
                items = pulses + [i for i in items
                                if (i["source"], i["external_id"]) not in seen]
                items = items[:limit]
        if items:
            # log what was injected so we can measure later whether it was actually relevant
            log.info("scenario.intel_injected", is_ot=is_ot,
                    external_ids=[i.get("external_id") for i in items])
        return items or None
    except Exception:
        log.warning("scenario.intel_fetch_failed", exc_info=True)
        return None

def _ground_entry_points(scenario: dict, vocab: dict[str, int],
                        frozen: list[int] | None = None) -> None:
    
    by_fold = {label.casefold(): (label, sid) for label, sid in vocab.items()}

    def _resolve(raw: Any) -> tuple[str, int] | None:
        return by_fold.get(raw.strip().casefold()) if isinstance(raw, str) else None

    used = _resolve(scenario.get("entry_point"))
    scenario["entry_point"] = used[0] if used else None
    scenario["entry_point_id"] = used[1] if used else None
    ids: list[int] = []
    labels: list[str] = []
    for hit in ([used] if used else []) + [_resolve(r) for r in
                                        (scenario.get("other_plausible_entry_points") or [])
                                        if isinstance(scenario.get("other_plausible_entry_points"), list)]:
        if hit and hit[1] not in ids:
            ids.append(hit[1])
            labels.append(hit[0])
    scenario["other_plausible_entry_points"] = labels
    scenario["plausible_entry_point_ids"] = list(frozen) if frozen else ids


def _generate_one_scenario(sess: Session, scenario_session: dict, base_ctx: dict, sc,
                    enriched: dict, llm: LLMClient, task_id: str, epoch: int,
                    sibling_texts: list[tuple[int, str]] | None = None,
                    coverage: _Coverage | None = None,
                    # Per-item id stamped onto BOTH Prompt_Log rows this call can write (the
                    # generation attempt and its repair turn), so a receipt joins back to the
                    # scenario it produced. Callers pass the ScopedThreatID.
                    *, correlation_id: str | None = None) -> tuple[dict, dict, Provenance | None]:    
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    actors = info.get("actors") or []
    # [A2] STRIDE category, already available from find_threats — no extra query needed. Used
    # to steer the scenario's shape (prompts._STRIDE_SCENARIO_SHAPES); if missing, prompt is
    # unaffected.
    category = info.get("category")
    tn = tuning.from_session(scenario_session)  # tuning settings frozen at session start, not live config
    # Fall back to an empty coverage when the caller doesn't have one yet.
    cov = coverage or _Coverage(vocab={}, frozen=None, others=None)
    # Intel is matched using the tech-inventory terms from coverage, never threat wording.
    intel_items = _fetch_intel(cov.intel_terms, cov.intel_ot, actors, limit=tn.prompt_intel_limit)
    # The set of IDs the model was allowed to cite. Left as None (not an empty set) when no
    # intel was sent at all, so validation skips the citation check instead of failing every id.
    injected_intel_ids = ({str(i.get("external_id")) for i in intel_items if i.get("external_id")}
                        if intel_items else None)
    entry_labels = sorted(cov.vocab) if cov.vocab else None
    if sibling_texts:
        messages = prompts.variant_scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                                intel_items=intel_items, existing=sibling_texts,
                                                entry_points=entry_labels,
                                                sibling_k=tn.variant_sibling_prompt_k,
                                                category=category)
    else:
        messages = prompts.scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                        intel_items=intel_items, entry_points=entry_labels,
                                        category=category)
    scenario, prov = _ask_ai(sess, llm, messages,
                            scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID, stage="scenario",
                            level=SubsystemLevel.SCENARIOS, epoch=epoch, task_id=task_id, expected_type=dict,
                            correlation_id=correlation_id,
                            temperature=get_settings().scenario_generation_temperature)
    # Use critical_service from base_ctx (what the model actually saw), not the raw
    # asset_context — placeholder values like "Unknown"/"TBD" are scrubbed out there, and
    # validation shouldn't require a value the model was never shown.
    report = validation.validate_scenario(
        scenario, threat_type, threat_name,
        asset_name=scenario_session["AssetName"],
        critical_service=base_ctx["asset_context"].get("critical_service"),
        injected_intel_ids=injected_intel_ids)
    # One retry to fix STRUCTURAL problems only (missing required fields) — never for
    # advisory warnings, which are just informational. We tell the model not to change the
    # facts, so this can't turn into a free reroll that dodges the similarity check below.
    # The retry is only accepted if it actually fixes more missing fields; if it fails to
    # parse, we just keep the original. Runs before moderation/grounding/similarity checks
    # so those all see the final version.
    missing = [e for e in report["errors"] if e.startswith("missing ")]
    if missing:
        repair_messages = [*messages,
            # Scrub DB ids like any other payload. Currently a no-op since this runs before
            # _ground_entry_points adds any ids — but it's safe even if that order changes later.
            {"role": "assistant", "content": json.dumps(prompts._scrub_db_keys(scenario))},
            {"role": "user", "content":
                "The previous response failed validation: " + "; ".join(missing) +
                ". Correct only these violations. Do not change factual content unless "
                "required. Return only the corrected JSON object."}]
        try:  # through _ask_ai, so Prompt_Log keeps both attempts and the stage lease renews
            repaired, r_prov = _ask_ai(sess, llm, repair_messages,
                                    scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID,
                                    stage="scenario", level=SubsystemLevel.SCENARIOS, epoch=epoch,
                                    task_id=task_id, expected_type=dict,
                                    # Deliberately the SAME id as the attempt above: CorrelationID
                                    # has no unique constraint and the evidence read returns every
                                    # matching row ordered by CreatedAt, so the two attempts group.
                                    correlation_id=correlation_id,
                                    temperature=get_settings().scenario_generation_temperature)
        except Exception:
            # Must roll back here. _ask_ai runs DB commits before and after the LLM call, over
            # a connection that stays open for the whole call — if it drops mid-call, the
            # session is left needing a rollback. Skip this and the next DB call outside this
            # try (the lease renewal in write_scenarios) would fail and mark the whole
            # SCENARIOS stage as errored, throwing away an already-generated, already-billed
            # scenario just because an optional repair attempt failed.
            sess.rollback()
            # This repair is optional: the original scenario already generated and passed
            # validation (maybe with warnings), so a failed repair must never destroy it. We
            # catch everything here on purpose — parse errors, provider errors, and
            # LLMSlotUnavailable should all just fall back to keeping the original. In
            # particular, letting LLMSlotUnavailable propagate would make Celery retry (and
            # re-bill) the whole stage just because a repair attempt couldn't find a slot.
            log.warning("scenario.repair_failed", session_id=scenario_session["SessionID"],
                        threat_id=sc.threat_id, exc_info=True)
        else:
            # Merge the repair into the original, never replace it outright. The model is
            # asked for "the corrected JSON object" but can legally return just a partial one
            # (e.g. only {"risk_statement": "..."}). Replacing wholesale would then silently
            # delete fields like entry_point, which would permanently cap this threat at one
            # scenario without any visible error. Merging means a repair can only overwrite
            # fields it actually returned — it can never accidentally delete one.
            merged = {**scenario, **repaired}
            # A merge can still accidentally EMPTY a field, though, which is just as bad as
            # deleting it: if the repair explicitly returns "other_plausible_entry_points": [],
            # that's a valid value that would overwrite the original and freeze the threat at
            # one scenario. So keep the original list whenever the repair's version is empty.
            if not merged.get("other_plausible_entry_points"):
                merged["other_plausible_entry_points"] = scenario.get("other_plausible_entry_points") or []
            # Validate the MERGED scenario, not just the raw repair — otherwise the saved
            # validation report could describe a different scenario than what actually gets
            # saved as ScenarioJSON.
            r_report = validation.validate_scenario(
                merged, threat_type, threat_name,
                asset_name=scenario_session["AssetName"],
                critical_service=base_ctx["asset_context"].get("critical_service"),
        injected_intel_ids=injected_intel_ids)
            still = [e for e in r_report["errors"] if e.startswith("missing ")]
            if len(still) < len(missing):
                scenario, report, prov = merged, r_report, r_prov
                log.info("scenario.repaired", session_id=scenario_session["SessionID"],
                        threat_id=sc.threat_id, was_missing=missing, still_missing=still)
    report["moderation"] = _moderation_report(scenario)
    
    _ground_entry_points(scenario, cov.vocab, cov.frozen)
    if sibling_texts:
        _flag_sibling_similarity(report, scenario, sibling_texts, tn.sibling_similarity_ratio)
    if cov.others:
        _flag_cross_threat_similarity(report, scenario, cov.others, tn.sibling_similarity_ratio)
    return scenario, report, prov


def _build_scoped_threat_row(scoped_id: str, sid: str, tenant: str, ss: int, sc: scoping.Scored,
                        entity_id: str | None, user_id: str | None) -> dict:
    return {
        "ScopedThreatID": scoped_id, "SessionID": sid, "TenantID": tenant, "EntityID": entity_id,
        "UserID": user_id, "SubsystemID": ss,
        "ThreatID": sc.threat_id, "Score": sc.score, "ScopeRank": sc.rank,
        "Selected": 1 if sc.selected else 0, "Reason": sc.reason, "RejectionKind": sc.rejection,
        "SelectionKind": sc.selection,
        "FactorsJSON": json.dumps(sc.factors) if sc.factors else None,
        "Superseded": 0, "CreatedAt": now(),
    }


def _scrub_model_output(scenario: dict, sid: str, threat_id: str | None) -> dict:
    """Outbound twin of the inbound redaction [gap-8]: the model's own text runs through the same
    _SECRET_PATTERNS before persistence, so /results, the Excel export and the audit trail all
    inherit the scrub from this one write-side point. Residual risk (unlabeled prose credentials,
    invented person names) stays documented in validation.validate_scenario.

    MUST NEVER RAISE: a paid generation is never lost to cleanup — on any error the original is
    stored and the failure logged (same advisory-tail discipline as _publish_regen_result)."""
    try:
        cleaned = _redact_value(scenario)
        if cleaned != scenario:
            log.info("scenario.output_redacted", session_id=sid, threat_id=threat_id)
        return cleaned
    except Exception:
        log.exception("scenario.output_scrub_failed", session_id=sid, threat_id=threat_id)
        return scenario


def _build_scenario_output_row(scoped_id: str, sid: str, tenant: str, ss: int, scenario: dict, report: dict,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_output_id: str | None = None) -> dict:

    scenario = _scrub_model_output(scenario, sid, info.get("threat_id"))
    identity = dal.identity_hash(sid, ss, info)
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.complete,
        "ScenarioJSON": json.dumps(scenario),
        "ValidationJSON": json.dumps(report),
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": identity, "ScenarioNumber": scenario_number,
        "ReplacesOutputID": replaces_output_id,
        "GenerationEpoch": epoch, "ErrorMessage": None, "CreatedAt": now(),
    }


def _build_error_output_row(scoped_id: str, sid: str, tenant: str, ss: int, client_msg: str,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_output_id: str | None = None) -> dict:    
    return {
        "OutputID": guid(), "SessionID": sid, "TenantID": tenant, "EntityID": entity_id, "UserID": user_id,
        "SubsystemID": ss,
        "ScopedThreatID": scoped_id, "Status": ScenarioStatus.error,
        "ScenarioJSON": None, "ValidationJSON": None,
        "Accepted": 0, "Superseded": 0,
        "IdentityHash": dal.identity_hash(sid, ss, info), "ScenarioNumber": scenario_number,
        "ReplacesOutputID": replaces_output_id,
        "GenerationEpoch": epoch,
        "ErrorMessage": client_msg, "CreatedAt": now(),
    }


def _select_unique_top_n(scoped: list[scoping.Scored], enriched: dict, top_n: int | None) -> int:

    seen: set[str] = set()
    kept = 0
    deduped = 0
    for sc in scoped:
        if not sc.selected:
            continue
        key = _dedup_key(enriched.get(sc.threat_id, {}))
        if key in seen:
            # This branch should never actually run — find_threats already de-dupes by this
            # same key before threats get here. Kept as a safety net anyway, since it's the
            # last check before a duplicate would trigger a paid scenario generation, and the
            # code that guarantees uniqueness lives in a different function. If `deduped` ever
            # goes above 0, that's a bug elsewhere, not evidence this check is doing real work.
            log.warning("scoping.duplicate_survived_identity_dedup",
                        threat_id=sc.threat_id, dedup_key=key)
            sc.selected, sc.reason = False, "duplicate of higher-ranked threat"
            # selection cleared WITH the demotion — `selection is not None ⟺ selected` is a
            # persisted contract (SelectionKind must be NULL on every Selected=0 row)
            sc.rejection, sc.selection = ScopingRejection.duplicate, None
            deduped += 1
        elif top_n is not None and kept >= top_n:
            sc.selected, sc.reason = False, f"beyond top-{top_n} cutoff"
            sc.rejection, sc.selection = ScopingRejection.top_n_cutoff, None
        else:
            seen.add(key)
            kept += 1
    return deduped


def _mark_next_set_targets_rescored_out(sess: Session, sid: str, ss: int, pairs: list, excluded_ids: set[str],
                                    tenant: str, entity_id: str | None, user_id: str | None) -> None:
    excluded_needing_marker = (excluded_ids - dal.threats_with_active_scenario(sess, sid, ss, excluded_ids)
                            if excluded_ids else set())
    if not excluded_needing_marker:
        return
    # Must retire outputs BEFORE the scoped rows: supersede_outputs_for_threats finds outputs
    # through their scoped row, so once that's retired it can no longer find them. Without
    # this order, a threat whose only output is a failure card (which doesn't count as an
    # "active scenario") would keep showing that stale card in /results even after its
    # parent threat disappears from the list.
    dal.supersede_outputs_for_threats(sess, sid, ss, excluded_needing_marker)
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, excluded_needing_marker)
    sess.execute(insert(m.Scoped_Threat), [
        _build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
        for sc, scoped_id, _t in pairs if sc.threat_id in excluded_needing_marker])


def _begin_full_run_attempt(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, epoch: int) -> set[str]:
    if epoch != _EPOCH:
        raise ValueError(
            f"full-run write_scenarios is only valid at the initial epoch {_EPOCH}, got {epoch} — "
            "a regen/next-set hop must pass target_threat_ids and take the targeted branch")
    attempt = dal.stage_attempt_count(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch)
    if attempt == 1:
        dal.supersede(sess, m.Scoped_Threat, sid, ss)
        dal.supersede(sess, m.Threat_Scenario_Output, sid, ss)
        not_selected = [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)
                        for sc, scoped_id, _t in pairs if not sc.selected]
        if not_selected:
            sess.execute(insert(m.Scoped_Threat), not_selected)
        sess.commit()
        return set()
    return dal.threats_with_active_scenario(
        sess, sid, ss, {sc.threat_id for sc, _scoped_id, _t in pairs if sc.selected})


def _reconcile_targeted_regen(sess: Session, sid: str, ss: int, tenant: str,
                            entity_id: str | None, user_id: str | None,
                            pairs: list, scenarios: dict, enriched: dict,
                            epoch: int, task_id: str, *, regen_mode: bool,
                            failed_ids: set[str] | None = None,
                            unresolved_targets: dict | None = None) -> bool:
    failed_ids = failed_ids or set()
    generated_ids = {sc.threat_id for sc, scoped_id, _t in pairs if scoped_id in scenarios}
    all_target_ids = {sc.threat_id for sc, _scoped_id, _t in pairs}
    excluded_ids = all_target_ids - generated_ids
    # These are two different situations that used to get lumped together: a target whose
    # generation FAILED (temporary — stays selected, a retry will try again) vs one that
    # genuinely no longer scores high enough to qualify (permanent). Treating a temporary
    # failure as "doesn't qualify anymore" used to send support down the wrong troubleshooting
    # path.
    rescored_ids = excluded_ids - failed_ids
    # Passed back to the caller so it knows which targets to retry. This matters for partial
    # successes too — a batch where some targets succeeded and others didn't used to report
    # plain success with no way to tell which ones still need a retry.
    if unresolved_targets is not None:
        unresolved_targets["failed_ids"] = failed_ids
        unresolved_targets["rescored_ids"] = rescored_ids
    if rescored_ids:
        log.warning("regen.target_no_longer_selected", session_id=sid, subsystem=ss,
                    threat_ids=sorted(rescored_ids))
    if failed_ids:
        log.warning("regen.target_generation_failed", session_id=sid, subsystem=ss,
                    threat_ids=sorted(failed_ids))

    if not regen_mode:
        _mark_next_set_targets_rescored_out(sess, sid, ss, pairs, excluded_ids, tenant, entity_id, user_id)

    if not generated_ids:
        if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch, task_id):
            sess.rollback()
            log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
            return False
        sess.commit()
        if failed_ids:
            # A generation failure always takes priority in the error message: if anything
            # failed, we say so and make it retryable, instead of showing one of the more
            # final-sounding messages below.
            raise dal.RegenerateConflict(
                f"scenario generation failed for {len(failed_ids)} threat(s); they remain "
                "selected and re-servable — retrying the same action repeats them",
                reason="generation_failed")
        if not pairs:
            raise dal.RegenerateConflict(
                "no unserved threats remain for this asset", reason="no_new_threats_found")
        raise dal.RegenerateConflict(
            f"threat(s) no longer meet the scoping cutoff and cannot be regenerated: {sorted(rescored_ids)}",
            reason="new_threat_did_not_qualify")

    generated_pairs = [(sc, scoped_id, t) for sc, scoped_id, t in pairs if scoped_id in scenarios]
    if regen_mode:
        dal.supersede_scoped_rows(sess, [t.scoped_threat_id for _sc, _scoped_id, t in generated_pairs])
    else:
        old_scoped_ids = dal.active_scoped_threat_ids(sess, sid, ss, generated_ids)
        dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, generated_ids)
        dal.supersede_by_scoped_threats(sess, sid, ss, old_scoped_ids)
    scoped_rows = []
    output_rows = []
    for sc, scoped_id, target in pairs:
        if sc.threat_id in excluded_ids:
            continue
        if regen_mode and scoped_id not in scenarios:
            continue
        scoped_rows.append(_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id))
        if scoped_id not in scenarios:
            continue
        scenario, report = scenarios[scoped_id]
        number = target.scenario_number if target is not None else 1
        output_rows.append(_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, enriched.get(sc.threat_id, {}),
                                                    scenario_number=number))
    if scoped_rows:
        sess.execute(insert(m.Scoped_Threat), scoped_rows)
    if output_rows:
        seen_keys: set[tuple[str, int]] = set()
        deduped_output_rows = []
        for r in output_rows:
            key = (r["IdentityHash"], r["ScenarioNumber"])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            deduped_output_rows.append(r)
        output_rows = deduped_output_rows
        by_number: dict[int, set[str]] = {}
        for h, number in seen_keys:
            by_number.setdefault(number, set()).add(h)
        retired: dict[tuple[str, int], str] = {}
        for number, hashes in by_number.items():
            for h, old_id in dal.supersede_by_identity_hashes(
                    sess, sid, ss, hashes, scenario_number=number).items():
                retired[(h, number)] = old_id
        for r in output_rows:
            r["ReplacesOutputID"] = retired.get((r["IdentityHash"], r["ScenarioNumber"]))
    if output_rows:
        sess.execute(insert(m.Threat_Scenario_Output), output_rows)
    return True


def _build_work_items(scoped_all: list[scoping.Scored],
                    target_threat_ids: set[str] | None,
                    regen_targets: dict[str, RegenTarget] | None,
                    ) -> tuple[list[tuple], int]:
    pairs: list[tuple[scoping.Scored, str, RegenTarget | None]]
    if regen_targets is not None:
        by_threat_targets: dict[str, list[RegenTarget]] = {}
        for t in regen_targets.values():
            by_threat_targets.setdefault(t.threat_id, []).append(t)
        pairs = [(sc, guid(), t)
                for sc in scoped_all if sc.threat_id in by_threat_targets
                for t in sorted(by_threat_targets[sc.threat_id], key=lambda t: t.scenario_number)]
    elif target_threat_ids is not None:
        pairs = [(sc, guid(), None) for sc in scoped_all if sc.threat_id in target_threat_ids]
    else:
        pairs = [(sc, guid(), None) for sc in scoped_all]
    scoped_threat_count = len({sc.threat_id for sc, _scoped_id, _t in pairs})

    return pairs, scoped_threat_count



def _prepare_scenario_batch(sess: Session, sid: str, ss: int, scenario_session: dict,
                            subsystems: list[dict], asset_context: dict, threats: list[dict],
                            target_threat_ids: set[str] | None,
                            regen_targets: dict[str, RegenTarget] | None,
                            targeted: bool) -> _ScenarioBatch:
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems)

    tn = tuning.from_session(scenario_session)  # tuning settings frozen at session start, not live config
    type_ids = sorted({t["threat_type_id"] for t in threats if t.get("threat_type_id") is not None})
    top_n = get_settings().scoping_top_n  # not session-tunable: None means let coverage decide
    if top_n is not None:
        top_n = min(top_n, tn.max_threats_per_asset)
    scoped_all = scoping.score_threats(threats, subsystems=subsystems,
                                    rules=dal.active_threat_rules(sess, type_ids),
                                    score_threshold=tn.scoping_score_threshold,
                                    base_score=tn.base_score,
                                    default_rule_weight=tn.default_rule_weight)
    enriched = {t["threat_id"]: t for t in threats}
    deduped = _select_unique_top_n(scoped_all, enriched, top_n) if not targeted else 0
    pairs, scoped_count = _build_work_items(scoped_all, target_threat_ids, regen_targets)
    entry_vocab, ambiguous = prompts.entry_point_vocabulary(
        subsystems, scenario_session["AssetName"])
    if ambiguous:
        log.warning("scenario.entry_points_ambiguous", session_id=sid, subsystem=ss,
                    labels=ambiguous)
    if not entry_vocab:
        # This is a WARNING, not just info, because it silently limits every threat in the
        # session to exactly one scenario each. Everything downstream still reports "ok" —
        # validation only checks the narrative fields, not entry points — so without this log
        # line, a session that generated an eighth of its intended output would look
        # completely normal. The count is also saved in the scoping_complete audit row so
        # it isn't lost.
        log.warning("scenario.entry_points_unavailable", session_id=sid, subsystem=ss,
                    subsystems=len(subsystems))
    fold = _fold_scenario_rows(dal.active_scenario_rows(sess, sid, ss))
    intel_terms, intel_ot = _intel_vocabulary(subsystems, asset_context)
    return _ScenarioBatch(base_ctx, enriched, deduped, pairs, scoped_count, fold, entry_vocab,
                        intel_terms, intel_ot)


def _retire_prior_card(sess: Session, sid: str, ss: int, info: dict) -> str | None:
    identity = dal.identity_hash(sid, ss, info)
    return dal.supersede_by_identity_hashes(sess, sid, ss, {identity}, scenario_number=1).get(identity)


def _persist_full_run_failure(sess: Session, sid: str, ss: int, tenant: str, entity_id: str | None,
                            user_id: str | None, sc, scoped_id: str, info: dict,
                            client_msg: str, epoch: int) -> None:
    retired_card = _retire_prior_card(sess, sid, ss, info)
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, {sc.threat_id})
    sess.execute(insert(m.Scoped_Threat),
                [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
    sess.execute(insert(m.Threat_Scenario_Output),
                [_build_error_output_row(scoped_id, sid, tenant, ss, client_msg, epoch,
                                        entity_id, user_id, info, replaces_output_id=retired_card)])
    sess.commit()


def _persist_full_run_scenario(sess: Session, sid: str, ss: int, tenant: str, entity_id: str | None,
                            user_id: str | None, sc, scoped_id: str, info: dict,
                            scenario: dict, report: dict, epoch: int) -> None:
    retired_card = _retire_prior_card(sess, sid, ss, info)
    # Same as _persist_full_run_failure: retire any existing active Scoped_Threat row for this
    # threat before inserting a new one. This matters on a Celery retry — if attempt 1 failed
    # after creating a scoped row, attempt 2 would otherwise create a second active row for
    # the same threat, silently breaking the "one active row per threat" rule.
    dal.supersede_by_threats(sess, m.Scoped_Threat, sid, ss, {sc.threat_id})
    sess.execute(insert(m.Scoped_Threat),
                [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
    sess.execute(insert(m.Threat_Scenario_Output),
                [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                            entity_id, user_id, info, replaces_output_id=retired_card)])
    sess.commit()


def write_scenarios(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, threats: list[dict],
                llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, target_threat_ids: set[str] | None = None,
                *, require_lock: bool = False,
                regen_targets: dict[str, RegenTarget] | None = None,
                on_before_commit: Callable[[list[Provenance | None]], None] | None = None,
                unresolved_targets: dict | None = None) -> list[Provenance | None]:

    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    if require_lock and not dal.holds_lock(sess, sid, ss, task_id):
        log.warning("subsystem.lock_lost_before_scenarios", session_id=sid, subsystem=ss)
        return []
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
        return []
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.SCENARIOS, StageStatus.RUNNING, epoch)

    targeted = target_threat_ids is not None or regen_targets is not None
    batch = _prepare_scenario_batch(sess, sid, ss, scenario_session, subsystems, asset_context, threats,
                                    target_threat_ids, regen_targets, targeted)
    base_ctx, enriched, deduped = batch.base_ctx, batch.enriched, batch.deduped
    pairs, scoped_threat_count = batch.pairs, batch.scoped_count
    siblings_by_hash, entry_vocab = batch.fold.siblings_by_hash, batch.entry_vocab
    cross_pairs = list(batch.fold.cross_pairs)

    provs: list[Provenance | None] = []
    scenarios: dict[str, tuple[dict, dict]] = {}
    already_done: set[str] = set()
    if not targeted:
        already_done = _begin_full_run_attempt(sess, sid, ss, tenant, entity_id, user_id, pairs, epoch)
    failures: list[str] = []
    failed_ids: set[str] = set()  # threat ids whose GENERATION failed — never "rescored out"
    first_failure: Exception | None = None
    for sc, scoped_id, target in pairs:
        if not sc.selected or sc.threat_id in already_done:
            continue
        sibling_texts = None
        if target is not None and target.identity_hash:
            sibling_texts = [(number, statement)
                            for output_id, number, statement in siblings_by_hash.get(target.identity_hash, [])
                            if output_id != target.output_id] or None
        own_identity = dal.identity_hash(sid, ss, enriched.get(sc.threat_id, {}))
        coverage = _Coverage(vocab=entry_vocab,
                            frozen=batch.fold.frozen_by_hash.get(own_identity),
                            others=[s for h, s in cross_pairs if h != own_identity] or None,
                            intel_terms=batch.intel_terms, intel_ot=batch.intel_ot)
        try:
            scenario, report, prov = _generate_one_scenario(sess, scenario_session, base_ctx, sc,
                                                            enriched, llm, task_id, epoch,
                                                            sibling_texts=sibling_texts,
                                                            coverage=coverage,
                                                            correlation_id=scoped_id)
        except LLMSlotUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — [R8] capture, don't swallow: kept as first_failure
            sess.rollback()
            first_failure = first_failure or exc
            failed_ids.add(sc.threat_id)
            client_msg = _failure_client_message(exc)
            failures.append(f"{enriched.get(sc.threat_id, {}).get('threat_name') or sc.threat_id}: {client_msg}")
            log.warning("scenario.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=sc.threat_id, error=repr(exc))
            if not targeted:
                _persist_full_run_failure(sess, sid, ss, tenant, entity_id, user_id, sc, scoped_id,
                                        enriched.get(sc.threat_id, {}), client_msg, epoch)
            continue
        provs.append(prov)
        if not targeted:
            if not dal.renew_lease(sess, sid, ss, SubsystemLevel.SCENARIOS, epoch, task_id):
                sess.rollback()
                log.warning("stage.claim_lost_midbatch", session_id=sid, subsystem=ss,
                            stage="SCENARIOS", epoch=epoch, committed=len(provs) - 1)
                break
            _persist_full_run_scenario(sess, sid, ss, tenant, entity_id, user_id, sc, scoped_id,
                                    enriched.get(sc.threat_id, {}), scenario, report, epoch)
        else:
            scenarios[scoped_id] = (scenario, report)
        cross_pairs.append((own_identity, str(scenario.get("scenario_statement") or "")))

    if failures and not provs and not already_done and first_failure is not None:
        raise first_failure

    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=tenant, EntityID=scenario_session["EntityID"],
                    Stage=WorkflowStage.SCENARIO_GENERATION, SubsystemID=ss,
                    EventType=AuditEventType.scoping_complete,
                    # entry_points: 0 means nothing in this batch could get a second scenario —
                    # the whole session is capped at one per threat. Recorded here (not just
                    # logged) so it's visible later; nothing else in /results shows this.
                    DetailJSON=json.dumps({"scoped": scoped_threat_count, "selected": len(provs),
                                        "deduped": deduped, "entry_points": len(entry_vocab)}))
    log.info("scenarios.deduped", session_id=sid, subsystem=ss, deduped=deduped, kept=len(provs))

    if targeted and not _reconcile_targeted_regen(
            sess, sid, ss, tenant, entity_id, user_id,
            pairs, scenarios, enriched, epoch, task_id,
            regen_mode=regen_targets is not None, failed_ids=failed_ids,
            unresolved_targets=unresolved_targets):
        return []
    partial_error = (f"{len(failures)} of {len(failures) + len(provs)} scenario(s) failed to "
                    f"generate: {'; '.join(failures)}") if failures else None
    # durable=not targeted: only the plain full-run path has nothing else uncommitted on `sess`
    # at this point (see map_controls' durable docstring) — targeted regen/next-set still has
    # buffered, uncommitted scenario rows here (_reconcile_targeted_regen), so it must keep
    # riding this transaction instead of forcing an early commit of unvalidated writes.
    _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch,
                            durable=not targeted)
    if not dal.finish_stage(sess, sid, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION,
                            epoch, task_id, error=partial_error):
        sess.rollback()
        log.warning("stage.claim_lost", session_id=sid, subsystem=ss, stage="SCENARIOS", epoch=epoch)
        return []
    if on_before_commit is not None:
        on_before_commit(provs)
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.SCENARIOS, StageStatus.AWAITING_DECISION, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="SCENARIOS", scenarios=len(provs))
    return provs


def _finalize_scenario_batch(sess: Session, scenario_session: dict, asset_context: dict,
                            subsystems: list[dict], llm: LLMClient, task_id: str, epoch: int,
                            *, durable: bool = False) -> None:
    control_mapping.map_controls(sess, scenario_session, asset_context, subsystems, llm,
                                ASSET_UNIT_ID, task_id, epoch, durable=durable)


def write_variant_scenarios(sess: Session, scenario_session: dict, subsystem_id: int,
                            subsystems: list[dict], asset_context: dict, llm: LLMClient,
                            task_id: str, epoch: int, max_variants: int,
                            exclude_threat_ids: set[str] | None = None) -> int:
    from sqlalchemy.exc import IntegrityError

    sid, ss, tenant = scenario_session["SessionID"], subsystem_id, scenario_session["TenantID"]
    entity_id, user_id = scenario_session["EntityID"], scenario_session.get("UserID")
    fold = _fold_scenario_rows(dal.active_scenario_rows(sess, sid, ss))
    eligible = dal.variant_eligible_primaries(
        sess, sid, max_variants, rows=fold.rows,
        attempt_slack=tuning.from_session(scenario_session).coverage_attempt_slack,
        exclude_threat_ids=exclude_threat_ids)
    if not eligible:
        log.info("variant.coverage_exhausted", session_id=sid, subsystem=ss)
        return 0
    entry_vocab, ambiguous = prompts.entry_point_vocabulary(
        subsystems, scenario_session["AssetName"])
    if ambiguous:
        log.warning("variant.entry_points_ambiguous", session_id=sid, subsystem=ss, labels=ambiguous)
    # Variants skip _prepare_scenario_batch, so intel terms are resolved here instead using
    # the same shared helper — otherwise every variant would silently get no intel block.
    intel_terms, intel_ot = _intel_vocabulary(subsystems, asset_context)
    threats = dal.active_threats(sess, sid, ss)
    enriched = {t["threat_id"]: t for t in threats}
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems)
    siblings_by_hash = {h: [(n, s) for _oid, n, s in v]
                        for h, v in fold.siblings_by_hash.items()}
    cross_pairs = list(fold.cross_pairs)

    created = 0
    for item in eligible:
        info = enriched.get(item["threat_id"])
        if not info:
            continue
        try:
            factors = json.loads(item["factors_json"]) if item["factors_json"] else []
        except (TypeError, ValueError):
            factors = []
        sel = item.get("selection_kind")
        sc = scoping.Scored(threat_id=item["threat_id"], score=item["score"] or 0.0,
                            rank=item["scope_rank"] or 0, selected=True,
                            reason=item["reason"] or "",
                            # older primaries (before this column existed) have NULL here — kept as None, never guessed
                            selection=SelectionReason(sel) if sel else None,
                            factors=factors)
        # Minted BEFORE the call, not after it, so the generation's Prompt_Log rows can carry it.
        # Left unused on the break/continue paths below — guid() is pure, so a discarded id is free.
        # This hoist and the correlation_id argument below are one change: passing the id while it
        # is still minted after the call would stamp receipts with the PREVIOUS card's id, which is
        # worse than NULL because a wrong id reads as an answer.
        scoped_id = guid()
        try:
            scenario, report, _prov = _generate_one_scenario(
                sess, scenario_session, base_ctx, sc, enriched, llm, task_id, epoch,
                sibling_texts=siblings_by_hash.get(item["identity_hash"]) or None,
                coverage=_Coverage(
                    vocab=entry_vocab,
                    frozen=fold.frozen_by_hash.get(item["identity_hash"]),
                    others=[s for h, s in cross_pairs if h != item["identity_hash"]] or None,
                    intel_terms=intel_terms, intel_ot=intel_ot),
                correlation_id=scoped_id)
        except LLMSlotUnavailable:
            sess.rollback()
            log.warning("variant.slots_exhausted", session_id=sid, subsystem=ss,
                        created=created, remaining=len(eligible) - created)
            break
        except Exception as exc:  # noqa: BLE001 — [R8] one variant's failure must not kill the batch
            sess.rollback()
            log.warning("variant.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=item["threat_id"], error=repr(exc))
            continue
        try:
            sess.execute(insert(m.Scoped_Threat),
                        [_build_scoped_threat_row(scoped_id, sid, tenant, ss, sc, entity_id, user_id)])
            sess.execute(insert(m.Threat_Scenario_Output),
                        [_build_scenario_output_row(scoped_id, sid, tenant, ss, scenario, report, epoch,
                                                    entity_id, user_id, info,
                                                    scenario_number=item["next_number"])])
            sess.commit()
        except IntegrityError:
            sess.rollback()
            log.info("variant.race_lost", session_id=sid, subsystem=ss, threat_id=item["threat_id"],
                    scenario_number=item["next_number"])
            continue
        cross_pairs.append((item["identity_hash"], str(scenario.get("scenario_statement") or "")))
        created += 1
    if created:
        try:
            _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch)
            sess.commit()
        except Exception as exc:  # noqa: BLE001 — [R8] finalize is best-effort; scenarios already committed
            sess.rollback()
            log.warning("variant.finalize_failed", session_id=sid, subsystem=ss,
                        created=created, error=repr(exc))
    return created


def _classify_llm_failure(exc: Exception) -> tuple[str, str]:
    """One shared classification of a terminal LLM/stage failure: a stable token a caller can
    switch on ('guardrail' | 'parse' | 'generic') plus the client-safe message. The TOKEN is
    the contract — treatment._classify_failure maps it to a TreatmentOutcomeReason — so no
    caller anywhere matches the English text (a rewording must never silently change a wire
    reason)."""
    if isinstance(exc, validation.LLMResponseParseError):
        return "parse", repr(exc)
    try:
        from litellm.exceptions import RejectedRequestError
    except ImportError:
        return "generic", "stage processing failed"
    if isinstance(exc, RejectedRequestError):
        return "guardrail", "content blocked by a configured safety guardrail"
    return "generic", "stage processing failed"


def _failure_client_message(exc: Exception) -> str:
    return _classify_llm_failure(exc)[1]


def _record_failure(sess: Session, scenario_session: dict, subsystem_id: int, exc: Exception,
                    epoch: int = _EPOCH, extra: dict | None = None) -> None:
    sess.rollback()
    sid = scenario_session["SessionID"]
    client_msg = _failure_client_message(exc)
    sess.execute(
        update(m.Subsystem_Stage_State)
        .where(m.Subsystem_Stage_State.SessionID == sid,
            m.Subsystem_Stage_State.SubsystemID == subsystem_id,
            m.Subsystem_Stage_State.Level.in_(list(_WORK_LEVELS)),
            m.Subsystem_Stage_State.GenerationEpoch == epoch,
            m.Subsystem_Stage_State.Status.in_([StageStatus.IDLE, StageStatus.RUNNING]))
        .values(Status=StageStatus.ERROR, ErrorMessage=client_msg, LeaseExpiresAt=None, UpdatedAt=now())
    )
    detail = {"error": client_msg, "subsystem_id": subsystem_id}
    if extra:
        detail.update(extra)
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    SubsystemID=subsystem_id, EventType=AuditEventType.stage_error,
                    DetailJSON=json.dumps(detail))
    sess.commit()
    # Item 27: explicit "scope" instead of leaving the client to infer it from whether
    # subsystem_id is present — see the typed ErrorEvent model (schemas.py) for the full contract.
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "subsystem_id": subsystem_id,
                    "scope": "stage", "message": client_msg, "generation_epoch": epoch, "ts": now().isoformat()})
    log.error("stage.error", session_id=sid, subsystem=subsystem_id, error=repr(exc))


def decide_session_outcome(sess: Session, scenario_session: dict) -> str | None:
    sid = scenario_session["SessionID"]
    statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if not statuses or any(s in (StageStatus.IDLE, StageStatus.RUNNING) for s in statuses):
        return None
    if dal.has_active_scenarios(sess, sid):
        dal.revive_errored_scenarios_to_review(sess, sid)
        statuses = [str(r["Status"]) for r in dal.stage_rows(sess, sid)]
    if any(s == StageStatus.AWAITING_DECISION for s in statuses):
        return "review" if _send_to_review(sess, scenario_session) else None
    if any(s == StageStatus.ERROR for s in statuses):
        return "cancelled" if _mark_session_failed(sess, scenario_session) else None
    log.warning("finalize.no_terminal_state", session_id=sid, statuses=statuses)
    return None


# KNOWN LIMITATION: session_entered_review's generation_epoch always reports the module-level
# _EPOCH default (1), even when a regenerate (epoch > 1) is what actually drove the session back
# into REVIEW via decide_session_outcome. Scenario_Session has no session-level GenerationEpoch
# column — epoch lives per subsystem/stage on Subsystem_Stage_State only — so there is no single
# "current epoch" value decide_session_outcome can read and thread through without adding an epoch
# parameter to decide_session_outcome itself and updating every caller (cascade.py's several call
# sites, reaper.py, sessions.py). Not fixed here; the durable, correct-epoch signal for a regen is
# progress.last_regen.epoch (see GET /v1/sessions/{id}), not this event's generation_epoch. See
# docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md §4.7.
def _send_to_review(sess: Session, scenario_session: dict, epoch: int = _EPOCH) -> bool:
    """Generation is finished: park at the review barrier AND end the session.

    The session's own lifecycle is "a generation request", not "a review workstream" — it ends
    when generation ends, which is what releases the asset (UX_Session_ActiveAsset is filtered on
    SessionStatus='active'). Each scenario then carries its own pending -> accepted/rejected
    lifecycle for as long as the reviewer needs, with no session left holding the asset open.

    CurrentStage/StageStatus stay REVIEW/AWAITING_DECISION: they describe the EXECUTION, and
    "awaiting a human decision" is still true. review_gate_reason tests that pair BEFORE it tests
    SessionStatus, so accept and regenerate keep passing the gate on a completed session — that
    ordering is load-bearing, not incidental.

    CompletedAt uses COALESCE so a next-set run (which re-reserves the session and comes back
    through here) never rewrites when generation first finished."""
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(CurrentStage=WorkflowStage.REVIEW, StageStatus=StageStatus.AWAITING_DECISION,
                SessionStatus=SessionStatus.completed,
                CompletedAt=func.coalesce(m.Scenario_Session.CompletedAt, now()), UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], Stage=WorkflowStage.REVIEW, EventType=AuditEventType.entered_review)
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.session_entered_review), "session_id": sid,
                    "status": str(StageStatus.AWAITING_DECISION), "generation_epoch": epoch, "ts": now().isoformat()})
    log.info("pipeline.entered_review", session_id=sid)
    return True


def _mark_session_failed(sess: Session, scenario_session: dict) -> bool:
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(SessionStatus=SessionStatus.cancelled, CurrentStage=WorkflowStage.CANCELLED,
                StageStatus=StageStatus.CANCELLED, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    EventType=AuditEventType.session_cancelled, DetailJSON=json.dumps({"reason": "all subsystems failed"}))
    sess.commit()
    # Item 27: explicit "scope" — see the typed ErrorEvent model (schemas.py) for the full contract.
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "scope": "session",
                    "message": "session failed: all subsystems errored", "ts": now().isoformat()})
    log.warning("pipeline.failed", session_id=sid)
    return True


def _announce_generation_started(sess: Session, scenario_session: dict, subsystem_id: int, epoch: int = _EPOCH) -> None:
    if not dal.subsystem_has_pending_work(sess, scenario_session["SessionID"], subsystem_id):
        return
    sid = scenario_session["SessionID"]
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                    EventType=AuditEventType.subsystem_advanced,
                    DetailJSON=json.dumps({"subsystem_id": subsystem_id}))
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.subsystem_started), "session_id": sid,
                    "subsystem_id": subsystem_id, "generation_epoch": epoch, "ts": now().isoformat()})


def _summarize_generation(sub_id: int, prov_i: Provenance | None, scen_provs: list[Provenance | None]) -> dict:
    return {
        "subsystem_id": sub_id, "identify_provenance": _summarize_ai_call(prov_i),
        "scenario_provenances": [_summarize_ai_call(p) for p in scen_provs],
        "scenario_count": len(scen_provs),
    }


def _process_all_supporting_systems(sess: Session, session_id: str, llm: LLMClient, task_id: str) -> None:
    row = dal.load_session(sess, session_id)
    if row is None:
        return
    scenario_session = dict(row)
    if scenario_session["CurrentStage"] == WorkflowStage.REVIEW:
        log.warning("pipeline.refused_review_session", session_id=session_id, task_id=task_id)
        return
    subsystems = json.loads(scenario_session["SubsystemsJSON"])
    asset_context = json.loads(scenario_session.get("AssetContextJSON") or "{}")
    log.info("pipeline.start", session_id=session_id, subsystems=len(subsystems), task_id=task_id)
    if dal.acquire_lock(sess, session_id, ASSET_UNIT_ID, task_id):
        sess.commit()
        try:
            categories = dal.active_category_names(sess)
            actor_examples = dal.active_actor_names(sess)
            _announce_generation_started(sess, scenario_session, ASSET_UNIT_ID)
            threats, prov_i = find_threats(sess, scenario_session, subsystems, asset_context, llm, task_id,
                                        categories=categories, actor_examples=actor_examples)
            sess.commit()
            threats_stage_done = True
            if not threats:
                threats = dal.active_threats(sess, session_id, ASSET_UNIT_ID)
                threats_stage_done = bool(threats) or dal.stage_completed_at_epoch_or_newer(
                    sess, session_id, ASSET_UNIT_ID, SubsystemLevel.THREATS, _EPOCH)
            if threats_stage_done:
                scen_provs = write_scenarios(sess, scenario_session, subsystems, asset_context, threats, llm, task_id,
                                            require_lock=True)
                dal.append_audit(sess, AuditID=guid(), SessionID=session_id, TenantID=scenario_session["TenantID"],
                                EntityID=scenario_session["EntityID"], Stage=WorkflowStage.SCENARIO_GENERATION,
                                SubsystemID=ASSET_UNIT_ID, EventType=AuditEventType.generation_complete,
                                DetailJSON=json.dumps(_summarize_generation(ASSET_UNIT_ID, prov_i, scen_provs)))
                sess.commit()
            else:
                log.warning("pipeline.threats_not_complete_skipping_scenarios", session_id=session_id, task_id=task_id)
        except LLMSlotUnavailable:
            raise
        except Exception as exc:  # noqa: BLE001 — capture, don't swallow ([R8]); lock must still release in finally
            _record_failure(sess, scenario_session, ASSET_UNIT_ID, exc)
            sess.commit()
        finally:
            if not dal.release_lock(sess, session_id, ASSET_UNIT_ID, task_id):
                log.warning("asset.lock_lost", session_id=session_id, task_id=task_id)
            sess.commit()
    else:
        log.warning("asset.locked", session_id=session_id, session_status=scenario_session["SessionStatus"])

    decide_session_outcome(sess, scenario_session)