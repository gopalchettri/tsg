from __future__ import annotations

import difflib
import json
import math
import re
from collections.abc import Callable
from typing import Any, NamedTuple

from sqlalchemy import insert, update
from sqlalchemy.orm import Session

from app.core.enums import (
    AuditEventType, ScenarioStatus, ScopingRejection, SelectionReason, SessionStatus, SSEEventType,
    StageStatus, SubsystemLevel, WorkflowStage,
)
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import execute_dml, guid, now
from app.core.config import get_settings
from app.core import tuning
from app.pipeline import control_mapping, grounding, prompts, scoping, validation
from app.pipeline.llm import LLMClient, LLMSlotUnavailable, Provenance, moderate
from app.sse import bus

log = get_logger(__name__)

_EPOCH = 1
_WORK_LEVELS = (SubsystemLevel.THREATS, SubsystemLevel.SCENARIOS)
_SCENARIO_TEXT_FIELDS = ("scenario_title", "scenario_statement", "risk_statement")
ASSET_UNIT_ID = 0
# sibling-similarity ratio lives in config (Settings.sibling_similarity_ratio) and arrives as a
# parameter on the _flag_* helpers, so a Config_Tuning session snapshot can override it.


class RegenTarget(NamedTuple):
    output_id: str
    threat_id: str
    scoped_threat_id: str
    scenario_number: int
    identity_hash: str | None


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
                        threshold: float | None = None) -> set[str]:
    """ThreatIDs from `threats` that mean the same as a higher-ranked threat in this batch, or as
    one already active on the session. ENFORCING: the caller drops these before the insert.

    This is the definition of "unique" for a threat — unique in MEANING. dal.identity_hash only
    catches exact/ID matches, so "Data leakage from X" and "Unauthorised disclosure of X" both
    survive it as distinct rows and the reviewer sees the same threat twice. Cosine on the
    asset-stripped label is the only instrument that can express the real rule.

    FIRST-WINS, compared against SURVIVORS only. Similarity is not transitive — A~B and B~C does
    not give A~C — so comparing against already-dropped labels would chain-drop C for resembling
    a B that is no longer there. Deterministic because the incoming order is: find_threats
    appends in the model's own relevance order, and dal.active_threats has an explicit ORDER BY
    (scoping.score_threats relies on the same property; see its sort)."""
    # Compare labels with the ASSET NAME STRIPPED, the same way grounding does before matching the
    # catalogue. threats_prompt mandates '<impact> of <asset name>', so every label in a session
    # ends with the same string; measured on real data that constant suffix lifts median pairwise
    # cosine from 0.814 to 0.899 and takes pairs at/above 0.92 from 1/253 to 30/253. Comparing the
    # full label mostly measures "same asset" (always true) rather than "same impact".
    # GATED ON IMPACT CLASS, never similarity alone. Measured against the live embedding model,
    # the closest pair in a realistic CII set was "Unauthorized disclosure of X" vs "Unauthorized
    # modification of X" at 0.969 — higher than EVERY true paraphrase, because a sentence
    # embedding is dominated by lexical overlap and those differ by one noun. Compared on label
    # alone the classes OVERLAP and no cosine cutoff separates them, so the signal would be noise.
    # Restricting comparison to threats sharing a STRIDE category drops exactly those pairs and
    # the classes separate cleanly (measured: 4/4 paraphrases caught, 0/5 false positives).
    # A missing category on either side still compares — for a log-only signal a missed line is
    # worse than an extra one.
    def _cat(t: dict) -> str:
        return str(t.get("category") or "").strip().casefold()

    def _key(t: dict) -> str:
        return asset_agnostic_name(threat_label(t), asset_name) or ""

    entries = [(t.get("threat_id"), _key(t), _cat(t)) for t in threats]
    entries = [(tid, lbl, c) for tid, lbl, c in entries if tid and lbl]
    prior_entries = [(_key(t), _cat(t)) for t in (priors or [])]
    prior_entries = [(lbl, c) for lbl, c in prior_entries if lbl]
    if not entries or not (prior_entries or len(entries) > 1):
        return set()
    labels = [lbl for _tid, lbl, _c in entries]
    prior = [lbl for lbl, _c in prior_entries]
    # this batch wins on a label clash
    cat_of = {lbl: c for lbl, c in prior_entries + [(lbl, c) for _tid, lbl, c in entries]}
    if threshold is None:  # session-tuned when the caller carries a snapshot; config otherwise
        threshold = get_settings().semantic_near_duplicate_threshold
    # Cross-class pairs are judged at this STRICTER ceiling instead of being skipped outright.
    # The category is the MODEL'S label: the same threat tagged 'Tampering' one round and
    # 'Information Disclosure' the next used to bypass dedup entirely. At 0.98 the measured
    # 0.969 disclosure/modification trap still survives (two real threats), while a relabelled
    # near-verbatim restatement does not. Config-static, deliberately not session-tunable.
    cross_threshold = max(get_settings().semantic_cross_category_threshold, threshold)
    try:
        # `texts` is the DISTINCT strings to embed — deduped only to avoid paying for the same
        # vector twice. It is not a count of comparable entries: N threats sharing one label
        # collapse to a single text, and the old `len(texts) < 2` bail-out then returned "no
        # duplicates" for the most clear-cut duplicate there is. The real "nothing to compare"
        # check is the entries/prior_entries guard above; this one only needs to catch empty.
        texts = list(dict.fromkeys([lbl for lbl in labels if lbl] + prior))
        if not texts:
            return set()

        vectors = dict(zip(texts, llm.embed(texts, kind="query")))

        norms = {t: math.sqrt(sum(x * x for x in v)) or 1.0 for t, v in vectors.items()}
    except Exception:
        # Never block generation on a failed scan: returning "no duplicates" degrades to today's
        # behaviour (identity dedup only), whereas raising would lose the whole round's threats.
        log.warning("threats.semantic_scan_failed", session_id=sid, subsystem=ss, exc_info=True)
        return set()
    dupes: set[str] = set()
    kept: list[str] = []  # survivors only — see the first-wins note in the docstring
    for tid, label, cat in entries:
        qv = vectors.get(label)
        if qv is None:
            kept.append(label)
            continue
        for other in prior + kept:
            ov = vectors.get(other)
            # No `other == label` guard. `kept` never contains this entry (it is appended only
            # after the entry survives) and `prior` is read before this batch is inserted, so
            # self-comparison is impossible by construction. That guard compared by VALUE, which
            # meant two DISTINCT threats whose stripped labels were byte-identical — cosine 1.0,
            # the strongest signal available — were the one pair silently skipped.
            if ov is None or len(ov) != len(qv):
                continue
            other_cat = cat_of.get(other, "")
            # Same class -> calibrated threshold. Different classes -> the cross ceiling, never a
            # blanket skip — see cross_threshold above. A missing category on either side still
            # compares at the normal threshold (a missed duplicate costs a paid generation; for
            # an unlabeled row the class-trap risk is unmeasurable either way).
            eff_threshold = threshold
            if cat and other_cat and cat != other_cat:
                eff_threshold = cross_threshold
            score = sum(x * y for x, y in zip(qv, ov)) / (norms[label] * norms[other])
            if score >= eff_threshold:
                dupes.add(tid)
                log.info("threats.semantic_near_duplicate", session_id=sid, subsystem=ss,
                        proposed=label, matched=other, category=cat or None,
                        cosine=round(score, 4), threshold=threshold)
                break
        else:
            kept.append(label)
    return dupes


def _statement_of(scenario_json: str | None) -> str:

    try:
        return str((json.loads(scenario_json) or {}).get("scenario_statement") or "")
    except (TypeError, ValueError):
        return ""


class _ScenarioFold(NamedTuple):
    rows: list
    siblings_by_hash: dict
    cross_pairs: list
    frozen_by_hash: dict


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
    if level is not None:
        if not dal.renew_lease(sess, sid, subsystem_id, level, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid,
                        subsystem=subsystem_id, level=str(level))
        if not dal.renew_lock_lease(sess, sid, subsystem_id, task_id):
            log.debug("lock.lease_renewal_skipped", session_id=sid, subsystem=subsystem_id)
    sess.commit()
    # expected_type drives provider-side JSON mode: json_object forces a top-level OBJECT, which
    # would make the threats stage (expected_type=list) fail on every call wherever
    # TSG_LLM_JSON_MODE is on. One source of truth for the shape — this parameter.
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
        # Per-item linkage (treatment: PlanID) — lets audit/evidence reads join a specific
        # attempt's receipt without time-window guessing. None for stage callers.
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


def _safe_text(v: Any, default: str | None) -> str | None:
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
        # The library-shaped form of ThreatName, persisted so ACCEPT-TIME triage (days later)
        # runs on the AI's own generalization rather than the fragile string-strip fallback.
        # Truncated to the column width — one over-long AI value must not DataError the whole
        # THREATS batch insert (executemany: every row in the round would be lost).
        "GenericName": generic_name[:500] if generic_name else None,
        "ThreatActorsJSON": json.dumps({"actors": gr.actors, "validated": gr.actors_validated}),
        "LibraryThreatType": gr.library_type, "LibraryThreatName": gr.library_name,
        "ThreatTypeID": gr.type_id, "ThreatCatalogueID": gr.catalogue_id,
        "GroundingStatus": gr.status, "GroundingScore": gr.score,
        "Superseded": 0, "CreatedAt": now(),
    }
    summary = {
        "threat_id": tid, "grounding_status": str(gr.status),
        # STRIDE category, carried so the semantic near-duplicate scan can gate on impact class.
        # Measured on the live embedder, "Unauthorized disclosure of X" vs "Unauthorized
        # modification of X" scores 0.969 — above every true paraphrase — so label similarity
        # alone cannot separate two impact classes. Same key name as dal.active_threats'.
        "category": pcat,
        "threat_type": ptype, "threat_name": pname,
        "library_threat_type": gr.library_type, "library_threat_name": gr.library_name,
        "threat_type_id": gr.type_id,
        "catalogue_id": gr.catalogue_id,
        "actors": gr.actors,
    }
    return row, summary


def _normalize(s: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", " ", s)).strip().casefold()


def _asset_boundary_pattern(asset_name: str) -> re.Pattern | None:
    """One boundary-aware pattern for every asset-name check and strip. Lookarounds, not \\b —
    asset names may start/end with non-word characters ('(PGS)'). A raw substring/sub match
    fires INSIDE unrelated words: asset 'CIS' matched 'decision' (rejecting every valid
    generic_name and corrupting the strip to 'Loss of de ion integrity'), which then flowed
    into grounding queries, the persisted GenericName, and accept-time triage."""
    # Tolerant on three axes a literal re.escape of the raw name was not — each one a measured
    # leak path for the asset name into GenericName and from there the shared library:
    #   * trailing punctuation on the NAME ('ACME Corp.') failed to match 'ACME Corp systems';
    #   * internal whitespace drift ('Power  Plant' in curated data vs 'Power Plant' in prose);
    #   * a possessive after the match ('Citizen Portal's credentials') left a dangling 's.
    a = (asset_name or "").strip().rstrip(".,;:!")
    if not a:
        return None
    body = r"\s+".join(re.escape(tok) for tok in a.split())
    return re.compile(r"(?<!\w)" + body + r"(?:'s)?(?!\w)", re.IGNORECASE)


def asset_agnostic_name(name: str | None, asset_name: str) -> str | None:
    """Strip the (boundary-matched) asset name out of a threat label. Returns None — never the
    original — when nothing but the asset name remains: the old `stripped or name` tail handed
    the raw ASSET-EMBEDDED string back to accept-time triage, which could auto-approve it into
    the tenant-less shared Threat_Catalogue. Every caller tolerates None (`or ""` in the
    near-duplicate scan; the accept fallback demotes to the review queue)."""
    if not name or not asset_name:
        return name
    pat = _asset_boundary_pattern(asset_name)
    if pat:
        # Consume an immediately-PRECEDING preposition with the asset span, so a MID-string
        # removal doesn't leave it dangling: 'Compromise of X leading to outage' used to strip to
        # 'Compromise of leading to outage' — the old cleanup below is $-anchored and only ever
        # fixed the tail.
        combined = re.compile(r"(?:\b(?:of|from|to|in|on|for|against|at)\s+)?" + pat.pattern,
                            pat.flags)
        stripped = combined.sub(" ", name)
    else:
        stripped = name
    stripped = re.sub(r"\s+", " ", stripped).strip(" ,;:-.'")
    stripped = re.sub(r"\s+(of|to|on|in|for|against)$", "", stripped, flags=re.IGNORECASE)
    return stripped or None


#: Filler the model emits when it has no real name — compared AFTER stripping brackets,
#: quotes and punctuation and casefolding, so 'N/A', '["N/A"]', '(none)', 'NULL', '- ' all
#: reduce to a member here. ONE list; extend it here, never at a call site.
_JUNK_NAME_TOKENS = frozenset({
    "", "na", "n a", "none", "null", "nil", "tbd", "unknown", "not applicable",
    "not available", "no name", "no threat", "empty",
})


def clean_library_name(name: str | None) -> str | None:
    """A name fit to enter the shared library, or None. Rejects null/empty values, bracketed
    or quoted junk ('N/A', ['NA'], [], '"None"'), the filler vocabulary above, and anything
    without at least two letter-bearing words. The floor matters because semantically EMPTY
    text embeds far from every catalogue entry, making junk the MOST likely text to slip under
    the auto-approve band into the library — the one triage band a curator never sees.
    Enforced at both writers: Stage-1 persistence (_generic_name_of) and accept-time
    auto-approve (defence in depth)."""
    if not name:
        return None
    core = re.sub(r"""[\[\]{}()<>'"`,;:._\-/\\]+""", " ", name)
    core = re.sub(r"\s+", " ", core).strip()
    if core.casefold() in _JUNK_NAME_TOKENS:
        return None
    if len([w for w in core.split() if any(ch.isalpha() for ch in w)]) < 2:
        return None
    # Return the name with WRAPPING junk stripped, not the raw input. This used to validate
    # `core` but return `name.strip()`, so '"Data exfiltration"' passed the checks and was stored
    # QUOTES AND ALL — becoming the accept-time triage query and, on auto-approve, the shared
    # library entry's literal wording. Only the wrapper is stripped; interior punctuation is the
    # name's own business ('e-mail', 'command & control').
    display = re.sub(r"""^[\s\[\]{}()<>'"`]+|[\s\[\]{}()<>'"`]+$""", "", name)
    display = display.strip(" ,;:.-")
    return display or None


def _generic_name_of(p: dict, asset_name: str) -> str | None:
    """The library-shaped form of a Stage-1 proposal: the AI's own `generic_name`, accepted
    only when it passes clean_library_name AND does not contain the asset name
    (boundary-matched) — the prompt is never the enforcement. Fallback is the
    `asset_agnostic_name` strip of `name`, which returns None rather than an asset-embedded
    string."""
    pat = _asset_boundary_pattern(asset_name)
    g = clean_library_name(_safe_text(p.get("generic_name"), None))
    if g and pat and pat.search(g):
        log.warning("threats.generic_name_leaks_asset", generic_name=g)
        g = None
    return g or asset_agnostic_name(_safe_text(p.get("name"), None), asset_name)


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


#: Ceiling on one proposal's grounding query text. Sits below llm._MAX_EMBED_CHARS (4000), which
#: RAISES rather than truncates — and that raise escapes find_threats, losing EVERY threat in the
#: round, not just the oversized one. A hard provider limit, so a constant and not a config knob.
_MAX_PROPOSAL_CHARS = 3500


def _usable_proposal(p: object) -> bool:
    """Is this element of the model's JSON array safe to persist?

    parse_json validates only that the TOP LEVEL is a list, so elements are whatever the model
    emitted. Three ways an unchecked element does real damage, all fixed by rejecting it here
    rather than by guarding each reader:

    * not a dict -> `.get()` raises AttributeError in grounding.prime_query_embeddings and again
      in the loop below. That is not the typed LLMResponseParseError [R8] expects, so it reaches
      the catch-all and CANCELS THE SESSION.
    * empty type/name -> nothing to ground, score or dedup on, and scenario_prompt rightly
      refuses it later. Because nothing ever UPDATEs Identified_Threat, the resulting error card
      re-raises identically on every regenerate: permanently unclearable.
    * over-long -> llm.embed raises and the whole round's threats are lost.
    """
    if not isinstance(p, dict):
        return False
    ptype = _safe_text(p.get("type"), "") or ""
    pname = _safe_text(p.get("name"), "") or ""
    return bool(ptype) and bool(pname) and len(ptype) + len(pname) <= _MAX_PROPOSAL_CHARS


def find_threats(sess: Session, scenario_session: dict, subsystems: list[dict], asset_context: dict, llm: LLMClient, task_id: str,
                epoch: int = _EPOCH, categories: list[str] | None = None,
                actor_examples: list[str] | None = None,
                supersede: bool = True, exclude: list[str] | None = None,
                prior_threats: list[dict] | None = None) -> tuple[list[dict], Provenance | None]:
    # `exclude` is the label strings that steer the prompt; `prior_threats` is the same threats as
    # rows, carrying each one's category so the near-duplicate scan can gate on impact class.
    # The caller already holds them, so this costs no extra query.
    sid, ss, tenant = scenario_session["SessionID"], ASSET_UNIT_ID, scenario_session["TenantID"]
    if not dal.claim_stage(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
        return [], None
    sess.commit()
    _send_live_update(sid, SSEEventType.stage_started, ss, SubsystemLevel.THREATS, StageStatus.RUNNING, epoch)
    tn = tuning.from_session(scenario_session)  # the session's frozen rulebook — never live config
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
    # Untrusted input, filtered ONCE at the boundary — see _usable_proposal. Every reader below
    # (and grounding.prime_query_embeddings) dereferences these elements, so guarding them here
    # is both the smallest and the only complete fix.
    usable = [p for p in proposals if _usable_proposal(p)]
    if len(usable) != len(proposals):
        log.warning("threats.proposals_dropped", session_id=sid,
                    dropped=len(proposals) - len(usable), received=len(proposals))
    proposals = usable
    if supersede:
        dal.supersede(sess, m.Identified_Threat, sid, ss)
    existing_identities = dal.active_identified_threat_identities(sess, sid, ss) if not supersede else set()
    threats: list[dict] = []
    rows: list[dict] = []
    duplicates = 0
    sector_ids = json.loads(scenario_session["SectorIDsJSON"]) if scenario_session.get("SectorIDsJSON") else []
    grounding_cache: dict = {}
    # Grounding and the identity fingerprint run on the LIBRARY-SHAPED name: the AI's own
    # generic_name when valid, the string-strip fallback otherwise (_generic_name_of).
    to_ground = [{**p, "name": _generic_name_of(p, scenario_session["AssetName"])}
                for p in proposals]  # every element is a dict — _usable_proposal guaranteed it
    grounding.prime_query_embeddings(llm, to_ground, grounding_cache)
    for p, gp in zip(proposals, to_ground):
        if len(rows) >= max_threats:            
            log.warning("threats.over_proposed", session_id=sid,
                        proposed=len(proposals), cap=max_threats)
            break
        
        if not dal.renew_lease(sess, sid, ss, SubsystemLevel.THREATS, epoch, task_id):
            log.warning("stage.lease_renewal_failed", session_id=sid, subsystem=ss, level=str(SubsystemLevel.THREATS))
        sess.commit()
        # Clipped to their column widths AT THE SOURCE, not in the row dict: one runaway AI
        # string would DataError the whole executemany batch (every threat in the round lost),
        # and clipping later would let the stored value disagree with the identity hash
        # computed from these same variables — a subsequent non-supersede round could then
        # re-admit a duplicate of exactly the rows that were clipped.
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
            continue
        existing_identities.add(identity)
        rows.append(row)
        threats.append(summary)
    # BEFORE the insert, not after: this is a gate now, not an observation. The identity check in
    # the loop above catches only exact/ID matches, so two proposals meaning the same thing in
    # different words both survive it — and both reach the reviewer as separate scenarios, each
    # costing a paid generation. Reversible without a deploy: Config_Tuning can set
    # semantic_near_duplicate_threshold to 1.0, which makes the gate unreachable for new sessions.
    dupe_ids = _semantic_duplicates(llm, sid, ss, threats, prior_threats,
                                    scenario_session["AssetName"],
                                    threshold=tn.semantic_near_duplicate_threshold)
    near_dupes = len(dupe_ids)
    if dupe_ids:
        rows = [r for r in rows if r["ThreatID"] not in dupe_ids]
        threats = [t for t in threats if t["threat_id"] not in dupe_ids]
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
    _send_live_update(sid, SSEEventType.stage_completed, ss, SubsystemLevel.THREATS, StageStatus.COMPLETE, epoch)
    log.info("stage.complete", session_id=sid, subsystem=ss, stage="THREATS", count=len(threats))
    return threats, prov




def _moderation_report(scenario: dict) -> dict:  
    text = " ".join(str(scenario.get(f) or "") for f in _SCENARIO_TEXT_FIELDS)
    text = " ".join([text] + [f"{c.get('name') or ''} {c.get('why') or ''}".strip()
                            for c in (scenario.get("controls") or []) if isinstance(c, dict)])
    r = moderate(text)
    return {"checked": r.checked, "flagged": r.flagged, "categories": r.categories, "error": r.error}




#: The subsystem-level technology-inventory fields intel search terms may come from.
#: Deliberately WITHOUT the subsystem asset_type: it resolves to the IT/OT category strings,
#: which are noise as product search terms — that field feeds only the is_ot preference. The
#: ASSET-level asset_type (free text, e.g. 'Power Plant') does join the terms.
_INTEL_TECH_FIELDS = ("technology_used", "vendor_name", "database_platforms",
                    "saas_platform_list", "public_cloud_platforms")


def _intel_vocabulary(subsystems: list[dict], asset_context: dict) -> tuple[list[str], bool]:
    """Intel search terms from the asset's TECHNOLOGY inventory and CLASSIFICATION taxonomy —
    never from threat wording.
    Threat names are deliberately business-impact prose, so their words match the BUSINESS
    words of advisories ('failure', 'maintenance', 'system') — which is how a power plant got
    Cisco/Fortinet/SharePoint CVEs while ICS advisories sat unused. Product names
    ('Siemens', 'SCADA', 'Windows Server') match what advisories actually describe.

    Sector/sub_sector/critical_service join them because they are curated dropdown values —
    the same vocabulary OTX pulses and CISA ICS advisories tag themselves with — not the
    free-text impact prose the rule above excludes. They are what rescues an asset whose
    entire technology inventory reads 'Custom Application' / 'NA' from matching nothing.

    Terms are drawn from whatever the context layer supplied — the same fields
    prompts.build_base_context sends to the model — with no field-name gate; placeholder values
    ("NA", "Unknown") are skipped by the shared is_placeholder test so they never become
    search terms.

    Returns (terms, is_ot). is_ot is true when ANY subsystem type or the asset type resolves
    OT via control_mapping.itot_family — deliberately NOT _resolve_itot, which returns None
    unless every component agrees, so a plant with one IT historian would never prefer ICS
    advisories. Empty terms → the caller sends no intel block at all (silence over noise —
    same as today's no-match path)."""
    terms: list[str] = []
    seen: set[str] = set()

    def _add(value: Any) -> None:
        from app.core.security import is_placeholder  # shared no-value test (scrub_context)

        for v in value if isinstance(value, (list, tuple)) else [value]:
            text = str(v).strip() if v is not None else ""
            if text and not is_placeholder(text) and text.casefold() not in seen:
                seen.add(text.casefold())
                terms.append(text)

    for sub in subsystems or []:
        for fld in _INTEL_TECH_FIELDS:
            _add(sub.get(fld))
    # Classification taxonomy, NOT threat prose: 'Energy'/'Power Generation' are curated
    # dropdown values, and they are exactly how OTX pulses and CISA ICS advisories label
    # themselves. Without them an asset whose whole inventory reads "Custom Application"
    # matches nothing and silently loses its intel block entirely.
    for fld in ("asset_type", "sector", "sub_sector", "critical_service"):
        _add(asset_context.get(fld))
    is_ot = any(control_mapping.itot_family(s.get("asset_type")) == "OT"
                for s in subsystems or [])
    is_ot = is_ot or control_mapping.itot_family(asset_context.get("asset_type")) == "OT"
    return terms, is_ot


def _fetch_intel(terms: list[str] | None, is_ot: bool,
                actors: list[str] | None = None, limit: int | None = None) -> list[dict] | None:
    """THE one owner of the intel cap: prompts._intel_block renders whatever this returns.
    `terms` come from _intel_vocabulary (technology inventory) — empty means no intel block."""
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
            # relevance is measurable only if what was injected is on record
            log.info("scenario.intel_injected", is_ot=is_ot,
                    external_ids=[i.get("external_id") for i in items])
        return items or None
    except Exception:
        log.warning("scenario.intel_fetch_failed", exc_info=True)
        return None


class _Coverage(NamedTuple):
    vocab: dict
    frozen: list | None
    others: list | None
    # Technology-derived intel vocabulary (_intel_vocabulary). Defaulted so a legacy
    # construction cannot TypeError inside a swallowed per-item try — a missing vocabulary
    # degrades to "no intel block", never to a failed scenario.
    intel_terms: list | None = None
    intel_ot: bool = False


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
                    coverage: _Coverage | None = None) -> tuple[dict, dict, Provenance | None]:    
    info = enriched.get(sc.threat_id, {})
    threat_type = info.get("library_threat_type") or info.get("threat_type")
    threat_name = info.get("library_threat_name") or info.get("threat_name")
    actors = info.get("actors") or []
    tn = tuning.from_session(scenario_session)  # the session's frozen rulebook — never live config
    # If coverage is provided, use it; otherwise, create a new _Coverage with empty vocab and None for frozen and others.
    cov = coverage or _Coverage(vocab={}, frozen=None, others=None)
    # Intel matched on the technology inventory carried by coverage — never on threat wording.
    intel_items = _fetch_intel(cov.intel_terms, cov.intel_ot, actors, limit=tn.prompt_intel_limit)
    # Exactly what the model was allowed to cite. None (not an empty set) when no block was
    # injected at all, so validation skips the citation check instead of flagging every id.
    injected_intel_ids = ({str(i.get("external_id")) for i in intel_items if i.get("external_id")}
                        if intel_items else None)
    entry_labels = sorted(cov.vocab) if cov.vocab else None
    if sibling_texts:
        messages = prompts.variant_scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                                intel_items=intel_items, existing=sibling_texts,
                                                entry_points=entry_labels,
                                                sibling_k=tn.variant_sibling_prompt_k)
    else:
        messages = prompts.scenario_prompt(base_ctx, threat_type, threat_name, actors=actors,
                                        intel_items=intel_items, entry_points=entry_labels)
    scenario, prov = _ask_ai(sess, llm, messages,
                            scenario_session=scenario_session, subsystem_id=ASSET_UNIT_ID, stage="scenario",
                            level=SubsystemLevel.SCENARIOS, epoch=epoch, task_id=task_id, expected_type=dict,
                            temperature=get_settings().scenario_generation_temperature)
    # critical_service comes from the PROMPT's view (base_ctx), not raw asset_context: the
    # allowlist gate scrubs placeholder values ("Unknown", "TBD"...), and validation must never
    # demand a service name the model was never shown.
    report = validation.validate_scenario(
        scenario, threat_type, threat_name,
        asset_name=scenario_session["AssetName"],
        critical_service=base_ctx["asset_context"].get("critical_service"),
        injected_intel_ids=injected_intel_ids)
    # One bounded repair turn, on STRUCTURAL misses only (the "missing <field>" entries from
    # validation._check_fields) — never on _mentions consistency warnings, which are advisory.
    # "Do not change factual content" keeps this from becoming a free re-roll that would defeat
    # _flag_sibling_similarity below. Accepted only if it strictly reduces the structural
    # misses; a repair that fails to parse keeps the original (same flag-never-raise posture
    # as validate_scenario itself). Runs BEFORE moderation/grounding/similarity so all
    # post-processing sees the final scenario.
    missing = [e for e in report["errors"] if e.startswith("missing ")]
    if missing:
        repair_messages = messages + [
            # Scrubbed like any other payload: today the scenario carries no ids (repair runs
            # before _ground_entry_points stamps entry_point_id/plausible_entry_point_ids), so
            # this is a no-op — and it stays correct if that ordering ever changes.
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
                                    temperature=get_settings().scenario_generation_temperature)
        except Exception:
            # MUST roll back first. _ask_ai does session-mutating DB work around the LLM call
            # (renew_lease + commit before, Prompt_Log insert + commit after) across a pooled
            # connection that idles for the whole call. A mid-transaction disconnect leaves the
            # Session needing an explicit rollback; without one the next statement — the
            # renew_lease in write_scenarios, which sits OUTSIDE the per-threat try — raises
            # PendingRollbackError and parks the whole SCENARIOS stage in ERROR, discarding a
            # batch of already-billed scenarios because an ADVISORY call failed. No-op on the
            # LLM/parse/slot paths (nothing pending there).
            sess.rollback()
            # The repair is ADVISORY: the primary scenario already generated, parsed and
            # validated (with warnings) — no repair failure may destroy it. Blanket on purpose:
            # a parse error, a provider error surviving retries, the chat char-cap ValueError,
            # and LLMSlotUnavailable all end the same way — keep the original. Slot exhaustion
            # especially must NOT propagate: Celery would retry the whole stage and re-bill the
            # completed primary call (same keep-going posture as moderate() in llm.py).
            log.warning("scenario.repair_failed", session_id=scenario_session["SessionID"],
                        threat_id=sc.threat_id, exc_info=True)
        else:
            # MERGE, never replace. The prompt asks for "the corrected JSON object", which
            # invites a partial one, and json_object mode + parse_json(dict) make
            # {"risk_statement": "..."} a perfectly legal repair. Replacing wholesale would then
            # DELETE entry_point/other_plausible_entry_points — _ground_entry_points would set
            # plausible_entry_point_ids=[], dal's coverage loop would skip the identity, and the
            # threat would be frozen at one scenario forever, logged as ordinary success. The
            # accept gate only counts the three narrative fields, so it cannot see that loss.
            # Merging makes the whole class impossible: a repair can overwrite only keys it
            # actually returned, and can never remove one.
            merged = {**scenario, **repaired}
            # ...but it CAN empty one, which costs exactly as much: an explicit
            # "other_plausible_entry_points": [] in the repair is a legal key that merging happily
            # accepts, and an empty list freezes the threat at one scenario just as a missing key
            # would. Keep the original whenever the repair's version is empty.
            if not merged.get("other_plausible_entry_points"):
                merged["other_plausible_entry_points"] = scenario.get("other_plausible_entry_points") or []
            # Validate the MERGED object, not the raw repair: validate_scenario's envelope also
            # carries assumptions/excluded_details, so a pre-merge report would be persisted
            # alongside a post-merge ScenarioJSON that disagrees with it.
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


def _build_scenario_output_row(scoped_id: str, sid: str, tenant: str, ss: int, scenario: dict, report: dict,
                            epoch: int, entity_id: str | None, user_id: str | None, info: dict,
                            scenario_number: int = 1, replaces_output_id: str | None = None) -> dict:

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
            # UNREACHABLE while find_threats holds the invariant — dal.identity_hash IS
            # _dedup_key, and find_threats already folded on it against both the in-batch set and
            # active_identified_threat_identities, so everything arriving here is already
            # key-unique. Kept anyway, as a live invariant check rather than dead code: it is the
            # last guard before a duplicate reaches a PAID scenario call, and the module that
            # maintains the invariant is a different one. `deduped` is therefore an alarm counter
            # that should read 0 forever — not evidence the model never repeats itself. Semantic
            # duplicates are a separate mechanism with its own counter.
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
    # Outputs FIRST — supersede_outputs_for_threats reaches them through the scoped row, so once
    # the scoped rows below are retired it can no longer find them. A threat reaching here whose
    # only active output is a FAILURE CARD (threats_with_active_scenario is complete-only, so it
    # does not exclude one) would otherwise keep that card active with its parent retired: the
    # card still renders in /results `scenarios[]` while its threat vanishes from `threats[]`.
    # The card is stale either way — the threat just rescored out of scope.
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
                            failed_ids: set[str] | None = None) -> bool:
    failed_ids = failed_ids or set()
    generated_ids = {sc.threat_id for sc, scoped_id, _t in pairs if scoped_id in scenarios}
    all_target_ids = {sc.threat_id for sc, _scoped_id, _t in pairs}
    excluded_ids = all_target_ids - generated_ids
    # Two DIFFERENT facts that used to share one log line and one reason code: a target whose
    # generation BLEW UP (transient — stays Selected=1, next click retries) versus one that
    # genuinely rescored out of scope (terminal — gets a Selected=0 marker below). Reporting a
    # provider error as "no longer meets the scoping cutoff" sent support down the wrong path.
    rescored_ids = excluded_ids - failed_ids
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
            # Failure wins the diagnosis: any failed target makes the click retryable, so the
            # terminal-sounding messages below must not fire. cascade treats this reason as
            # retryable when settling (never `exhausted`).
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


def _prepare_scenario_batch(sess: Session, sid: str, ss: int, scenario_session: dict,
                            subsystems: list[dict], asset_context: dict, threats: list[dict],
                            target_threat_ids: set[str] | None,
                            regen_targets: dict[str, RegenTarget] | None,
                            targeted: bool) -> _ScenarioBatch:
    base_ctx = prompts.build_base_context(scenario_session["AssetName"], asset_context, subsystems)

    tn = tuning.from_session(scenario_session)  # the session's frozen rulebook — never live config
    type_ids = sorted({t["threat_type_id"] for t in threats if t.get("threat_type_id") is not None})
    top_n = get_settings().scoping_top_n  # deliberately NOT tunable: None = coverage decides
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
        # WARNING, not INFO. An empty vocabulary silently caps the WHOLE session at one scenario
        # per threat: scenario_prompt omits the entry-point fields, _ground_entry_points writes
        # plausible_entry_point_ids=[], and dal.variant_eligible_primaries then skips every
        # identity. validate_scenario only checks the three narrative fields, so validation_status
        # still reads "ok" — an 8-system asset ships an eighth of its analysis looking like a
        # clean run. The count also rides the scoping_complete audit row so it survives the logs.
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
    # Mirror _persist_full_run_failure: retire any prior active Scoped_Threat row for this threat
    # before inserting the new one. On a Celery redelivery (attempt >= 2), a threat whose
    # attempt-1 scenario ERRORED is retried here — its attempt-1 scoped row was still active, so
    # this path minted a SECOND active row per threat: invisible (invariants.py exempts the
    # table; aggregates absorb it) but a standing violation of the active-row rule.
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
                on_before_commit: Callable[[list[Provenance | None]], None] | None = None) -> list[Provenance | None]:

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
                                                            coverage=coverage)
        except LLMSlotUnavailable:
            raise
        except Exception as exc:
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
                    # entry_points: 0 means no threat in this batch could earn a second scenario —
                    # the whole session is capped at one per threat. Durable here because the log
                    # line alone is invisible to anyone reading the session's history, and nothing
                    # else on the board or in /results reveals the collapse.
                    DetailJSON=json.dumps({"scoped": scoped_threat_count, "selected": len(provs),
                                        "deduped": deduped, "entry_points": len(entry_vocab)}))
    log.info("scenarios.deduped", session_id=sid, subsystem=ss, deduped=deduped, kept=len(provs))

    if targeted and not _reconcile_targeted_regen(
            sess, sid, ss, tenant, entity_id, user_id,
            pairs, scenarios, enriched, epoch, task_id,
            regen_mode=regen_targets is not None, failed_ids=failed_ids):
        return []
    partial_error = (f"{len(failures)} of {len(failures) + len(provs)} scenario(s) failed to "
                    f"generate: {'; '.join(failures)}") if failures else None
    _finalize_scenario_batch(sess, scenario_session, asset_context, subsystems, llm, task_id, epoch)
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
                            subsystems: list[dict], llm: LLMClient, task_id: str, epoch: int) -> None:
    control_mapping.map_controls(sess, scenario_session, asset_context, subsystems, llm,
                                ASSET_UNIT_ID, task_id, epoch)


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
    # Variants never run _prepare_scenario_batch, so the intel vocabulary is resolved here from
    # the same shared helper — without this, every variant would silently lose its intel block.
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
                            # legacy primaries (pre-column) carry NULL — cloned as None, never guessed
                            selection=SelectionReason(sel) if sel else None,
                            factors=factors)
        try:
            scenario, report, prov = _generate_one_scenario(
                sess, scenario_session, base_ctx, sc, enriched, llm, task_id, epoch,
                sibling_texts=siblings_by_hash.get(item["identity_hash"]) or None,
                coverage=_Coverage(
                    vocab=entry_vocab,
                    frozen=fold.frozen_by_hash.get(item["identity_hash"]),
                    others=[s for h, s in cross_pairs if h != item["identity_hash"]] or None,
                    intel_terms=intel_terms, intel_ot=intel_ot))
        except LLMSlotUnavailable:
            sess.rollback()
            log.warning("variant.slots_exhausted", session_id=sid, subsystem=ss,
                        created=created, remaining=len(eligible) - created)
            break
        except Exception as exc:
            sess.rollback()
            log.warning("variant.generation_failed", session_id=sid, subsystem=ss,
                        threat_id=item["threat_id"], error=repr(exc))
            continue
        scoped_id = guid()
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
        except Exception as exc:
            sess.rollback()
            log.warning("variant.finalize_failed", session_id=sid, subsystem=ss,
                        created=created, error=repr(exc))
    return created


def _failure_client_message(exc: Exception) -> str:
    if isinstance(exc, validation.LLMResponseParseError):
        return repr(exc)
    try:
        from litellm.exceptions import RejectedRequestError
    except ImportError:
        return "stage processing failed"
    if isinstance(exc, RejectedRequestError):
        return "content blocked by a configured safety guardrail"
    return "stage processing failed"


def _record_failure(sess: Session, scenario_session: dict, subsystem_id: int, exc: Exception, epoch: int = _EPOCH) -> None:
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
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"], EntityID=scenario_session["EntityID"],
                    SubsystemID=subsystem_id, EventType=AuditEventType.stage_error,
                    DetailJSON=json.dumps({"error": client_msg, "subsystem_id": subsystem_id}))
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid, "subsystem_id": subsystem_id,
                    "message": client_msg, "ts": now().isoformat()})
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


def _send_to_review(sess: Session, scenario_session: dict) -> bool:
    sid = scenario_session["SessionID"]
    res = execute_dml(
        sess,
        update(m.Scenario_Session)
        .where(m.Scenario_Session.SessionID == sid,
            m.Scenario_Session.SessionStatus == SessionStatus.active,
            m.Scenario_Session.CurrentStage != WorkflowStage.REVIEW)
        .values(CurrentStage=WorkflowStage.REVIEW, StageStatus=StageStatus.AWAITING_DECISION, UpdatedAt=now())
    )
    if res.rowcount != 1:
        return False
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], Stage=WorkflowStage.REVIEW, EventType=AuditEventType.entered_review)
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.session_entered_review), "session_id": sid,
                    "status": str(StageStatus.AWAITING_DECISION), "ts": now().isoformat()})
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
    bus.publish(sid, {"type": str(SSEEventType.error), "session_id": sid,
                    "message": "session failed: all subsystems errored", "ts": now().isoformat()})
    log.warning("pipeline.failed", session_id=sid)
    return True


def _announce_generation_started(sess: Session, scenario_session: dict, subsystem_id: int) -> None:
    if not dal.subsystem_has_pending_work(sess, scenario_session["SessionID"], subsystem_id):
        return
    sid = scenario_session["SessionID"]
    dal.append_audit(sess, AuditID=guid(), SessionID=sid, TenantID=scenario_session["TenantID"],
                    EntityID=scenario_session["EntityID"], SubsystemID=subsystem_id,
                    EventType=AuditEventType.subsystem_advanced,
                    DetailJSON=json.dumps({"subsystem_id": subsystem_id}))
    sess.commit()
    bus.publish(sid, {"type": str(SSEEventType.subsystem_started), "session_id": sid,
                    "subsystem_id": subsystem_id, "ts": now().isoformat()})


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
        except Exception as exc:
            _record_failure(sess, scenario_session, ASSET_UNIT_ID, exc)
            sess.commit()
        finally:
            if not dal.release_lock(sess, session_id, ASSET_UNIT_ID, task_id):
                log.warning("asset.lock_lost", session_id=session_id, task_id=task_id)
            sess.commit()
    else:
        log.warning("asset.locked", session_id=session_id, session_status=scenario_session["SessionStatus"])

    decide_session_outcome(sess, scenario_session)