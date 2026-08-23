"""Provide actor-name cleaning, matching, triage, promotion, and linking helpers.

Inputs are threat rows, proposed actor names, database sessions, and promotion state.
Helpers return cleaned names, lookup indexes, triage results, candidate rows, or link
names; promotion helpers may create actors, queue review candidates, and write audit logs.
Empty, filler, duplicate, overlong, or unresolved names are ignored or deferred according
to the helper's rules.
"""
from __future__ import annotations

import difflib
import re
from collections.abc import Iterator, Sequence
from typing import Any, NamedTuple

from sqlalchemy import RowMapping, select
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.config import get_settings
from app.core.enums import CandidateKind, CandidateStatus, TriageVerdict
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import guid
from app.pipeline import grounding

# Actor names need a separate filler check because valid names may be one word.
from app.pipeline.tasks import _JUNK_NAME_TOKENS

log = get_logger(__name__)

# Use one normalized key for actor-name lookups.
_norm = grounding.norm_actor_name

_ACTOR_JUNK = frozenset(_norm(t) for t in _JUNK_NAME_TOKENS)


def _clean_actor_name(name: str) -> str | None:
    """Clean one proposed actor name for automatic creation.

    Input is a raw actor name. Return the trimmed display name, or ``None`` for an empty,
    filler, or letterless name. This function has no side effects and preserves internal
    punctuation, including hyphens.
    """
    display = re.sub(r"""^[\s\[\]{}()<>'"`]+|[\s\[\]{}()<>'"`]+$""", "", name).strip(" ,;:.-")
    core = _norm(display)
    if not core or core in _ACTOR_JUNK or not any(ch.isalpha() for ch in core):
        return None
    return display


def _extract_actor_names_per_threat(rows: Sequence[RowMapping]) -> tuple[dict[int, list[str]], set[str]]:
    """Parse proposed actors and group unique names by threat.

    Input is a sequence of threat rows with ``ThreatID`` and ``ThreatActorsJSON`` values.
    Return a threat-to-name mapping and the set of names for preloading. Names are trimmed,
    limited to 200 characters, filtered for filler text, deduplicated by normalized identity,
    and capped at ``max_actors_per_threat``; filler names are logged and excess names are
    dropped. The settings lookup and logging are the only side effects.
    """
    parsed_actors: dict[int, list[str]] = {}
    all_actor_names: set[str] = set()
    max_actors = get_settings().max_actors_per_threat
    for row in rows:
        raw = [a.strip()[:200].rstrip() for a in grounding.stored_actors(row["ThreatActorsJSON"])
            if a.strip()]
        actors, seen = [], set()
        for a in raw:
            key = _norm(a)
            if not key or key in _ACTOR_JUNK:
                log.info("accept.actor_filler_dropped", actor=a, threat_id=row["ThreatID"],
                        note="filler/letterless text is 'no actor identified', not a name")
                continue
            if key in seen:
                continue
            seen.add(key)
            actors.append(a)
        if len(actors) > max_actors:
            log.warning("accept.actor_list_capped", threat_id=row["ThreatID"],
                        kept=max_actors, dropped=len(actors) - max_actors)
            actors = actors[:max_actors]
        parsed_actors[row["ThreatID"]] = actors
        all_actor_names.update(actors)
    return parsed_actors, all_actor_names


def _trigrams(text: str) -> set[str]:
    """Return all three-character substrings in normalized text.

    Input is normalized actor text; return an empty set when it has fewer than three
    characters. This function has no side effects.
    """
    return {text[i:i + 3] for i in range(len(text) - 2)}


def _build_trigram_index(actor_table: list[tuple[int, str, str, set[str]]]) -> dict[str, set[int]]:
    """Build a trigram-to-row-index map for actor matching.

    Input is the in-memory actor table ``(id, name, normalized_name, tokens)``. Return an
    index for spelling candidates; names shorter than three characters contribute no trigrams,
    so callers also need the token index. This function has no side effects.
    """
    index: dict[str, set[int]] = {}
    for i, (_aid, _name, norm, _tokens) in enumerate(actor_table):
        for tg in _trigrams(norm):
            index.setdefault(tg, set()).add(i)
    return index


def _build_token_index(actor_table: list[tuple[int, str, str, set[str]]]) -> dict[str, set[int]]:
    """Build a token-to-row-index map for actor matching.

    Input is the in-memory actor table ``(id, name, normalized_name, tokens)``. Return an
    index for names sharing complete words, including words too short for trigrams. This
    function has no side effects.
    """
    index: dict[str, set[int]] = {}
    for i, (_aid, _name, _norm, tokens) in enumerate(actor_table):
        for tok in tokens:
            index.setdefault(tok, set()).add(i)
    return index


def _preload_actor_memo(sess: Session, rows: Sequence[RowMapping], all_actor_names: set[str],
                        resolved: dict) -> tuple[list[tuple[int, str, str, set[str]]],
                                                dict[str, set[int]], dict[str, set[int]]]:
    """Preload active actors, links, and matching indexes for one accept operation.

    Inputs are a database session, threat rows, proposed names, and the mutable resolution
    cache. Return the actor table plus trigram and token indexes. Populate the cache with
    actor identities and existing links; skip the actor query when no names were proposed.
    Database reads and cache mutation are side effects.
    """
    actor_table = ([(aid, name, (nk := _norm(name)), set(nk.split()))
                    for aid, name in dal.active_actors(sess)]
                if all_actor_names else [])
    for actor_id, name, nkey, _tokens in actor_table:
        resolved.setdefault(("actor", name), actor_id)
        resolved.setdefault(("actor_cf", name.casefold()), actor_id)
        if nkey:
            resolved.setdefault(("actor_norm", nkey), actor_id)
    trigram_index = _build_trigram_index(actor_table)
    token_index = _build_token_index(actor_table)
    known_type_ids = {r["ThreatTypeID"] for r in rows if r["ThreatTypeID"] is not None}
    if known_type_ids and actor_table:
        for type_id, actor_id in sess.execute(
            select(m.ThreatType_ThreatActor_Map.ThreatTypeID, m.ThreatType_ThreatActor_Map.ThreatActorID)
            .where(m.ThreatType_ThreatActor_Map.ThreatTypeID.in_(known_type_ids))
        ):
            resolved[("link", type_id, actor_id)] = True
    return actor_table, trigram_index, token_index


def pending_card_identities(sess: Session) -> set[tuple[str, str]]:
    """Return normalized identities already represented by pending or rejected cards.

    Input is a database session. Return ``(candidate_kind, identity)`` pairs; actor names use
    normalized actor identity, while other candidates use stripped case-insensitive text.
    Rejected cards remain included to prevent automatic requeueing. This function only reads
    the database.
    """
    identities: set[tuple[str, str]] = set()
    for kind, generic, name in dal.candidate_identity_rows(sess):
        if (kind or CandidateKind.threat) == CandidateKind.actor:
            folded = _norm(name or "")
        else:
            folded = (generic or name or "").strip().casefold()
        if folded:
            identities.add((str(kind or CandidateKind.threat), folded))
    return identities


def resolve_actor_id_by_identity(sess: Session, name: str) -> int | None:
    """Find the active actor ID matching a normalized actor identity.

    Inputs are a database session and actor name. Return the first matching active ID, or
    ``None`` for empty or unknown names; database ordering determines which ID is returned if
    duplicate normalized names exist. This function only reads the database.
    """
    key = _norm(name)
    if not key:
        return None
    for aid, aname in dal.active_actors(sess):
        if _norm(aname) == key:
            return aid
    return None


class _ActorTriage(NamedTuple):
    """Carry a triage verdict, optional matched actor, and similarity score."""
    verdict: TriageVerdict
    matched_id: int | None      # Existing actor ID for duplicate or review.
    matched_name: str | None    # Stored name for the review record.
    ratio: float | None         # Highest score, or None with no actors.


def _actor_similarity(key: str, qtokens: set[str], akey: str, atokens: set[str]) -> float:
    """Return the greater character or shared-token similarity for two actors.

    Inputs are normalized names and their precomputed token sets. Return a score from the
    larger comparison, using zero when either token set is empty. This function has no side
    effects.
    """
    char = difflib.SequenceMatcher(None, key, akey).ratio()
    tokens = len(qtokens & atokens) / min(len(qtokens), len(atokens)) if qtokens and atokens else 0.0
    return max(char, tokens)


def _triage_actor_name(key: str, actor_table: list[tuple[int, str, str, set[str]]],
                    trigram_index: dict[str, set[int]], token_index: dict[str, set[int]],
                    tn: tuning.ResolvedTuning) -> _ActorTriage:
    """Classify one normalized actor name as duplicate, review, or novel.

    Inputs are a normalized query, actor table, trigram and token indexes, and resolved tuning.
    Return an ``_ActorTriage`` result: exact matches are rejected as duplicates, scores at or
    above ``triage_auto_approve_cosine`` require review, and lower scores are novel. Both
    indexes are used because short shared words have no trigram. This function has no side
    effects.
    """
    qtrigrams = _trigrams(key)
    qtokens = set(key.split())
    if qtrigrams or qtokens:
        indices: set[int] = set()
        for tg in qtrigrams:
            indices |= trigram_index.get(tg, set())
        for tok in qtokens:
            indices |= token_index.get(tok, set())
        candidates: Iterator[tuple[int, str, str, set[str]]] = (actor_table[i] for i in indices)
    else:
        candidates = iter(actor_table)
    best: tuple[float, int, str] | None = None
    for aid, aname, akey, atokens in candidates:
        if not akey:
            continue
        if akey == key:
            return _ActorTriage(TriageVerdict.auto_reject, aid, aname, 1.0)
        sim = _actor_similarity(key, qtokens, akey, atokens)
        if best is None or sim > best[0]:
            best = (sim, aid, aname)
    if best is None:
        return _ActorTriage(TriageVerdict.auto_approve, None, None, None)
    sim, aid, aname = best
    if sim >= tn.triage_auto_approve_cosine:
        return _ActorTriage(TriageVerdict.review, aid, aname, sim)
    return _ActorTriage(TriageVerdict.auto_approve, None, aname, sim)


class _ActorPromoCtx(NamedTuple):
    """Hold database, cache, indexes, audit, and promotion state for one accept operation."""
    sess: Session
    resolved: dict
    pending_cards: set
    actor_table: list[tuple[int, str, str, set[str]]]
    trigram_index: dict[str, set[int]]
    token_index: dict[str, set[int]]
    tn: tuning.ResolvedTuning
    auto_mode: bool
    candidate_rows: list[dict]
    actor_triage: list[dict]    # Similarity details for the audit record.
    sid: str
    tenant: Any
    entity: Any
    stamp: Any
    actor_id: Any


def _queue_or_mint_row_actors(ctx: _ActorPromoCtx, row: RowMapping, type_id: int | None,
                            actors: list[str]) -> None:
    """Resolve, mint, or queue proposed actors for one threat row.

    Inputs are promotion context, a threat row, its type ID, and proposed names. Reuse known
    identities, defer queued or rejected names, mint novel cleaned names in automatic mode, and
    append review candidates for similar or unsafe names. Mutate context caches, actor indexes,
    candidate rows, and audit details; database writes and logs may also occur.
    """
    for actor_name in actors:
        aident = _norm(actor_name)
        # Try exact, case-insensitive, then normalized identity.
        actor_id = ctx.resolved.get(("actor", actor_name))
        if actor_id is None:
            actor_id = ctx.resolved.get(("actor_cf", actor_name.casefold()))
        if actor_id is None and aident:
            actor_id = ctx.resolved.get(("actor_norm", aident))
            if actor_id is not None and ("actor_triage", aident) not in ctx.resolved:
                # Distinct name from the `fate` looked up further down: this one is freshly
                # constructed and never None, while that one is an Optional dict lookup.
                exact_fate = _ActorTriage(TriageVerdict.auto_reject, actor_id, None, 1.0)
                ctx.resolved[("actor_triage", aident)] = exact_fate
                ctx.actor_triage.append({"name": actor_name, "verdict": exact_fate.verdict,
                                        "ratio": exact_fate.ratio, "matched_actor_id": actor_id,
                                        "matched_name": exact_fate.matched_name})
        if actor_id is not None:
            ctx.resolved[("actor", actor_name)] = actor_id
            ctx.resolved[("actor_cf", actor_name.casefold())] = actor_id
            continue
        if not aident:
            log.warning("accept.actor_name_unusable", actor=actor_name,
                        threat_id=row["ThreatID"])
            continue
        tri_key = ("actor_triage", aident)
        fate = ctx.resolved.get(tri_key)
        entry: dict | None = None
        if fate is None:
            fate = _triage_actor_name(aident, ctx.actor_table, ctx.trigram_index,
                                    ctx.token_index, ctx.tn)
            ctx.resolved[tri_key] = fate
            entry = {"name": actor_name, "verdict": fate.verdict, "ratio": fate.ratio,
                    "matched_actor_id": fate.matched_id, "matched_name": fate.matched_name}
            ctx.actor_triage.append(entry)
        if fate.verdict is TriageVerdict.auto_reject:
            ctx.resolved[("actor", actor_name)] = fate.matched_id
            ctx.resolved[("actor_cf", actor_name.casefold())] = fate.matched_id
            ctx.resolved[("actor_norm", aident)] = fate.matched_id
            continue
        akey = ("actor_cand", aident)
        if akey in ctx.resolved or (CandidateKind.actor, aident) in ctx.pending_cards:
            log.info("accept.actor_association_deferred", actor=actor_name, type_id=type_id,
                    threat_id=row["ThreatID"],
                    note="identity already queued for review or previously rejected — "
                        "approve/re-add it via PATCH /v1/tsg/threat-library/threat-types/{id}")
            continue
        if fate.verdict is TriageVerdict.auto_approve and ctx.auto_mode:
            cleaned = _clean_actor_name(actor_name)
            if cleaned is not None:
                new_id = dal.upsert_threat_actor(ctx.sess, cleaned, created_by=ctx.actor_id)
                for spelling in {actor_name, cleaned}:
                    ctx.resolved[("actor", spelling)] = new_id
                    ctx.resolved[("actor_cf", spelling.casefold())] = new_id
                ctx.resolved[("actor_norm", aident)] = new_id
                new_index = len(ctx.actor_table)
                new_tokens = set(aident.split())
                ctx.actor_table.append((new_id, cleaned, aident, new_tokens))
                for tg in _trigrams(aident):
                    ctx.trigram_index.setdefault(tg, set()).add(new_index)
                for tok in new_tokens:
                    ctx.token_index.setdefault(tok, set()).add(new_index)
                if entry is not None:
                    entry["minted_id"] = new_id
                log.info("accept.actor_minted", actor=cleaned, actor_id=new_id,
                        threat_id=row["ThreatID"], ratio=fate.ratio)
                continue
            log.info("accept.actor_junk_demoted", actor=actor_name, threat_id=row["ThreatID"])
        ctx.resolved[akey] = True
        ctx.candidate_rows.append({
            "CandidateID": guid(), "TenantID": ctx.tenant, "EntityID": ctx.entity,
            "SessionID": ctx.sid, "ProposedCategory": None,
            "ProposedType": row["ThreatType"], "ProposedName": actor_name,
            "ProposedGenericName": None,
            "Status": CandidateStatus.pending, "ThreatTypeID": type_id,
            "ThreatCatalogueID": None,
            "ReviewedBy": None, "ReviewedAt": None, "CreatedAt": ctx.stamp,
            "CandidateKind": CandidateKind.actor, "CreatedBy": ctx.actor_id,
        })


def _link_actors_to_threat_type(sess: Session, type_id: int, actors: list[str],
                                resolved: dict) -> list[str]:
    """Link resolved actors to a threat type and return newly linked names.

    Inputs are a database session, threat type ID, actor names, and the resolution cache.
    Return names whose links were created; do not create actors, and leave unknown names for
    review and later approval. Database writes and pending-link logs are side effects.
    """
    newly_linked: list[str] = []
    for actor_name in actors:
        actor_id = resolved.get(("actor", actor_name))
        if actor_id is None:
            actor_id = resolved.get(("actor_cf", actor_name.casefold()))
        if actor_id is None:
            log.info("accept.actor_link_pending_review", actor=actor_name, type_id=type_id,
                    note="name is queued as a review card — approval creates and links it")
            continue
        link_key = ("link", type_id, actor_id)
        if link_key not in resolved:
            if dal.link_type_actor(sess, type_id, actor_id):
                newly_linked.append(actor_name)
            resolved[link_key] = True
    return newly_linked


def log_withheld_links(resolved: dict, type_id: int, actors: list[str], threat_id) -> None:
    """Log resolved actors withheld from an already existing threat type.

    Inputs are the resolution cache, threat type ID, actor names, and threat ID. Log only
    resolved actors without a recorded link; do not modify the cache or database. This audit
    behavior preserves curator ownership of an existing type's actor set.
    """
    withheld = [n for n in actors
                if (aid := (resolved.get(("actor", n))
                            or resolved.get(("actor_cf", n.casefold())))) is not None
                and ("link", type_id, aid) not in resolved]
    if withheld:
        log.info("accept.actor_links_withheld", type_id=type_id, actors=withheld,
                threat_id=threat_id,
                note="type pre-exists this accept; curator owns its actor set — add via "
                    "PATCH /v1/tsg/threat-library/threat-types/{id} if the attribution is real")
