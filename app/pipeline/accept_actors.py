"""Actor candidacy for the accept-time promotion phase — the actor twin of accept.py's
threat/catalogue triage, split out so accept.py stays the orchestration layer.

One responsibility: decide what happens to each LLM-proposed actor NAME on an accepted
threat — recognized (an existing actor, reused), minted (master switch ON only, junk-gated),
or queued as an admin review card — and keep every layer keyed on ONE identity convention
(grounding.norm_actor_name), so an identity remembered by one layer can never be missed by
another. Deliberately decoupled from the threat's own GroundingScore: how novel the ACTOR is
has nothing to do with how well its THREAT matched.
"""
from __future__ import annotations

import difflib
import re
from collections.abc import Sequence
from typing import Any, NamedTuple

from sqlalchemy import RowMapping, select
from sqlalchemy.orm import Session

from app.core import tuning
from app.core.enums import CandidateKind, CandidateStatus, TriageVerdict
from app.core.logging import get_logger
from app.db import dal
from app.db import models as m
from app.db.dal import guid
from app.pipeline import grounding

# clean_library_name's two-real-words floor would reject legitimate one-word actor roles
# ("Hacktivist", "Cybercriminal"), so actors get their own junk gate built from the SAME
# token list as the threat path's gate.
from app.pipeline.tasks import _JUNK_NAME_TOKENS

log = get_logger(__name__)

# THE one actor-identity key (Unicode-aware; see grounding.norm_actor_name).
_norm = grounding.norm_actor_name

# ponytail: fixed bound, not config — one threat naming more than this many distinct actors is
# model drift, not analysis; raise it here if a real case ever appears.
_MAX_ACTORS_PER_THREAT = 10

_ACTOR_JUNK = frozenset(_norm(t) for t in _JUNK_NAME_TOKENS)


def _clean_actor_name(name: str) -> str | None:
    """The actor-name fitness gate for minting: the cleaned display text, or None if the name
    may not enter the shared library unreviewed. Mirrors clean_library_name's lesson: return
    the name with wrapping junk REMOVED (a '"APT-Nova"' proposal must not become the literal
    stored spelling), never the raw input."""
    display = re.sub(r"""^[\s\[\]{}()<>'"`]+|[\s\[\]{}()<>'"`]+$""", "", name).strip(" ,;:.-")
    core = _norm(display)
    if not core or core in _ACTOR_JUNK or not any(ch.isalpha() for ch in core):
        return None
    return display


def _extract_actor_names_per_threat(rows: Sequence[RowMapping]) -> tuple[dict[int, list[str]], set[str]]:
    """Per-threat actor lists plus the union of all names seen (for the bulk table preload).

    Reads the RAW stored list deliberately, for ALL accepted rows: unverified threats store
    their actors ungated (validated=false), verified ones store them canonicalized-and-kept
    (grounding's §8.4 step 5) — either way a validated_actors gate would hide exactly the
    novel names the banded triage exists to judge.

    THE normalization boundary for actor names — four rules, applied once for every consumer:
    * strip → bound to Threat_Actor's real width of 200 → rstrip (an over-long card
      ProposedName DataErrors the whole batched candidate INSERT on MSSQL — invisible to
      SQLite tests; a re-exposed trailing space defeats exact-name equality);
    * FILLER dropped with a log: "Unknown"/"N/A"/letterless text is the model saying "no
      actor identified" — the same hygiene Stage-1 applies to threat names via
      clean_library_name, applied at the same kind of boundary;
    * per-threat dedup by normalized identity, FIRST spelling wins — before the cap, so ten
      spelling variants of one actor can never evict a genuinely distinct name;
    * hard per-threat cap, logged, never silent."""
    parsed_actors: dict[int, list[str]] = {}
    all_actor_names: set[str] = set()
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
                continue  # same identity twice on one threat — first spelling wins
            seen.add(key)
            actors.append(a)
        if len(actors) > _MAX_ACTORS_PER_THREAT:
            # The open prompt removed the closed list's implicit cardinality bound; this is
            # the explicit one. Never silent: the drop is logged with what was kept.
            log.warning("accept.actor_list_capped", threat_id=row["ThreatID"],
                        kept=_MAX_ACTORS_PER_THREAT, dropped=len(actors) - _MAX_ACTORS_PER_THREAT)
            actors = actors[:_MAX_ACTORS_PER_THREAT]
        parsed_actors[row["ThreatID"]] = actors
        all_actor_names.update(actors)
    return parsed_actors, all_actor_names


def _trigrams(text: str) -> set[str]:
    """Every run of 3 characters in a normalized name — the shared-substring signal a
    trigram inverted index shortlists on. Empty for text under 3 characters (see the
    short-name fallback in _triage_actor_name)."""
    return {text[i:i + 3] for i in range(len(text) - 2)}


def _build_trigram_index(actor_table: list[tuple[int, str, str, set[str]]]) -> dict[str, set[int]]:
    """{trigram: set(actor_table indices)} over every active actor's normalized name, built
    ONCE per accept from data already loaded (zero new queries). Narrows the CHARACTER-ratio
    signal: two names differing by a small edit always share most trigrams.

    NOT sufficient alone for the TOKEN-containment signal — see _build_token_index, which
    _triage_actor_name always consults alongside this one. A shared word's trigrams are
    every 3-char run INSIDE it, but a run that crosses the word's boundary depends on
    whatever surrounds the word in each string; a 1-2 character shared word ("AQ", "PK") has
    NO trigram entirely inside itself, so if it sits next to different neighbors in the two
    names (a different word order/adjacency), none of its boundary-crossing trigrams match
    either — a genuine full-containment pair can then share zero trigrams even though
    _actor_similarity's token check would score it 1.0. Confirmed empirically: "AQ PK" vs
    "PK Brigade AQ" (token containment 1.0) shares no trigram at all. Trigrams alone are
    therefore NOT a safe narrowing mechanism for token containment; only the union with
    _build_token_index is."""
    index: dict[str, set[int]] = {}
    for i, (_aid, _name, norm, _tokens) in enumerate(actor_table):
        for tg in _trigrams(norm):
            index.setdefault(tg, set()).add(i)
    return index


def _build_token_index(actor_table: list[tuple[int, str, str, set[str]]]) -> dict[str, set[int]]:
    """{token: set(actor_table indices)} over every active actor's precomputed word set,
    built ONCE per accept alongside the trigram index (same single pass over data already
    loaded, zero new queries). THE safety net for token containment: a candidate sharing
    even one whole word with the proposed name is found here regardless of how that word
    sits relative to its neighbors — exactly the case a trigram-only shortlist can miss for
    short shared words (see _build_trigram_index). Cheap: far fewer distinct tokens than
    trigrams in any real name."""
    index: dict[str, set[int]] = {}
    for i, (_aid, _name, _norm, tokens) in enumerate(actor_table):
        for tok in tokens:
            index.setdefault(tok, set()).add(i)
    return index


def _preload_actor_memo(sess: Session, rows: Sequence[RowMapping], all_actor_names: set[str],
                        resolved: dict) -> tuple[list[tuple[int, str, str, set[str]]],
                                                dict[str, set[int]], dict[str, set[int]]]:
    """Bulk-load the FULL active actor table (small — it doubles as the triage comparison
    set, with each name's identity key AND token set computed ONCE here) and the type→actor
    links for the rows' known types into the in-accept memo, so the promotion loop issues no
    per-actor query. Also builds the trigram AND token indices (_build_trigram_index,
    _build_token_index — BOTH required, see _build_trigram_index's docstring for why
    trigrams alone can miss a token-containment match) from the SAME pass — two more
    in-memory steps over data already in hand, not a new query. Two DB queries, both skipped
    when the rows propose no actors. Returns ([(id, name, norm, token_set)], trigram_index,
    token_index) for _triage_actor_name.

    setdefault, not assignment: legacy master rows CAN share one normalized identity (the
    natural key is exact-name), so the LOWEST id wins deterministically — the same rule as
    _triage_actor_name's first-match scan, so the two layers can never disagree.

    Deliberately NOT cached across accepts (unlike dal.active_actor_names' prompt-hint
    cache): accepts happen far less often than Stage-1 calls, so the DB-read savings would
    be small, while a cache spanning accept boundaries would leak actors from a mint that
    later rolls back (this runs inside a savepoint) into a shared structure a later,
    unrelated accept could match against — a "ghost" actor that was never really committed.
    Building fresh per accept means a rollback is always clean."""
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
        # No actor-id IN() filter on purpose: it never narrowed anything the memo would look
        # up (only links to soft-deleted actors, which no key ever probes) while pushing the
        # bound-parameter count toward pyodbc's 2100 limit as the actor table grows.
        for type_id, actor_id in sess.execute(
            select(m.ThreatType_ThreatActor_Map.ThreatTypeID, m.ThreatType_ThreatActor_Map.ThreatActorID)
            .where(m.ThreatType_ThreatActor_Map.ThreatTypeID.in_(known_type_ids))
        ):
            resolved[("link", type_id, actor_id)] = True  # pre-existing link, not newly created
    return actor_table, trigram_index, token_index


def pending_card_identities(sess: Session) -> set[tuple[str, str]]:
    """Cross-session dedup set: (kind, folded identity) of every PENDING and REJECTED
    curation card, folded HERE — beside the accept-side writers of the same identities — so
    both conventions live in one module: threat identity = strip().casefold() of
    generic-or-name (the loop's `ident`), actor identity = grounding.norm_actor_name (so
    "APT-Nova" queued or rejected yesterday suppresses "APT Nova" today). Rejected rows count
    deliberately: an admin's "no" must stick under BOTH switch postures; re-opening a
    rejected proposal is a deliberate curator action (library CRUD), never an accept
    side-effect. Accepted rows are excluded — their identity lives in the master tables,
    which the existence memo covers."""
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
    """Identity-guarded lookup for the WRITE paths (admin approve, library CRUD): the active
    actor whose normalized spelling matches `name`, or None. Guards the one hole exact-name
    upserts leave open — 'APT Nova' approved against an existing 'APT-Nova' must REUSE it,
    not mint a normalized twin the read layer would then resolve ambiguously. Lowest id wins
    (same rule as the preload and triage). One bounded read of a small table, on
    admin-frequency call sites only."""
    key = _norm(name)
    if not key:
        return None
    for aid, aname in dal.active_actors(sess):
        if _norm(aname) == key:
            return aid
    return None


class _ActorTriage(NamedTuple):
    """One proposed actor name's banded verdict against the full active actor table."""
    verdict: TriageVerdict
    matched_id: int | None      # the existing row it duplicates (auto_reject) / best hit (review)
    matched_name: str | None    # that row's stored spelling, for the calibration audit
    ratio: float | None         # best similarity measured; None only on an empty table


def _actor_similarity(key: str, qtokens: set[str], akey: str, atokens: set[str]) -> float:
    """Similarity of two normalized actor names: the MAX of the character ratio and token
    containment (shared words / the shorter name's word count). The character ratio alone is
    length-coupled — 'terrorist' vs 'terrorist extremist' scores 0.643, reading a real
    duplicate as novel just because the library spells it as a compound. Token containment
    catches exactly that shape ('competitor' ⊂ 'industrial spy competitor' → 1.0). Taking the
    max can only move a name TOWARD the human-review lane, never toward a merge — merging is
    identity-only upstream. Token sets are ALWAYS precomputed by the caller (once per query,
    once per actor at table-build time) — this function does no .split()/set() work itself,
    so it stays cheap to call across an entire trigram-or-token shortlist."""
    char = difflib.SequenceMatcher(None, key, akey).ratio()
    tokens = len(qtokens & atokens) / min(len(qtokens), len(atokens)) if qtokens and atokens else 0.0
    return max(char, tokens)


def _triage_actor_name(key: str, actor_table: list[tuple[int, str, str, set[str]]],
                    trigram_index: dict[str, set[int]], token_index: dict[str, set[int]],
                    tn: tuning.ResolvedTuning) -> _ActorTriage:
    """Banded triage of one PROPOSED actor name — the same three lanes catalogue names get in
    accept._decide_candidate_fate, adapted to short text labels:

      spelling-normalized IDENTITY (and only identity): the name IS an existing actor → reuse
        (normally resolved by the memo before triage ever runs; kept here as the belt);
      >= approve knob vs anything (_actor_similarity): similar but not identical → curator queue;
      below vs EVERYTHING: genuinely novel.

    The reject knob is DELIBERATELY not a merge band here: a character-similarity ratio is
    length-coupled and negation-blind — at 0.95, every >=20-char pair differing by one character
    reads "identical", so "Authorized third-party user" would silently absorb "UNauthorized
    third-party user" and attribute a threat to its opposite. Merging is therefore reserved for
    exact normalized identity; everything merely similar fails toward the human. The approve
    knob is shared with the embedding triage (config.py documents the coupling) — under the
    default switch OFF it only picks the card's audit label, never whether a card exists.

    SCANS THE TRIGRAM-OR-TOKEN SHORTLIST, not the full table — `key` MUST already be
    normalized (callers pass the identity string they already computed; no re-normalizing
    here). BOTH indices are required, not just the trigram one: trigram overlap alone can
    silently miss a genuine token-containment match when the shared word is 1-2 characters
    and sits next to different neighbors in the two names — confirmed empirically ("AQ PK"
    vs "PK Brigade AQ" shares zero trigrams despite 1.0 token containment; see
    _build_trigram_index's docstring for the exact mechanism). The token index closes that
    gap: a candidate sharing even one WHOLE WORD with the query is found there regardless of
    context, so the union of both indices can never miss what _actor_similarity's own two
    signals (character ratio, token containment) could score above the floor. A normalized
    query under 3 characters with a single, short token produces no trigrams at all and
    would fall through to the FULL table only if it ALSO shares no token with anything —
    real actor names are essentially never this short, and unlike the char-ratio pre-filter
    this design rejected, a full-scan fallback can never silently drop a real match, only
    cost more when it (rarely) triggers."""
    qtrigrams = _trigrams(key)
    qtokens = set(key.split())
    if qtrigrams or qtokens:
        indices: set[int] = set()
        for tg in qtrigrams:
            indices |= trigram_index.get(tg, set())
        for tok in qtokens:
            indices |= token_index.get(tok, set())
        candidates = (actor_table[i] for i in indices)
    else:
        candidates = iter(actor_table)  # degenerate empty query: nothing to shortlist by
    best: tuple[float, int, str] | None = None
    for aid, aname, akey, atokens in candidates:
        if not akey:
            continue
        if akey == key:
            return _ActorTriage(TriageVerdict.auto_reject, aid, aname, 1.0)
        sim = _actor_similarity(key, qtokens, akey, atokens)
        if best is None or sim > best[0]:
            best = (sim, aid, aname)
    if best is None:  # empty/unseeded table, or nothing shared a trigram — a first/unrelated
        return _ActorTriage(TriageVerdict.auto_approve, None, None, None)  # actor is novel
    sim, aid, aname = best
    if sim >= tn.triage_auto_approve_cosine:
        return _ActorTriage(TriageVerdict.review, aid, aname, sim)
    return _ActorTriage(TriageVerdict.auto_approve, None, aname, sim)


class _ActorPromoCtx(NamedTuple):
    """Per-accept constants for actor candidacy, bundled so the per-row helper's signature
    stays readable. `actor_table`, `trigram_index` AND `token_index` are deliberately MUTABLE state: an
    auto-minted actor is appended to both so a later paraphrase in the same accept resolves
    as its duplicate — the two are always updated together (see the mint branch below)."""
    sess: Session
    resolved: dict
    pending_cards: set
    actor_table: list[tuple[int, str, str, set[str]]]
    trigram_index: dict[str, set[int]]
    token_index: dict[str, set[int]]
    tn: tuning.ResolvedTuning
    auto_mode: bool
    candidate_rows: list[dict]
    actor_triage: list[dict]    # calibration details; joins the promotion_triage audit record
    sid: str
    tenant: Any
    entity: Any
    stamp: Any
    actor_id: Any


def _queue_or_mint_row_actors(ctx: _ActorPromoCtx, row: RowMapping, type_id: int | None,
                            actors: list[str]) -> None:
    """Actor-name candidacy for ONE threat row:

      duplicate (spelling-normalized IDENTITY only — see _triage_actor_name on why similarity
        never merges): resolve the memo to the existing row — no card, no mint; a VARIANT
        spelling resolution is recorded in the calibration audit (the one decision that
        changes attribution must leave a trace);
      already queued or previously REJECTED (cross-session card set): nothing is minted and
        nothing re-queues, under BOTH switch postures — an admin's "no" sticks; the deferred
        association is logged, never silently lost;
      novel (below the approve knob vs everything): master switch ON mints it (junk-gated,
        logged); OFF queues a card;
      review (similar-but-not-identical): a card in BOTH modes — the curator decides."""
    for actor_name in actors:
        aident = _norm(actor_name)
        # Resolution order: exact spelling → casefold → NORMALIZED identity. The normalized
        # tier is what makes one accept's "APT-Nova" and "APT Nova" the SAME actor even when
        # the first was minted seconds ago.
        actor_id = ctx.resolved.get(("actor", actor_name))
        if actor_id is None:
            actor_id = ctx.resolved.get(("actor_cf", actor_name.casefold()))
        if actor_id is None and aident:
            actor_id = ctx.resolved.get(("actor_norm", aident))
            if actor_id is not None and ("actor_triage", aident) not in ctx.resolved:
                # Resolved by IDENTITY, not exact spelling: a real dedup decision — audit it
                # once per identity so band calibration sees duplicates, not only novelties.
                fate = _ActorTriage(TriageVerdict.auto_reject, actor_id, None, 1.0)
                ctx.resolved[("actor_triage", aident)] = fate
                ctx.actor_triage.append({"name": actor_name, "verdict": fate.verdict,
                                        "ratio": fate.ratio, "matched_actor_id": actor_id,
                                        "matched_name": fate.matched_name})
        if actor_id is not None:
            # known actor — remember THIS spelling too, so the linker's exact/casefold
            # lookups resolve it without repeating the normalization walk
            ctx.resolved[("actor", actor_name)] = actor_id
            ctx.resolved[("actor_cf", actor_name.casefold())] = actor_id
            continue
        if not aident:
            # Belt only — _extract_actor_names_per_threat already drops letterless text.
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
            # Checked BEFORE the mint branch on purpose: the identity is already queued — or
            # was REJECTED by an admin — so neither a mint nor a second card may proceed.
            # This row's (type, actor) association is deferred to the curator, not lost.
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
                # actor_table, trigram_index AND token_index are updated TOGETHER, always —
                # a later merely-similar proposal in this same accept must be able to find
                # this row via EITHER index, not just via the exact-identity memo above.
                new_index = len(ctx.actor_table)
                new_tokens = set(aident.split())
                ctx.actor_table.append((new_id, cleaned, aident, new_tokens))
                for tg in _trigrams(aident):
                    ctx.trigram_index.setdefault(tg, set()).add(new_index)
                for tok in new_tokens:
                    ctx.token_index.setdefault(tok, set()).add(new_index)
                if entry is not None:
                    entry["minted_id"] = new_id  # audit: minted, vs demoted-to-card
                log.info("accept.actor_minted", actor=cleaned, actor_id=new_id,
                        threat_id=row["ThreatID"], ratio=fate.ratio)
                continue
            # junk text in the novel band — demoted to a card, never an unreviewed master row
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
    """Link actor names to this threat type; returns only the names that got a BRAND-NEW link,
    for audit.

    RESOLVE-AND-LINK ONLY — creation is never this function's job, under either posture:
    _queue_or_mint_row_actors runs FIRST each row and has already resolved duplicate spellings
    to their existing rows, minted genuinely novel names (master switch ON, junk-gated) or
    queued them as review cards. A name still unknown here is therefore a CARDED one —
    skipping its link is the expected outcome and the card is the operator trace; approval
    links it live (accept.resolve_candidate)."""
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
            if dal.link_type_actor(sess, type_id, actor_id):  # True only when a NEW link row was inserted
                newly_linked.append(actor_name)
            resolved[link_key] = True
    return newly_linked


def log_withheld_links(resolved: dict, type_id: int, actors: list[str], threat_id) -> None:
    """The ONE 'links withheld' trace (both promotion passes call it, so the wording can never
    drift between them). Filters to names that RESOLVED to a master row but whose (type,
    actor) link doesn't exist — the only names the PATCH hint is actionable for; carded and
    unknown names have their own traces."""
    withheld = [n for n in actors
                if (aid := (resolved.get(("actor", n))
                            or resolved.get(("actor_cf", n.casefold())))) is not None
                and ("link", type_id, aid) not in resolved]
    if withheld:
        log.info("accept.actor_links_withheld", type_id=type_id, actors=withheld,
                threat_id=threat_id,
                note="type pre-exists this accept; curator owns its actor set — add via "
                    "PATCH /v1/tsg/threat-library/threat-types/{id} if the attribution is real")
