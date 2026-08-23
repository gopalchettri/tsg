"""Provide actor-name cleaning, matching, triage, promotion, and linking helpers.

Inputs are threat rows, proposed actor names, database sessions, and promotion state.
Helpers return cleaned names, lookup indexes, triage results, candidate rows, or link
names; promotion helpers may create actors, queue review candidates, and write audit logs.
Empty, filler, duplicate, overlong, or unresolved names are ignored or deferred according
to the helper's rules.
"""
from __future__ import annotations

import re

from sqlalchemy.orm import Session

from app.core.enums import CandidateKind
from app.core.logging import get_logger
from app.db import dal
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


