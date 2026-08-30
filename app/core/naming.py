"""The one name-identity key for master-library dedup.

Lives in `app/core` because BOTH layers need it and neither may import the other: `app/db/dal`
uses it to decide whether a master row already exists, and `app/pipeline/grounding` uses it for
actor identity. Importing grounding from dal would pull in embeddings/llm and risk a cycle.
"""
from __future__ import annotations

import re
import unicodedata

# Unicode-aware on purpose: these are NVARCHAR columns, and Cyrillic/CJK names are real names,
# not junk to strip. Only genuinely empty input folds to "".
_NON_WORD_RE = re.compile(r"[\W_]+")
# Letter<->digit boundaries count as separators, so "APT41", "APT-41" and "APT 41" are one
# identity regardless of which spelling reached the database first.
_ALNUM_BOUNDARY_RE = re.compile(r"(?<=[^\W\d_])(?=\d)|(?<=\d)(?=[^\W\d_])")


def normalize_name(name: str) -> str:
    """Comparison key for master-row identity: casefold, NFKD-decompose and drop combining marks
    (so 'Fáncy Bear' == 'Fancy Bear'), split letter<->digit boundaries, collapse non-word runs to
    one space. Letters in any script survive.

    This is what makes dedup the APPLICATION's guarantee rather than the database's: the upserts
    in db/dal.py resolve an existing row through this key before inserting, so a duplicate cannot
    be created even on a database whose unique indexes were never built. The filtered unique
    indexes remain as a concurrency backstop, not as the mechanism.

    Verified against the curated baseline (scripts/Seed_to_Threat_library.sql): the 27 threat-type
    names, 75 catalogue names and 13 actor names all normalize to DISTINCT values, so this can
    never merge two legitimately different library entries.

    WHAT IT COLLAPSES, exactly — separators become a SPACE, they are not deleted:
        "Ransomware" / "ransomware " / "RANSOMWARE" / "Ransomware"  -> one identity
        "APT41" / "APT-41" / "APT 41" / "apt  41"                   -> one identity
        "Fancy Bear" / "Fáncy Bear"                                 -> one identity
    but NOT a separator against nothing INSIDE a word:
        "Ransom-ware" -> "ransom ware"  is NOT  "Ransomware" -> "ransomware"
    Deleting separators instead would also fold that pair, and is collision-free on today's 115
    curated names — deliberately not done: it would change actor identity, which accept_actors'
    memo, triage and card-identity fold already depend on, to catch a spelling the model does not
    realistically produce. Revisit only if such twins actually appear.

    ponytail: Python-side only, so two writers committing in the same instant with DIFFERENT
    spellings ("APT-41" and "APT 41") can both miss the lookup and both insert — the raw-name
    unique index sees different strings and allows both. Identical names are still blocked, with
    the loser getting the winner's id back. Closing the remaining window means persisting this
    value in a NormalizedName column and moving the unique index onto it (docs/
    TSG_Gap_Analysis_vs_SDD_v1.4.md item C8); not done, because a column on three tables to cover
    a few milliseconds would deepen the very index dependence this design removes.
    """
    decomposed = unicodedata.normalize("NFKD", name.casefold())
    stripped = "".join(ch for ch in decomposed if not unicodedata.combining(ch))
    return _NON_WORD_RE.sub(" ", _ALNUM_BOUNDARY_RE.sub(" ", stripped)).strip()


def display_threat_names(row) -> tuple[str | None, str | None]:
    """(threat_type, threat_name) for DISPLAY PROSE: the curator's library wording when the
    row carries it, else the model's. ONE place, used by every presenter (sessions scenario
    body, treatment plan, plan Excel) so two screens can never show different names for the
    same threat. Typed API fields still report both spellings separately."""
    return (row.get("LibraryThreatType") or row.get("ThreatType"),
            row.get("LibraryThreatName") or row.get("ThreatName"))
