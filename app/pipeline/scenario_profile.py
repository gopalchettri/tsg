"""Asset PROFILE identity and name substitution — the two pure halves of the scenario library.

A scenario is content, not a per-request computation. Control_Library already proves the model:
1,288 pre-written rows, reused by everyone, zero AI. The threat side should match. Two things
have to be true for that to be safe, and both live here:

1. A PROFILE KEY that says when two assets are interchangeable for scenario purposes.
   Classification codes and technology labels ONLY — never a name, an entity id, or free text —
   so the derived answer is safe to share across tenants while asset data stays isolated.
   The subsystem list is ordered and positional: two assets share a key only when they have the
   same NUMBER of supporting systems, in the same order, with the same technology at each
   position. That is stricter than a flat union of technologies, deliberately, because it is
   what makes position-matched name substitution exact rather than approximate.

2. SUBSTITUTION that refuses rather than guesses. The stored text was written about a real
   asset with real system names; serving it to a different asset means swapping those names.
   Every step here fails CLOSED: a length mismatch, an unmapped name, or any trace of a source
   name surviving the swap returns None, and the caller generates instead. The cost of refusing
   is money. The cost of guessing is a GRC register that names the wrong system, which is
   exactly the kind of confident-and-wrong output this whole redesign exists to prevent.

Leaf module: stdlib only, no app imports, so any stage can call it without an import cycle.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any

#: Asset-level classification that changes what threat scenarios look like. NOT `name`,
#: `description` or anything free-text: those identify a customer's asset, and a key built from
#: them would never match twice anyway.
_ASSET_PROFILE_FIELDS = ("asset_type", "sector", "sub_sector")

#: Per-supporting-system profile. Vendor and platform names are PRODUCT vocabulary (fixed
#: dropdown values), not customer identifiers — and they are the whole reason two SCADA assets
#: attract the same threats. `name` is excluded for the same reason as above.
_SUBSYSTEM_PROFILE_FIELDS = ("asset_type", "criticality", "technology_used", "vendor_name",
                             "database_platforms", "saas_platform_list", "public_cloud_platforms")


def _norm(value: Any) -> Any:
    """Order-insensitive inside one multi-select field, order-SENSITIVE across systems."""
    if isinstance(value, (list, tuple)):
        return sorted(str(v).strip().casefold() for v in value if v is not None and str(v).strip())
    if value is None:
        return None
    return str(value).strip().casefold()


def profile_key(sector_ids: list[int] | None, asset_context: dict,
                subsystems: list[dict] | None) -> str:
    """The identity two assets must share before one's scenarios may be served to the other.

    sector_ids ride along because library VISIBILITY is scoped by them
    (grounding.visible_to_this_sector): two assets with identical technology but different
    sector scope see different candidate threats, so their scenario sets are not
    interchangeable."""
    payload = {
        "sectors": sorted(int(s) for s in (sector_ids or [])),
        "asset": {f: _norm(asset_context.get(f)) for f in _ASSET_PROFILE_FIELDS},
        # A LIST, not a set: position is part of the key, because substitution is positional.
        "systems": [{f: _norm(sub.get(f)) for f in _SUBSYSTEM_PROFILE_FIELDS}
                    for sub in subsystems or []],
    }
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def live_names(asset_name: str | None, subsystems: list[dict] | None) -> list[str]:
    """The names a scenario written for this asset may legitimately mention, in the positional
    order the profile key fixes: [asset, system 1, system 2, ...]. Blanks are kept as "" so a
    system with no name never shifts the positions of the ones after it."""
    return [str(asset_name or "").strip()] + [str(s.get("name") or "").strip()
                                            for s in subsystems or []]


def _mentions(haystack: str, needle: str) -> bool:
    """Case-insensitive whole-token containment. Used only to REFUSE, never to substitute."""
    if not needle:
        return False
    return re.search(r"(?<!\w)" + re.escape(needle) + r"(?!\w)", haystack, re.IGNORECASE) is not None


def substitute_names(scenario_json: str, source_names: list[str],
                    target_names: list[str]) -> dict | None:
    """Re-point a stored scenario at a different asset, or refuse.

    Returns the rewritten scenario dict, or None meaning "do not serve this — generate".
    Every refusal below is a case where serving would risk putting one customer's system name
    in another customer's risk register:

      * the two name lists are different lengths (the profile key should make this impossible,
        so reaching it means the key and the stored row disagree — trust neither);
      * a source name survives the swap in any casing, which means the model wrote a variant
        ("the scada hmi", "SCADA HMI Server") that exact replacement could not reach.

    Longest source name first, so replacing "SCADA" cannot corrupt "SCADA HMI Server" by
    rewriting its prefix and leaving an orphaned suffix behind.
    """
    if len(source_names) != len(target_names):
        return None
    try:
        text = scenario_json if isinstance(scenario_json, str) else json.dumps(scenario_json)
        json.loads(text)                       # must already be valid before we touch it
    except (TypeError, ValueError):
        return None
    pairs = sorted(((s, t) for s, t in zip(source_names, target_names) if s and s != t),
                key=lambda p: -len(p[0]))
    for source, target in pairs:
        text = re.sub(r"(?<!\w)" + re.escape(source) + r"(?!\w)",
                    target.replace("\\", "\\\\"), text)
    # Refuse on ANY residue. A single survivor means the swap was incomplete, and an incomplete
    # swap is a wrong document that reads as a right one.
    for source, target in zip(source_names, target_names):
        if source and source != target and _mentions(text, source):
            return None
    try:
        out = json.loads(text)
    except ValueError:
        return None                            # a name containing JSON metacharacters
    return out if isinstance(out, dict) else None
