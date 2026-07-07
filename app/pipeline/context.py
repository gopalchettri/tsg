""" before the AI pipeline can start, this file figures out
which asset and which supporting systems the user is asking about, using the
organization's own existing data — and makes sure the user is actually allowed
to see that asset.

Stage-0 context resolution.

The caller supplies entity/sector/user/asset ids; everything else is resolved by
JOIN to the platform's own tables (the module owns no asset→context mapping).
The same resolved context pre-fills the UI and builds the AI prompt, so they stay
consistent. The requested asset must belong to the requested entity.
"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError


def check_asset_belongs_to_entity(sess: Session, asset_id: int, entity_id: str) -> None:
    """ checks that the chosen asset really belongs to the
    caller's own organization — so one company can never see or touch another
    company's data.

    Bind the two independent caller inputs (asset_id, entity): the asset's owning
    entity must equal `entity_id`, or reject. Mode is config-driven (ASSET_ENTITY_BINDING):
      - 'service' (default): asset.(asset_service_column) → onboarding_service_entity.service_id → group_id
      - 'none': skip (dev/local only; assert_security_posture blocks it in staging/prod)
    The injected column name is validated as a plain identifier, so it can't be an injection vector.
    """
    s = get_settings()
    mode = s.asset_entity_binding
    if mode == "none":
        return

    # mode == 'service': asset → service → owning group
    # Which column on `ctm_scan_entity` points to the owning service is a fact
    # about a platform TSG doesn't control — so it's read from config instead of
    # hardcoded — a rename on that platform's side only needs a config change
    # here, not a TSG code change.
    svc = s.asset_service_column.strip()
    # This string comes from a human-editable setting and gets spliced straight
    # into the SQL below, so it must be validated first to rule out a
    # SQL-injection payload.
    if not svc.isidentifier():
        raise RuntimeError(f"ASSET_SERVICE_COLUMN is not a valid column name: {svc!r}")
    try:
        entity_int = int(entity_id)  # group.id is an int; a non-numeric entity can't own via it
    except (TypeError, ValueError):
        raise EntityForbidden(f"asset {asset_id} not owned by entity {entity_id}")
    found = sess.execute(
        text(
            "SELECT 1 FROM onboarding_service_entity ose "
            f"JOIN ctm_scan_entity a ON a.[{svc}] = ose.service_id "
            "WHERE a.id = :asset_id AND ose.group_id = :entity"),
        {"asset_id": asset_id, "entity": entity_int},
    ).first()
    if not found:
        raise EntityForbidden(f"asset {asset_id} not owned by entity {entity_id}")


def _guess_if_internet_facing(row: Any) -> str:
    """ makes a rough guess whether a supporting system is
    reachable from the public internet or only used internally.

    Derive exposure: internet-facing if a public url/hosting is present,
    else internal; default 'default'. `# ponytail: heuristic (an educated guess,
    not a precise measurement) — tune with real data.`
    """
    hosting = str(row.get("hosting_location") or "").lower()  # real column may be int/code, not text
    if row.get("url") or hosting in ("public", "internet", "cloud"):
        return "internet-facing"
    if hosting:
        return "internal"
    return "default"


def gather_asset_details(
    sess: Session, *, asset_id: int, entity_id: str, sector_id: int | None, user_id: str | None,
) -> dict[str, Any]:
    """ the main function here — gathers everything about the
    chosen asset (its name, its sector, and every supporting system it has)
    into one bundle, which is used both to show the user a summary and to feed
    the AI prompts later.

    Stage-0 entry point (SDD §5.1): join the caller's ids against the platform's own
    tables to build the single context dict that both pre-fills the UI and feeds the AI
    prompt. Ownership is checked first ([R2]) so nothing below it can leak another
    entity's asset or subsystem data. Sector/parent-sector are a GLOBAL taxonomy
    (`onboarding_sectors` has no owning-entity column), so resolving them by id is not
    an entity boundary and needs no scoping.
    """
    check_asset_belongs_to_entity(sess, asset_id, entity_id)

    # Select only the columns we actually use, so a real TSG whose other
    # ctm_scan_entity columns differ from the SDD dictionary can't break resolution.
    asset = sess.execute(
        select(m.ctm_scan_entity.c.id, m.ctm_scan_entity.c.name, m.ctm_scan_entity.c.criticality)
        .where(m.ctm_scan_entity.c.id == asset_id)
    ).mappings().first()
    if asset is None:
        raise EntityForbidden(f"asset {asset_id} not found")

    # Sectors form a two-level tree: a specific sub-sector, and the broader
    # sector it belongs to.
    #
    # Sector tree (§5.1): a leaf with parent_id → sub-sector; its parent → sector.
    sector = parent_sector = None
    if sector_id is not None:
        sector = sess.execute(
            select(m.onboarding_sectors).where(m.onboarding_sectors.c.id == sector_id)
        ).mappings().first()
        if sector and sector["parent_id"]:
            parent_sector = sess.execute(
                select(m.onboarding_sectors).where(m.onboarding_sectors.c.id == sector["parent_id"])
            ).mappings().first()

    # Every asset can have several supporting systems linked to it — this looks
    # them all up.
    #
    # Supporting systems (M:N) → SubsystemsJSON (NOT NULL, must be populated).
    rows = sess.execute(
        select(m.onboarding_supporting_systems)
        .join(
            m.ctm_scan_entity_supporting_system,
            m.ctm_scan_entity_supporting_system.c.onboarding_supporting_system_id
            == m.onboarding_supporting_systems.c.id,
        )
        .where(m.ctm_scan_entity_supporting_system.c.ctm_scan_entity_id == asset_id)
    ).mappings().all()

    subsystems = [
        {
            "id": r["id"],
            "name": r["name"],
            "exposure_level": _guess_if_internet_facing(r),
            "criticality": asset["criticality"],
            "interfaces": [],  # sourced from a named field when available, else []
        }
        for r in rows
    ]
    if not subsystems:
        #  an asset with zero supporting systems would create a
        # session with nothing to actually do, which would just sit around until
        # the cleanup job eventually removes it — so we refuse to even start one,
        # right here, with a clear error, instead of letting a confusing empty
        # session slip through.
        #
        # SubsystemsJSON is NOT NULL and the AUTO fan-out iterates it; an asset with no
        # supporting systems would spawn a zero-work session that only the reaper cleans up.
        # Enforce the "must be populated" contract at Stage-0 rather than failing silently later.
        raise NotFoundError(f"asset {asset_id} has no supporting systems to scan")

    return {
        "asset": dict(asset),
        "entity_id": str(entity_id),
        "sector": dict(sector) if sector else None,
        "parent_sector": dict(parent_sector) if parent_sector else None,
        "sector_ids": [s["id"] for s in (sector, parent_sector) if s],
        # this is only used to remember who asked for this, for the permanent history
        # log — it does NOT control what the user is allowed to do; that permission
        # check happens separately.
        #
        # provenance only (→ session UserID / audit ActorUserID); NOT an authz principal — auth uses deps.principal
        "user_id": user_id,
        "subsystems": subsystems,
        "subsystems_json": json.dumps(subsystems),
    }
