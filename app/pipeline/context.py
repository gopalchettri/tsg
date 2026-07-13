""" before the AI pipeline can start, this file figures out
which asset and which supporting systems the user is asking about, using the
organization's own existing data.

Stage-0 context resolution.

The caller supplies entity/sector/user/asset ids; everything else is resolved by
JOIN to the platform's own tables (the module owns no asset→context mapping).
The same resolved context pre-fills the UI and builds the AI prompt, so they stay
consistent.
"""
from __future__ import annotations

import json
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError


def _validate_supporting_system_ids(asset_id: int, supporting_system_ids: list[int]) -> None:
    """Reject bad input before touching the database: no duplicate ids, and at
    least one supporting system must be requested.
    """
    duplicates = sorted({i for i in supporting_system_ids if supporting_system_ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate supporting_system_id(s): {duplicates}")
    if not supporting_system_ids:
        raise NotFoundError(f"asset {asset_id} has no supporting systems to scan")


def _load_asset(sess: Session, asset_id: int) -> tuple[dict[str, Any], Any]:
    """Fetch the asset row itself, plus its critical service name via an outer
    join (the asset may not have one, hence outerjoin instead of join).

    Deliberately excludes ctm_scan_entity.owner_custodian: it's an internal
    person/team name, not threat-relevant, and every other free-text owner-identity
    field in this schema (onboarding_supporting_systems.system_managed_by) is
    excluded the same way — never surfaced to the model.
    """
    asset_row = sess.execute(
        select(m.ctm_scan_entity.id, m.ctm_scan_entity.name, m.ctm_scan_entity.criticality,
            m.ctm_scan_entity.description, m.ctm_scan_entity.data_handled, m.ctm_scan_entity.type,
            m.ctm_scan_entity.operating_system, m.ctm_scan_entity.location,
            m.ctm_scan_entity.target_rto_hours, m.ctm_scan_entity.target_rpo_hours,
            m.onboarding_services.name.label("critical_service"))
        .select_from(m.ctm_scan_entity)
        .outerjoin(m.onboarding_services,
            m.onboarding_services.id == m.ctm_scan_entity.tier1_critical_service_id)
        .where(m.ctm_scan_entity.id == asset_id)
    ).mappings().first()
    if asset_row is None:
        raise EntityForbidden(f"asset {asset_id} not found")
    asset = dict(asset_row)
    critical_service = asset.pop("critical_service")
    return asset, critical_service


def _load_sector(sess: Session, sector_id: int | None) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Sectors are self-referencing (a sector can have a parent sector), so this
    self-joins the table to itself via an alias to pull both rows in one query.
    """
    if sector_id is None:
        return None, None
    parent = m.onboarding_sectors.__table__.alias("parent_sector")
    row = sess.execute(
        select(m.onboarding_sectors.id, m.onboarding_sectors.name, m.onboarding_sectors.parent_id,
            parent.c.id.label("parent_id_resolved"), parent.c.name.label("parent_name"))
        .select_from(m.onboarding_sectors)
        .outerjoin(parent, parent.c.id == m.onboarding_sectors.parent_id)
        .where(m.onboarding_sectors.id == sector_id)
    ).mappings().first()
    if row is None:
        raise NotFoundError(f"sector {sector_id} not found")
    sector = {"id": row["id"], "name": row["name"], "parent_id": row["parent_id"]}
    parent_sector = None
    if row["parent_id_resolved"] is not None:
        parent_sector = {"id": row["parent_id_resolved"], "name": row["parent_name"]}
    return sector, parent_sector


def _load_supporting_systems(
    sess: Session, asset_id: int, supporting_system_ids: list[int],
) -> dict[int, Mapping[str, Any]]:
    """Fetch only the requested supporting systems, and only if each one is
    actually linked to this asset (the join enforces that).

    Deliberately excludes onboarding_supporting_systems.system_managed_by (owner
    name, not threat-relevant — see _load_asset) and .url (internal endpoint
    detail with no bearing on which STRIDE threats apply).
    """
    ss_rows: dict[int, Mapping[str, Any]] = {
        r["id"]: dict(r) for r in sess.execute(
            select(m.onboarding_supporting_systems.id, m.onboarding_supporting_systems.name,
                m.onboarding_supporting_systems.asset_type,
                m.onboarding_supporting_systems.incident_description,
                m.onboarding_supporting_systems.technology_used,
                m.onboarding_supporting_systems.vendor_name,
                m.onboarding_supporting_systems.database_platforms)
            .join(m.ctm_scan_entity_supporting_system,
                m.ctm_scan_entity_supporting_system.onboarding_supporting_system_id
                == m.onboarding_supporting_systems.id)
            .where(
                m.ctm_scan_entity_supporting_system.ctm_scan_entity_id == asset_id,
                m.onboarding_supporting_systems.id.in_(supporting_system_ids),
            )
        ).mappings()
    }
    # any requested id that didn't come back from the query above either
    # doesn't exist or isn't linked to this asset — reject the whole request
    missing = [i for i in supporting_system_ids if i not in ss_rows]
    if missing:
        raise EntityForbidden(f"supporting system(s) {missing} not linked to asset {asset_id}")
    return ss_rows


def _load_category_lookup(sess: Session, ss_rows: dict[int, Mapping[str, Any]]) -> dict[int, str]:
    """Small, fixed-size batched lookup shared across every supporting system —
    O(1) in query count regardless of how many were requested, and skipped
    entirely when nothing requested actually needs it.
    """
    category_ids = {row["asset_type"] for row in ss_rows.values() if row.get("asset_type") is not None}
    if not category_ids:
        return {}
    return {
        r["id"]: r["name"] for r in sess.execute(
            select(m.ctm_scan_category.id, m.ctm_scan_category.name)
            .where(m.ctm_scan_category.id.in_(category_ids))
        ).mappings()
    }


def _build_subsystems(
    supporting_system_ids: list[int], ss_rows: dict[int, Mapping[str, Any]],
    category_lookup: dict[int, str], criticality: Any,
) -> list[dict[str, Any]]:
    """Build the output list in the caller's requested order (not DB order),
    resolving each subsystem's asset_type id to its human-readable name.
    """
    subsystems = []
    for ssid in supporting_system_ids:
        ss_row = ss_rows[ssid]
        subsystems.append({
            "id": ss_row["id"],
            "name": ss_row.get("name"),
            "criticality": criticality,  # scoping input — stays even though it's dropped from the AI-prompt allowlist
            "asset_type": (category_lookup.get(ss_row["asset_type"]) if ss_row.get("asset_type") is not None else None),
            "past_incidents": ss_row.get("incident_description"),
            "technology_used": ss_row.get("technology_used"),
            "vendor_name": ss_row.get("vendor_name"),
            "database_platforms": ss_row.get("database_platforms"),
        })
    return subsystems


def _resolve_sector_names(
    sector: dict[str, Any] | None, parent_sector: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
    """Sector edge case: sector_id IS the sub-sector/leaf. If it has no parent, it
    represents a top-level sector with no leaf — sub_sector stays None.
    """
    if sector is None:
        return None, None
    if parent_sector is not None:
        return parent_sector["name"], sector["name"]
    return sector["name"], None


def gather_asset_details(
    sess: Session, *, asset_id: int, entity_id: str, sector_id: int | None, user_id: str | None,
    supporting_system_ids: list[int],
) -> dict[str, Any]:
    """Look up one asset plus its sector/parent-sector and the requested supporting
    systems, then package everything into a single dict — some fields shaped for the
    UI, plus JSON-encoded copies of the same data for the AI prompt.
    """
    _validate_supporting_system_ids(asset_id, supporting_system_ids)

    asset, critical_service = _load_asset(sess, asset_id)
    sector, parent_sector = _load_sector(sess, sector_id)
    ss_rows = _load_supporting_systems(sess, asset_id, supporting_system_ids)
    category_lookup = _load_category_lookup(sess, ss_rows)
    subsystems = _build_subsystems(supporting_system_ids, ss_rows, category_lookup, asset["criticality"])
    resolved_sector, resolved_sub_sector = _resolve_sector_names(sector, parent_sector)

    # this is the trimmed-down view of the asset that goes into the AI prompt —
    # only the fields the model actually needs, not the full asset row
    asset_context = {
        "cii_asset_description": asset.get("description"),
        "critical_service": critical_service,
        "sector": resolved_sector,
        "sub_sector": resolved_sub_sector,
        "data_handled": asset.get("data_handled"),
        "asset_type": asset.get("type"),  # the ASSET's own declared type — distinct from each subsystem's own asset_type below
        "operating_system": asset.get("operating_system"),
        "location": asset.get("location"),
        "target_rto_hours": asset.get("target_rto_hours"),
        "target_rpo_hours": asset.get("target_rpo_hours"),
    }

    return {
        "asset": asset,
        "entity_id": str(entity_id),
        "sector": sector,
        "parent_sector": parent_sector,
        "sector_ids": [s["id"] for s in (sector, parent_sector) if s],
        # this is only used to remember who asked for this, for the permanent history
        # log — it does NOT control what the user is allowed to do; that permission
        # check happens separately.
        #
        # provenance only (→ session UserID / audit ActorUserID); NOT an authz principal — auth uses deps.principal
        "user_id": user_id,
        "subsystems": subsystems,
        "subsystems_json": json.dumps(subsystems),
        "asset_context": asset_context,
        "asset_context_json": json.dumps(asset_context),
    }
