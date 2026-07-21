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

from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError

log = get_logger(__name__)

# onboarding_supporting_systems columns that store a single option_value code as a plain
# int (not a JSON array) — same option/option_value resolution as the multiselect columns
# above, just one code per row instead of a decoded array.
_SINGLESELECT_OPTION_CODES = {
    "accessability_channel": "acc-channel",
    "hosting_location": "hosting-location",
    "network_connectivity_primary_dr": "network-connectivity",
    "dr_drill_frequency": "dr-drill",
}

# onboarding_supporting_systems columns that store their value as a JSON array of
# option_value codes (e.g. technology_used = "[6]") rather than a plain scalar —
# same option/option_value resolution as asset_type, just multi-valued and keyed by
# a fixed option.code per column instead of a single hardcoded option_id.
_MULTISELECT_OPTION_CODES = {
    "technology_used": "technology-used",
    "database_platforms": "database-platforms",
    "targeted_users": "targeted-users",
    "saas_platform_list": "saas-platforms",
    "public_cloud_platforms": "pub-c-platforms",
}


def _validate_supporting_system_ids(asset_id: int, supporting_system_ids: list[int]) -> None:
    """Reject bad input before touching the database: no duplicate ids, and at
    least one supporting system must be requested.
    """
    duplicates = sorted({i for i in supporting_system_ids if supporting_system_ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate supporting_system_id(s): {duplicates}")
    if not supporting_system_ids:
        raise NotFoundError(f"asset {asset_id} has no supporting systems to scan")


def _load_asset(sess: Session, asset_id: int) -> tuple[dict[str, Any], list[str] | None]:
    """Fetch the asset row itself, plus the name of every service it's linked to via
    `ctm_scan_entity_bu` (batched lookup, same style as _load_category_lookup) — an asset can
    legitimately link to more than one (confirmed live: asset 1 has 2 rows), so this returns a
    list, not a single value. Replaces the old join through `ctm_scan_entity.
    tier1_critical_service_id`: that field is confirmed unpopulated on every current asset (see
    dal.py::asset_owning_entities, fixed the same way in an earlier session).

    Deliberately excludes ctm_scan_entity.owner_custodian: it's an internal
    person/team name, not threat-relevant, and every other free-text owner-identity
    field in this schema (onboarding_supporting_systems.managed_by) is
    excluded the same way — never surfaced to the model.
    """
    asset_row = sess.execute(
        select(m.ctm_scan_entity.id, m.ctm_scan_entity.name, m.ctm_scan_entity.criticality,
            m.ctm_scan_entity.description, m.ctm_scan_entity.data_handled, m.ctm_scan_entity.type,
            m.ctm_scan_entity.operating_system, m.ctm_scan_entity.location,
            m.ctm_scan_entity.target_rto_hours, m.ctm_scan_entity.target_rpo_hours)
        .where(m.ctm_scan_entity.id == asset_id)
    ).mappings().first()
    if asset_row is None:
        raise EntityForbidden(f"asset {asset_id} not found")
    asset = dict(asset_row)

    service_ids = sorted({sid for sid in sess.execute(
        select(m.ctm_scan_entity_bu.service_id).where(m.ctm_scan_entity_bu.ctm_scan_entity_id == asset_id)
    ).scalars() if sid is not None})
    critical_service = None
    if service_ids:
        names = {
            r["id"]: r["name"] for r in sess.execute(
                select(m.onboarding_services.id, m.onboarding_services.name)
                .where(m.onboarding_services.id.in_(service_ids))
            ).mappings()
        }
        critical_service = [names[sid] for sid in service_ids if sid in names] or None
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
    actually linked to this asset (the join enforces that). Pulls every column
    on the real table that carries threat-relevant information — usage scale,
    accessibility/hosting/network exposure, DR/backup posture, data-residency,
    and RTO/RPO targets — not just the original narrow subset.

    Cross-checked against the org's own SupportingSystemDetails reporting query
    (asset_id -> ctm_scan_entity_supporting_system -> onboarding_supporting_systems,
    with ctm_scan_category/option/option_value resolving asset_type and the
    single/multi-value coded columns — see _load_category_lookup/
    _load_singleselect_lookup/_load_multiselect_lookup): every column that query
    resolves is covered here or by one of those three lookups, except
    onboarding_supporting_systems.managed_by (owner name, not threat-relevant —
    see _load_asset) and .url, still deliberately excluded, and the
    creation_date/created_by/date_updated/updated_by audit columns, never
    modeled for any table in this codebase. min_no_of_transactions/
    max_no_of_transactions are the one addition beyond that reference query —
    real, non-audit, threat-relevant columns worth keeping even though that
    particular report doesn't select them.
    """
    ss_rows: dict[int, Mapping[str, Any]] = {
        r["id"]: dict(r) for r in sess.execute(
            select(m.onboarding_supporting_systems.id, m.onboarding_supporting_systems.name,
                m.onboarding_supporting_systems.asset_type,
                m.onboarding_supporting_systems.min_no_of_transactions,
                m.onboarding_supporting_systems.max_no_of_transactions,
                m.onboarding_supporting_systems.accessability_channel,
                m.onboarding_supporting_systems.technology_used,
                m.onboarding_supporting_systems.user_base_count,
                m.onboarding_supporting_systems.vendor_name,
                m.onboarding_supporting_systems.maintenance_contract_exists,
                m.onboarding_supporting_systems.hosting_location,
                m.onboarding_supporting_systems.dr_location,
                m.onboarding_supporting_systems.network_connectivity_primary_dr,
                m.onboarding_supporting_systems.last_dr_test_date,
                m.onboarding_supporting_systems.backup_multi_site,
                m.onboarding_supporting_systems.backup_retention_period_days,
                m.onboarding_supporting_systems.backup_tested,
                m.onboarding_supporting_systems.offsite_air_gapped_backup,
                m.onboarding_supporting_systems.data_residency_restrictions,
                m.onboarding_supporting_systems.data_residency_restriction_justification,
                m.onboarding_supporting_systems.document_drp_exists,
                m.onboarding_supporting_systems.dr_drill_frequency,
                m.onboarding_supporting_systems.database_platforms,
                m.onboarding_supporting_systems.saas_backup_required,
                m.onboarding_supporting_systems.saas_platform_list,
                m.onboarding_supporting_systems.public_cloud_platforms,
                m.onboarding_supporting_systems.rto_target_mins,
                m.onboarding_supporting_systems.rpo_target_mins,
                m.onboarding_supporting_systems.data_loss_incident_last_3_years,
                m.onboarding_supporting_systems.incident_description,
                m.onboarding_supporting_systems.targeted_users)
            .join(m.ctm_scan_entity_supporting_system,
                m.ctm_scan_entity_supporting_system.onboarding_supporting_system_id
                == m.onboarding_supporting_systems.id)
            .where(
                m.ctm_scan_entity_supporting_system.ctm_scan_entity_id == asset_id,
                m.onboarding_supporting_systems.id.in_(supporting_system_ids),
                m.onboarding_supporting_systems.is_deleted == False,  # noqa: E712 — SQLAlchemy binary expr, not a Python bool
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


def _decode_codes(raw: str | None) -> list[int]:
    """Parse one JSON-array-of-codes column value (e.g. "[6]"). The real column is
    user/vendor-populated free-form JSON, not app-controlled — malformed or legacy
    data must degrade to "unresolved", never crash the whole session-creation
    request over one bad row on one subsystem. Shared by every caller that decodes
    this shape, so a fix here covers all of them at once."""
    if not raw:
        return []
    try:
        return [int(v) for v in json.loads(raw)]
    except (ValueError, TypeError) as exc:
        log.warning("context.multiselect_decode_failed", raw=raw[:200], error=str(exc))
        return []


def _load_multiselect_lookup(
    sess: Session, ss_rows: dict[int, Mapping[str, Any]],
) -> dict[str, dict[int, str]]:
    """Batched resolution for the 5 JSON-array-of-codes columns above. Returns
    {column_name: {code: resolved_name}}, skipping any column nothing requested
    actually has a value for, and any option group not found in `option`.
    """
    needed_cols = [c for c in _MULTISELECT_OPTION_CODES if any(row.get(c) for row in ss_rows.values())]
    if not needed_cols:
        return {}
    option_ids = {
        r["code"]: r["id"] for r in sess.execute(
            select(m.option.code, m.option.id)
            .where(m.option.code.in_([_MULTISELECT_OPTION_CODES[c] for c in needed_cols]))
        ).mappings()
    }
    codes_by_col: dict[str, set[int]] = {}
    for col in needed_cols:
        if _MULTISELECT_OPTION_CODES[col] not in option_ids:  # option group not seeded — leave unresolved
            continue
        codes = {code for row in ss_rows.values() for code in _decode_codes(row.get(col))}
        if codes:
            codes_by_col[col] = codes
    if not codes_by_col:
        return {}
    relevant_option_ids = {option_ids[_MULTISELECT_OPTION_CODES[col]] for col in codes_by_col}
    names_by_option: dict[int, dict[int, str]] = {}
    for r in sess.execute(
        select(m.option_value.option_id, m.option_value.value, m.option_value.name)
        .where(m.option_value.option_id.in_(relevant_option_ids))
    ).mappings():
        names_by_option.setdefault(r["option_id"], {})[r["value"]] = r["name"]
    return {col: names_by_option.get(option_ids[_MULTISELECT_OPTION_CODES[col]], {}) for col in codes_by_col}


def _resolve_multiselect(raw: str | None, lookup: dict[int, str]) -> list[str] | None:
    """Decode one JSON-array-of-codes column value into human-readable names."""
    codes = _decode_codes(raw)
    return [lookup.get(code, str(code)) for code in codes] if codes else None




def _load_singleselect_lookup(
    sess: Session, ss_rows: dict[int, Mapping[str, Any]],
) -> dict[str, dict[int, str]]:
    """Batched resolution for the 4 single-value option_value-code columns above. Same
    {column_name: {code: resolved_name}} shape as _load_multiselect_lookup, minus the
    JSON-array decode step — these columns already hold one option_value code as a plain int.
    """
    needed_cols = [c for c in _SINGLESELECT_OPTION_CODES if any(row.get(c) is not None for row in ss_rows.values())]
    if not needed_cols:
        return {}
    option_ids = {
        r["code"]: r["id"] for r in sess.execute(
            select(m.option.code, m.option.id)
            .where(m.option.code.in_([_SINGLESELECT_OPTION_CODES[c] for c in needed_cols]))
        ).mappings()
    }
    resolvable_cols = [c for c in needed_cols if _SINGLESELECT_OPTION_CODES[c] in option_ids]  # option group not seeded — leave unresolved
    if not resolvable_cols:
        return {}
    relevant_option_ids = {option_ids[_SINGLESELECT_OPTION_CODES[c]] for c in resolvable_cols}
    names_by_option: dict[int, dict[int, str]] = {}
    for r in sess.execute(
        select(m.option_value.option_id, m.option_value.value, m.option_value.name)
        .where(m.option_value.option_id.in_(relevant_option_ids))
    ).mappings():
        names_by_option.setdefault(r["option_id"], {})[r["value"]] = r["name"]
    return {c: names_by_option.get(option_ids[_SINGLESELECT_OPTION_CODES[c]], {}) for c in resolvable_cols}


def _resolve_singleselect(raw: int | None, lookup: dict[int, str]) -> str | None:
    """Decode one single-value option_value-code column into its human-readable name."""
    return lookup.get(raw, str(raw)) if raw is not None else None


def _build_subsystems(
    supporting_system_ids: list[int], ss_rows: dict[int, Mapping[str, Any]],
    category_lookup: dict[int, str], multiselect_lookup: dict[str, dict[int, str]],
    singleselect_lookup: dict[str, dict[int, str]], criticality: Any,
) -> list[dict[str, Any]]:
    """Build the output list in the caller's requested order (not DB order),
    resolving each subsystem's asset_type id, the JSON-array-of-codes columns, and
    the single-value option_value-code columns to their human-readable names.

    last_dr_test_date/rto_target_mins/rpo_target_mins are converted to
    str/float here (not left as datetime/Decimal) — both go straight into
    json.dumps() below via subsystems_json, which can't serialize either type.
    """
    subsystems = []
    for ssid in supporting_system_ids:
        ss_row = ss_rows[ssid]
        last_dr_test_date = ss_row.get("last_dr_test_date")
        rto_target_mins = ss_row.get("rto_target_mins")
        rpo_target_mins = ss_row.get("rpo_target_mins")
        subsystems.append({
            "id": ss_row["id"],
            "name": ss_row.get("name"),
            "criticality": criticality,  # scoping input — stays even though it's dropped from the AI-prompt allowlist
            "asset_type": (category_lookup.get(ss_row["asset_type"]) if ss_row.get("asset_type") is not None else None),
            "past_incidents": ss_row.get("incident_description"),
            "technology_used": _resolve_multiselect(ss_row.get("technology_used"), multiselect_lookup.get("technology_used", {})),
            "vendor_name": ss_row.get("vendor_name"),
            "database_platforms": _resolve_multiselect(ss_row.get("database_platforms"), multiselect_lookup.get("database_platforms", {})),
            "targeted_users": _resolve_multiselect(ss_row.get("targeted_users"), multiselect_lookup.get("targeted_users", {})),
            "saas_platform_list": _resolve_multiselect(ss_row.get("saas_platform_list"), multiselect_lookup.get("saas_platform_list", {})),
            "public_cloud_platforms": _resolve_multiselect(ss_row.get("public_cloud_platforms"), multiselect_lookup.get("public_cloud_platforms", {})),
            "min_no_of_transactions": ss_row.get("min_no_of_transactions"),
            "max_no_of_transactions": ss_row.get("max_no_of_transactions"),
            "user_base_count": ss_row.get("user_base_count"),
            "accessability_channel": _resolve_singleselect(ss_row.get("accessability_channel"), singleselect_lookup.get("accessability_channel", {})),
            "hosting_location": _resolve_singleselect(ss_row.get("hosting_location"), singleselect_lookup.get("hosting_location", {})),
            "dr_location": ss_row.get("dr_location"),
            "network_connectivity_primary_dr": _resolve_singleselect(ss_row.get("network_connectivity_primary_dr"), singleselect_lookup.get("network_connectivity_primary_dr", {})),
            "dr_drill_frequency": _resolve_singleselect(ss_row.get("dr_drill_frequency"), singleselect_lookup.get("dr_drill_frequency", {})),
            "maintenance_contract_exists": ss_row.get("maintenance_contract_exists"),
            "last_dr_test_date": last_dr_test_date.isoformat() if last_dr_test_date is not None else None,
            "backup_multi_site": ss_row.get("backup_multi_site"),
            "backup_retention_period_days": ss_row.get("backup_retention_period_days"),
            "backup_tested": ss_row.get("backup_tested"),
            "offsite_air_gapped_backup": ss_row.get("offsite_air_gapped_backup"),
            "data_residency_restrictions": ss_row.get("data_residency_restrictions"),
            "data_residency_restriction_justification": ss_row.get("data_residency_restriction_justification"),
            "document_drp_exists": ss_row.get("document_drp_exists"),
            "saas_backup_required": ss_row.get("saas_backup_required"),
            "rto_target_mins": float(rto_target_mins) if rto_target_mins is not None else None,
            "rpo_target_mins": float(rpo_target_mins) if rpo_target_mins is not None else None,
            "data_loss_incident_last_3_years": ss_row.get("data_loss_incident_last_3_years"),
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
    multiselect_lookup = _load_multiselect_lookup(sess, ss_rows)
    singleselect_lookup = _load_singleselect_lookup(sess, ss_rows)
    subsystems = _build_subsystems(supporting_system_ids, ss_rows, category_lookup, multiselect_lookup, singleselect_lookup, asset["criticality"])
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
