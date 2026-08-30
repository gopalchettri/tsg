"""Stage-0 context resolution.

Given entity/sector/user/asset ids, loads the asset, its sector, and its
supporting systems from the platform's own tables (no local mapping data).
The same resolved context feeds both the UI and the AI prompt.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.db import models as m
from app.db.dal import EntityForbidden, NotFoundError

log = get_logger(__name__)

# Columns storing one option_value.id as a plain int (not a JSON array).
# Note: match on option_value.ID, not .value — the two differ in this table.
_SINGLESELECT_OPTION_CODES = {
    "accessability_channel": "acc-channel",
    "hosting_location": "hosting-location",
    "network_connectivity_primary_dr": "network-connectivity",
    "dr_drill_frequency": "dr-drill",
    "managed_by": "managed-by",  # In-house vs Outsourced: third-party exposure, not an owner name
}

# Columns storing a JSON array of option_value ids, e.g. technology_used = "[6]".
_MULTISELECT_OPTION_CODES = {
    "technology_used": "technology-used",
    "database_platforms": "database-platforms",
    "targeted_users": "targeted-users",
    "saas_platform_list": "saas-platforms",
    "public_cloud_platforms": "pub-c-platforms",
}


def _validate_supporting_system_ids(asset_id: int, supporting_system_ids: list[int]) -> None:
    """No duplicate ids, and at least one id required."""
    duplicates = sorted({i for i in supporting_system_ids if supporting_system_ids.count(i) > 1})
    if duplicates:
        raise ValueError(f"duplicate supporting_system_id(s): {duplicates}")
    if not supporting_system_ids:
        raise NotFoundError(f"asset {asset_id} has no supporting systems to scan")


def _load_asset(sess: Session, asset_id: int) -> tuple[dict[str, Any], list[str] | None]:
    """Load the asset row plus the names of every service it's linked to via
    ctm_scan_entity_bu (an asset can link to more than one service).

    owner_custodian is skipped on purpose: it's a person/team name, not
    threat-relevant, same as onboarding_supporting_systems.managed_by.
    """
    asset_row = sess.execute(
        select(m.ctm_scan_entity.id, m.ctm_scan_entity.name, m.ctm_scan_entity.criticality,
            m.ctm_scan_entity.description, m.ctm_scan_entity.data_handled, m.ctm_scan_entity.type,
            m.ctm_scan_entity.ctm_category_id,
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
    """Sectors can have a parent sector, so self-join the table to pull both rows in one query."""
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
    """Fetch the requested supporting systems, but only the ones actually linked
    to this asset — the join enforces that.

    url and the audit columns (created/updated by/date) are deliberately
    excluded; everything else threat-relevant is included.
    """
    ss_rows: dict[int, Mapping[str, Any]] = {
        r["id"]: dict(r) for r in sess.execute(
            select(m.onboarding_supporting_systems.id,
                m.onboarding_supporting_systems.name,
                m.onboarding_supporting_systems.asset_type,
                m.onboarding_supporting_systems.min_no_of_transactions,
                m.onboarding_supporting_systems.max_no_of_transactions,
                m.onboarding_supporting_systems.url,                
                m.onboarding_supporting_systems.accessability_channel,
                m.onboarding_supporting_systems.technology_used,
                m.onboarding_supporting_systems.user_base_count,
                m.onboarding_supporting_systems.targeted_users,
                m.onboarding_supporting_systems.managed_by,
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
                )
            .join(m.ctm_scan_entity_supporting_system,
                m.ctm_scan_entity_supporting_system.onboarding_supporting_system_id
                == m.onboarding_supporting_systems.id)
            .where(
                m.ctm_scan_entity_supporting_system.ctm_scan_entity_id == asset_id,
                m.onboarding_supporting_systems.id.in_(supporting_system_ids),
                m.onboarding_supporting_systems.is_deleted == False,
            )
        ).mappings()
    }
    # requested id missing from the result = doesn't exist or isn't linked to this asset
    missing = [i for i in supporting_system_ids if i not in ss_rows]
    if missing:
        raise EntityForbidden(f"supporting system(s) {missing} not linked to asset {asset_id}")
    return ss_rows


def _load_category_lookup(sess: Session, ss_rows: dict[int, Mapping[str, Any]]) -> dict[int, str]:
    """One batched lookup for all requested supporting systems — single query, skipped if none need it."""
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
    """Parse a JSON array of codes, e.g. "[6]" -> [6]. Data is user-entered, so
    bad JSON returns [] instead of raising.
    """
    if not raw:
        return []
    try:
        return [int(v) for v in json.loads(raw)]
    except (ValueError, TypeError) as exc:
        log.warning("context.multiselect_decode_failed", raw=raw[:200], error=str(exc))
        return []


def _fold_code(code: str) -> str:
    """Lowercase a code so Python dict lookups match SQL's case-insensitive comparison."""
    return str(code).strip().lower()


def _load_multiselect_lookup(
    sess: Session, ss_rows: dict[int, Mapping[str, Any]],
) -> dict[str, dict[int, str]]:
    """Resolve the 5 JSON-array-of-codes columns to names.

    Returns {column_name: {code: name}}, skipping columns with no values and
    option groups missing from `option`.
    """
    needed_cols = [c for c in _MULTISELECT_OPTION_CODES if any(row.get(c) for row in ss_rows.values())]
    if not needed_cols:
        return {}
    # Casefold both sides: SQL matches case-insensitively, Python dict lookup doesn't.
    option_ids = {
        str(r["code"]).strip().lower(): r["id"] for r in sess.execute(
            select(m.option.code, m.option.id)
            .where(m.option.code.in_([_MULTISELECT_OPTION_CODES[c] for c in needed_cols]))
        ).mappings()
    }
    codes_by_col: dict[str, set[int]] = {}
    for col in needed_cols:
        if _fold_code(_MULTISELECT_OPTION_CODES[col]) not in option_ids:
            log.warning("context.option_group_not_seeded",
                        column=col, code=_MULTISELECT_OPTION_CODES[col])
            continue
        codes = {code for row in ss_rows.values() for code in _decode_codes(row.get(col))}
        if codes:
            codes_by_col[col] = codes
    if not codes_by_col:
        return {}
    relevant_option_ids = {option_ids[_fold_code(_MULTISELECT_OPTION_CODES[col])] for col in codes_by_col}
    names_by_option: dict[int, dict[int, str]] = {}
    for r in sess.execute(
        select(m.option_value.option_id, m.option_value.id, m.option_value.name)
        .where(m.option_value.option_id.in_(relevant_option_ids))
    ).mappings():
        names_by_option.setdefault(r["option_id"], {})[r["id"]] = r["name"]
    return {col: names_by_option.get(option_ids[_fold_code(_MULTISELECT_OPTION_CODES[col])], {}) for col in codes_by_col}


def _resolve_multiselect(raw: str | None, lookup: dict[int, str]) -> list[str] | None:
    """Decode codes to names. Unresolvable codes are dropped, not stringified —
    a raw id like 1105 in the prompt would read to the model as a fact.
    All-unresolvable therefore yields None, not ['1105'].
    """
    names = [lookup[code] for code in _decode_codes(raw) if code in lookup]
    return names or None


def _load_singleselect_lookup(
    sess: Session, ss_rows: dict[int, Mapping[str, Any]],
) -> dict[str, dict[int, str]]:
    """Same as _load_multiselect_lookup but for the 4 single-value columns (no JSON-array decode)."""
    needed_cols = [c for c in _SINGLESELECT_OPTION_CODES if any(row.get(c) is not None for row in ss_rows.values())]
    if not needed_cols:
        return {}
    option_ids = {  # casefolded — see _load_multiselect_lookup
        _fold_code(r["code"]): r["id"] for r in sess.execute(
            select(m.option.code, m.option.id)
            .where(m.option.code.in_([_SINGLESELECT_OPTION_CODES[c] for c in needed_cols]))
        ).mappings()
    }
    resolvable_cols = [c for c in needed_cols if _fold_code(_SINGLESELECT_OPTION_CODES[c]) in option_ids]
    missing_cols = [c for c in needed_cols if c not in resolvable_cols]
    if missing_cols:
        log.warning("context.option_group_not_seeded",
                    columns=missing_cols, codes=[_SINGLESELECT_OPTION_CODES[c] for c in missing_cols])
    if not resolvable_cols:
        return {}
    relevant_option_ids = {option_ids[_fold_code(_SINGLESELECT_OPTION_CODES[c])] for c in resolvable_cols}
    names_by_option: dict[int, dict[int, str]] = {}
    for r in sess.execute(
        select(m.option_value.option_id, m.option_value.id, m.option_value.name)
        .where(m.option_value.option_id.in_(relevant_option_ids))
    ).mappings():
        names_by_option.setdefault(r["option_id"], {})[r["id"]] = r["name"]
    return {c: names_by_option.get(option_ids[_fold_code(_SINGLESELECT_OPTION_CODES[c])], {}) for c in resolvable_cols}


def _resolve_singleselect(raw: int | None, lookup: dict[int, str]) -> str | None:
    """Resolve one code to its name, or None if unresolvable."""
    return lookup.get(raw) if raw is not None else None


def _build_subsystems(
    supporting_system_ids: list[int], ss_rows: dict[int, Mapping[str, Any]],
    category_lookup: dict[int, str], multiselect_lookup: dict[str, dict[int, str]],
    singleselect_lookup: dict[str, dict[int, str]], criticality: Any,
) -> list[dict[str, Any]]:
    """Build the output list in the caller's requested order, resolving each
    subsystem's option codes to names.

    last_dr_test_date/rto_target_mins/rpo_target_mins are converted to
    str/float here so json.dumps() below (subsystems_json) can serialize them.

    last_dr_test_date also treats SQL Server's datetime minimum (1753-01-01,
    or 1900-01-01 for smalldatetime) as "never tested" and emits None instead
    of that sentinel date.
    """
    subsystems = []
    for ssid in supporting_system_ids:
        ss_row = ss_rows[ssid]
        last_dr_test_date = ss_row.get("last_dr_test_date")
        # .year works for both date and datetime; no real DR test predates 1900
        if last_dr_test_date is not None and last_dr_test_date.year <= 1900:
            last_dr_test_date = None
        rto_target_mins = ss_row.get("rto_target_mins")
        rpo_target_mins = ss_row.get("rpo_target_mins")
        subsystems.append({
            "id": ss_row["id"],
            "name": ss_row.get("name"),
            "criticality": criticality,  # scoping input — stays even though it's dropped from the AI-prompt allowlist
            "asset_type": (category_lookup.get(ss_row["asset_type"]) if ss_row.get("asset_type") is not None else None),
            # RAW ctm_scan_category id — one member of the session's asset-category union
            # (threat_retrieval.session_category_ids), which now feeds ONLY the data-driven
            # control ITOT filter (threat retrieval reads the whole active catalogue — the
            # catalogue has no asset-type column). The resolved name above stays for display
            # + ranking text.
            "asset_type_id": ss_row.get("asset_type"),
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
            "managed_by": _resolve_singleselect(ss_row.get("managed_by"), singleselect_lookup.get("managed_by", {})),
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
    """sector_id is the leaf sector. No parent means it's top-level, so sub_sector stays None."""
    if sector is None:
        return None, None
    if parent_sector is not None:
        return parent_sector["name"], sector["name"]
    return sector["name"], None


def gather_asset_details(
    sess: Session, *, asset_id: int, entity_id: str, sector_id: int | None, user_id: str | None,
    supporting_system_ids: list[int], subsector_id: int | None = None,
) -> dict[str, Any]:
    """Look up the asset, its sector, and the requested supporting systems, and
    package it all into one dict — UI-shaped fields plus JSON copies for the AI prompt.

    Pass subsector_id, not sector_id: _load_sector expects the leaf/child
    sector row and derives the parent itself. sector_id is accepted only as a
    fallback for callers that predate subsector_id.
    """
    _validate_supporting_system_ids(asset_id, supporting_system_ids)

    asset, critical_service = _load_asset(sess, asset_id)
    sector, parent_sector = _load_sector(sess, subsector_id or sector_id)
    ss_rows = _load_supporting_systems(sess, asset_id, supporting_system_ids)
    category_lookup = _load_category_lookup(sess, ss_rows)
    multiselect_lookup = _load_multiselect_lookup(sess, ss_rows)
    singleselect_lookup = _load_singleselect_lookup(sess, ss_rows)
    subsystems = _build_subsystems(supporting_system_ids, ss_rows, category_lookup, multiselect_lookup, singleselect_lookup, asset["criticality"])
    resolved_sector, resolved_sub_sector = _resolve_sector_names(sector, parent_sector)

    # trimmed view of the asset for the AI prompt — only fields the model needs
    asset_context = {
        "cii_asset_description": asset.get("description"),
        "critical_service": critical_service,
        "sector": resolved_sector,
        "sub_sector": resolved_sub_sector,
        "data_handled": asset.get("data_handled"),
        "asset_type": asset.get("type"),  # the ASSET's own declared type — distinct from each subsystem's own asset_type below
        # RAW ctm_scan_category id of the asset itself — unioned with the subsystems' ids into
        # the session's asset-category set (threat_retrieval.session_category_ids), which the
        # control ITOT filter consumes. Stripped from the AI prompt by the redaction list.
        "asset_type_id": asset.get("ctm_category_id"),
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
        # audit/history only — not an authz principal; auth uses deps.principal
        "user_id": user_id,
        "subsystems": subsystems,
        "subsystems_json": json.dumps(subsystems),
        "asset_context": asset_context,
        "asset_context_json": json.dumps(asset_context),
    }
