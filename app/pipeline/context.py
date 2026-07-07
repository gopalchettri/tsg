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
from typing import TYPE_CHECKING, Any, Mapping

from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db import models as m
from app.db.dal import ContextMismatchError, EntityForbidden, NotFoundError

if TYPE_CHECKING:
    from app.api.schemas import CreateSessionBody

# §5.1 — the option groups the platform's onboarding UI curates for supporting-system
# fields; onboarding_supporting_systems stores the *code* (option_value.value), never
# the label, so validate_ui_supplied_context resolves both through option_value.name.
_OPTION_ACCESSIBILITY_CHANNEL = 1012
_OPTION_HOSTING_ENVIRONMENT = 1015


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


def _guess_if_internet_facing(hosting_environment: str | None) -> str:
    """ makes a rough guess whether a supporting system is
    reachable from the public internet or only used internally.

    Derive exposure from the UI-supplied hosting_environment label: internet-facing if
    it names something public/internet/cloud, else internal; default 'default' when
    nothing was supplied. `# ponytail: heuristic (an educated guess, not a precise
    measurement) — tune with real data.`
    """
    hosting = str(hosting_environment or "").lower()
    if hosting in ("public", "internet", "cloud"):
        return "internet-facing"
    if hosting:
        return "internal"
    return "default"


def gather_asset_details(
    sess: Session, *, asset_id: int, entity_id: str, sector_id: int | None, user_id: str | None,
    supporting_systems: list[dict],
) -> dict[str, Any]:
    """ the main function here — gathers everything about the
    chosen asset (its name, its sector, and every supporting system it has)
    into one bundle, which is used both to show the user a summary and to feed
    the AI prompts later. The supporting-system details themselves are supplied
    directly by the UI (`supporting_systems`) and validated against the real DB
    separately, by `validate_ui_supplied_context`.

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
        select(m.ctm_scan_entity.c.id, m.ctm_scan_entity.c.name, m.ctm_scan_entity.c.criticality,
              m.ctm_scan_entity.c.description, m.ctm_scan_entity.c.data_handled,
              m.ctm_scan_entity.c.tier1_critical_service_id)
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

    # The UI supplies the supporting-system list directly now (validated separately by
    # validate_ui_supplied_context) — this is a pass-through, not a DB join.
    #
    # Supporting systems (UI-supplied) → SubsystemsJSON (NOT NULL, must be populated).
    subsystems = [
        {
            "id": s["id"],
            "name": s.get("name"),
            "exposure_level": _guess_if_internet_facing(s.get("hosting_environment")),
            "criticality": asset["criticality"],  # [R12] scoping input — stays even though it's dropped from the AI-prompt allowlist
            "asset_type": s.get("asset_type"),
            "accessibility_channel": s.get("accessibility_channel"),
            "system_managed_by": s.get("system_managed_by"),
            "hosting_environment": s.get("hosting_environment"),
            "data_residency": s.get("data_residency"),
            "past_incidents": s.get("past_incidents"),
        }
        for s in supporting_systems
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


def _check(mismatches: list[dict], field: str, expected: Any, got: Any) -> None:
    """Shared null-rule comparator every scalar/lookup check in
    validate_ui_supplied_context goes through, so the rule is defined once: both
    "not set" (expected AND got are None) is OK; anything else that differs is a
    mismatch — collected, never raised immediately (callers raise once at the end)."""
    if expected is None and got is None:
        return
    if expected != got:
        mismatches.append({"field": field, "expected": expected, "got": got})


def validate_ui_supplied_context(
    sess: Session, *, asset_row: Mapping[str, Any], sector_row: Mapping[str, Any] | None,
    parent_sector_row: Mapping[str, Any] | None, supporting_systems: list[dict],
    body: "CreateSessionBody",
) -> None:
    """ double-checks every piece of context the UI sent along with
    the session-creation request against the platform's own real data, and rejects
    the whole request (collecting every mismatch, not just the first) if anything
    doesn't line up.

    Stage-0 UI-context validation (13-field mapping): fetch phase is a SMALL FIXED
    number of batched queries (independent of how many supporting systems are in the
    request), then a pure-Python compare phase against the DB null rule (`_check`).
    Called from `create_session` right after `gather_asset_details`, in the SAME
    sess/transaction — `asset_row`/`sector_row`/`parent_sector_row` are exactly what
    `gather_asset_details` already fetched, reused here rather than re-queried.
    """
    mismatches: list[dict] = []

    # --- fetch phase (batched, fixed query count) ---
    service_name = None
    tier1_id = asset_row.get("tier1_critical_service_id")
    if tier1_id is not None:
        service_name = sess.execute(
            select(m.onboarding_services.c.name).where(m.onboarding_services.c.id == tier1_id)
        ).scalar()

    ss_ids = [s["id"] for s in supporting_systems]
    ss_rows: dict[int, Mapping[str, Any]] = {}
    if ss_ids:
        # Scope to the requested asset via ctm_scan_entity_supporting_system — without this
        # join, a caller authorized for their own asset could pass another entity's
        # supporting-system id and have its real DB row (name, incident history,
        # data-residency flag, ...) echoed back as "expected" in the 422 mismatch body.
        ss_rows = {
            r["id"]: r for r in sess.execute(
                select(m.onboarding_supporting_systems)
                .join(m.ctm_scan_entity_supporting_system,
                      m.ctm_scan_entity_supporting_system.c.onboarding_supporting_system_id
                      == m.onboarding_supporting_systems.c.id)
                .where(
                    m.ctm_scan_entity_supporting_system.c.ctm_scan_entity_id == asset_row.get("id"),
                    m.onboarding_supporting_systems.c.id.in_(ss_ids),
                )
            ).mappings()
        }

    option_rows = sess.execute(
        select(m.option_value.c.option_id, m.option_value.c.value, m.option_value.c.name)
        .where(m.option_value.c.option_id.in_([_OPTION_ACCESSIBILITY_CHANNEL, _OPTION_HOSTING_ENVIRONMENT]))
    ).mappings()
    option_lookup = {(r["option_id"], r["value"]): r["name"] for r in option_rows}

    managed_by_values = {s["system_managed_by"] for s in supporting_systems if s.get("system_managed_by")}
    matched_managed_by: set[str] = set()
    if managed_by_values:
        lowered = {v.lower() for v in managed_by_values}
        user_rows = sess.execute(
            select(m.user.c.username, m.user.c.email, m.user.c.name, m.user.c.surname).where(
                or_(
                    func.lower(m.user.c.username).in_(lowered),
                    func.lower(m.user.c.email).in_(lowered),
                    func.lower(m.user.c.name + " " + m.user.c.surname).in_(lowered),
                )
            )
        ).mappings()
        for r in user_rows:
            for candidate in (r["username"], r["email"],
                              f"{r['name']} {r['surname']}" if r["name"] and r["surname"] else None):
                if candidate:
                    matched_managed_by.add(candidate.lower())

    # --- compare phase (pure Python, no further IO) ---
    _check(mismatches, "cii_asset_description", asset_row.get("description"), body.cii_asset_description)
    _check(mismatches, "data_handled", asset_row.get("data_handled"), body.data_handled)
    _check(mismatches, "critical_service", service_name, body.critical_service)

    # Sector edge case: sector_id IS the sub-sector/leaf. If it has no parent, it
    # represents a top-level sector with no leaf — compare `sector` directly against
    # its own name, and `sub_sector` must be absent (nothing to compare it against).
    if sector_row is None:
        expected_sector = expected_sub_sector = None
    elif parent_sector_row is not None:
        expected_sector = parent_sector_row.get("name")
        expected_sub_sector = sector_row.get("name")
    else:
        expected_sector = sector_row.get("name")
        expected_sub_sector = None
    _check(mismatches, "sector", expected_sector, body.sector)
    _check(mismatches, "sub_sector", expected_sub_sector, body.sub_sector)

    for ui_sys in supporting_systems:
        ssid = ui_sys["id"]
        row = ss_rows.get(ssid)
        if row is None:
            mismatches.append({"field": f"supporting_systems[{ssid}]",
                               "expected": "exists in onboarding_supporting_systems", "got": "not found"})
            continue
        _check(mismatches, f"supporting_systems[{ssid}].name", row.get("name"), ui_sys.get("name"))
        _check(mismatches, f"supporting_systems[{ssid}].past_incidents",
               row.get("incident_description"), ui_sys.get("past_incidents"))
        db_residency = None if row.get("data_residency_restrictions") is None else bool(row["data_residency_restrictions"])
        _check(mismatches, f"supporting_systems[{ssid}].data_residency", db_residency, ui_sys.get("data_residency"))
        _check(mismatches, f"supporting_systems[{ssid}].asset_type", row.get("asset_type"), ui_sys.get("asset_type"))

        expected_access = (option_lookup.get((_OPTION_ACCESSIBILITY_CHANNEL, row["accessability_channel"]))
                           if row.get("accessability_channel") is not None else None)
        _check(mismatches, f"supporting_systems[{ssid}].accessibility_channel",
               expected_access, ui_sys.get("accessibility_channel"))

        expected_hosting = (option_lookup.get((_OPTION_HOSTING_ENVIRONMENT, row["hosting_location"]))
                            if row.get("hosting_location") is not None else None)
        _check(mismatches, f"supporting_systems[{ssid}].hosting_environment",
               expected_hosting, ui_sys.get("hosting_environment"))

        managed_by = ui_sys.get("system_managed_by")
        if managed_by and managed_by.lower() not in matched_managed_by:
            mismatches.append({"field": f"supporting_systems[{ssid}].system_managed_by",
                               "expected": "an existing dbo.user (username/email/name surname)", "got": managed_by})

    if mismatches:
        raise ContextMismatchError(mismatches)
