"""Retired feature symbols must never come back as CODE.

Config_Threat_Rule and its rule engine were removed 2026-08 (silent-omission gating), and the
IsUniversal column was withdrawn the same week (the master tables are frozen). Prose may still
mention them as history — that is fine and deliberate. What must never happen is the symbols
reappearing as *identifiers*: the realistic vector is a merge from a pre-removal branch quietly
restoring an import, a model class, or a call site, which would ship half a resurrected feature
with no reviewer noticing.

Checked at the AST level, so docstrings and comments are naturally exempt: only actual names,
attributes, argument names, and import targets count.
"""
from __future__ import annotations

import ast
from pathlib import Path

_APP = Path(__file__).resolve().parents[1] / "app"

_RETIRED = {
    "Config_Threat_Rule",
    "ThreatRuleType",
    "active_threat_rules",
    "upsert_threat_rule",
    "apply_ot_rules",
    "_apply_rules",
    "gate_matching_subsystems",
    "_RULE_KEY_FIELDS",
    "IsUniversal",              # withdrawn column (frozen master tables)
    # threat_retrieval_top_k: DELIBERATELY REINTRODUCED by the library-first rerank-gate
    # redesign (docs/TSG_LibraryFirst_ThreatIdentification_Plan.md). The old symbol was an
    # unused eligibility cap; the new one is the Top-K pool bound that keeps the relevance
    # gate constant-cost as the catalogue grows — removed from this tripwire per its own
    # instructions above.
    "universal_threat_families",  # the old cap's exemption list, still retired
    "default_rule_weight",
    "auto_ot_relevance_weight",
    "ThreatRuleCreate",
    "ThreatRuleUpdate",
    "ThreatRuleRow",
    # --- 2026-08 sector retirement (survives the 2026-08-28 catalogue return) ---
    "SectorID",                   # sector logic removed; the frozen columns stay unmapped
    "visible_to_this_sector",
    "how_specific_is_this_sector",
    # NOTE: the Threat_Catalogue family (Threat_Catalogue, ThreatCatalogueID, catalogue_id,
    # upsert_threat_catalogue, find_catalogue_id_by_norm_name, both junction maps,
    # link_type_actor, link_catalogue_category) was REMOVED from this list 2026-08-28: the
    # user reverted the crm_threat_risk_register interlude and the catalogue is the live
    # library again. The register-era symbols below replace them.
    # --- 2026-08-28 crm register reversal ---
    "crm_threat_risk_register",
    "crm_threat_risk_register_threat_actor",
    "crm_threat_risk_register_control",
    "crm_threat_risk_register_category",
    "crm_risk_category",
    "crm_theme",
    "crm_threat_actor",
    "ThreatRiskRegisterID",
    "insert_register_threat",
    "register_actor_pairs",
    "register_display_map",
    "register_threat_active",
    "register_rows_active",
    "categories_for_register_threats",
    "find_register_threat_id_by_norm_name",
    "_next_register_code",
    "register_passage_text",
    "get_possible_themes",
    "link_register_actor",
    "link_register_control",
    "run_promotion_phase",        # accept only ACCEPTS; the promote API is the sole writer
    "_pick_sector_for_promotion",
    "resolve_candidate",
    "Threat_Candidate_Review",
    "CandidateStatus",
    "CandidateKind",
    "TriageVerdict",
    "RetryOutcome",
    "retry_one_promotion",
    "retry_failed_promotions",
    "dismiss_promotion",
    "stamp_promotion_failure",
    "clear_promotion_failure",
    "promotion_auto_approve_enabled",
    "library_promotion_threshold",
    "triage_auto_reject_cosine",
    "triage_auto_approve_cosine",
    "Threat_Library_Import_Run",  # bulk importer retired with the catalogue
    "threat_library_import_max_upload_mb",
}


def _identifiers(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            yield node.id, node.lineno
        elif isinstance(node, ast.Attribute):
            yield node.attr, node.lineno
        elif isinstance(node, ast.arg):
            yield node.arg, node.lineno
        elif isinstance(node, ast.alias):
            yield node.name.split(".")[-1], getattr(node, "lineno", 0)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name, node.lineno
        elif isinstance(node, ast.keyword) and node.arg:
            yield node.arg, getattr(node.value, "lineno", 0)


def test_retired_symbols_never_reappear_as_code() -> None:
    offenders = []
    for py in sorted(_APP.rglob("*.py")):
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
        for name, lineno in _identifiers(tree):
            if name in _RETIRED:
                offenders.append(f"{py.relative_to(_APP.parent)}:{lineno}: {name}")
    assert not offenders, (
        "retired feature symbols used as CODE again — if this is a merge from an old branch, "
        "the removal must win; if the feature is being deliberately reintroduced, delete it "
        "from _RETIRED with a rationale:\n  " + "\n  ".join(offenders))

