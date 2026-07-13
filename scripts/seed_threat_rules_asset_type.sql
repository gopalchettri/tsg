-- ============================================================================
-- TSG — seed real Config_Threat_Rule exclusion rules keyed on asset_type.
--
-- Why: app/pipeline/scoping.py's rule engine can now resolve `asset_type` as a
-- RuleKey (extended this session), but Config_Threat_Rule had zero rows for
-- ANY field before this script — nothing has ever actually been excluded.
-- This is the first real rule content in the system.
--
-- Classification basis: all 71 active Threat_Type rows were reviewed against
-- one rule — a threat is OT-equipment-specific ONLY when its own name hardwires
-- OT field equipment (SCADA, RTU, IED, protection relay/breaker) as the target,
-- so it cannot attach to a non-OT asset. Generic mechanisms (privilege
-- escalation, credential theft, log/audit gaps, DoS, tampering, spoofing) stay
-- universal even when their catalogue examples happen to be OT-flavored —
-- over-classifying as OT-only would silently hide a real threat from IT
-- systems, judged the worse error. Full classification with per-threat
-- justification was presented for review; no corrections were returned, so
-- proceeding with the original 12 OT / 59 universal split.
--
-- Effect once run: a supporting system whose asset_type resolves to anything
-- OTHER than "Operational Technology (OT)" (ctm_scan_category.id=3) stops
-- getting scenarios written for these 12 threat types — the tech_gate fails,
-- Selected=0, reason "tech_gate:asset_type failed", recorded in
-- Scoped_Threat.FactorsJSON. OT-tagged systems (the DEWA test asset's
-- supporting systems included) are completely unaffected — every rule here
-- requires the value they already have.
--
-- RuleValue is the TEXT category name, not the raw code "3" — asset_type now
-- flows through validate_ui_supplied_context/scoping as the resolved
-- ctm_scan_category.name (see Part E of this session's plan), so _matches()
-- takes its case-insensitive text branch here, not the numeric branch.
--
-- Contract (same as every other script in this folder): idempotent
-- (guarded IF NOT EXISTS per row, safe to re-run), never touches any other
-- row, never drops anything. Config_Threat_Rule is TSG's own table (not a
-- platform mirror) — still following the manual-review-then-run convention
-- since this is a real administrative write outside normal app flow.
--
-- ThreatRuleID is a plain int PK, NOT IDENTITY (app/db/models.py:239,
-- bootstrap_schema.sql Section 2 — same "curator-seeded, explicit id"
-- pattern as Threat_Category; confirmed via grep that app/ never INSERTs
-- into this table, only SELECTs it in dal.py:541, so no auto-generated-key
-- readback is ever needed). Every INSERT below must supply ThreatRuleID
-- explicitly — 1-12, matching seed order.
--
-- Run with SSMS or sqlcmd against your local dev DB.
-- ============================================================================

DECLARE @RuleValue nvarchar(450) = N'Operational Technology (OT)';
DECLARE @CreatedBy nvarchar(200) = N'seed_threat_rules_asset_type.sql';

-- ThreatRuleID 1  / ThreatTypeID 5  — Disruption of RTU availability or responsiveness
-- ThreatRuleID 2  / ThreatTypeID 9  — Exposure of sensitive RTU data
-- ThreatRuleID 3  / ThreatTypeID 15 — Identity spoofing of RTU components
-- ThreatRuleID 4  / ThreatTypeID 16 — Unauthorized modification of SCADA data or configuration
-- ThreatRuleID 5  / ThreatTypeID 20 — Unauthorized privilege escalation within RTU subsystem
-- ThreatRuleID 6  / ThreatTypeID 23 — Unauthorized access to SCADA operational or configuration information
-- ThreatRuleID 7  / ThreatTypeID 26 — Interruption or degradation of SCADA availability from internal actions or failures
-- ThreatRuleID 8  / ThreatTypeID 27 — Unauthorized privilege escalation within the internal SCADA environment
-- ThreatRuleID 9  / ThreatTypeID 28 — Unauthorized modification of RTU data or configuration
-- ThreatRuleID 10 / ThreatTypeID 54 — Device/response suppression (protection-relay/breaker communication)
-- ThreatRuleID 11 / ThreatTypeID 64 — Network-level DoS to SCADA/RTU
-- ThreatRuleID 12 / ThreatTypeID 68 — Telemetry spoofing (forged RTU/IED field telemetry)

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 5 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (1, 'tech_gate', 5, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 9 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (2, 'tech_gate', 9, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 15 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (3, 'tech_gate', 15, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 16 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (4, 'tech_gate', 16, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 20 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (5, 'tech_gate', 20, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 23 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (6, 'tech_gate', 23, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 26 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (7, 'tech_gate', 26, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 27 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (8, 'tech_gate', 27, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 28 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (9, 'tech_gate', 28, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 54 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (10, 'tech_gate', 54, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 64 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (11, 'tech_gate', 64, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

IF NOT EXISTS (SELECT 1 FROM Config_Threat_Rule WHERE ThreatTypeID = 68 AND RuleKey = 'asset_type' AND RuleType = 'tech_gate')
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, IsDeleted, CreateDate, CreatedBy)
    VALUES (12, 'tech_gate', 68, 'asset_type', @RuleValue, 1, 0, SYSUTCDATETIME(), @CreatedBy);

-- Verify
SELECT ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, IsActive, CreatedBy
FROM Config_Threat_Rule
WHERE RuleKey = 'asset_type'
ORDER BY ThreatTypeID;
