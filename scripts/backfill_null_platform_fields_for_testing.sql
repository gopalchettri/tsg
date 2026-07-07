-- ============================================================================
-- TSG backfill — DEWA-Dubai OT test scenario for local POST /v1/sessions testing.
--
-- Why: app.pipeline.context.validate_ui_supplied_context (new validation layer)
-- checks every UI-supplied field against real DB rows. ctm_scan_entity.data_handled,
-- ctm_scan_entity.tier1_critical_service_id, and onboarding_supporting_systems.
-- incident_description are NULL on every row in this dev DB today — no payload
-- can supply non-null values for them without failing validation.
--
-- Theme, and why this asset: this dev DB already has REAL, already-seeded DEWA
-- (Dubai Electricity & Water Authority) OT/CII assets (ids 5-11) — nothing about
-- the DEWA theme is invented, just chosen. Asset id 7, "Power Transmission &
-- Substation Automation System (PTAS)", is used here: its existing description
-- ("substations, protection relays, breakers, transformers, switchgear,
-- SCADA/RTU/IED communications, ... grid stability support") is textbook OT/ICS
-- and it has the richest linked supporting-system set (5 systems: ICS, OT Telecom
-- Network, Remote Terminal Units, SCADA System, SCMS) of any DEWA asset in this DB.
-- Sector: Energy (id 1) / Electricity (id 12) -- an exact, unforced fit.
--
-- Known imperfection, flagged rather than hidden: no onboarding_services row in
-- this DB precisely represents "power transmission / grid operations" (checked
-- all 58 rows). "Solar power generation" (id 7, sector 12 Electricity) is the
-- closest real, valid option -- a generation-side service standing in for a
-- transmission-side asset. If a more precise service is added to onboarding_services
-- later, swap tier1_critical_service_id below and the "critical_service" text in
-- your test payload to match.
--
-- Contract (same as scripts/bootstrap_schema.sql): idempotent (WHERE ... IS NULL
-- guards, safe to re-run), never touches any other row, never drops anything.
-- Read this before running -- this touches platform-owned tables (app/db/models.py
-- marks them read-only to the app; this script is the documented out-of-band path
-- for hand-editing them on your own local/dev instance, same convention as
-- bootstrap_schema.sql).
--
-- Run with SSMS or sqlcmd against your local dev DB only (per .env, APP_ENV=dev,
-- Trusted_Connection, SQLEXPRESS -- not shared production).
-- ============================================================================

UPDATE ctm_scan_entity
SET data_handled = 'Substation telemetry (voltage, current, breaker/switch status), protection-relay event logs, SCADA/RTU/IED control commands and setpoints, grid topology and switching-state data, engineering-workstation and HMI operator credentials',
    tier1_critical_service_id = 7  -- FK to onboarding_services.id = "Solar power generation" -- closest real match, see note above
WHERE id = 7
  AND data_handled IS NULL
  AND tier1_critical_service_id IS NULL;

UPDATE onboarding_supporting_systems
SET incident_description = 'Unauthorized configuration change detected on an engineering workstation during a scheduled maintenance window, 2024-06-14; confirmed accidental misconfiguration by an authorized technician, no operational impact, access controls tightened afterward.'
WHERE id = 1003 AND incident_description IS NULL;  -- ICS

UPDATE onboarding_supporting_systems
SET incident_description = 'Intermittent packet loss on the OT telecom backhaul link between two substations, 2024-09-02, degraded SCADA polling cycle for approximately 40 minutes; resolved by failover to the redundant fiber path.'
WHERE id = 1004 AND incident_description IS NULL;  -- OT Telecom Network

UPDATE onboarding_supporting_systems
SET incident_description = 'Firmware anomaly on a field RTU caused delayed status reporting from a remote switchgear site, 2025-01-20; RTU firmware rolled back to the last known-good version, normal reporting restored within 2 hours.'
WHERE id = 1005 AND incident_description IS NULL;  -- Remote Terminal Units

UPDATE onboarding_supporting_systems
SET incident_description = 'Brief SCADA HMI unavailability during a planned server patch cycle, 2024-11-11; control handed to local manual mode at the affected substation for 25 minutes per standard operating procedure, no unplanned outage.'
WHERE id = 1006 AND incident_description IS NULL;  -- SCADA System

UPDATE onboarding_supporting_systems
SET incident_description = 'False-positive alarm storm from the substation control management system following sensor calibration drift, 2025-02-05; affected sensors recalibrated, alarm thresholds reviewed and adjusted.'
WHERE id = 1007 AND incident_description IS NULL;  -- SCMS

-- Verify
SELECT id, name, data_handled, tier1_critical_service_id FROM ctm_scan_entity WHERE id = 7;
SELECT id, name, incident_description FROM onboarding_supporting_systems WHERE id IN (1003, 1004, 1005, 1006, 1007);
