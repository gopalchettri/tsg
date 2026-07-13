-- ============================================================================
-- TSG — add asset/subsystem-level columns to 2 platform tables app code
-- reads (ctm_scan_entity, onboarding_supporting_systems).
--
-- Why: app/db/models.py declares these as real mapped columns, and
-- app/pipeline/context.py's asset/subsystem lookups (used on every
-- POST /v1/sessions) explicitly SELECT them — without them the app fails
-- with "Msg 207 ... Invalid column name" on the very first real session
-- creation against a database missing them.
--
-- ctm_scan_entity/onboarding_supporting_systems are PLATFORM tables TSG
-- reuses but never creates (SDD §7.7) — these columns were added out-of-band
-- on specific databases at different points in this engagement and never
-- propagated to every database, since no TSG migration or bootstrap script
-- tracks platform-table schema. This script is that missing, explicit,
-- reviewable step, kept current as context.py's column set grows.
--
-- Types match app/db/models.py exactly. data_handled/system_managed_by
-- (original 2, ctm_scan_entity) predate this session; left exactly as
-- originally shipped rather than retyped to match the newer additions'
-- convention below, to avoid an unreviewed change on a column some database
-- already has. operating_system/location/target_rto_hours/target_rpo_hours
-- (ctm_scan_entity) and technology_used/vendor_name/database_platforms
-- (onboarding_supporting_systems) are new this session — UnicodeText uses
-- nvarchar(max) (confirmed via live INFORMATION_SCHEMA against the real DB:
-- every UnicodeText column in this schema is nvarchar(max), never the
-- deprecated ntext data_handled happened to ship with earlier). All nullable
-- (models.py declares none NOT NULL), so every ADD here is safe/non-breaking
-- on a table that may already have rows.
--
-- Contract (same as every other script in this folder): idempotent
-- (IF COL_LENGTH ... IS NULL guards, safe to re-run), touches only these
-- columns, never drops or modifies anything else.
--
-- Run with SSMS or sqlcmd against whichever database you're standing up
-- (same database bootstrap_schema.sql targets) — before real session
-- creation, and before backfill_null_platform_fields_for_testing.sql if
-- you're also running that for local testing.
-- ============================================================================

IF OBJECT_ID('dbo.ctm_scan_entity', 'U') IS NOT NULL
BEGIN
    IF COL_LENGTH('dbo.ctm_scan_entity', 'data_handled') IS NULL
        ALTER TABLE ctm_scan_entity ADD data_handled ntext NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'system_managed_by') IS NULL
        ALTER TABLE ctm_scan_entity ADD system_managed_by nvarchar(100) NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'operating_system') IS NULL
        ALTER TABLE ctm_scan_entity ADD operating_system nvarchar(200) NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'location') IS NULL
        ALTER TABLE ctm_scan_entity ADD location nvarchar(200) NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'target_rto_hours') IS NULL
        ALTER TABLE ctm_scan_entity ADD target_rto_hours int NULL;
    IF COL_LENGTH('dbo.ctm_scan_entity', 'target_rpo_hours') IS NULL
        ALTER TABLE ctm_scan_entity ADD target_rpo_hours int NULL;
END

IF OBJECT_ID('dbo.onboarding_supporting_systems', 'U') IS NOT NULL
BEGIN
    IF COL_LENGTH('dbo.onboarding_supporting_systems', 'technology_used') IS NULL
        ALTER TABLE onboarding_supporting_systems ADD technology_used nvarchar(max) NULL;
    IF COL_LENGTH('dbo.onboarding_supporting_systems', 'vendor_name') IS NULL
        ALTER TABLE onboarding_supporting_systems ADD vendor_name nvarchar(200) NULL;
    IF COL_LENGTH('dbo.onboarding_supporting_systems', 'database_platforms') IS NULL
        ALTER TABLE onboarding_supporting_systems ADD database_platforms nvarchar(300) NULL;
END

-- Verify
SELECT TABLE_NAME, COLUMN_NAME, DATA_TYPE, IS_NULLABLE
FROM INFORMATION_SCHEMA.COLUMNS
WHERE (TABLE_NAME = 'ctm_scan_entity' AND COLUMN_NAME IN
        ('data_handled', 'system_managed_by', 'operating_system', 'location', 'target_rto_hours', 'target_rpo_hours'))
   OR (TABLE_NAME = 'onboarding_supporting_systems' AND COLUMN_NAME IN
        ('technology_used', 'vendor_name', 'database_platforms'))
ORDER BY TABLE_NAME, COLUMN_NAME;
