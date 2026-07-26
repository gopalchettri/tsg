"""Config_Threat_Rule: ThreatRuleID -> IDENTITY + natural-key unique index.

The threat-library import (CLI + POST /v1/tsg/threat-library/import) now auto-writes
boost-only rules via dal.upsert_threat_rule, which relies on (a) the DB assigning ids
(no application-side MAX+1 arithmetic — two concurrent imports must not race an id) and
(b) UX_ConfigThreatRule_NaturalKey turning a concurrent/redelivered duplicate into a
catchable IntegrityError. Without (b), a redelivered import would slip a second
identical relevance_flag row in and scoping._apply_rules — which sums fired rule
weights additively — would silently DOUBLE that threat's score boost.

MSSQL cannot ALTER COLUMN an existing column into IDENTITY (engine limitation, unlike
0022's type-only changes), so an existing table is genuinely recreated: rename old,
create new with IDENTITY(22,1), copy rows under IDENTITY_INSERT (SQL Server auto-bumps
the seed past the max copied id), drop old. Curator-seeded rows 1-21 keep their ids
exactly. Guarded like 0015/0016: a fresh DB (no table) gets the full new shape; a DB
already converted is a no-op.

A duplicate-rows pre-check fails LOUD before any change: the unique index cannot be
created over existing duplicate active rows, and curator data is never auto-deleted by
a migration — the error names the situation for a human to resolve.

Revision ID: 0027
Revises: 0026
"""
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
IF OBJECT_ID('dbo.Config_Threat_Rule', 'U') IS NULL
BEGIN
    CREATE TABLE Config_Threat_Rule (
        ThreatRuleID  int            IDENTITY(22,1) NOT NULL CONSTRAINT PK_Config_Threat_Rule PRIMARY KEY,
        RuleType      nvarchar(50)   NOT NULL,
        ThreatTypeID  int            NOT NULL,
        RuleKey       nvarchar(200)  NOT NULL,
        RuleValue     nvarchar(450)  NULL,
        Metadata      nvarchar(max)  NULL,
        CreateDate    datetime2      NULL,
        CreatedBy     nvarchar(200)  NULL,
        UpdateDate    datetime2      NULL,
        UpdatedBy     nvarchar(200)  NULL,
        IsActive      bit            NOT NULL,
        IsDeleted     bit            NOT NULL
    );
END
ELSE IF COLUMNPROPERTY(OBJECT_ID('dbo.Config_Threat_Rule'), 'ThreatRuleID', 'IsIdentity') = 0
BEGIN
    -- Fail loud BEFORE touching anything if duplicate active natural keys already exist:
    -- the unique index below could not be created, and deleting curator rows is not a
    -- decision a migration may make.
    IF EXISTS (
        SELECT ThreatTypeID, RuleType, RuleKey, RuleValue
        FROM Config_Threat_Rule WHERE IsActive = 1 AND IsDeleted = 0
        GROUP BY ThreatTypeID, RuleType, RuleKey, RuleValue
        HAVING COUNT(*) > 1
    )
        THROW 50027, 'Config_Threat_Rule has duplicate active (ThreatTypeID, RuleType, RuleKey, RuleValue) rows — resolve them manually (curator data is never auto-deleted by a migration), then re-run.', 1;

    EXEC sp_rename 'dbo.PK_Config_Threat_Rule', 'PK_Config_Threat_Rule_Old';
    EXEC sp_rename 'dbo.Config_Threat_Rule', 'Config_Threat_Rule_Old';

    CREATE TABLE Config_Threat_Rule (
        ThreatRuleID  int            IDENTITY(22,1) NOT NULL CONSTRAINT PK_Config_Threat_Rule PRIMARY KEY,
        RuleType      nvarchar(50)   NOT NULL,
        ThreatTypeID  int            NOT NULL,
        RuleKey       nvarchar(200)  NOT NULL,
        RuleValue     nvarchar(450)  NULL,
        Metadata      nvarchar(max)  NULL,
        CreateDate    datetime2      NULL,
        CreatedBy     nvarchar(200)  NULL,
        UpdateDate    datetime2      NULL,
        UpdatedBy     nvarchar(200)  NULL,
        IsActive      bit            NOT NULL,
        IsDeleted     bit            NOT NULL
    );

    SET IDENTITY_INSERT Config_Threat_Rule ON;
    INSERT INTO Config_Threat_Rule (ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue,
                                    Metadata, CreateDate, CreatedBy, UpdateDate, UpdatedBy,
                                    IsActive, IsDeleted)
        SELECT ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue,
               Metadata, CreateDate, CreatedBy, UpdateDate, UpdatedBy,
               IsActive, IsDeleted
        FROM Config_Threat_Rule_Old;
    SET IDENTITY_INSERT Config_Threat_Rule OFF;

    DROP TABLE Config_Threat_Rule_Old;
END

IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_ConfigThreatRule_NaturalKey'
               AND object_id = OBJECT_ID('dbo.Config_Threat_Rule'))
CREATE UNIQUE INDEX UX_ConfigThreatRule_NaturalKey
    ON Config_Threat_Rule(ThreatTypeID, RuleType, RuleKey, RuleValue)
    WHERE IsActive = 1 AND IsDeleted = 0;
"""
    )


def downgrade() -> None:
    # Deliberate no-op (same discipline as 0015/0016): auto-written rules may now live in
    # the table, and un-IDENTITY-ing would require another destructive recreate for no
    # operational benefit.
    pass
