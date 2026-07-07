"""[R12] Config_Threat_Rule — the scoping rule-config table (SDD §5.4 / Appendix A.1).

The SDD describes this table as already part of the target platform schema, but this
environment's bootstrap-created DB (and any DB stood up by a pre-0016 bootstrap script)
doesn't have it — verified by a live INFORMATION_SCHEMA probe before this migration was
written. Guarded CREATE: a no-op wherever the table already exists (same heal-if-missing
pattern as 0015). Schema only — rules are curator-seeded config, not app-written data.

Revision ID: 0016
Revises: 0015
"""
from alembic import op

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
IF OBJECT_ID('dbo.Config_Threat_Rule', 'U') IS NULL
CREATE TABLE Config_Threat_Rule (
    ThreatRuleID  int            NOT NULL CONSTRAINT PK_Config_Threat_Rule PRIMARY KEY,
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
)"""
    )


def downgrade() -> None:
    # Deliberate no-op: on a platform-baseline DB the table pre-existed this migration,
    # and where this migration did create it, curator-entered rules may now live in it —
    # dropping would destroy config data. Same discipline as 0015's downgrade.
    pass
