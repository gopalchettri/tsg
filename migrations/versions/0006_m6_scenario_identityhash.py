"""M6 — Threat_Scenario_Output active-identity: filtered UNIQUE(SessionID, IdentityHash)
WHERE Superseded=0, replacing the bare unique that could not coexist with
multi-generation retention (§5.5/§5.8, [R3]).

Revision ID: 0006
Revises: 0005
"""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Best-effort drop of any pre-existing NON-filtered unique index on IdentityHash
    # (the bare UNIQUE(SessionID, IdentityHash) the SDD baseline described).
    op.execute(
        """
        DECLARE @sql nvarchar(max) = NULL;
        SELECT @sql = STRING_AGG('DROP INDEX ' + QUOTENAME(i.name) + ' ON dbo.Threat_Scenario_Output;', ' ')
        FROM sys.indexes i
        WHERE i.object_id = OBJECT_ID('dbo.Threat_Scenario_Output')
          AND i.is_unique = 1 AND i.is_primary_key = 0 AND i.has_filter = 0
          AND EXISTS (
            SELECT 1 FROM sys.index_columns ic
            JOIN sys.columns c ON c.object_id = ic.object_id AND c.column_id = ic.column_id
            WHERE ic.object_id = i.object_id AND ic.index_id = i.index_id AND c.name = 'IdentityHash');
        IF @sql IS NOT NULL EXEC sp_executesql @sql;
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output(SessionID, IdentityHash) "
        "WHERE Superseded = 0"
    )


def downgrade() -> None:
    op.execute("DROP INDEX UX_Scenario_ActiveIdentity ON Threat_Scenario_Output")
