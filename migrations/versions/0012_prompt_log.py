"""Prompt_Log — one row per LLM call (SDD §8.2 prompt provenance + the dev/ops
diagnostic record for parse failures; raw model output lives here, never in the
client-visible ErrorMessage/audit/SSE channels)

Revision ID: 0012
Revises: 0011
"""
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE Prompt_Log ("
        " LogID nvarchar(36) NOT NULL PRIMARY KEY,"
        " SessionID nvarchar(36) NOT NULL,"
        " TenantID nvarchar(200) NULL,"
        " EntityID nvarchar(200) NULL,"
        " UserID nvarchar(200) NULL,"
        " SubsystemID int NOT NULL,"
        " Stage nvarchar(20) NOT NULL,"
        " PromptVersion nvarchar(20) NOT NULL,"
        " Messages nvarchar(max) NOT NULL,"
        " ResponseText nvarchar(max) NULL,"
        " Model nvarchar(200) NULL,"
        " ModelVersion nvarchar(100) NULL,"
        " ParseSucceeded bit NOT NULL,"
        " CreatedAt datetime2 NOT NULL"
        ")"
    )
    op.execute("CREATE INDEX IX_PromptLog_Session ON Prompt_Log(SessionID, SubsystemID)")


def downgrade() -> None:
    op.execute("DROP TABLE Prompt_Log")
