"""Delete the PROFILE stage — drop Subsystem_Profile entirely (UI now supplies
descriptive asset/subsystem context directly, DB-validated instead of AI-summarized).

Revision ID: 0019
Revises: 0018
"""
from alembic import op

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP TABLE Subsystem_Profile")  # implicitly drops UX_Profile_Active with it


def downgrade() -> None:
    op.execute(
        "CREATE TABLE Subsystem_Profile ("
        "ProfileID       nvarchar(36)  NOT NULL CONSTRAINT PK_Subsystem_Profile PRIMARY KEY, "
        "SessionID       nvarchar(36)  NOT NULL, "
        "TenantID        nvarchar(200) NULL, "
        "EntityID        nvarchar(200) NULL, "
        "SubsystemID     int           NOT NULL, "
        "ProfileJSON     nvarchar(max) NOT NULL, "
        "ValidationJSON  nvarchar(max) NULL, "
        "Accepted        int           NOT NULL, "
        "Superseded      int           NOT NULL, "
        "CreatedAt       datetime2     NULL"
        ")"
    )
    op.execute(
        "CREATE UNIQUE INDEX UX_Profile_Active ON Subsystem_Profile(SessionID, SubsystemID) "
        "WHERE Superseded = 0"
    )
