"""M5 — filtered UNIQUE: one active Subsystem_Profile per (session, subsystem) ([R3])

Revision ID: 0005
Revises: 0004
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE UNIQUE INDEX UX_Profile_Active ON Subsystem_Profile(SessionID, SubsystemID) "
        "WHERE Superseded = 0"
    )


def downgrade() -> None:
    op.execute("DROP INDEX UX_Profile_Active ON Subsystem_Profile")
