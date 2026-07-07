"""M8 — Scenario_Session.IdempotencyKey (dedup POST /v1/sessions) + IX_Session_Active
(cheap index-only-scan COUNT for the admission-control backpressure ceiling)

Revision ID: 0009
Revises: 0008
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session ADD IdempotencyKey nvarchar(200) NULL")
    op.execute(
        "CREATE UNIQUE INDEX UX_Session_IdempotencyKey ON Scenario_Session(EntityID, IdempotencyKey) "
        "WHERE IdempotencyKey IS NOT NULL"
    )
    op.execute(
        "CREATE NONCLUSTERED INDEX IX_Session_Active ON Scenario_Session(SessionStatus) "
        "WHERE SessionStatus = 'active'"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IX_Session_Active ON Scenario_Session")
    op.execute("DROP INDEX UX_Session_IdempotencyKey ON Scenario_Session")
    op.execute("ALTER TABLE Scenario_Session DROP COLUMN IdempotencyKey")
