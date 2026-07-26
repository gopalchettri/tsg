"""ActorType on Scenario_Audit — separate WHO PERFORMED an event from WHO IS ACCOUNTABLE.

`ActorUserID` is back-filled from Scenario_Session.UserID for worker-written rows, so every
audit row names an accountable user (dal.append_audit). That answers "who do I call about
this?", but it also means a `generation_complete` row written by a background worker minutes
later reads the session owner's name even though no human was present and the AI produced the
content — one column carrying two different meanings with no way to tell them apart.

ActorType carries the second meaning explicitly:
    user   - a human performed it (session_started, session_cancelled, the accept family)
    system - a worker/the pipeline performed it; ActorUserID names who is answerable

NULLABLE and NOT back-filled on purpose: Scenario_Audit is an append-only ledger, so rewriting
historical rows would falsify records that were true when written. A NULL here means exactly
"written before this column existed" — a fact, not a gap. New rows always carry a value.

Revision ID: 0028
Revises: 0027
"""
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Guarded ADD, same idiom as 0015/0026: a no-op on a database that already has the column,
    # so re-running against a bootstrap-created schema is safe.
    op.execute(
        "IF COL_LENGTH('dbo.Scenario_Audit', 'ActorType') IS NULL "
        "ALTER TABLE Scenario_Audit ADD ActorType nvarchar(20) NULL"
    )


def downgrade() -> None:
    # Unlike 0015/0026's no-op downgrades (those columns are baseline schema on some databases),
    # ActorType is introduced HERE and nowhere else, so dropping it cannot destroy baseline
    # schema. Guarded so a downgrade on a database that never got the column is still a no-op.
    op.execute(
        "IF COL_LENGTH('dbo.Scenario_Audit', 'ActorType') IS NOT NULL "
        "ALTER TABLE Scenario_Audit DROP COLUMN ActorType"
    )
