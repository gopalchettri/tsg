"""Rename five AuditEventType values to self-explanatory names (2026-07-03 clarity fix).

`stage_decision`/`stage1_accepted`/`stage3_accepted`/`cascade_hop`/`cascade_regenerated` were
too abstract to understand at a glance — renamed in code to `review_decision`/
`profiles_accepted`/`scenarios_accepted`/`regeneration_completed`/`threat_regrounded`. Since
the enum's contract is "member value == the exact string in Scenario_Audit.EventType", the
rename must reach existing rows too, or the DB and the code disagree. Deliberate one-time
UPDATE, not a violation of the append-only audit convention (which governs application
writes, not pre-production schema/vocabulary corrections) — done now because production
doesn't exist yet (only this environment's dev rows carry the old strings), and because M10
will make this table WORM, after which such a correction would no longer be possible.

Revision ID: 0017
Revises: 0016
"""
from alembic import op

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

_RENAMES = [
    ("stage_decision", "review_decision"),
    ("stage1_accepted", "profiles_accepted"),
    ("stage3_accepted", "scenarios_accepted"),
    ("cascade_hop", "regeneration_completed"),
    ("cascade_regenerated", "threat_regrounded"),
]


def upgrade() -> None:
    for old, new in _RENAMES:
        op.execute(f"UPDATE Scenario_Audit SET EventType = '{new}' WHERE EventType = '{old}'")


def downgrade() -> None:
    for old, new in _RENAMES:
        op.execute(f"UPDATE Scenario_Audit SET EventType = '{old}' WHERE EventType = '{new}'")
