"""CHECK constraint on Scenario_Session.SessionStatus (INV-5).

Three filtered indexes (`UX_Session_ActiveAsset` (0004), `IX_Session_Active` (0009),
`IX_Session_CompletedByAsset` (0024)) each hardcode a raw string literal ('active'/
'completed') in their WHERE clause against this column, with nothing in the database
tying that literal to the SessionStatus enum (app/core/enums.py) it's meant to track —
a bad/typo'd status value written by any future code path was previously accepted
silently. This migration adds a real DB-enforced CHECK restricting the column to the
enum's exact current members.

This constraint does NOT by itself catch a future *rename* of one of those enum values —
the constraint's literal set has to be updated by hand alongside any such rename, same as
the 3 filtered indexes' own hardcoded literals. What closes that drift is the new
`invariants._assert_filtered_index_literals` boot check, which cross-checks each filtered
index's stored `filter_definition` text against the live SessionStatus enum values every
time the app boots — this constraint and that check are two halves of the same fix.

Revision ID: 0025
Revises: 0024
"""
from alembic import op

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "IF NOT EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Session_Status') "
        "ALTER TABLE Scenario_Session ADD CONSTRAINT CK_Session_Status "
        "CHECK (SessionStatus IN ('active', 'completed', 'cancelled'))"
    )


def downgrade() -> None:
    op.execute(
        "IF EXISTS (SELECT 1 FROM sys.check_constraints WHERE name = 'CK_Session_Status') "
        "ALTER TABLE Scenario_Session DROP CONSTRAINT CK_Session_Status"
    )
