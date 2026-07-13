"""Drop three write-only/dead columns confirmed by full-repo grep + read
(2026-07-09 dead-column cleanup).

Adversarial re-verification (independent grep of app/, tests/, migrations/,
scripts/, docs/, documents/ -- every call site read in full, not just grep
hits) confirmed these three columns are never read anywhere and never
written on the table below:

- `Scenario_Session.ActiveTaskID` -- every real ActiveTaskID write/read in
  the repo (`app/db/dal.py:311,317,353,379,383,418`; `app/pipeline/reaper.py:126`)
  targets `Subsystem_Stage_State`, never `Scenario_Session`.
  `create_session`'s values dict (`app/api/sessions.py:139-148`) omits it.
  Zero `session["ActiveTaskID"]` access anywhere, including every consumer
  of `get_authorized_session()`'s full-row dict. Corroborated by
  `documents/handbooks/04-database-data-layer.md:260` ("Dead column...
  always NULL").
- `Scenario_Session.ErrorMessage` -- all 4 real ErrorMessage write sites
  (`dal.py:421,505`; `reaper.py:222`; `tasks.py:424`) target
  `Subsystem_Stage_State`; the one `Threat_Scenario_Output` insert
  (`tasks.py:379`) sets it to `None`. Zero writes/reads against
  `Scenario_Session.ErrorMessage`. Corroborated by handbook line 261.
- `Scenario_Audit.TaskID` -- all 12 `append_audit()` call sites checked in
  full; none passes `TaskID=`. `Scenario_Audit` has no whole-row select
  anywhere in the repo, so unlike the two columns above this doesn't even
  touch a live `SELECT *`-style statement. Corroborated by handbook line 406.

None of the three is part of any index or constraint (re-confirmed against
`scripts/bootstrap_schema.sql` and every migration, including 0022 which
just retyped `Scenario_Session.ActiveTaskID` and `Scenario_Audit.TaskID`
nvarchar(36) -> uniqueidentifier as DDL type-maintenance only -- that
retyping doesn't refute dead status). So each drop below is a plain
`ALTER TABLE ... DROP COLUMN`, no index/constraint teardown needed.

`app/db/models.py` has the corresponding `Column(...)` declarations removed
in this same change -- `dal.load_session`/`get_session`/
`latest_completed_session` do `select(m.Scenario_Session)` (whole-row),
which SQLAlchemy Core expands to every column `models.py` declares, so the
model and the DB schema must drop in the same deploy or session loads throw
"Invalid column name" in production.

Revision ID: 0023
Revises: 0022
"""
from alembic import op

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session DROP COLUMN ActiveTaskID")
    op.execute("ALTER TABLE Scenario_Session DROP COLUMN ErrorMessage")
    op.execute("ALTER TABLE Scenario_Audit DROP COLUMN TaskID")


def downgrade() -> None:
    op.execute("ALTER TABLE Scenario_Session ADD ActiveTaskID uniqueidentifier NULL")
    op.execute("ALTER TABLE Scenario_Session ADD ErrorMessage nvarchar(max) NULL")
    op.execute("ALTER TABLE Scenario_Audit ADD TaskID uniqueidentifier NULL")
