"""0019 — rebuild guard indexes whose SHAPE has drifted from what the code needs.

WHY THIS EXISTS: every guard index up to now was created by a plain
`CREATE UNIQUE INDEX` (0004/0005/0006/0010) or by scripts/bootstrap_schema.sql's
`IF NOT EXISTS (... WHERE name = '<name>')` guard. Both only ever reasoned about
the index NAME. An index carrying a required name but built over the wrong
columns — by hand, or against an externally-seeded threat library whose category
column is called `ThreatCategoryID` rather than `PrimaryThreatCategoryID` —
therefore survives every re-run of every script forever: bootstrap sees the name
and skips, the migration would only ever try to create a name that is already
taken. Meanwhile it enforces a rule the application never asked for, so the
duplicate-master race `dal.upsert_threat_*` deliberately loses (R10) is not
actually guarded, and `invariants.verify_startup` now (correctly) refuses to
boot the API and the Celery worker against it.

This migration is the repair: it reads the live catalogue through the SAME
function the boot check uses (`invariants.read_index_catalog`), compares it
against the SAME specs (`invariants.REQUIRED_INDEXES`), and rebuilds anything
that does not line up from `IndexSpec.ddl()` — so a repaired database is
correct by exactly the definition boot is about to test it against, with no
second copy of the DDL that could drift again.

Re-runnable in effect: on a database whose indexes are already right it finds no
drift and executes no DDL at all.

SAFETY: dropping the wrong index and creating the right one happens inside
alembic's transaction, and SQL Server DDL is transactional — so if the correct
UNIQUE index cannot be built because the drifted one had been letting duplicate
rows in, the whole migration rolls back and the database is left exactly as it
was, with an error naming the index and the duplicates to clean up first.

Revision ID: 0019
Revises: 0018
"""
from alembic import op

from app.db.invariants import IndexSpec, diff_index_catalog, read_index_catalog

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None

# Columns the natural-key guards are keyed on that a PRE-EXISTING threat library
# can predate. The master tables are seeded externally (SDD §7.7) — TSG creates
# them only when they are absent, so a deployment that already had its own
# Threat_Type/Threat_Catalogue never received these columns from any script, and
# rebuilding the natural-key index would fail with "Invalid column name" before
# it ever got to the real work. Adding a NULLable column is additive: no existing
# row changes, and re-running is a no-op.
_REQUIRED_MASTER_COLUMNS = [
    ("Threat_Type", "PrimaryThreatCategoryID", "int NULL"),
    ("Threat_Type", "SectorID", "int NULL"),
    ("Threat_Catalogue", "SectorID", "int NULL"),
]


def plan_repair(bind) -> list[tuple[IndexSpec, list[str]]]:
    """Work out — without executing anything — exactly what has to happen to bring
    every guard index to the shape `invariants.REQUIRED_INDEXES` declares.

    Returns `(spec, [statements])` per index needing work, so the decision can be
    tested against a real (drifted) database without a SQL Server to run it on,
    and so an operator can see the plan before it runs.
    """
    drift = diff_index_catalog(read_index_catalog(bind))
    plan: list[tuple[IndexSpec, list[str]]] = []
    for spec, found in drift.wrong_shape:
        # `found` can name more than one table: an index name is unique only
        # per-table in SQL Server, so the required name may be sitting on the
        # wrong table entirely while the right table has nothing at all.
        plan.append((spec, [f"DROP INDEX {spec.name} ON {live.table}" for live in found] + [spec.ddl()]))
    for spec in drift.not_unique:
        plan.append((spec, [f"DROP INDEX {spec.name} ON {spec.table}", spec.ddl()]))
    for spec in drift.missing:
        plan.append((spec, [spec.ddl()]))
    return plan


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "mssql":
        return  # SQLite dev/test databases build their indexes in tests/conftest.py

    for table, column, coltype in _REQUIRED_MASTER_COLUMNS:
        op.execute(
            f"IF COL_LENGTH('dbo.{table}', '{column}') IS NULL "
            f"ALTER TABLE {table} ADD {column} {coltype}"
        )

    for spec, statements in plan_repair(bind):
        for statement in statements:
            try:
                op.execute(statement)
            except Exception as exc:  # noqa: BLE001 — re-raised immediately, just annotated
                raise RuntimeError(
                    f"could not rebuild {spec.name} as {spec.describe()}: the database already "
                    f"holds rows that violate it (the drifted index it replaces was not enforcing "
                    f"this rule). De-duplicate {spec.table} on ({', '.join(spec.columns)}) — where "
                    f"the index is filtered, soft-deleting the losers with IsDeleted = 1 is enough "
                    f"— then re-run this migration."
                ) from exc


def downgrade() -> None:
    """No-op on purpose. This migration does not add a feature to undo — it
    replaces broken indexes with correct ones. Reinstating the broken shape is
    not a state any code supports, and 0010/0006/0005/0004's own downgrades
    still drop these indexes if a full unwind is what is wanted."""
