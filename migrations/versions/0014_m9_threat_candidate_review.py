"""M9 — Threat_Candidate_Review (SDD §5.7 step 3; unblocks R10 library promotion).

Confirmed absent from models.py/migrations/anywhere in the app before this
(ROADMAP §1 M9 row: "table doesn't exist... anywhere in the app yet") — this
migration creates the table fresh rather than re-keying a pre-existing one.

Scope note: this is an audit ledger of promotion EVENTS (one row per threat
promoted on accept), not a pending-review queue — R11's curator gate (which
would consume a pre-accept "pending" state) is a separate, not-yet-built
feature. Rows are created and immediately marked Status='accepted' within the
same accept transaction that resolves them, so no natural-key uniqueness is
enforced here: two different sessions legitimately promoting the same
proposed threat name each get their own audit row. The real concurrency-safety
guard for the underlying masters is the M2 natural-key UNIQUE indexes on
Threat_Type/Threat_Catalogue/Threat_Actor (migration 0010), which this
migration does not touch.

Revision ID: 0014
Revises: 0013
"""
from alembic import op

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "CREATE TABLE Threat_Candidate_Review ("
        "CandidateID nvarchar(36) NOT NULL PRIMARY KEY, "
        "TenantID nvarchar(200) NOT NULL, "
        "EntityID nvarchar(200) NULL, "
        "SessionID nvarchar(36) NOT NULL, "
        "ProposedCategory nvarchar(200) NOT NULL, "
        "ProposedType nvarchar(300) NOT NULL, "
        "ProposedName nvarchar(500) NOT NULL, "
        "Status nvarchar(20) NOT NULL, "
        "ThreatTypeID int NULL, "
        "ThreatCatalogueID int NULL, "
        "ReviewedBy nvarchar(200) NULL, "
        "ReviewedAt datetime2 NULL, "
        "CreatedAt datetime2 NOT NULL"
        ")"
    )


def downgrade() -> None:
    op.execute("DROP TABLE Threat_Candidate_Review")
