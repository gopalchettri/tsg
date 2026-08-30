# Deploying the scenario-lifecycle release

Read this before deploying. The code **cannot ship correctly without the migration**, and one part
of it is not optional in the usual sense: skipping it strands existing data permanently.

---

## What changed, in one paragraph

A TSG session used to be a single-shot funnel: generation finished, the session parked at REVIEW
holding its asset, and the *first* accept call decided every scenario at once and closed the
session. Accepting one scenario stranded the rest forever.

Now the session's job ends when **generation** ends. It completes itself at the review barrier,
which releases the asset immediately, and each scenario carries its own decision — pending,
accepted, or rejected — for as long as the reviewer needs, across days and across people.

---

## 1. Run the schema script — BEFORE deploying the code

```
scripts/TSG_Core.sql
```

Guarded and idempotent; safe to re-run. It applies:

| Object | Purpose |
|---|---|
| `Threat_Scenario_Output.RejectedAt` / `RejectedBy` | Records who declined a scenario and when |
| `CK_ScenarioOutput_DecisionExclusive` | A scenario cannot be both accepted and rejected |
| `Scenario_Audit.ScenarioID` | Which scenario a decision event is about |
| `IX_ScenarioAudit_Output` | Makes "the decision history of this scenario" a seek, not a scan |

**Customer/UAT sites provision from the mirrors instead** — `scripts/eyshield_handoff/1. TSG_Core.sql`
(install) and `TSG_Core_UAT.sql` (upgrade). Both are byte-identical to the canonical script and a
test enforces that; do not hand-edit them.

## 2. The backfill — mandatory wherever the existing data matters

**Development / a freshly created database: ignore this section.** The backfill matches zero rows
when there is nothing parked at REVIEW, and the script is safe to run either way. It stays in the
script rather than being a separate step precisely so nobody has to remember it later, when the
environment does hold data somebody cares about.

**UAT / production: this is not optional.** It runs inside the same script. Every session sitting
at `active` + `REVIEW` flips to `completed`:

```sql
UPDATE Scenario_Session
    SET SessionStatus = 'completed',
        CompletedAt   = COALESCE(CompletedAt, SYSUTCDATETIME()),
        UpdatedAt     = SYSUTCDATETIME()
WHERE SessionStatus = 'active' AND CurrentStage = 'REVIEW';
```

**Why it is not optional.** Those sessions were closed by the old accept path, which no longer
completes anything. Without the backfill nothing will ever close them: they hold their asset open
forever and block every new assessment for it. Idempotent — the WHERE matches nothing on a re-run.

## 3. Order: schema first, then code

The app asserts its required indexes and its route registry **at boot**. Deployed against an
un-migrated database it refuses to start. That is designed behaviour, not a fault — it fails
loudly at deploy rather than quietly at runtime. Migrate first and it is a non-event.

## 4. Client-visible changes

| Change | What clients must do |
|---|---|
| A session reports `SessionStatus = completed` while its scenarios still await decisions | **Do not treat `completed` as "review finished".** The status rollup reports `awaiting_review` for exactly this state — poll that. |
| Accept is repeatable | Calling accept again with different scenario ids is normal, not an error |
| New: `POST /v1/sessions/{session_id}/scenarios/reject` | Body `{"scenario_ids": [...]}`. Records a decision; does not delete anything |
| Accept's 404 body may carry `already_rejected`; reject's may carry `already_accepted` | Both are typed values in `details.unacceptable[].reason` |
| `session_entered_review` SSE event | Unchanged name. It now also means the asset has been released |

## 5. Who may decide — a deliberate decision

Entity scope is the whole authorization boundary. **Any authenticated colleague in the entity may
view, generate, regenerate, accept and reject** any assessment in it. Per-user access control was
built during development and removed on purpose: covering for a teammate is normal work, and a
second person approving a remediation plan is a requirement that owner-only access makes
impossible.

Accountability is preserved by the audit trail, not by access control — one `Scenario_Audit` row
per decided scenario naming the acting user. This is a **detective** control: a wrong decision is
attributable after the fact rather than blocked beforehand.

`tests/test_open_access.py` pins this so it is not "fixed" back as though it were an oversight. If
per-user isolation is wanted later, that is a product decision to re-make.

Authentication is **not** relaxed: every route verifies `X-API-Key` against a stored hash and
checks entity scope, and `app/api/route_audit.py` refuses to boot if any route misses that. A URL
on its own returns 401.

## 6. Verify after deploying

```bash
cd tsg && .venv/Scripts/python.exe -m pytest tests -q && .venv/Scripts/python.exe scripts/test_pipeline_guards.py
```

Then, against the deployed environment:

1. Run an assessment to completion → the session reads `completed` and the asset is free
2. Accept one scenario → the others stay `undecided`
3. Accept another → succeeds (this is the behaviour the release exists for)
4. Reject an accepted one → 404 `already_accepted`
5. `GET /v1/sessions/{id}/scenarios/{scenario_id}/treatment-plan/audit` → one row per decision,
   each naming the scenario and the person

## Rollback

The schema changes are additive and the old code ignores the new columns, so rolling the **code**
back is safe. The **backfill is not reversible** — those sessions are completed, which is the
correct end state under either version, but under the old code they can no longer be accepted.
Complete any in-flight reviews before deploying if that matters to you.
