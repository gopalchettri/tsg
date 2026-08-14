# Treatment Plan API — End-to-End Test Guide

For developers and testers. Every payload, table and query below is taken from the current code
(`app/api/treatment.py`, `app/api/schemas.py`, `app/db/dal.py`, `scripts/TSG_Core.sql`).
Design rationale lives in `docs/RISK_TREATMENT_PLAN_SDD.md` — this file is only how to test.

**9 operations across 8 paths.** All are entity-scoped and mounted only when the feature flag is on.

---

## 0. Setup

### 0.1 Database

On a database that has **never** run TSG, run the numbered scripts in `scripts/eyshield_handoff/`
in order (see `scripts/readme.txt`) — `0. TSG_Preflight.sql` and `6. TSG_Verify.sql` are read-only
checks; do not skip them.

On a database that already runs TSG sessions, re-running `1. TSG_Core.sql` alone is enough for this
feature — it creates `Risk_Treatment_Plan` + its indexes and adds `Prompt_Log.CorrelationID` and
`Risk_Treatment_Plan.ErrorReason` (plus a one-time backfill for rows that failed before that column
existed). All blocks are guarded, so it is safe to re-run.

> ⚠️ **Run the SQL BEFORE deploying the code.** The worker writes `ErrorReason` on every failure
> path, so code-before-DB fails every plan. Every earlier treatment change was safe in either
> order — this one is not.

> **`TSG_Core.sql` is not sufficient on its own.** The gap-analysis half of the plan reads
> `Threat_Scenario_Control_Map`, `Control_Library`, `Control_Library_Standard_Map` and
> `Control_Standard`, which come from `4. Control_library.sql` (+ its seed). Without them the POST
> still returns 202 and a plausible-looking plan is produced — but with an **empty library-mapped
> control list**, and the only signal is a `library control lookup failed` warning, which the poll
> GET does not show. Read it via the evidence endpoint (§3.9): `validation.warnings` on a COMPLETE
> plan, or `input_snapshot.warnings` on any plan (the snapshot always carries it).

### 0.2 Configuration

| Setting | Value | Note |
|---|---|---|
| `TSG_RISK_MODULE_ENABLED` | `true` | With it off, **all 9 operations return 404 by absence** — the router is never mounted. |
| `TSG_AUTH_DEV_MODE` | `true` | Local test boxes only — see the warning below. |

> **Both settings are read once at process start** (`get_settings()` is cached) and the router is
> mounted at import. Editing `.env` while the stack is running changes nothing. Edit first, or
> restart **both** the API and the worker afterwards.

> ⚠️ **`AUTH_DEV_MODE` has no environment guard.** `config.assert_security_posture` returns
> immediately when it is on, *before* the staging/prod JWT checks run — so it bypasses token
> validation in **every** `APP_ENV`, including production. Never set it outside a local box.

### 0.3 Start the stack

From the repo root, in PowerShell:

```powershell
.\run.ps1
```

That opens the `tsg-celery`, `tsg-beat`, `tsg-api` and `tsg-flower` windows (referred to by name in
§7). Useful variants: `.\run.ps1 -Check` (dependency pre-flight only), `-Reload` (uvicorn
auto-reload), `-NoFlower`, and `.\stop.ps1` to stop everything.

`run.ps1` fails closed if Memurai (Redis), MongoDB or `MSSQL$SQLEXPRESS` is not running.

By hand instead, one per window:

```powershell
.\.venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8000
```

```powershell
.\.venv\Scripts\celery.exe -A app.pipeline.celery_worker.celery_app worker -P gevent -c 50 -l info
```

Note the `-A` target differs between the worker and the beat/flower/inspect commands. The worker's
first start can take 1–3 minutes while local embedding/reranker models load.

Confirm before testing:

```powershell
.\.venv\Scripts\celery.exe -A app.pipeline.celery_app.celery_app inspect ping -t 5
```

Expect `pong`, plus `GET /health` and `GET /readyz` returning OK.

**The worker is mandatory.** The POST only queues work — with no worker the plan stays `RUNNING`
until it passes the staleness window and then reads as timed out.

### 0.4 Authentication

Every call below sends:

```
X-API-Key: <your API key — see docs/TSG_API_AUTHENTICATION_GUIDE.md>
X-User-Id: tester1
X-Entity-Id: <entity_id_of_the_session>
X-Tenant-Id: DESC
```

`X-User-Id` becomes the acting user recorded in `UserID`, `ActorUserID` and `ReviewedBy`.
There is **no `user_id` field in any request body** — a body-supplied user would be unverified text.

**Base URL used in examples:** `http://127.0.0.1:8000`

### 0.5 Produce an accepted scenario (prerequisite)

A treatment plan can only be generated for an **accepted, non-superseded** scenario. If you do not
already have one, create it first — this is the full threat + scenario pipeline and takes minutes,
not seconds.

**1. Create a session** (`entity_id` / `asset_id` must be a real pair — ownership is checked
server-side; send `subsector_id`, the child row, not just `sector_id`):

```bash
curl -i -X POST "http://127.0.0.1:8000/v1/sessions" \
  -H "Content-Type: application/json" -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC" \
  -d '{"entity_id":"78","asset_id":103,"service_id":335,"sector_id":95,"subsector_id":111,"supporting_system_id":[321,322,323,324]}'
```

→ `202` with `session_id` — that is your `{S}`.

**2. Poll until the review barrier:**

```bash
curl -s "http://127.0.0.1:8000/v1/sessions/{S}" -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC"
```

Repeat until `progress.overall == "awaiting_review"` (values: `pending`, `in_progress`,
`awaiting_review`, `complete`, `error`, `cancelled`).

**3. Accept the scenarios:**

```bash
curl -s -X POST "http://127.0.0.1:8000/v1/sessions/{S}/accept" \
  -H "Content-Type: application/json" -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC" \
  -d '{"mode":"all"}'
```

`mode` is required: `all`, `none`, or `subset` (with `output_ids`). Accept only works from
`awaiting_review` — a 409 here means step 2 had not finished.

**4. Collect the output ids:**

```bash
curl -s "http://127.0.0.1:8000/v1/sessions/{S}/accepted-scenarios" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC"
```

Every `scenarios[].output_id` is a usable `{O}`.

### 0.6 Or find an existing one in SQL

```sql
SELECT TOP 20
       s.SessionID, s.EntityID, s.AssetName,
       o.OutputID, o.Accepted, o.Superseded,
       JSON_VALUE(o.ScenarioJSON, '$.scenario_title') AS ScenarioTitle
FROM   Scenario_Session s
JOIN   Threat_Scenario_Output o ON o.SessionID = s.SessionID
WHERE  o.Accepted = 1
  AND  o.Superseded = 0
ORDER  BY o.CreatedAt DESC;
```

Take one `SessionID`, its `OutputID` and its `EntityID` — every test below uses these three.

### 0.7 Confirm the concurrency index exists

```sql
SELECT name, is_unique, filter_definition
FROM   sys.indexes
WHERE  object_id = OBJECT_ID('dbo.Risk_Treatment_Plan');
```

Expect `UX_TreatmentPlan_ActiveOutput` — `is_unique = 1`, filter `([Superseded]=(0))`.
This index, not any SELECT, is what makes a duplicate POST return 409. The app refuses to boot without it.

---

## 1. Tables at a glance

| Table | Treatment feature uses it for | Written by |
|---|---|---|
| `Risk_Treatment_Plan` | One row per generation attempt. The row's `Status` **is** the state machine. Never deleted — regeneration supersedes. | POST, worker, cancel, review |
| `Scenario_Audit` | The 4 lifecycle events; source of both audit APIs | POST, worker, cancel, review |
| `Prompt_Log` | One row per AI **reply**. Linked to the plan by `CorrelationID = PlanID` | Worker (`_ask_ai`) |
| `Scenario_Session` | Authorization boundary (`EntityID`) + asset context for the AI + `AssetName` in the register | read-only |
| `Threat_Scenario_Output` | The accepted scenario: gate checks, scenario text, `scenario_title` | read-only |
| `Scoped_Threat`, `Identified_Threat` | Threat category / type / name / actors for the AI context | read-only |
| `Threat_Scenario_Control_Map`, `Control_Library`, `Control_Library_Standard_Map`, `Control_Standard` | The scenario's mapped controls — one half of the gap analysis | read-only |

> **`Prompt_Log` is written *after* the model replies**, not when the call is made. A failure in
> transport (timeout, bad key, provider 5xx) leaves **no row at all**; only a reply that failed to
> parse leaves one, with `ParseSucceeded = 0`. An ERROR plan can therefore legitimately show
> `attempts: []` in the evidence bundle — that is not a lost receipt.

**Stored vocabularies** (use these exact strings in SQL):

- `Risk_Treatment_Plan.Status` → `RUNNING` | `COMPLETE` | `ERROR`
- `Risk_Treatment_Plan.ReviewStatus` → `approved` | `changes_requested` | NULL (not reviewed)
- `Risk_Treatment_Plan.TreatmentStrategy` → always `Mitigate`
- `Risk_Treatment_Plan.RiskLevel` → `Low` | `Medium` | `High` | `Critical`
- `Scenario_Audit.EventType` → `treatment_plan_requested` | `treatment_plan_outcome` | `treatment_plan_cancelled` | `treatment_plan_reviewed`
- `Prompt_Log.Stage` → `treatment_plan`

> **GUID casing when joining audit rows.** `DetailJSON.plan_id` is written by Python in **lowercase**;
> `CAST(PlanID AS nvarchar)` in SQL Server produces **uppercase**. The queries below therefore compare
> as `uniqueidentifier` (`TRY_CAST(... AS uniqueidentifier) = p.PlanID`) so they work on any
> collation. A plain text comparison only matches on a case-insensitive database.

---

## 2. The end-to-end happy path (run in this order)

Substitute `{S}` = SessionID, `{O}` = OutputID, `{E}` = EntityID.

**Record every plan id you are given** — plan rows are never deleted, so the same scenario
accumulates versions and reusing the wrong id is the easiest way to misread a result:
**`{P1}`** from Step 1 (superseded at Step 7), **`{P2}`** from Step 7, **`{P3}`** from Step 10.
Step 9 needs `{P1}`; §3.4's verification needs `{P3}`.

### Step 1 — Generate the plan

```bash
curl -i -X POST "http://127.0.0.1:8000/v1/sessions/{S}/scenarios/{O}/treatment-plan" \
  -H "Content-Type: application/json" -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC" \
  -d '{"existing_controls":["annual patching","network firewall"],"likelihood_rating":4,"impact_rating":5,"final_risk_rating":20,"risk_level":"Critical","risk_identification_date":"2026-06-14T08:31:00","risk_owner":"Head of OT Operations","impacted_business_division":"Water Treatment Operations","existing_controls_all_subsystems":"No","existing_controls_all_subsystems_justification":"Controls deployed on IT systems only."}'
```

**Expect `202`.** Save the `plan_id` as `{P1}`.

```sql
SELECT PlanID, Status, TreatmentStrategy, RiskLevel, Superseded, ActiveTaskID,
       RiskIdentificationDate, CreatedAt, UpdatedAt, CompletedAt
FROM   Risk_Treatment_Plan
WHERE  SessionID = '{S}' AND OutputID = '{O}' AND Superseded = 0
ORDER  BY CreatedAt DESC;
```

Expect exactly one **active** row: `Status='RUNNING'`, `Superseded=0`, `TreatmentStrategy='Mitigate'`,
`RiskLevel='Critical'`, `CompletedAt` NULL. `ActiveTaskID` fills in within a second once the worker
claims it. (Drop the `Superseded = 0` predicate to see the full version history — on a scenario that
has been through this guide before, older versions are still there.)

### Step 2 — Duplicate POST must be rejected

Immediately repeat the exact call from Step 1.

**Expect `409`** with `details.reason = "generation_in_progress"`. Re-run the Step 1 query — still
exactly one active row, and its `PlanID` is unchanged.

### Step 3 — Poll until COMPLETE

```bash
curl -s "http://127.0.0.1:8000/v1/sessions/{S}/scenarios/{O}/treatment-plan" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC"
```

Repeat every few seconds. `status` goes `RUNNING` → `COMPLETE` (typically 10–60s, LLM dependent).

```sql
SELECT Status, ErrorMessage, CompletedAt, LEN(PlanJSON) AS PlanChars,
       LEN(InputSnapshotJSON) AS SnapshotChars, ValidationJSON
FROM   Risk_Treatment_Plan
WHERE  PlanID = '{P1}';
```

Expect `Status='COMPLETE'`, `ErrorMessage` NULL, `CompletedAt` set, `PlanChars` > 0.

Verify the AI receipt:

```sql
SELECT LogID, Stage, PromptVersion, Model, ModelVersion, ParseSucceeded, CreatedAt,
       LEN(Prompt) AS PromptChars, LEN(ResponseText) AS ReplyChars
FROM   Prompt_Log
WHERE  CorrelationID = '{P1}'
ORDER  BY CreatedAt;
```

Expect at least one row with `Stage='treatment_plan'` and `ParseSucceeded=1`.

### Step 4 — Check the board

```bash
curl -s "http://127.0.0.1:8000/v1/sessions/{S}/treatment-plans" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC"
```

Your scenario shows `status: "COMPLETE"`; scenarios with no plan show `plan_id: null`.

### Step 5 — Approve it

```bash
curl -s -X POST "http://127.0.0.1:8000/v1/sessions/{S}/scenarios/{O}/treatment-plan/review" \
  -H "Content-Type: application/json" -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC" \
  -d '{"decision":"approved","comment":"Adopted as written."}'
```

**Expect `200`.** Then:

```sql
SELECT ReviewStatus, ReviewedBy, ReviewComment,
       CONVERT(varchar(27), ReviewedAt, 126) AS ReviewedAtIso,
       CONVERT(varchar(27), UpdatedAt,  126) AS UpdatedAtIso
FROM   Risk_Treatment_Plan WHERE PlanID = '{P1}';
```

`ReviewedAtIso` must be the **same instant** as the response's `reviewed_at` — one value is computed
once and both stored and echoed. The two strings never match exactly: the column is `datetime2(7)`
so SQL renders seven fractional digits (`2026-08-11T06:48:19.1234560`) while the wire carries
Python's six (`2026-08-11T06:48:19.123456`, and no fractional part at all when it lands on a whole
second). Compare the instant — or use `CONVERT(varchar(26), ReviewedAt, 126)` to line them up.

`ReviewedBy` must be `tester1` — taken from the header, never from the body.

### Step 6 — Check the entity register

```bash
curl -s "http://127.0.0.1:8000/v1/entities/{E}/treatment-plans?review_status=approved&limit=50" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC"
```

Your plan appears with `asset_name` and `scenario_title` populated.

### Step 7 — Regenerate (proves versioning)

Repeat Step 1, adding steering:

```json
{"existing_controls":["annual patching","network firewall"],"likelihood_rating":4,"impact_rating":5,
 "final_risk_rating":20,"risk_level":"Critical",
 "user_note":"vendor owns the network; prefer host-level controls"}
```

**Expect `202` with a NEW `plan_id`** — record it as `{P2}`.

```sql
SELECT PlanID, Status, Superseded, ReviewStatus, CreatedAt
FROM   Risk_Treatment_Plan
WHERE  SessionID = '{S}' AND OutputID = '{O}'
ORDER  BY CreatedAt;
```

Expect **two** rows: `{P1}` with `Superseded=1` (keeping `ReviewStatus='approved'` as history) and
`{P2}` with `Superseded=0`, `Status='RUNNING'`, `ReviewStatus=NULL`.
**A new version always starts unreviewed** — approval never carries across versions.

> Re-running Step 6's `?review_status=approved` call now returns **nothing**. That is correct, not
> data loss: the register lists only active plans (`Superseded=0`), and `{P2}` is unreviewed. The
> approved version is still in the table and still reachable via the audit trail (§3.7) and the
> evidence bundle (§3.9).

### Step 8 — Read the audit trail

**Wait until `{P2}` reaches COMPLETE first** (re-poll Step 3). The final `outcome` event is written
by the worker when it finishes; until then the trail correctly ends at the second `requested`.

```bash
curl -s "http://127.0.0.1:8000/v1/sessions/{S}/scenarios/{O}/treatment-plan/audit" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC"
```

Expect, oldest first: `requested` → `outcome` → `reviewed` → `superseded` → `requested` → `outcome`.

```sql
SELECT EventType, ActorUserID, ActorType, DetailJSON, CreatedAt
FROM   Scenario_Audit
WHERE  SessionID = '{S}'
  AND  EventType IN ('treatment_plan_requested','treatment_plan_outcome',
                     'treatment_plan_cancelled','treatment_plan_reviewed')
ORDER  BY CreatedAt, AuditID;
```

### Step 9 — Pull the evidence bundle for the OLD version

```bash
curl -s "http://127.0.0.1:8000/v1/sessions/{S}/scenarios/{O}/treatment-plan/evidence?version={P1}" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC"
```

**Expect `200`** — superseded versions are deliberately readable. `attempts[]` contains the exact
prompt and raw reply.

### Step 10 — Cancel a running generation

**First confirm `{P2}` is COMPLETE or ERROR** (poll Step 3). A fresh RUNNING plan cannot be
superseded, so POSTing over one returns `409 generation_in_progress` — the concurrency guard doing
its job, not a cancel failure.

Then POST a fresh generation (Step 1) — **record this third plan id as `{P3}`** — and **immediately**:

```bash
curl -s -X POST "http://127.0.0.1:8000/v1/sessions/{S}/scenarios/{O}/treatment-plan/cancel" \
  -H "X-API-Key: <API_KEY>" -H "X-User-Id: tester1" -H "X-Entity-Id: {E}" -H "X-Tenant-Id: DESC"
```

**Expect `200`** → `{"status":"ERROR","error_message":"cancelled by user"}`.
If the worker beat you to it, expect `409 not_in_progress` — also correct.

> **Cancel stops the record, not the worker.** The in-flight LLM call runs to completion and its
> `Prompt_Log` receipt still lands (it is the spend record); the worker then finds its CAS refused
> and drops the result with `treatment.finish_dropped`. A cancelled plan legitimately has rows in
> `Prompt_Log` and a `PlanJSON` of NULL.

---

## 3. API reference — one section per endpoint

### 3.1 POST `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan`

**When to use:** the user clicks *Generate plan* on an accepted scenario — and again for *Regenerate*.
The same endpoint does both; there is no separate regenerate route, because a regeneration **is** a new
version of the same thing.

**Why it returns 202, not the plan:** an LLM call takes tens of seconds. Holding an HTTP request open
that long fails behind load balancers, so the work is queued and the GET is the observation point.

**Request** (5 required + 6 optional):

```json
{
  "existing_controls": ["annual patching", "network firewall", "quarterly access review"],
  "likelihood_rating": 4,
  "impact_rating": 5,
  "final_risk_rating": 20,
  "risk_level": "Critical",
  "risk_identification_date": "2026-06-14T08:31:00",
  "risk_owner": "Head of OT Operations",
  "impacted_business_division": "Water Treatment Operations",
  "existing_controls_all_subsystems": "No",
  "existing_controls_all_subsystems_justification": "Controls deployed on IT systems only.",
  "user_note": "vendor owns the network layer; prefer host-level controls"
}
```

| Field | Rule |
|---|---|
| `existing_controls` | **Required**, may be `[]` but the key must be present. Max 50 items, each ≤500 chars. Baseline for the gap analysis. |
| `likelihood_rating` / `impact_rating` | Required, 1–5 |
| `final_risk_rating` | Required, 1–25. Taken as-is — never re-derived. |
| `risk_level` | Required, exactly `Low`/`Medium`/`High`/`Critical` |
| `risk_identification_date` | Optional. Any offset is converted to UTC and stored naive. |
| `risk_owner` | Optional, ≤200. Echoed to output but **never shown to the AI** (it is a person's name). |
| `impacted_business_division` | Optional, ≤200. Echoed **and** shown to the AI as org context. |
| `existing_controls_all_subsystems` (+ `_justification`) | Optional `Yes`/`No` + ≤1000 chars. Steers the AI's sub-system answer. |
| `user_note` | Optional, ≤1000. Steering text for a regenerate. Redacted before use. |

**Response 202:**

```json
{"plan_id":"b9fe2c07-4d3a-4a51-8e2f-6c1d90a7e4b3",
 "session_id":"5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
 "output_id":"1a2b3c4d-5e6f-4788-898a-8b8c8d8e8f90","status":"RUNNING"}
```

**Tables:** writes `Risk_Treatment_Plan`, `Scenario_Audit`. Reads `Scenario_Session`,
`Threat_Scenario_Output`, `Scoped_Threat`, `Identified_Threat`, `Threat_Scenario_Control_Map`,
`Control_Library`, `Control_Library_Standard_Map`, `Control_Standard`.

**Verify:**

```sql
SELECT p.PlanID, p.Status, p.Superseded, p.TreatmentStrategy, p.RiskLevel, p.UserID,
       p.RiskIdentificationDate, p.CreatedAt,
       a.ActorUserID, a.ActorType, a.CreatedAt AS AuditAt
FROM   Risk_Treatment_Plan p
LEFT JOIN Scenario_Audit a
       ON a.SessionID = p.SessionID
      AND a.EventType = 'treatment_plan_requested'
      AND TRY_CAST(JSON_VALUE(a.DetailJSON, '$.plan_id') AS uniqueidentifier) = p.PlanID
WHERE  p.SessionID = '{S}' AND p.OutputID = '{O}'
ORDER  BY p.CreatedAt DESC;
```

**Failures:** `404` session/scenario unknown · `403` session outside your entities ·
`409 scenario_superseded` · `409 scenario_not_accepted` · `409 generation_in_progress` · `422` bad body.

---

### 3.2 GET `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan`

**When to use:** poll it after the POST until `status` is `COMPLETE` or `ERROR`; then it is the page
that displays the plan. **This is the only endpoint that returns the plan document.**

**Why polling and not a webhook:** one endpoint serves both "is it ready?" and "give me the result",
so the UI needs no second route and no job-id bookkeeping.

**There is also a live hint — but polling stays.** The worker publishes an advisory
`treatment_plan_result` event on the session stream (`GET /v1/sessions/{id}/events`) when a plan
reaches a committed COMPLETE/ERROR, so a client can refetch at once instead of waiting for its next
tick. It is **not** a completion signal, and a UI that stops polling will hang:

| Never publishes | Why |
|---|---|
| Dead worker | The row stays `RUNNING`; only this GET's read-time projection calls it timed out. No reaper exists to fire an event later. |
| LLM at capacity | The autoretry bumps the progress clock every attempt, so the row never even *becomes* stale. |
| Cancel / review | Written in the API process; only the worker publishes. Other tabs learn nothing. |
| Any publish failure | Opens a circuit breaker that silences **all** events from that worker process for a cooldown window. |

So: keep a slow backstop poll (e.g. 30s instead of 3s), listen with
`addEventListener("treatment_plan_result", …)` — the events are named, so `onmessage` receives
nothing — and match on **`output_id`**, because a regeneration mints a new `plan_id`. Plan state is
also absent from the stream's `reconcile` payload, so fetch the board (§3.3) on connect and on every
reconnect.

**Request:** none.

**Response 200** — exactly these 11 keys:

```json
{
  "plan_id": "b9fe2c07-4d3a-4a51-8e2f-6c1d90a7e4b3",
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "output_id": "1a2b3c4d-5e6f-4788-898a-8b8c8d8e8f90",
  "status": "COMPLETE",
  "treatment_strategy": "Mitigate",
  "scenario": {
    "threat_category": "Elevation of Privilege",
    "threat_type": "Credential Abuse",
    "threat_name": "Stolen RDP credentials",
    "threat_actors": ["Nation-state/APT", "Malicious insider"],
    "scenario_title": "Ransomware via exposed RDP",
    "scenario_statement": "A ransomware operator gains access through an internet-exposed RDP service…",
    "risk_statement": "Loss of treatment-plant availability for an extended outage window."
  },
  "risk_level": "Critical",
  "review_status": "approved",
  "risk_identification_date": "2026-06-14T08:31:00",
  "plan": {
    "title": "Remote Access Hardening for the OT Engineering Segment",
    "treatment_plan": "Mitigate",
    "action_plan": "Actions A1–A4 remove direct RDP exposure and broker remote access behind MFA.",
    "applicable_to_all_subsystems": "No",
    "controls_to_be_implemented": {
      "control_coverage": "gaps",
      "controls": [
        {"control_type":"preventive","control_name":"Brokered remote access with MFA",
         "description":"Terminate remote engineering sessions on an MFA jump host.",
         "priority":"Critical","control_code":"CII-CID-028","control_library_id":201}
      ]
    },
    "remediation_action_plan": [
      {"action_id":"A1","action":"Remove the internet-facing RDP publication.",
       "owner":"Network Operations Team","priority":"Critical","dependencies":"None",
       "timeline":"within 14 days","success_criteria":"External scan shows no reachable RDP."}
    ],
    "mitigation_timeline": "90 days overall; critical actions within 30 days",
    "mitigation_owner": "OT Security Team",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Water Treatment Operations"
  },
  "error_message": null
}
```

`control_library_id` is resolved server-side against **this scenario's own mapped-control list**
(the snapshot's `library_mapped`), matched case- and whitespace-insensitively — so a code the model
invented, *or a real library code that is not mapped to this scenario*, resolves to null.
`control_code` is what the model echoed, overwritten with the library's canonical spelling whenever
it matches.

**`reason` — switch on this, never on `error_message`.** It is set only when `status` is `ERROR`
(null on RUNNING and COMPLETE), and it is the field that tells four outcomes apart which would
otherwise all read as a plain failure:

| `reason` | What happened | What the UI should offer |
|---|---|---|
| `cancelled` | A human stopped it | Regenerate |
| `timed_out` | No progress past the staleness window. **Projected, never stored** — SQL still shows `RUNNING` | Regenerate |
| `enqueue_failed` | Broker was down; nothing ever ran | Retry now |
| `content_blocked` | A safety guardrail refused it | **Do NOT auto-retry** — the input must change |
| `invalid_plan` | The model returned an unusable document | Retry |
| `generation_failed` | LLM/pipeline failure — also what rows that failed before this column existed read as | Retry |

**Two trims testers must know about, or they will file false bugs:**

1. **Envelope fields are hidden, not missing.** `review_comment`, `reviewed_by`, `reviewed_at`,
   `warnings`, `moderation_flagged`, `created_at`, `completed_at` are populated and stored but not
   serialized. Confirm them with SQL, not with this response.
2. **The `plan` object is filtered to *at most* 10 keys** (the tuple above, in that order). Five are
   structurally guaranteed by `_validate_plan` — `treatment_plan`, `risk_owner`,
   `impacted_business_division` (server-injected, always present) and `controls_to_be_implemented`,
   `remediation_action_plan` (AI-generated, but `_validate_plan` raises `TreatmentPlanInvalid` if
   either is absent/malformed, so a COMPLETE row always has them); the other five come from the model
   with no structural guarantee and are simply absent if it omits them. (`risk_owner` and
   `impacted_business_division` are present as *keys* even when the POST omitted them — the value is
   then `null`.) As of the 7-field AI schema (see revision history), `PlanJSON` in the database no
   longer holds anything wider than these 10 keys — there is no hidden superset to go looking for in
   SQL any more. `controls_to_be_implemented` is itself now an object, `{control_coverage,
   controls[]}`, not a bare array — see N22 below.

**Staleness:** a `RUNNING` row untouched for longer than the staleness window is *presented* as
`ERROR` / `"generation timed out — request it again"`. The stored row is not changed — SQL will still
show `RUNNING`. That mismatch is correct.

> The window is **not** simply `TREATMENT_STALE_SECONDS`. The field default is 900s, but whenever the
> setting is left unset it is auto-raised to `max(900, llm_timeout_seconds × (llm_max_retries + 1) × 2)`.
> With the shipped defaults (90s / 3 retries) that is 900s; with the UAT profile
> `TSG_LLM_TIMEOUT_SECONDS=600` it becomes **4800s**. Read the effective value off the running app,
> not off `.env`.

**Tables:** reads `Risk_Treatment_Plan` (+ outer join `Threat_Scenario_Output` for `scenario`),
`Scenario_Session` for authorization. Writes nothing.

**Verify — this is what the API is showing you:**

```sql
SELECT p.PlanID, p.Status, p.ErrorMessage, p.RiskLevel, p.ReviewStatus,
       p.ReviewComment, p.ReviewedBy, p.ReviewedAt,          -- hidden on the wire, present here
       p.RiskIdentificationDate, p.CreatedAt, p.CompletedAt,
       JSON_VALUE(o.ScenarioJSON, '$.scenario_title') AS ScenarioTitle,
       JSON_VALUE(p.PlanJSON, '$.mitigation_owner')   AS MitigationOwner,
       JSON_VALUE(p.PlanJSON, '$.controls_to_be_implemented.control_coverage')
                                                       AS ControlCoverage  -- nested, but IS returned
FROM   Risk_Treatment_Plan p
LEFT JOIN Threat_Scenario_Output o ON o.OutputID = p.OutputID
WHERE  p.SessionID = '{S}' AND p.OutputID = '{O}' AND p.Superseded = 0;
```

> **Legacy rows:** plans stored before the v0.12 nesting keep `control_coverage` at the TOP
> level — the nested path above returns NULL for them (query `$.control_coverage` instead).
> That NULL is not a bug: the API lifts the old shape at read time, so the GET shows the
> nested value either way. Stored rows are never rewritten.

Note the title here comes from SQL's JSON parser; the API parses the blob in Python and degrades a
corrupt blob to `null` rather than erroring. They agree on well-formed JSON.

**Failures:** `404` no plan ever requested (or it is superseded — use evidence instead) · `403` · `404` unknown session.

---

### 3.3 GET `/v1/sessions/{session_id}/treatment-plans` — the board

**When to use:** the session screen listing every accepted scenario. One call instead of N polls.

**Why it exists:** with 12 accepted scenarios the UI would otherwise fire 12 requests every poll cycle.

**Request:** none.

**Response 200:**

```json
{"session_id":"5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e","accepted_scenarios":2,
 "plans":[
   {"output_id":"1a2b…","scenario_title":"Ransomware via exposed RDP","plan_id":"b9fe…",
    "status":"COMPLETE","risk_level":"Critical","review_status":"approved",
    "error_message":null,"created_at":"2026-08-10T09:12:44","completed_at":"2026-08-10T09:14:02"},
   {"output_id":"9f3c…","scenario_title":"Insider tampering with dosing setpoints","plan_id":null,
    "status":null,"risk_level":null,"review_status":null,
    "error_message":null,"created_at":null,"completed_at":null}]}
```

`plan_id: null` means no plan was ever requested — the UI shows a Generate button.
A session with no accepted scenarios returns `accepted_scenarios: 0`, **not** a 404 (see N24).

**Tables:** reads `Threat_Scenario_Output` LEFT JOIN `Risk_Treatment_Plan`, plus `Scenario_Session`.

**Verify:**

```sql
SELECT o.OutputID,
       JSON_VALUE(o.ScenarioJSON, '$.scenario_title') AS ScenarioTitle,
       p.PlanID, p.Status, p.RiskLevel, p.ReviewStatus, p.ErrorMessage,
       p.CreatedAt, p.CompletedAt
FROM   Threat_Scenario_Output o
LEFT JOIN Risk_Treatment_Plan p
       ON p.OutputID = o.OutputID AND p.Superseded = 0
WHERE  o.SessionID = '{S}' AND o.Accepted = 1 AND o.Superseded = 0
ORDER  BY o.CreatedAt, o.OutputID;
```

Row count must equal `accepted_scenarios`.

---

### 3.4 POST `…/treatment-plan/cancel`

**When to use:** the user clicked Generate by mistake, or on the wrong scenario, and wants the run
stopped **now** rather than waiting out the staleness window.

**Why a CAS and not a delete:** if the worker finished a millisecond earlier, its result must stand.
The conditional update either wins cleanly or reports 409 — it can never half-cancel.

**Scope limit:** cancel works **only while `Status='RUNNING'`**. A finished plan cannot be cancelled —
use review (`changes_requested`) or regenerate instead.

**What it does not do:** it does not revoke the Celery task. See the note at Step 10.

**Request:** none (empty body).

**Response 200:**

```json
{"plan_id":"b9fe2c07-4d3a-4a51-8e2f-6c1d90a7e4b3","status":"ERROR","error_message":"cancelled by user"}
```

**Tables:** writes `Risk_Treatment_Plan` (Status→ERROR) and `Scenario_Audit` (`treatment_plan_cancelled`).

**Verify:**

```sql
SELECT p.Status, p.ErrorMessage, p.CompletedAt, a.EventType, a.ActorUserID, a.CreatedAt
FROM   Risk_Treatment_Plan p
LEFT JOIN Scenario_Audit a
       ON a.SessionID = p.SessionID
      AND a.EventType = 'treatment_plan_cancelled'
      AND TRY_CAST(JSON_VALUE(a.DetailJSON, '$.plan_id') AS uniqueidentifier) = p.PlanID
WHERE  p.PlanID = '{P3}';
```

Expect `Status='ERROR'`, `ErrorMessage='cancelled by user'`, and one audit row naming the user.
Use `{P3}` — the plan Step 10 cancelled — not `{P2}`, which Step 10's POST superseded.

**Failures:** `409 not_in_progress` when the plan is not RUNNING or the worker won the race · `404` no plan.

---

### 3.5 POST `…/treatment-plan/review` — accept **or** reject

**When to use:** a human has read the plan and decides. `approved` = adopt it. `changes_requested` = reject it.

**Why the reviewer is not in the body:** an identity sent in JSON is unverified text. The name recorded
in `ReviewedBy` comes from the login token, so the audit record is evidence rather than a claim.

**Request:**

```json
{"decision":"approved","comment":"A3 timeline extended per operations; otherwise adopted as written."}
```

or

```json
{"decision":"changes_requested","comment":"7-day timeline impossible for OT. Phase around the maintenance window."}
```

`decision` is required and must be exactly `approved` or `changes_requested`. `comment` is optional,
≤2000 chars, redacted before storage (see N18).

**Response 200:**

```json
{"plan_id":"b9fe…","review_status":"approved","reviewed_by":"tester1","reviewed_at":"2026-08-11T06:48:19.123456"}
```

**Only a COMPLETE, current plan can be reviewed.** RUNNING or ERROR → `409 not_complete`.
Re-reviewing overwrites (latest wins) — a rejection can later become an approval.

**Tables:** writes `Risk_Treatment_Plan` (Review* columns) and `Scenario_Audit` (`treatment_plan_reviewed`).

**Verify:**

```sql
SELECT p.ReviewStatus, p.ReviewComment, p.ReviewedBy,
       CONVERT(varchar(27), p.ReviewedAt, 126) AS ReviewedAtIso,
       CONVERT(varchar(27), p.UpdatedAt,  126) AS UpdatedAtIso,
       JSON_VALUE(a.DetailJSON, '$.decision') AS AuditDecision,
       a.ActorUserID, a.ActorType, a.CreatedAt
FROM   Risk_Treatment_Plan p
LEFT JOIN Scenario_Audit a
       ON a.SessionID = p.SessionID
      AND a.EventType = 'treatment_plan_reviewed'
      AND TRY_CAST(JSON_VALUE(a.DetailJSON, '$.plan_id') AS uniqueidentifier) = p.PlanID
WHERE  p.PlanID = '{P1}'
ORDER  BY a.CreatedAt DESC;
```

`ReviewedAt` equals `UpdatedAt` **at review time**. Once the version is superseded (Step 7),
`UpdatedAt` is re-stamped to the supersede instant — that is the timestamp §3.7's `superseded` event
uses — while `ReviewedAt` stays frozen. Both being equal is therefore only expected before a regenerate.

---

### 3.6 GET `/v1/entities/{entity_id}/treatment-plans` — the register

**When to use:** the management view — *"which Critical risks still have no approved plan?"*
This is the only endpoint that spans assets and sessions.

**Why it is entity-scoped:** it crosses sessions, so it enforces entity membership directly
(`403` if `{entity_id}` is not in your `X-Entity-Id`).

**Query parameters:**

| Param | Default | Bounds | Note |
|---|---|---|---|
| `status` | none | free string | `RUNNING` / `COMPLETE` / `ERROR`. Matches the **displayed** status: a timed-out RUNNING plan is returned by `status=ERROR` and excluded from `status=RUNNING`. A typo returns an empty page, not a 422. |
| `review_status` | none | free string | `approved` / `changes_requested` |
| `risk_level` | none | free string | `Low` / `Medium` / `High` / `Critical` |
| `limit` | 100 | 1–500 | |
| `offset` | 0 | ≥0 | |

Example: `?risk_level=Critical&review_status=changes_requested&limit=50`

**Response 200:**

```json
{"entity_id":"E-1042","limit":50,"offset":0,
 "plans":[{"plan_id":"b9fe…","session_id":"5b7c…","output_id":"1a2b…",
   "asset_name":"Water Treatment SCADA","scenario_title":"Ransomware via exposed RDP",
   "status":"COMPLETE","risk_level":"Critical","review_status":"approved",
   "reviewed_by":"tester1","error_message":null,
   "created_at":"2026-08-10T09:12:44","completed_at":"2026-08-10T09:14:02"}]}
```

**Tables:** reads `Risk_Treatment_Plan` JOIN `Scenario_Session` LEFT JOIN `Threat_Scenario_Output`.
Note it filters `Scenario_Session.EntityID` (the authorization truth), not the plan's own copy.

**Verify — the exact query the API runs (unfiltered form):**

```sql
SELECT p.PlanID, p.SessionID, p.OutputID, p.Status, p.RiskLevel, p.ReviewStatus,
       p.ReviewedBy, p.ReviewedAt, p.ErrorMessage, p.CreatedAt, p.UpdatedAt, p.CompletedAt,
       ss.AssetName,
       JSON_VALUE(o.ScenarioJSON, '$.scenario_title') AS ScenarioTitle
FROM   Risk_Treatment_Plan p
JOIN   Scenario_Session ss         ON ss.SessionID = p.SessionID
LEFT JOIN Threat_Scenario_Output o ON o.OutputID  = p.OutputID
WHERE  ss.EntityID = '{E}' AND p.Superseded = 0
ORDER  BY p.CreatedAt DESC, p.PlanID;
```

To reproduce `?status=ERROR`, append the projection branch — substituting the **effective** stale
window (§3.2), not necessarily 900:

```sql
  AND ( p.Status = 'ERROR'
     OR (p.Status = 'RUNNING' AND p.UpdatedAt < DATEADD(second, -900, SYSUTCDATETIME())) )
```

and for `?status=RUNNING`:

```sql
  AND p.Status = 'RUNNING' AND p.UpdatedAt >= DATEADD(second, -900, SYSUTCDATETIME())
```

---

### 3.7 GET `…/treatment-plan/audit` — one scenario's history

**When to use:** *"who asked for this plan, who approved it, and what came before?"* — the per-scenario
answer during a review meeting or an audit query.

**Why it synthesizes `superseded` events:** those are not written as audit rows; they are derived from
the version chain so the timeline shows the replacement without an extra table.

**Request:** none.

**Response 200** (oldest first). `session_id` is present on every event but always `null` here — it is
only populated on the entity-wide feed:

```json
{"session_id":"5b7c…","output_id":"1a2b…","events":[
 {"at":"2026-08-10T09:12:44","event":"requested","actor":"tester1","actor_type":"user",
  "session_id":null,"detail":{"plan_id":"b9fe…","output_id":"1a2b…"}},
 {"at":"2026-08-10T09:14:02","event":"outcome","actor":"tester1","actor_type":"system",
  "session_id":null,"detail":{"plan_id":"b9fe…","status":"COMPLETE","warnings":0}},
 {"at":"2026-08-11T06:48:19","event":"reviewed","actor":"tester1","actor_type":"user",
  "session_id":null,"detail":{"plan_id":"b9fe…","decision":"approved","comment":"Adopted as written."}},
 {"at":"2026-08-11T07:02:10","event":"superseded","actor":null,"actor_type":null,
  "session_id":null,"detail":{"plan_id":"b9fe…"}}]}
```

**Tables:** reads `Risk_Treatment_Plan` (all versions) and `Scenario_Audit`.

**Verify:**

```sql
-- version chain (the source of the synthesized 'superseded' entries)
SELECT PlanID, Status, Superseded, ReviewStatus, CreatedAt, UpdatedAt, CompletedAt
FROM   Risk_Treatment_Plan
WHERE  SessionID = '{S}' AND OutputID = '{O}'
ORDER  BY CreatedAt;

-- the recorded events
SELECT a.EventType, a.ActorUserID, a.ActorType, a.DetailJSON, a.CreatedAt
FROM   Scenario_Audit a
WHERE  a.SessionID = '{S}'
  AND  a.EventType IN ('treatment_plan_requested','treatment_plan_outcome',
                       'treatment_plan_cancelled','treatment_plan_reviewed')
  AND  TRY_CAST(JSON_VALUE(a.DetailJSON, '$.plan_id') AS uniqueidentifier) IN
       (SELECT PlanID FROM Risk_Treatment_Plan
        WHERE SessionID = '{S}' AND OutputID = '{O}')
ORDER  BY a.CreatedAt, a.AuditID;
```

Every `Superseded=1` row in the first query must appear as a `superseded` event in the response, and
its `UpdatedAt` is that event's timestamp.

**Failures:** `404` when no plan version has ever existed for this scenario.

---

### 3.8 GET `/v1/entities/{entity_id}/treatment-plans/audit` — compliance feed

**When to use:** *"show me all treatment-plan activity in July"* — one request instead of a database ticket.

**Query parameters:**

| Param | Default | Bounds | Note |
|---|---|---|---|
| `from` | none | ISO datetime | Wire name is `from` (the Python name is `since`). Any offset is converted to UTC. |
| `to` | none | ISO datetime | **Inclusive** upper bound |
| `user_id` | none | string | Exact match on the acting user |
| `limit` | 200 | 1–1000 | |
| `offset` | 0 | ≥0 | |

Example: `?from=2026-07-01T00:00:00&to=2026-07-31T23:59:59&limit=500`

**Timezone test worth running:** send `?from=2026-07-01T00:00:00%2B05:30`. It must filter from
`2026-06-30T18:30:00` UTC, not from `00:00`. Compare against the SQL below with that literal.

**Response 200** (newest first; `session_id` is populated here because the feed spans sessions):

```json
{"entity_id":"E-1042","limit":500,"offset":0,"events":[
 {"at":"2026-08-11T06:48:19","event":"reviewed","actor":"tester1","actor_type":"user",
  "session_id":"5b7c…","detail":{"plan_id":"b9fe…","decision":"approved"}}]}
```

**Tables:** reads `Scenario_Audit` only.

**Verify:**

```sql
SELECT a.SessionID, a.EventType, a.ActorUserID, a.ActorType, a.DetailJSON, a.CreatedAt
FROM   Scenario_Audit a
WHERE  a.EntityID  = '{E}'
  AND  a.EventType IN ('treatment_plan_requested','treatment_plan_outcome',
                       'treatment_plan_cancelled','treatment_plan_reviewed')
  AND  a.CreatedAt >= '2026-07-01T00:00:00'
  AND  a.CreatedAt <= '2026-07-31T23:59:59'
ORDER  BY a.CreatedAt DESC, a.AuditID DESC
OFFSET 0 ROWS FETCH NEXT 500 ROWS ONLY;
```

---

### 3.9 GET `…/treatment-plan/evidence?version={plan_id}`

**When to use:** an auditor or engineer asks *"what exactly was the AI given, and what did it say?"* —
including for versions replaced months ago.

**Why `version` is required:** the point of this endpoint is inspecting a **specific** version, so the
caller must name it; there is no implicit "current".

**Query parameter:** `version` — **required**, the `plan_id`. Superseded versions are allowed.
Omitting it is a `422`; a malformed or foreign GUID is a `404`.

**Response 200:**

```json
{"plan_id":"b9fe…","status":"COMPLETE",
 "input_snapshot":{"asset":"Water Treatment SCADA","threat":{"…":"…"},
   "existing_controls":{"scenario_suggested":["…"],"library_mapped":["…"],"register_controls":["annual patching"]},
   "risk_assessment":{"likelihood_rating":4,"impact_rating":5,"final_risk_rating":20,"risk_level":"Critical"},
   "treatment_strategy":"Mitigate"},
 "validation":{"warnings":[],"moderation":{"checked":false,"flagged":false}},
 "attempts":[{"at":"2026-08-10T09:13:05","prompt":"[system]\n…","response":"{\"title\": …}",
   "model_name":"gpt-5","model_version":"2026-05-01","prompt_version":"1.0","parse_succeeded":true}]}
```

**`status` here is the STORED value, deliberately unprojected** — a stale RUNNING plan reads `RUNNING`
here while the poll GET shows `ERROR`. Evidence reports the record as written.

**`attempts` may legitimately be empty** on a failed generation (see §1) — the receipt only exists
once the model replied.

Where to read the hidden warnings: `validation.warnings` on a **COMPLETE** plan. On an **ERROR**
plan `validation` is `null` (the failure path writes no ValidationJSON) — read
`input_snapshot.warnings` instead, which carries `library control lookup failed` and the
Step-4-map warnings on every plan regardless of outcome.

**Tables:** reads `Risk_Treatment_Plan` and `Prompt_Log`.

**Verify:**

```sql
SELECT p.PlanID, p.Status, LEN(p.InputSnapshotJSON) AS SnapshotChars, p.ValidationJSON
FROM   Risk_Treatment_Plan p
WHERE  p.PlanID = '{P1}' AND p.SessionID = '{S}' AND p.OutputID = '{O}';

SELECT l.CreatedAt, l.Model, l.ModelVersion, l.PromptVersion, l.ParseSucceeded,
       LEN(l.Prompt) AS PromptChars, LEN(l.ResponseText) AS ReplyChars
FROM   Prompt_Log l
WHERE  l.CorrelationID = '{P1}'
ORDER  BY l.CreatedAt;
```

The second query's row count must equal `attempts.length`.

---

## 4. Negative tests

| # | Test | Expected |
|---|---|---|
| N1 | POST on a **non-accepted** scenario | `409` · `details.reason = scenario_not_accepted` |
| N2 | POST on a **superseded** scenario | `409` · `scenario_superseded` |
| N3 | Two POSTs back-to-back | 2nd → `409` · `generation_in_progress`, and only one row exists |
| N4 | POST with `"likelihood_rating": 9` | `422` |
| N5 | POST with `"risk_level": "critical"` (lowercase) | `422` — values are case-exact |
| N6 | POST omitting `existing_controls` entirely | `422` — `[]` is legal, absent is not |
| N7 | POST with 51 controls, or one control >500 chars | `422` |
| N8 | Any call with a session from another entity | `403` |
| N9 | GET before any POST | `404` · "no treatment plan has been requested for this scenario" |
| N10 | Cancel a `COMPLETE` plan | `409` · `not_in_progress` |
| N11 | Review a `RUNNING` plan | `409` · `not_complete` |
| N12 | Review with `"decision":"rejected"` | `422` — only `approved` / `changes_requested` |
| N13 | Evidence without `?version=` | `422` |
| N14 | Evidence with `?version=not-a-guid` | `404` (never a 500) |
| N15 | Register with `?limit=501` | `422` |
| N16 | Entity feed with `?from=notadate` | `422` |
| N17 | Any path with `TSG_RISK_MODULE_ENABLED=false` (restart first) | `404` — routes are not mounted |
| N18 | Review comment containing a fake secret | Stored **redacted** in `ReviewComment` and in `DetailJSON` |

### N19 — Staleness projection (forced)

**Needs a RUNNING plan.** By this point the scenario's active plan is ERROR (Step 10 cancelled it),
so create one that nothing will claim: **close the `tsg-celery` window**, then POST a fresh
generation. It stays RUNNING. Save that `plan_id` as `{P4}`.

```sql
UPDATE Risk_Treatment_Plan
SET    UpdatedAt = DATEADD(hour, -5, SYSUTCDATETIME())
WHERE  PlanID = '{P4}' AND Status = 'RUNNING';
```

(Confirm it reports **1 row affected**. If your effective stale window exceeds 5 hours — see §3.2 —
use a larger interval.)

Then: the poll GET shows `status: "ERROR"` / `"generation timed out — request it again"`, the board and
register agree, `?status=ERROR` on the register **includes** it, `?status=RUNNING` **excludes** it —
while SQL still shows `Status='RUNNING'` (never rewritten).

Now POST again: expect `202` (takeover). The forced-stale row is now `Superseded=1` and a new
`Superseded=0` / `RUNNING` row exists. Do not expect a particular *total* row count — by this point
the scenario carries every earlier version too (rows are never deleted); check the newest two:

```sql
SELECT TOP 2 PlanID, Status, Superseded, CreatedAt, UpdatedAt
FROM   Risk_Treatment_Plan
WHERE  SessionID = '{S}' AND OutputID = '{O}'
ORDER  BY CreatedAt DESC;
```

**Restart the worker afterwards**, and let the takeover plan finish before running N20.

### N20 — Enqueue failure

First confirm the scenario's active plan is `COMPLETE` or `ERROR` (poll §3.2). Against a fresh
RUNNING plan this POST is a `409 generation_in_progress` that never reaches the broker — no 500,
no log line, and the test looks broken.

In an **elevated** PowerShell: `Stop-Service Memurai`. POST, expect `500`, and the row parked at
`Status='ERROR'` with `ErrorMessage='failed to queue generation — request it again'` — never left
stuck in RUNNING. Expect `treatment.enqueue_failed` in the `tsg-api` window. Then
`Start-Service Memurai`.

Do not run `.\run.ps1` while Memurai is stopped — its pre-flight fails closed and starts nothing.

### N21 — LLM failure (the most common real failure)

Point the worker at a nonexistent model (`TSG_INFERENCE_MODEL=does-not-exist`) or block the LLM
endpoint, restart the worker, then POST. Expect:

- poll GET → `status: "ERROR"` with a **client-safe** `error_message` (never a stack trace)
- `Risk_Treatment_Plan`: `ErrorMessage` set, `CompletedAt` set, `PlanJSON` NULL
- one `treatment_plan_outcome` audit row whose `DetailJSON` carries `status=ERROR`
- `treatment.failed` in the `tsg-celery` window
- evidence: `attempts: []` if the call failed in transport, or one row with `ParseSucceeded=0` if the
  model replied but the reply was unparseable

### N22 — Coverage branch (existing controls already cover everything)

Build the baseline from what this scenario actually identified — both halves, skipping NULLs
(`SuggestedControl` is nullable when the mapper fell back to scenario text):

```sql
SELECT SuggestedControl
FROM   Threat_Scenario_Control_Map
WHERE  OutputID = '{O}' AND SuggestedControl IS NOT NULL;

SELECT JSON_QUERY(ScenarioJSON, '$.controls') AS ScenarioControls
FROM   Threat_Scenario_Output WHERE OutputID = '{O}';
```

Copy those names into `existing_controls` and POST. **Save this plan_id as `{P5}`.** Wait for
`COMPLETE`, then check the document — `control_coverage` now lives nested under
`controls_to_be_implemented`, not as its own top-level key (and unlike the old top-level field, it
IS part of the visible `plan` object on the GET response, since `controls_to_be_implemented` is one
of the 10 keys served):

```sql
SELECT JSON_VALUE(PlanJSON, '$.controls_to_be_implemented.control_coverage') AS Coverage,
       JSON_QUERY(PlanJSON, '$.controls_to_be_implemented.controls') AS Controls,
       JSON_QUERY(PlanJSON, '$.remediation_action_plan')             AS Actions
FROM   Risk_Treatment_Plan WHERE PlanID = '{P5}';
```

> `{P5}` is freshly generated, so the nested paths apply. For plans stored BEFORE the v0.12
> nesting, these paths return NULL (the old shape keeps `control_coverage` top-level and the
> controls table as a bare array) — the API lifts those at read time, SQL does not.

Expect `covered` with an empty or near-empty control list, and a `remediation_action_plan` pivoted to
verification actions (test effectiveness, evidence, monitor for drift) — never an empty action table.

Coverage is the **model's** judgement, not a server-side set comparison: `gaps` with a short control
list is a plausible outcome if it considers the coverage partial. Treat `covered` + a long list of
new controls as the real failure — the server flags that contradiction as a warning in
`ValidationJSON` rather than blocking it.

### N23 — Paging

**Precondition:** the register lists only *active* plans, one per scenario — so the entity needs at
least **two different scenarios** with plans. Run Step 1 against a second accepted scenario `{O2}`
first, otherwise `?offset=1` correctly returns `plans: []` and the test cannot pass.

`GET /v1/entities/{E}/treatment-plans?limit=1&offset=0` then `?limit=1&offset=1`: the two `plan_id`s
must differ and match rows 1 and 2 of §3.6's ordering (`CreatedAt DESC, PlanID`).

The audit-feed half needs no precondition (events are plentiful by now):
`GET /v1/entities/{E}/treatment-plans/audit?limit=1&offset=0` vs `?limit=1&offset=1`
(ordering `CreatedAt DESC, AuditID DESC`).

### N24 — Empty board

Run a second session and accept it with `{"mode":"none"}`. Then
`GET /v1/sessions/{S2}/treatment-plans`: expect `200` with `accepted_scenarios: 0` and `plans: []`,
**not** a 404.

---

## 5. Reset between test runs

```sql
-- inspect first
SELECT PlanID, SessionID, OutputID, Status, Superseded, CreatedAt
FROM   Risk_Treatment_Plan WHERE SessionID = '{S}' ORDER BY CreatedAt;

-- TEST DATABASES ONLY — the product never deletes plan rows
DELETE FROM Prompt_Log
WHERE  CorrelationID IN (SELECT PlanID FROM Risk_Treatment_Plan WHERE SessionID = '{S}');

DELETE FROM Scenario_Audit
WHERE  SessionID = '{S}'
  AND  EventType IN ('treatment_plan_requested','treatment_plan_outcome',
                     'treatment_plan_cancelled','treatment_plan_reviewed');

DELETE FROM Risk_Treatment_Plan WHERE SessionID = '{S}';
```

To re-test without deleting anything, just POST again — regeneration supersedes and gives you a clean
active row while keeping the history.

---

## 6. Quick reference

| # | Method | Path | Body | Success |
|---|---|---|---|---|
| 1 | POST | `/v1/sessions/{s}/scenarios/{o}/treatment-plan` | yes | 202 |
| 2 | GET | `/v1/sessions/{s}/scenarios/{o}/treatment-plan` | — | 200 |
| 3 | GET | `/v1/sessions/{s}/treatment-plans` | — | 200 |
| 4 | POST | `/v1/sessions/{s}/scenarios/{o}/treatment-plan/cancel` | — | 200 |
| 5 | POST | `/v1/sessions/{s}/scenarios/{o}/treatment-plan/review` | yes | 200 |
| 6 | GET | `/v1/entities/{e}/treatment-plans` | — | 200 |
| 7 | GET | `/v1/sessions/{s}/scenarios/{o}/treatment-plan/audit` | — | 200 |
| 8 | GET | `/v1/entities/{e}/treatment-plans/audit` | — | 200 |
| 9 | GET | `/v1/sessions/{s}/scenarios/{o}/treatment-plan/evidence?version={p}` | — | 200 |

---

## 7. When it doesn't work — where to look

Every failure mode is named in a structured log line in one of the windows `run.ps1` opens.

| Symptom | Look for | Window |
|---|---|---|
| Plan stuck `RUNNING`, `ActiveTaskID` NULL | nothing at all — the task never reached a worker. Check `inspect ping` and Flower for `tsg.generate_treatment_plan` | `tsg-celery` |
| Plan stuck `RUNNING`, `ActiveTaskID` set | `treatment.claim_rejected`, or LLM slot backoff | `tsg-celery` |
| Plan went `ERROR` | `treatment.failed` — carries the real exception; the client-safe half is in `ErrorMessage` | `tsg-celery` |
| Result vanished after a cancel or regenerate | `treatment.finish_dropped` — the CAS refused a retired row | `tsg-celery` |
| POST returned 500 | `treatment.enqueue_failed` — broker unreachable | `tsg-api` |
| Plan completed but controls look empty | `treatment.library_controls_read_failed` — emitted at POST time, in the request | `tsg-api` |
| …and the recorded half of the same problem | the Step-4-map warning in `input_snapshot.warnings` / `validation.warnings` (see §3.9) | — (stored, not logged) |
| `plan` is null on a COMPLETE row | `treatment.stored_json_unparseable` — corrupt stored blob, degraded to null | `tsg-api` |
| Confirming a human action landed | `treatment.cancelled`, `treatment.reviewed` | `tsg-api` |
| Normal success | `treatment.complete` | `tsg-celery` |
| No live event arrived, but the plan is COMPLETE | `sse.publish_failed` with `event_type=treatment_plan_result` — one line per cooldown window, so it undercounts drops. Confirm the client used `addEventListener` (not `onmessage`) and matched on `output_id`. | `tsg-celery` |
