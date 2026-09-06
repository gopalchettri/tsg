# TSG API Smoke Testing Guide — Simple Version (for QA)

> **The source code is the authority.** Every request and response below was read out of
> the Pydantic models in `app/api/schemas.py` and `app/api/schemas_treatment.py`, and the
> routes out of `app/api/*.py`. If this guide and the code ever disagree, the code wins and
> this guide is the bug. `tests/test_docs_track_the_schema.py` pins the treatment-plan
> examples to their models so that drift fails a test instead of misleading you silently.

Every test below is one **card** with the same layout, so you always know where to look:

| Card section | Answers |
|---|---|
| Why does this API exist? | Why the app needs it (the rationale) |
| What does it do? | Plain-English behaviour |
| When do you call it? | Preconditions — what must be true first |
| Input / Output | The complete request and response payloads |
| Tables used | Which DB tables it reads and writes |
| Verify in the database | Copy-paste SQL to confirm the API told the truth |
| Must-fail checks | Wrong calls and the exact error each must return |
| Pass if | The one-line pass criterion |

---

## Part 1 — The Big Picture (read this first)

### What is TSG?

TSG is an app that uses AI to find security risks. You give it an **asset**
(a computer system a company owns), and the AI produces:

- **Threats** — bad things that could happen to that system.
- **Scenarios** — short stories describing *how* each bad thing could happen.

A human then reads the scenarios and **accepts** the good ones.

### What is a "session"?

Think of a session like a **restaurant order**:

1. **You place the order** → "AI, study asset 100 and find its risks." (Test 1)
2. **The kitchen cooks** → the AI works in the background — this takes time. (Test 2 is you checking)
3. **You taste the food** → you read the threats and scenarios it made. (Test 3)
4. **You give feedback** → "redo this one" (Test 4), "give me more" (Test 5).
5. **The order closes** → you accept (Test 6) or cancel (Test 7). The session is finished forever.

One session = one complete order, from start to finish.

### What is a "smoke test"?

A quick check that the app basically works — like starting a car and listening
to the engine before a long trip. Not a deep test of everything. Budget: **~4 hours**.

| Priority | Tests | What they cover | Time |
|---|---|---|---|
| **P1 — must do** | 1–7 | The full order journey | ~2.5 h |
| **P2 — if time permits** | 8–9 | Live progress feed + "what was accepted?" lookup | ~1 h |
| **P3 — skip if rushed** | 10–16 | Admin tools + health checks | ~0.75 h |

**Coverage:** the app registers 48 routes and this guide has a card for 47 of them. The
one deliberate omission is `GET /dev/sse-test` — a developer helper page that is mounted
only when `app_env` is `local`/`dev` (`app/main.py`), is hidden from `/openapi.json`
(`include_in_schema=False`), takes no auth, and serves a static HTML file
(`app/static/sse_test.html`). It has no JSON contract, so there is nothing to smoke-test.

You will create **two sessions**: **Session A** for Tests 1–6 (the whole journey),
and **Session B** only so Test 7 has something to cancel (Session A is already
finished after Test 6 — you can't cancel a finished order).

### Words you will see everywhere

| Word | Plain meaning |
|---|---|
| `session_id` | The order number. You get it in Test 1 and use it in every other test. |
| `scenario_id` | The ID of ONE scenario card. Needed to say "redo THIS one" or "accept THIS one". (This column used to be called `output_id`/`OutputID` — it's `scenario_id` everywhere now, in the JSON and in `Scenario_Audit.ScenarioID`.) |
| **Stage** | Which step of cooking the order is at (`SCENARIO_GENERATION` = AI writing, `REVIEW` = waiting for you). A finished session now stays at `REVIEW` — `APPROVED` is a historical value old sessions carry; nothing writes it any more, because scenarios are decided individually instead of the whole session flipping to "done" at once. |
| `AWAITING_DECISION` | "The AI is finished. A human must decide now." Most tests wait for this state. |
| `generation_epoch` | A batch counter. First batch = 1, next batch = 2, … Highest number = newest. |
| `Superseded` | "Replaced." The app **never deletes** old scenarios — it marks them `Superseded=1` and writes a new row. Active rows are always `Superseded=0`. |
| **The reaper** | A background janitor job (`tsg.reap`). It cleans up stuck or stale sessions **on its own, with no API call**. If a session changed state and nobody touched it — that was probably the reaper, not a bug. |
| **Idempotency** | "Safe to send twice." Same create request twice with the same `Idempotency-Key` header → the same session back, not two sessions. |
| **SSE** | Server-Sent Events. The server pushes updates to you live — a pizza tracker instead of calling the shop. |

### HTTP status codes used in this guide

| Code | Meaning in plain English |
|---|---|
| `200` | "Done. Here's your answer." |
| `201` | "Created. Here's the new row." |
| `202` | "Accepted — I'm working on it **in the background**. Not done yet!" |
| `401` | "Who are you? You didn't log in properly." |
| `403` | "I know who you are, but you're not allowed to see this." (another company's data) |
| `404` | "That thing doesn't exist." (bad ID) |
| `409` | "You can't do that **right now**." (e.g. accepting an already-finished session) |
| `422` | "Your request is malformed." (missing or invalid fields) |
| `503` | "I'm alive, but something I depend on (database, Redis) is down." |

### The error format (same for every API)

Every failed call returns a body shaped like this:

```json
{"error_code": "some_code", "message": "human-readable text", "details": {"optional": "extras"}}
```

`details` only appears when the handler has something extra to say — most
errors are just `error_code` + `message`. "Expect 409 `accept_conflict`" means:
HTTP 409, and the body's `error_code` is `"accept_conflict"`.

The two you will hit most often, in full. A missing or wrong auth header:

```json
401 {"error_code": "unauthorized", "message": "unauthorized"}
```

A malformed body — `details.errors` is FastAPI's own per-field report, with its internal
`ctx` key stripped, so every entry carries exactly `type`, `loc`, `msg` and `input`:

```json
422 {
  "error_code": "validation_error",
  "message": "validation error",
  "details": {
    "errors": [
      {"type": "missing", "loc": ["body", "asset_id"], "msg": "Field required", "input": {"entity_id": "78"}}
    ]
  }
}
```

One error never uses this envelope: a request body over 16 MB is refused by middleware
that runs *before* the error handlers, so it returns
`413 {"error_code": "payload_too_large", "message": "request body exceeds the 16777216 byte limit"}`
with no `details` key at all.

### The four rules that explain most "weird" behavior

1. **`202` means "working on it", not "done."** Only the board (Test 2) tells you it finished.
2. **Nothing is ever deleted.** Replaced scenarios get `Superseded=1`; filter `Superseded=0` in your SQL — **except when you also care about accepted rows**, because an accepted scenario keeps its decision even after a later regenerate supersedes it, and `GET /results` deliberately still returns it (Test 3). For those queries the predicate is `(Superseded=0 OR Accepted=1)`. Library rows get `IsDeleted=1`.
3. **The reaper acts alone.** Sessions can change state with no API call — that's the janitor, not a bug.
4. **Two identity columns in the logbook** (`Scenario_Audit`): `ActorUserID` names who's accountable, but it's only set on rows a human actually caused — `session_started`, `review_decision`, an explicit cancel, a library promotion — where it carries your `X-User-Id`. `ActorType` says who performed the action (`user` = a person called the API, `system` = a background worker). On every row the pipeline writes on its own, `ActorUserID` is **`NULL`** and `ActorType='system'` — the app deliberately stopped stamping the session owner's name onto worker-written rows, because a timeline reading `you / you / you / you` end to end couldn't tell which of those rows you actually caused. A `NULL` `ActorUserID` is information ("the pipeline did this"), not a gap.

---

## Part 1b — Implementation Sequence (build in this order)

Part 4 onward tests each API on its own. This part is the **order to call them in**, for
whoever is wiring up a client. Each step names what to send, what to keep from the reply, and
the one field that says it is safe to move on.

**The rule that catches everyone:** the obvious-looking fields lie about readiness.
`session_status` reads `completed` the moment generation finishes, long before a human has
decided anything, and `current_stage` then stays `REVIEW` forever. The field that answers
"does a human still owe a decision" is `progress.overall`, and nothing else.

**No field is ever omitted.** No route in this app trims empty values, so every reply carries
every field its model declares, with `null` or `[]` standing in for whatever does not apply. A
key you do not see in a real reply is a key that does not exist — treat its absence as a bug
report, not as "the server left it out this time". This is why the examples in this guide are
full-length even when most of the values are `null`.

### A. Session lifecycle (Tests 1–7a, 9–9b)

| # | Call | Send | Keep from the reply | Gate before the next step |
|---|---|---|---|---|
| 1 | `POST /v1/sessions` | asset, entity, supporting systems | `session_id` | HTTP `202`. Send `Idempotency-Key` if your caller can retry |
| 2 | `GET /v1/sessions/{session_id}` | — | `progress.overall`, `progress.controls` | `overall` is `awaiting_review`. Poll every 5–10 s, or open the stream (§D) |
| 3 | `GET /v1/sessions/{session_id}/results` | — | every `scenario_id` | `controls_mapped` is `true` on the cards you intend to render |
| 4 | `POST .../regenerate/scenarios` *(optional)* | `scenario_ids` | `epoch` | `progress.last_regen.epoch` equals the epoch you got back |
| 5 | `POST .../scenarios/next-set` *(optional)* | no body | `epoch` | `progress.last_next_set.epoch` equals it — then read `.outcome` |
| 6 | `POST .../accept` and/or `POST .../scenarios/reject` | `mode` (+ ids), or `scenario_ids` | `accepted_count` / `rejected_count` | both are repeatable and decide per scenario; neither ends the session |
| 7 | `POST .../scenarios/{scenario_id}/promote-to-library` *(optional)* | no body | `created_count` | the scenario must already be accepted |
| 8 | `GET .../audit` | filters | — | read-only, callable any time |

Two things that are **not** steps in this flow. `POST .../cancel` only works while
`session_status` is `active`, so it is a "stop it before generation finishes" action, never a
way to walk away from a review. And `GET .../accepted-scenarios` plus the cross-session reads
(`/v1/users/{user_id}/scenarios`, `/v1/entities/{entity_id}/scenarios`) are downstream feeds —
call them whenever you need them, in no particular order.

### B. Treatment plans (Tests 7b–7l)

These routes exist only when the risk module is switched on. With it off the paths are a bare
`404` with **no error body at all** — that is FastAPI saying "no such route", not the app
saying "feature disabled".

| # | Call | Send | Keep from the reply | Gate before the next step |
|---|---|---|---|---|
| 1 | accept the scenario (§A step 6) | — | `scenario_id` | the scenario reads `accepted: true`, or step 2 refuses |
| 2 | `POST .../treatment-plan` | the register's risk data, 12 keys | `plan_id` | HTTP `202`. **First generation only** — a second call is `409 plan_already_exists` |
| 3 | `GET .../treatment-plan/status` | — | `progress.overall` | it leaves `generating`. Poll here, not step 4 |
| 4 | `GET .../treatment-plan` | — | `plan` | `status` is `COMPLETE` |
| 5 | `POST .../treatment-plan/review` | `decision` **and** `plan_id` | `review_status` | `plan_id` is required and names the version you actually read |

Every version after the first is minted by `POST .../treatment-plan/regenerate` with a literal
`{}` body, never by calling step 2 again. Read the board
(`GET /v1/sessions/{session_id}/treatment-plans`) instead of polling step 3 once per scenario,
and the register (`GET /v1/entities/{entity_id}/treatment-plans`) when the question spans
sessions. Cancel, evidence and the two audit trails are independent of this order.

### C. Admin (Tests 10–10f, 13–13b, 16a–16c)

1. **`POST /v1/tsg/api-clients`** — mint the `X-API-Key` that every other section needs. The
   secret appears in this one response and is never recoverable; only its SHA-256 hash is
   stored. Do this first or nothing else authenticates.
2. **`POST /v1/tsg/threat-library/embeddings/update`** — only when SQL master data changed
   behind the app's back. Then poll `GET .../embeddings/status/{job_id}` or watch
   `GET .../embeddings/events/{job_id}`.
3. **`GET /v1/tsg/grounding/threshold`** — if `origin` is anything but `calibrated`, run
   `POST /v1/tsg/grounding/calibrate` once for the current model pair, then re-read it.
4. **`GET /v1/tsg/threat-intel/feeds`** — refresh only the feeds that read stale or errored.

None of these scope to an entity, so they take `X-Admin-Key` plus `X-API-Key` and `X-User-Id`,
and never `X-Entity-Id`. The API-client routes are the exception: `X-Admin-Key` alone, plus
`X-User-Id` on create and revoke for attribution.

### D. Polling versus watching the live stream

Every background job publishes live events **and** writes a durable field. The event is
best-effort and is **never replayed**, so a dropped connection loses it in silence. The durable
field survives. Watch the event so the UI feels immediate; confirm on the field before you
call anything finished.

| What finished | Durable field to confirm on | Live event | Why the event alone is not enough |
|---|---|---|---|
| Session generation | `progress.overall` on the board | `session_entered_review` | a client that reconnects after it fired has no way to learn that it did |
| "Give me more" | `progress.last_next_set.epoch` | `next_set_result` | the event cannot tell your click apart from a colleague's in another tab |
| "Redo this one" | `progress.last_regen.epoch` | `regen_result` | the event carries no `epoch` at all, so there is nothing on it to match |
| Treatment plan | `GET .../treatment-plan/status` | `treatment_plan_result` | several failure paths never publish the event, and a review verdict never does |
| Admin job | `GET .../status/{job_id}` | `embedding_`/`grounding_`/`intel_job_update` | job ids expire with the Celery result backend, roughly an hour |

Two constraints on any stream in this app. A browser's native `EventSource` **cannot** be used
anywhere here, because every stream needs custom auth headers and `EventSource` cannot set
them — drive it with `fetch()` and a `ReadableStream` reader instead. And all SSE routes share
one process-wide concurrency cap, so an admin stream left open counts against session streams;
past the cap you get `503 sse_capacity_exceeded` with a `Retry-After` header before the stream
opens.

### E. Generate your client from the spec, not from this guide

`/openapi.json` publishes every model, every enum and every event payload described here.
Generate your types from it, so a renamed status or a new reason code becomes a compile error
instead of a silent mismatch months later. Use this guide for the ordering and the reasoning
above, which a schema cannot express.

---

## Part 2 — Setup (do once before testing)

### 1. Start the app

Get the API, the Celery worker, and the database running (see `tsg/SETUP_AND_RUN_GUIDE.md`). Then:

```
GET /health   →   must return 200 with `{"status": "ok"}`
```

If this fails, nothing else will work. Fix it first.

### 2. Authenticate (there is no dev-mode shortcut any more)

Earlier versions of this app had a dev-mode auth bypass (`TSG_AUTH_DEV_MODE`,
headers `X-Dev-Entities`/`X-Dev-User`). **That is gone.** The setting no longer
exists at all — `app/core/config.py` explicitly notes the old
`jwt_*`/`auth_dev_mode` settings are retired. Every call now authenticates
with real headers, checked by `get_principal` in `app/api/deps.py`:

| Header | What it carries | Missing/blank it → |
|---|---|---|
| `X-API-Key` | Your API key, checked against a stored `API_Client` hash | `401 unauthorized` |
| `X-User-Id` | The acting user's id — becomes `ActorUserID` on the audit rows you cause, and `Scenario_Session.UserID` | `401 unauthorized` |
| `X-Entity-Id` | The company/tenant you're acting for — must match the session's own `EntityID` or you get `403 forbidden` | `401 unauthorized` |
| `X-Tenant-Id` | The customer org the caller belongs to; required, but not itself checked against the session | `401 unauthorized` |

You need a working API key before any of this works. Keys are minted with
`X-Admin-Key` (a separate, admin-only credential — see the next section) via
`POST /v1/tsg/api-clients`. That's a one-time setup step, not a per-test call,
so the full request/response shape isn't repeated here — read
`app/api/api_clients.py` for the exact contract when you need to provision a
key.

**A complete example request** — every session call in this guide looks like
this; only the method/path/body change:

```bash
curl -s -X POST "http://localhost:8000/v1/sessions" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: 78" \
  -d '{"entity_id": "78", "asset_id": 103, "service_id": 335, "subsector_id": 111, "supporting_system_id": [321, 322, 323, 324]}'
```

### 3. Admin key (Tests 10–13b and 16a–16c)

Admin routes gated by `require_admin` (`app/api/deps.py`) need only:

- header `X-Admin-Key: <value of TSG_ADMIN_API_KEY>` — for local dev, copy it
  from `tsg/.env` (it's a secret, deliberately not printed here)

Missing or wrong `X-Admin-Key` → `401`. Unlike the session APIs above, these
routes do **not** need `X-API-Key`/`X-Entity-Id`/`X-Tenant-Id` — they work on
shared cross-tenant data, not any one company's.

One exception: **provisioning or revoking an API key**
(`POST /v1/tsg/api-clients`, `POST .../{client_id}/revoke`) additionally
requires `X-User-Id` — not for authentication, but for attribution (it's
written to `CreatedBy`/`RevokedBy`); the route returns `400` without it. A
few other admin routes — embeddings, grounding calibration **and threat intel**, i.e. every
admin route except the three API-client ones — use a different dependency,
`get_admin_principal`, which layers `X-API-Key` + `X-User-Id` on
top of the router's `X-Admin-Key` gate — if `X-Admin-Key` alone gets you a
`401` on some admin route, check whether that route needs those two as well.

Set the key once for the copy-paste commands below:

```bash
export TSG_ADMIN_API_KEY="<copy the value from tsg/.env>"
```

### 4. The running example

All tests use: entity (company) **`"78"`**, asset **`103`**, service
**`335`**, sub-sector **`111`**, and supporting systems
**`[321, 322, 323, 324]`** — note that's a JSON **array** of ids, not a
single number: `supporting_system_id` takes 1–50 subsystem ids (see
`CreateSessionBody` in `app/api/schemas.py`). The acting user is
**`qa-user`**. If those don't exist in your database, substitute real IDs —
the steps stay the same.

### 5. SQL dialect notes (this is MSSQL / SQL Server)

- Use `TOP 5`, not `LIMIT 5`.
- `Scenario_Session.AssetID` (and `EntityID`, `TenantID`) are stored as **text** — quote them: `AssetID='103'`, not `AssetID=103`.

---

## Part 3 — Database Map (every table the tests touch)

### SQL Server tables

| Table | What it holds |
|---|---|
| `Scenario_Session` | 1 row per session — the order's overall status (`SessionStatus`, `CurrentStage`, `StageStatus`, `CompletedAt`). |
| `Subsystem_Stage_State` | 3 rows per session: a `THREATS` stage row, a `SCENARIOS` stage row, and a `_LOCK` row (an internal mutex — ignore it when reading progress). |
| `Identified_Threat` → `Scoped_Threat` → `Threat_Scenario` | The production chain: raw threat → refined threat → final scenario. This last table used to be called `Threat_Scenario_Output` and its id column `OutputID`; both are gone — it's `Threat_Scenario.ScenarioID` now. `Superseded=0` = active. `Accepted=1` = accepted by a human. |
| `Threat_Scenario_Control_Map` | Step-4 control mapping: which `Control_Library` rows were matched to each scenario, and their rank/score. |
| `Scenario_Audit` | The logbook. Append-only — every action adds a row, nothing is ever edited. `EventType` names the action; `ScenarioID` (not `OutputID`) names which scenario an event is about. See Part 3a. |
| `Prompt_Log` | 1 row per AI call (even failed ones) — your proof the AI actually ran. |
| `Threat_Type`, `Threat_Catalogue`, `Threat_Actor`, `Threat_Category` + map tables | The master threat library. **Read-only** except when a scenario is promoted into it — automatically at accept time (`library_promoted`), or explicitly via `POST .../promote-to-library`. The admin routes that used to let someone hand-edit or bulk-import library rows were removed (2026-08) as unused complexity — there is no `Config_Threat_Rule`, `Threat_Candidate_Review`, or `Threat_Library_Import_Run` table any more. |
| `Control_Library`, `Control_Standard`, `Control_Library_Standard_Map` | The 1,288 security controls, their standards (ISO, NIST…), and the links between them. |
| `Risk_Treatment_Plan` | One LLM-generated risk-treatment-plan attempt per accepted scenario. |
| `Grounding_Calibration_Run` | One row per grounding-threshold calibration sweep. This table also **is** the live threshold — the newest successful row for a given model pair is what the pipeline reads; there's no separate settings store. |
| `API_Client` | One row per API caller (Shield today). Only a SHA-256 hash of the secret is stored, never the plaintext — this is what `X-API-Key` gets checked against. |

### MongoDB collections (database `tsg_embeddings`)

| Collection | What it holds |
|---|---|
| `embeddings` | The AI-matching vector cache for master data. |
| `threat_intel` | Cached live threat-intel items (CISA KEV, OTX…). |
| `intel_feed_status` | Per-feed last attempt / success / error. |

`Scenario_Audit` — the logbook — has a section of its own: **Part 3a**, below.

**One big warning before you start:** the reaper (Part 1) can flip a stuck
stage to ERROR/IDLE or a stale session to `cancelled` **without any API call**.
If that happens mid-test, it's the janitor doing its job — not a failed test.

---

## Part 3a — The Audit Trail (what gets recorded, and how to check it)

Everything so far is about checking that an API **works**. This part is about
checking that what it did was **recorded**. TSG protects critical
infrastructure, so "who approved this threat scenario, and when?" has to have
an answer — and `Scenario_Audit` is where that answer lives.

**The one rule: the logbook is append-only.** Rows are only ever added — never
edited, never deleted. That's what makes it trustworthy: you can read it top to
bottom and reconstruct exactly what happened.

### The two name columns

Every row carries two identities, and they answer different questions:

| Column | Answers | What you'll see |
|---|---|---|
| `ActorUserID` | who is **accountable** — but only set on rows a human actually caused | your `X-User-Id`, on the handful of events a person triggers directly; `NULL` on everything the pipeline wrote by itself |
| `ActorType` | who **performed** it | `user` = a person called the API · `system` = a background worker did it while nobody was watching |

**Why you need both:** a single column can't distinguish "nobody," "the
pipeline," and "a specific person." So: on every row a human caused
(`session_started`, `review_decision`, an explicit `session_cancelled`,
`library_promoted`), `ActorUserID` names them and `ActorType='user'`. On every
row the pipeline wrote unattended (`subsystem_advanced`, `grounding_summary`,
`scoping_complete`, `controls_mapped`, `generation_complete`,
`entered_review`, `regeneration_completed`, `stage_error`, and an
auto-triggered `session_cancelled`), `ActorUserID` is `NULL` and
`ActorType='system'` — **not** the session owner's name. An earlier version of
this table used to back-fill the session owner's username onto every
worker-written row, on the theory that a `NULL` "reads as missing" — the cost
was a timeline that read `you / you / you / you` end to end with no way to
tell which of those rows you actually caused. That back-fill was removed
specifically so `ActorUserID = NULL` reliably means "the pipeline did this,"
with `ActorType` stating that outright rather than you having to infer it.

`ActorType` is `NULL` only on old rows written before the column existed.
Those are deliberately never back-filled — rewriting an append-only ledger
would falsify records that were true when written.

### Which test writes which events

You don't need the exact test numbering to use this — what matters is which
**action** writes which **event type**:

| When | Events written | `ActorType` |
|---|---|---|
| **Creating a session** | `session_started` immediately, then per subsystem as the worker runs: `subsystem_advanced`, `grounding_summary`, `scoping_complete`, `controls_mapped`, `generation_complete` — then once, when every subsystem reaches the review barrier: `entered_review` | `user` on `session_started`, `system` on the rest |
| **Regenerating scenarios** | `scoping_complete`, `controls_mapped`, `regeneration_completed` (with `Granularity`) — **not** `generation_complete`, which only fires on the initial run | `system` |
| **Requesting the next set** | `next_set_outcome` (the authoritative per-click summary), plus `generation_complete` when the additive/variant fallback actually produces scenarios | `system` |
| **Accepting scenarios** | `review_decision` (with `Decision`: `accept`/`partial`/`reject`) always; `scenarios_accepted` too, unless you accepted with `mode: "none"`; one `scenario_accepted`/`scenario_rejected` row per scenario decided; `library_promoted` per threat whose library entry changed | `user` |
| **Cancelling** | `session_cancelled` | `user` when you call cancel yourself; `system` when the pipeline auto-cancels a session where every subsystem failed (`DetailJSON: {"reason": "all subsystems failed"}`) |
| **Any stage failure** (after retries) | `stage_error` | `system` |

Two columns only appear on specific events: `Decision` on the accept family,
and `Granularity` on `regeneration_completed`.

**Regenerating records exactly what happened, not what you typed.** The
`regeneration_completed` row's `DetailJSON` holds the resolved target threat
ids, the `scenario_ids` you requested, the actual `old`→`new` scenario
replacements, any threats that failed or got rescored out, and the epoch.
There is **no free-text note field any more** — an earlier version of the
regenerate request body accepted a `user_note`, but it never reached the
model (it appeared nowhere in the prompts, only in a failure-path audit
record), so it was removed entirely.

**The record can't drift from the work.** The audit row is written inside the
same database transaction as the scenarios it describes — they land together or
not at all. You will never find regenerated scenarios with no record of the
regeneration.

### Replay a whole session in one query

Run this at the end of the P1 journey, using Session A's id:

```sql
SELECT CreatedAt, EventType, Decision, Granularity, ActorUserID, ActorType, DetailJSON
FROM Scenario_Audit WHERE SessionID='<sid>' ORDER BY CreatedAt;
```

A healthy run reads like a story:

1. `session_started` — your username, `ActorType='user'` (you placed the order)
2. a block of `system` rows with `ActorUserID` **`NULL`** (the AI worked, unattributed by design)
3. `entered_review` — `system` (it finished)
4. `regeneration_completed` if you regenerated — `system`
5. `review_decision` — back to `ActorType='user'` (you decided)

**Pass if:** every step you performed has a row; `ActorUserID` names you on
the rows a human triggers (`session_started`, `review_decision`, an explicit
cancel, a library promotion) and is `NULL` in between; and the `user`/`system`
split matches who actually acted.

### Three things that look wrong but aren't

- **Accepting with `mode: "none"` writes no `scenarios_accepted` row.** You get
  `review_decision` with `Decision='reject'` and nothing else — correct,
  because no scenario was flipped. The decision is still fully recorded.
- **`session_cancelled` can appear with `ActorType='system'`.** Cancel is
  normally something you trigger yourself, but the pipeline writes the same
  event when every stage failed — `DetailJSON` then says
  `{"reason": "all subsystems failed"}`.
- **Some event types you might expect simply aren't defined any more.**
  Earlier versions of this trail reserved `auto_run_enqueued`,
  `threat_regrounded`, and `auto_fanout_review` for future use; none of the
  three exist in the current `AuditEventType` enum at all — don't go looking
  for rows with those `EventType` values. `AuditDecision.regenerate` is still
  defined but still has no writer: a regenerate is recorded through
  `regeneration_completed`, never through `Scenario_Audit.Decision='regenerate'`.
  Separately, `scenario_unaccepted` (undoing an accept after the fact) is
  defined but has no route that writes it yet.

### What the trail does not cover

- **No API exposes it.** There is no endpoint that returns audit rows — every
  audit report is a SQL query against the database.
- **Admin embedding actions (Test 10) write a log line, not a row.** Rebuilding
  the vector cache leaves no `Scenario_Audit` entry, so don't go looking for
  one. The threat/control library's own manual-edit and bulk-import admin
  routes were removed from this app (2026-08) as unused complexity — the only
  way a library row changes now is at accept time (`library_promoted`, above)
  or through the explicit `promote-to-library` route, both of which land in
  `Scenario_Audit` *and* in the promoted row's own
  `CreatedAt`/`CreatedBy`/`UpdatedAt`/`UpdatedBy` columns.

---

## Part 4 — The Core Journey (P1: Tests 1–7, must do)

### Test 1 — Create a Session ("Start the order")

| | |
|---|---|
| **API** | `POST /v1/sessions` |
| **Why does this API exist?** | Everything in TSG happens inside a session. This is the only way to start one — without it there are no threats, no scenarios, nothing to review. |
| **What does it do?** | Starts a new AI run for one asset. The work happens in the background, so it answers immediately with `202` and a session id. |
| **When do you call it?** | Anytime — as long as that asset has no other **active** session (one active order per asset). |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/sessions" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: DESC" \
  -d '{"asset_id": 103, "entity_id": "78", "service_id": 335, "subsector_id": 111, "supporting_system_id": [321, 322, 323, 324]}'
```

- Auth is header-based, not dev-mode headers: `X-API-Key` authenticates the calling service (hashed and matched against `API_Client`); `X-User-Id`, `X-Entity-Id`, and `X-Tenant-Id` carry the acting identity. All four are **required** — any missing/blank one is `401 unauthorized`. There is no `X-Dev-Entities`/`X-Dev-User` any more; dev-mode auth was removed.
- `entity_id` in the body must match the `X-Entity-Id` header — the header names the entity the API-key holder is scoped to, the body field is what `require_entity` actually checks against it.
- `supporting_system_id` is a **JSON array** of ids (1–50, no duplicates) — not a single int. `service_id` and `subsector_id`/`sector_id` are all **optional** (they narrow threat/control matching — omit if unknown; send `subsector_id`, the sub-sector child row, over `sector_id` — the parent — when you have it, since the pipeline needs the child).
- Optional header `Idempotency-Key: <string>` — see step 3 below.
- There is **no `user_id` body field**. The app learns who you are from `X-User-Id` and records it as
  `Scenario_Audit.ActorUserID`. A `user_id` sent in the body is silently ignored.

**Output (complete response):**

```json
202 {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "user_id": "qa-user"}
```

`user_id` is the session's owning user — you, the authenticated caller.

**How to test:**

1. Send the request. **Write down the `session_id` — this is Session A.**
2. Poll Test 2 and confirm the pipeline starts running.
3. Idempotency ("safe to send twice"):
   - Re-send the same body with header `Idempotency-Key: my-key-1` → `200` with the SAME session id (not a new `202`).
   - Send `Idempotency-Key: my-key-1` again with a **different `asset_id`** → `409 idempotency_key_conflict`.
   - **Only `asset_id` is compared.** `reserve_idempotency_key_or_get_existing` returns
     `conflict = row["AssetID"] != asset_id` and looks at nothing else, so re-using the key with
     the same asset but a changed `service_id`, `subsector_id` or `supporting_system_id` gives you
     `200` and the ORIGINAL session — your new values are silently ignored, not applied. Vary
     `asset_id` if you want to see the 409.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Write (sync) | 1 row, before the 202 returns |
| `Subsystem_Stage_State` | Write (sync) | 3 rows: THREATS, SCENARIOS, `_LOCK` |
| `Scenario_Audit` | Write (sync + worker) | `session_started`, then worker events |
| `Identified_Threat`, `Scoped_Threat`, `Threat_Scenario`, `Prompt_Log` | Write (worker) | fill in later, as the AI runs |
| 9 platform tables (`ctm_scan_*`, `onboarding_*`, `option`/`option_value`) + master library | Read only | context about the asset |

**Verify in the database** — the first 2 queries return rows immediately; `Prompt_Log` fills as the AI runs:

```sql
-- The order row exists:
SELECT SessionID, SessionStatus, CurrentStage, StageStatus, AssetID, EntityID
FROM Scenario_Session WHERE SessionID='<sid>';

-- Exactly 3 stage rows (THREATS, SCENARIOS, _LOCK):
SELECT Level, Status, GenerationEpoch, AttemptCount, ErrorMessage
FROM Subsystem_Stage_State WHERE SessionID='<sid>';

-- Did the worker actually call the AI? (rows appear as the pipeline runs)
SELECT Stage, ParseSucceeded, Model, CreatedAt
FROM Prompt_Log WHERE SessionID='<sid>' ORDER BY CreatedAt;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Leave out `asset_id` or `entity_id` | `422` |
| `supporting_system_id` is empty, has more than 50 ids, or repeats an id | `422` |
| Missing or blank `X-API-Key`, `X-User-Id`, `X-Entity-Id`, or `X-Tenant-Id` | `401 unauthorized` |
| Use an asset the entity doesn't own | `403 forbidden` |
| Name an asset that has no supporting systems on record, or a `sector_id`/`subsector_id` that doesn't exist | `404 not_found` — the message names which |
| Create again while Session A is still active for the same asset | `409 active_session_exists` (`details.active_session_id`) |
| The app is already at its configured active-session cap, globally or for your entity | `503 capacity_exceeded` with a `Retry-After` header |
| The tuning rulebook (`Config_Tuning`) has been edited into a state that breaks the scoring invariants | `422 unprocessable_entity` carrying the curated reason. Surfaced here on purpose rather than minting a session under broken arithmetic — it is a config problem, not a request problem |
| The Celery broker is unreachable when the session is queued | `503 service_unavailable` — and the session that was just written is **cancelled for you** before the error returns, so start a fresh call rather than polling the id you never received |
| Same `Idempotency-Key` + a different `asset_id` | `409 idempotency_key_conflict` (`details.existing_session_id` names the original) |
| Same `Idempotency-Key` + the same `asset_id`, any other field changed | `200` returning the original session (NOT a new `202`); the changed fields are ignored |

**Pass if:** you got `202` with a valid UUID, and Test 2 shows the pipeline running.

---

### Test 2 — Get Session Board ("Is my order ready yet?")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}` |
| **Why does this API exist?** | Creation is asynchronous — the `202` only means "started". Someone has to be able to ask "done yet?", and every other action is gated on the answer. |
| **What does it do?** | Shows the session's current stage and status. The ONLY way to know the background work finished. |
| **When do you call it?** | After Test 1, repeatedly (every 5–10 s), until `progress.overall` says `awaiting_review`. Also after Tests 4–7 to watch the state change. |

**Input (complete request):**

```bash
curl -s "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: DESC"
```

**Output (complete response):**

```json
200 {
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "entity_id": "78",
  "asset_id": 103,
  "asset_name": "CAD Platform",
  "user_id": "qa-user",
  "session_status": "active",
  "current_stage": "REVIEW",
  "stage_status": "COMPLETE",
  "progress": {
    "threats": "COMPLETE",
    "scenarios": "COMPLETE",
    "overall": "awaiting_review",
    "controls": "COMPLETE",
    "timings": {"threats": 34.21, "scenarios": 42.03, "controls": 604.12},
    "error_message": {},
    "last_next_set": null,
    "last_regen": null,
    "coverage": null
  }
}
```

`current_stage="REVIEW"` + `progress.overall="awaiting_review"` = **"the AI is done — a human must decide now."** That's the state Tests 3–6 wait for. **This is a real behavior change to watch for:** the API no longer ever publishes `AWAITING_DECISION` on the wire — internally the DB still parks the SCENARIOS stage at `SCENARIOS_AWAITING_DECISION`, but both the top-level `stage_status` and `progress.scenarios` are translated to `COMPLETE` for publication (generation genuinely IS finished at that point). The one field that tells you a human still owes a decision is `progress.overall`. `progress.controls` is a separate roll-up of Step-4 control mapping (`PENDING`/`RUNNING`/`COMPLETE`) — it's the longest step in the pipeline, so scenarios can appear before their controls do; wait for it to read `COMPLETE` before treating a card's `controls` list as final. `progress.error_message` is a dict now (keyed by `"threats"`/`"scenarios"`), not a single string — empty `{}` on a clean board. `progress.timings` says how long each step took, in seconds, keyed by step — read it
straight off the board instead of timing your own polls. Three rules go with it: a step has
**no key at all** until it finishes (a missing key means "not measured", never zero); the
whole object is `null` both on a session that ran before timings were recorded AND on one that
has only just started — `build_board` ends with `return timings or None`, so it is never `{}`; and `threats`/`scenarios` are non-overlapping wall-clock spans
while `controls` overlaps neither — control mapping is the tail of generation, and it is
routinely the longest step of the three.
`progress.coverage` stays `null` unless coverage reporting is enabled (off by default). (There is no `supporting_systems` array — the pipeline works on the whole asset, so `asset_id`/`asset_name` are stated once and one `progress` object holds the stage statuses.)

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Read | session status |
| `Subsystem_Stage_State` | Read | stage statuses (`_LOCK` row excluded from the board) |
| `Threat_Scenario` | Read | whether any scenario is still undecided (drives `progress.overall`) and how many have controls mapped (drives `progress.controls`) |
| `Scenario_Audit` | Read | the newest `next_set_outcome` / `regeneration_completed` rows, which ARE `last_next_set` / `last_regen` |

This API writes nothing.

**Verify in the database** — must match what the API told you:

```sql
SELECT SubsystemID, Level, Status, GenerationEpoch, ErrorMessage
FROM Subsystem_Stage_State WHERE SessionID='<sid>' AND Level<>'_LOCK';
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Random made-up UUID | `404 not_found` |
| Session A's id, but a different `X-Entity-Id` header | `403 forbidden` |

**Pass if:** the stage eventually reaches `current_stage="REVIEW"` with `progress.overall="awaiting_review"`, without `progress.threats` or `progress.scenarios` ever showing `ERROR`.

---

### Test 3 — Get Session Results ("Show me what you made")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/results` |
| **Why does this API exist?** | The scenarios ARE the product. The human reviewer needs to read them before deciding, and Tests 4 & 6 need the `scenario_id`s this returns. |
| **What does it do?** | Returns everything the AI generated for this session: each scenario, its threat, its actors, and its mapped security controls. |
| **When do you call it?** | Only after Test 2 shows `current_stage="REVIEW"` and `progress.overall="awaiting_review"`. |

**Input (complete request):**

```bash
curl -s "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/results" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: DESC"
```

**Output (complete response):**

```json
200 {
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "entity_id": "78",
  "asset_id": 103,
  "asset_name": "CAD Platform",
  "user_id": "qa-user",
  "progress": {
    "threats": "COMPLETE",
    "scenarios": "COMPLETE",
    "overall": "awaiting_review",
    "controls": "COMPLETE",
    "timings": {"threats": 34.21, "scenarios": 42.03, "controls": 604.12},
    "error_message": {},
    "last_next_set": null,
    "last_regen": null,
    "coverage": null
  },
  "scenarios": [
    {"scenario_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
     "scenario": {
       "threat_category": "Tampering",
       "threat_type": "unauthorized modification of firmware",
       "threat_name": "Unauthorized firmware update of Remote Terminal Unit (RTU)",
       "scenario_title": "Remote Terminal Unit (RTU) — Unauthorized firmware push",
       "scenario_statement": "An attacker with OT network access pushes unsigned firmware to the RTU, compromising the integrity of its control logic.",
       "risk_statement": "The RTU provides the Substation Control critical service; corrupted firmware could cause a sustained outage.",
       "supporting_systems_involved": [
         {"supporting_system_id": 321, "supporting_system": "OT Telecom Network",
          "is_entry_point": true,
          "justification": "The firmware push travels over this network to reach the RTU."}
       ]
     },
     "threat": {
       "threat_id": "d290f1ee-6c54-4b01-90e6-d701748f0851",
       "threat_category": "Tampering",
       "threat_category_id": 4,
       "threat_type": "unauthorized modification of firmware",
       "threat_name": "Unauthorized firmware update of Remote Terminal Unit (RTU)",
       "threat_type_id": 14,
       "library_threat_type": "Unauthorized modification of firmware",
       "library_threat_name": "Unauthorized firmware update",
       "grounding_status": "verified",
       "threat_catalogue_id": 42,
       "is_threat_type_ai_generated": false,
       "is_threat_ai_generated": false,
       "grounding_score": 100.0,
       "score": 70.0,
       "scope_rank": 3
     },
     "actors": [
       {"actor_id": 12, "actor_name": "Nation-state/APT"},
       {"actor_id": 31, "actor_name": "Malicious insider"}
     ],
     "controls": [
       {"control_id": 201,
        "control_code": "CII-CID-201",
        "domain": "Identification & Authentication",
        "control_name": "Multi-Factor Authentication",
        "map_rank": 1,
        "score": 93.0,
        "standards": [
          {"standard_id": 3, "standard_name": "NIST SP 800-53 Rev. 5"},
          {"standard_id": 7, "standard_name": "ISO 27001:2022"}
        ]}
     ],
     "accepted": false,
     "accepted_by": null,
     "accepted_at": null,
     "rejected_by": null,
     "rejected_at": null,
     "moderation_checked": false,
     "moderation_flagged": null,
     "moderation_categories": [],
     "validation_status": "ok",
     "validation_errors": [],
     "generation_epoch": 1,
     "scenario_number": 1,
     "gen_started_at": "2026-08-31T09:16:02",
     "gen_finished_at": "2026-08-31T09:16:44",
     "gen_seconds": 42.03,
     "scenario_source": "generated",
     "controls_unavailable": false,
     "controls_mapped": true,
     "controls_mapping_exhausted": false,
     "controls_mapping_exhaustion_reason": null,
     "replaced_scenarios": []}
  ]
}
```

**Seeing the versions a regenerate replaced (`?include_replaced=true`):**

Every scenario carries its own history, **inside the card itself**, in
`replaced_scenarios`. It is **newest first** -- `[0]` is the version it directly
replaced, then that one's predecessor, and so on. It is `[]` for a scenario that
replaced nothing (first run, "generate next set", alternates), and its length is
how many times the scenario has been regenerated: 2 entries means you are looking
at version 3.

By default the list is empty even for a regenerated scenario. Add the flag to get
the old versions themselves:

```bash
curl -s "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/results?include_replaced=true" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC"
```

```json
200 {
  "scenarios": [
    {"scenario_id": "cccc3333-0000-4000-8000-000000000003",
     "scenario": {"scenario_statement": "An insider deliberately deploys ransomware..."},
     "scenario_number": 1,
     "replaced_scenarios": [
       {"scenario_id": "bbbb2222-0000-4000-8000-000000000002",
        "scenario": {"scenario_statement": "A contractor's laptop spreads ransomware..."},
        "replaced_scenarios": []},
       {"scenario_id": "aaaa1111-0000-4000-8000-000000000001",
        "scenario": {"scenario_statement": "An attacker plugs in an infected USB drive..."},
        "replaced_scenarios": []}
     ]}
  ]
}
```

- Each entry in `replaced_scenarios` is a **full scenario card**, in the exact same shape as a top-level one — its own `threat`, `actors`, `controls`, `scenario_source`, everything — abbreviated above to just the fields that differ. The old versions are **nested inside the card that replaced them**. There is no
  top-level `replaced_scenarios` array and no id list to cross-reference -- open a
  card and its whole history is right there.
- The list is **flat**: v3 holds `[v2, v1]` side by side, and those entries' own
  `replaced_scenarios` are always `[]`. Never recurse.
- Old versions keep the controls they had mapped, so you can compare old vs new
  on controls as well as on the narrative.
- **Without the flag nothing changes.** Every card's `replaced_scenarios` is `[]`.
- Only ever returns scenarios from **this** session.

**What the list actually contains — three queries, not one.** `/results` runs a first SELECT for
the ACTIVE rows (`Superseded=0`), then one for rows with `Accepted=1`, then one for rows with a
`RejectedAt`, and **appends** whatever the earlier passes missed. Neither decision query filters
on `Superseded`, on purpose: a decision is a human fact on the record, so the version a reviewer
accepted OR declined must never vanish from the default view just because a later regenerate
superseded it. Consequence for your SQL and your client: the response can legitimately contain
superseded rows and can be LONGER than the number of current scenarios, and the array is **not**
globally sorted — each pass is ordered by threat, then `scenario_number`, then `scenario_id`, but
the appended decided rows sit after all the active ones. Tell them apart by `accepted` and
`rejected_at`.

**Within the active half the order is deterministic** — sorted by threat, then `scenario_number`,
then `scenario_id`, added specifically so a session being polled mid-generation never reshuffles
rows between calls. Still match
scenarios by `scenario_id`, never by position: a regenerate or "generate next set" click
inserts fresh rows, which shifts where existing cards fall in the sorted list even
though their relative order never does.

**How to read it:**

- Each scenario now carries its **own `threat` object** directly
  (`scenarios[].threat`) — there is no more top-level `threats[]` array to
  cross-reference. `threat.threat_id` still identifies which identified threat
  this scenario answers, and `threat.grounding_status` tells you whether it
  matched an approved library entry (`verified`) or is a novel, still-eligible
  candidate (`unverified`).
- Actors live in their own sibling list, `scenarios[].actors` — one row per
  adversary, always taken from the library (the model never names one).
- **Controls live in their own sibling list, NOT inside `scenario`** — read
  `scenarios[].controls`, not `scenarios[].scenario.controls` (older scripts may
  still point at either the wrong nesting or an old `controls`-inside-`scenario`
  spot).
- There is now only **one** control list: `controls` = real controls matched
  from **your library**, best match first. This is a library-first redesign —
  the model no longer proposes its own control names, so the old
  `suggested_controls` / `unmatched_suggestions` fields are **gone**. A library
  gap is reported the same way as before, just with one fewer list: an empty
  `controls` once `controls_mapped` is `true`.
- `gen_started_at` / `gen_finished_at` / `gen_seconds` are that ONE scenario's own
  generation clock. Three fields rather than one because generation runs several scenarios
  at once, so a batch shares a `gen_started_at` — which is what explains durations that
  look like they overlap. All three are `null` on scenarios written before timings existed.
- `generation_epoch` is 1 on a first run; Tests 4–5 create higher numbers.
- `scenario_number` is the scenario's **slot** for its threat. One threat can
  own more than one scenario (slots 1, 2, …), and a regenerate (Test 4) writes
  the replacement into the **same slot** — which is exactly why the count never
  changes.
- **Failure card:** `"scenario": null` means the AI failed on that one threat
  (the board's `error_message` says why); `threat` is still populated, so you
  can see which one. Retry exactly that one via Test 4. This view deliberately
  shows failure cards so you can retry them, but accept (Test 6) filters them
  out — that's why a card is visible here yet can never be accepted or reach
  downstream systems. **Cards appear on the session's first run only** —
  when a *regeneration* (Test 4) fails, no card is written and your previous
  scenario stays in place instead.
- `accepted_by`/`accepted_at` and `rejected_by`/`rejected_at` record who
  decided and when — null until a decision happens. A scenario can never carry
  both an acceptor and a rejecter (enforced in the database).

**`controls_mapped` tells you whether to trust an empty `controls` list:**

| What you see | What it means | What to do |
|---|---|---|
| `true` + non-empty list | Normal success | — |
| `false`, session **not** yet at `REVIEW` | Mapping hasn't run yet — it's the LAST step, so scenarios appear before their controls | Nothing is wrong. Poll Test 2, call again |
| `false`, session **already** at `REVIEW` | Control library was empty/unreachable when the session ran | Seed it (`Seed_to_Control_library.sql`); a redo (Test 4/5) picks these up. Worker log shows `controls.no_candidates` |
| `true` + `"controls": []` | Mapping ran, nothing matched well enough | A library-gap signal, not a crash |
| `controls_unavailable: true` | This response could NOT read the control mapping (a transient database error) — `controls` is empty because we didn't get to look, not because the library has nothing | Retry; do not read the empty list as a library gap |
| `controls_mapping_exhausted: true` | This scenario used up its mapping attempt limit (5 by default) without succeeding — likely a real problem (e.g. the control library has nothing for this category), not just "still working" | This is PERMANENT: nothing retries it again automatically. Stop polling; surface it to a human. Recovering it needs a regenerate (`POST /regenerate/scenarios`) or a manual re-run |

**`moderation_checked` works the same way:** `false` = moderation never ran
(off by default, or service down), so `moderation_flagged: null` is expected,
not missing. Only trust `moderation_flagged` once `moderation_checked` is `true`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Read | session + auth check |
| `Subsystem_Stage_State`, `Scenario_Audit` | Read | this route embeds the whole board, so it runs `build_board` and therefore Test 2's reads as well |
| `Identified_Threat`, `Scoped_Threat`, `Threat_Scenario` | Read | the chain — active rows, plus accepted rows regardless of `Superseded` (see above) |
| `Threat_Scenario_Control_Map`, `Control_Library` | Read | the mapped `controls` on each card |
| `Control_Library_Standard_Map`, `Control_Standard` | Read | the `standards[]` inside each control |
| `Threat_Actor` | Read | actor names, on the legacy-name fallback path |

This API writes nothing.

**Verify in the database** — row count must equal the length of `scenarios[]`. Note the
predicate: **not** `Superseded=0` alone. The endpoint returns active rows PLUS any accepted row
even when superseded, so a `Superseded=0`-only query under-counts as soon as somebody accepts a
scenario and then regenerates it:

```sql
SELECT ScenarioID, SubsystemID, Accepted, Superseded, GenerationEpoch, ScenarioJSON, ValidationJSON
FROM Threat_Scenario
WHERE SessionID='<sid>' AND (Superseded=0 OR Accepted=1 OR RejectedAt IS NOT NULL)
ORDER BY GenerationEpoch;
```

**Must-fail checks:** same as Test 2 — bad id → `404 not_found`, wrong entity → `403 forbidden`.

**Pass if:** `scenarios[]` is non-empty, every scenario has a non-null `scenario_id`
and a populated `threat`, and you **wrote down at least one `scenario_id`** for Tests 4 and 6.

---
### Test 4 — Regenerate Scenarios ("Redo this one, I don't like it")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/regenerate/scenarios` |
| **Why does this API exist?** | Reviewers reject individual scenarios, not whole sessions. Without this, one bad scenario would force re-running everything. |
| **What does it do?** | Rewrites ONLY the scenarios you name, leaving siblings untouched. There is no steering-text field — `user_note` was accepted by the old body for a year but never reached the model (it appears nowhere in the prompts and was only ever stamped into a failure record), so it was removed outright rather than kept as a field that lies about what it does. |
| **When do you call it?** | Only while the session is at `REVIEW` / `AWAITING_DECISION`, with `scenario_id`(s) from Test 3. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/regenerate/scenarios" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>" \
  -d '{"scenario_ids": ["6ba7b810-9dad-11d1-80b4-00c04fd430c8"]}'
```

**Output (complete response):**

```json
202 {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "user_id": "qa-user",
     "status": "regenerating",
     "epoch": 2}
```

`epoch` is always present on this response — it is the same `RegenerateResponse` shape next-set uses (Test 5), and both routes return it for the same reason: a `202` only means "accepted", not "finished."

**How to test:**

1. Send the request and keep the `epoch` from the response.
2. Poll Test 2 until `progress.last_regen.epoch` (not `last_next_set` — that field belongs only to next-set clicks; the two never share one field, since each is written from a different audit event) equals the epoch you got back.
3. Re-run Test 3 and check: the named scenario's text **changed**, it now has a **new `scenario_id`**, its `generation_epoch` is **higher**, and every sibling is **unchanged**.
4. If also running Test 8 (SSE): watch for a `regen_result` event naming the replaced ids as `requested_scenario_ids` and the replacements as `new_scenario_ids` — not `requested_output_ids`/`new_output_ids`; those field names never existed on the wire.

**The count normally does not change: 5 scenarios in → 5 scenarios out.** Regenerate
**replaces**; only Test 5 (next-set) grows the list. The database will hold 6
rows — the retired original keeps `Superseded=1`, and `/results` returns the live one.

**The one case where the count DOES grow — regenerating a scenario you had already accepted.**
`/results` returns active rows *plus* accepted rows regardless of `Superseded` (Test 3), so the
accepted old version stays on the list beside its replacement and you count 6, not 5. That is
correct rather than a duplicate: an accept is a decision on record and must not disappear
because somebody regenerated afterwards. Tell the two apart by `accepted` — the retired one
reads `accepted: true`, the fresh one `accepted: false`. If you want the count to stay at 5,
regenerate before accepting, not after.

**Three things can happen — and two of them look like "nothing happened".**
All three leave you with the same number of scenarios, so check this table
before reporting a bug:

| Outcome | What you see in Test 3 | Is it a bug? |
|---|---|---|
| **Success** | the targeted scenario has new text, a **new `scenario_id`**, and `generation_epoch: 2`; the other 4 are untouched | no — this is the pass case |
| **The AI failed on that scenario** | **nothing changed** — same text, same `scenario_id`, same epoch. The board's `error_message` (Test 2) says what failed, and the session stays at REVIEW | **no.** A redo that fails deliberately keeps your original rather than destroying it, so you are never left with a hole. Read the error and retry the same call |
| **The threat no longer qualifies** | nothing changed; on the live stream, `regen_result` carries an empty `new_scenario_ids` and `reason: "new_threat_did_not_qualify"` | no — see Test 8's reason-code table for the message to show a user |

> ⚠️ Note the difference from Test 3's **failure card**: a failure card
> (`"scenario": null`) is written on the session's **first run**. A failed
> *regeneration* writes no card at all — it leaves the previous scenario in
> place, because that scenario still occupies the slot.

**The old `scenario_id` is not "dead" the way it used to be.** Re-run Test 3
(which returns the active rows, plus any accepted row) and you'll see the fresh
id — alongside the retired one, if you had already accepted it. But unlike the old app, naming the RETIRED `scenario_id` in a later
accept no longer 404s: `Accepted` is now deliberately decoupled from
`Superseded` — `AcceptBody.scenario_ids` may name **any** version of a
scenario, current or superseded, and the named version becomes the accepted
one (`app/pipeline/accept.py`'s `_assert_one_version_per_scenario` and
`app/db/dal.py`'s `_decidable_where` both confirm this — there is no more
`superseded` refusal reason at all). What still fails is a genuinely wrong or
stale id, or one from a different session — see Test 6's reason table.

**Why the DB check looks like it does:** the old scenario row is NOT
deleted — it's marked `Superseded=1` and a brand-new row is inserted at the
next epoch. History is kept forever.

**One threat can own several scenarios.** Regenerate replaces **per row**, so
redoing one scenario never disturbs another scenario of the same threat — and
you can name several ids in one call, each replacing only its own.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Read (rare write) | Read for the auth and review-gate checks. **Never re-reserved and never moved off REVIEW** on the normal path: regeneration rewrites scenarios that already exist, so re-reserving the asset would block a fresh session on it, and the session stays parked at REVIEW/AWAITING_DECISION while a human is deciding. The one exception is the recovery branch inside the gate — if the previous run was abandoned by a dead worker, it finalises that session row (status→completed, stage→REVIEW) before letting you through. |
| `Subsystem_Stage_State` | Write (sync) | SCENARIOS level reset to a new epoch, back to IDLE |
| `Scoped_Threat`, `Threat_Scenario` | Write (worker) | old row superseded, new row inserted |
| `Prompt_Log`, `Scenario_Audit` | Write (worker) | AI call + `regeneration_completed` logbook row |
| `Identified_Threat` | Read (worker) | the session's sibling threats, read to rank the regenerated one. Never written by this route |
| Master library tables | — | **never touched** by this API |

**Verify in the database:**

```sql
-- Targeted row now Superseded=1; replacement at the next epoch; siblings untouched:
SELECT ScenarioID, Superseded, GenerationEpoch, CreatedAt
FROM Threat_Scenario WHERE SessionID='<sid>' AND Superseded=1
ORDER BY GenerationEpoch, CreatedAt;

-- The logbook recorded it:
SELECT EventType, Granularity, DetailJSON
FROM Scenario_Audit
WHERE SessionID='<sid>' AND EventType='regeneration_completed';
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Call while session is NOT at REVIEW (still cooking) | `409 regenerate_conflict` |
| Unknown or already-superseded `scenario_id` | `409 regenerate_conflict` (`details.reason: "output_not_found_or_superseded"`) |
| A `scenario_id` that is not a valid GUID | `422 validation_error` — **not** the 409 above. `RegenerateScenariosBody` canonicalizes the ids, so a malformed one is rejected by the schema and never reaches the lookup |
| Empty list, or more than 50 ids | `422` |
| Unknown `session_id` | `404 not_found` |
| Session belongs to a different entity than your `X-Entity-Id` | `403 forbidden`. The session row is loaded first and the entity compared afterwards, so an existing session outside your entity is a `403`, never a `404` |

**Pass if:** only the named scenario changed; the session stays at REVIEW; the replacement row has a higher epoch.

---

### Test 5 — Generate Next Set ("Give me a few more")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/next-set` |
| **Why does this API exist?** | The first batch may not cover everything. Reviewers need "more of the same asset" without starting a new session and losing what's already reviewed. |
| **What does it do?** | Asks the AI for another batch of brand-new scenarios (never served before) for the same asset. **It adds — it never replaces.** |
| **When do you call it?** | Only while the session is at `REVIEW` / `AWAITING_DECISION`. No body needed. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/scenarios/next-set" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>"
```

(No body at all.)

**Output (complete response):**

```json
202 {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "user_id": "qa-user",
     "status": "generating",
     "epoch": 3}
```

`202` means "queued", not "finished" — the work runs on a background worker
and can take minutes. Reading Test 3 before it lands gives you a **short but
perfectly valid-looking** list, which is exactly how a half-finished run gets
mistaken for a finished one. Keep the `epoch`: it is how you tell your click
apart from anyone else's.

**Unlike Test 4, this route briefly re-opens the session.** Next-set
generates genuinely *new* scenarios, so for the duration of the run it takes
the asset back: `SessionStatus` flips `completed → active`, `CurrentStage →
SCENARIO_GENERATION`, `StageStatus → RUNNING` — so a Test 2 poll mid-click
can show `session_status: "active"` again. That is expected, not a
regression: `tasks._send_to_review` flips it back to `completed`/`REVIEW`
the moment the run reaches the barrier again.

**How to test:**

1. Call it and keep the `epoch` from the response.
2. Poll Test 2 until `progress.last_next_set.epoch` **equals that number**. Until
   then you are looking at an *earlier* click's result, not yours. (Don't poll for
   "does the stage look done" — that cannot tell your click apart from a colleague's
   click in another tab, and it spins forever if the worker is down.)
3. Read `progress.last_next_set.outcome` — it says what to do next:

| `outcome` | Meaning | What the user should do |
|---|---|---|
| `complete` | the full batch of 5 landed | nothing |
| `partial_retryable` | fewer, because some generations **failed** | **click again — it retries them** |
| `exhausted` | fewer (maybe zero), because nothing further exists for this asset | stop; this asset is done |

`requested` / `delivered` / `variants` give the counts, so a UI can say
"Added 3 of 5". `variants` is how many are alternate takes on threats you already
had rather than brand-new ones.

4. Re-run Test 3: the count must have **grown** and every earlier scenario must
   **still be there**.

**Why a short result is not automatically a bug.** `exhausted` is a correct final
answer, not a failure. And a `partial_retryable` count is deliberately *not* padded
with filler — a generation that failed stays visible instead of being hidden behind
a substitute scenario.

**Using the live stream instead of polling?** See Test 8. Short version: the
`next_set_result` event carries the same fields, but it is best-effort and never
replayed, so never treat "I saw the event" as your only definition of done —
confirm against `last_next_set.epoch`, which survives a dropped connection.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Write (sync) | briefly re-reserved for the run — `SessionStatus` completed→active, `CurrentStage`→SCENARIO_GENERATION, `StageStatus`→RUNNING — then flipped back to completed/REVIEW when the run reaches the barrier again |
| `Subsystem_Stage_State` | Write (sync) | SCENARIOS reset for the new epoch; a THREATS epoch is also reserved in case the additive branch needs it |
| `Scoped_Threat`, `Threat_Scenario`, `Identified_Threat` | Write (worker) | new rows on the additive branch — prior threats/scenarios are never superseded |
| `Prompt_Log`, `Scenario_Audit` | Write (worker) | AI call + `next_set_outcome` logbook row |
| Master tables | — | never touched |

**Verify in the database** — active counts must stack up (5 → 10 → 15) and no
earlier-epoch row may flip to `Superseded=1`:

```sql
SELECT GenerationEpoch, COUNT(*) AS active
FROM Threat_Scenario
WHERE SessionID='<sid>' AND Superseded=0
GROUP BY GenerationEpoch ORDER BY GenerationEpoch;
```

**Must-fail checks:** same `409 regenerate_conflict` family as Test 4 (not at
REVIEW, subsystem lock held), **plus** one next-set-only cause — the asset was
re-claimed by someone else during the brief re-reserve window: `409
regenerate_conflict` (`details.reason: "asset_busy"`), which is transient and
worth an immediate retry. Same `404`/`403` for a bad or out-of-scope id.

**Pass if:** counts accumulate and nothing old disappears.

---

### Test 6 — Accept Session ("I'll take these. Done.")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/accept` |
| **Why does this API exist?** | The human decision is the whole point of the app — AI proposes, a person disposes. This records that decision. |
| **What does it do?** | You pick which scenarios to keep (`all` / `none` / `subset`), and each named scenario gets `Accepted=1`. |
| **When do you call it?** | Only while the session is at `REVIEW` / `AWAITING_DECISION` — **any number of times.** Accept is repeatable: generation already completes the session at the review barrier (see the callout below), so scenarios left undecided today stay decidable on a later visit, and re-deciding the same ones is a harmless no-op rather than a conflict. |

**Input (complete request)** — three modes; test `subset` first:

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/accept" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>" \
  -d '{"mode": "subset", "scenario_ids": ["b3fc2c96-3f66-4562-8fa6-5717afa63f66"]}'
```

| Mode | Body | Meaning |
|---|---|---|
| `all` | `{"mode": "all"}` | accept every currently active scenario |
| `none` | `{"mode": "none"}` | accept nothing (still a valid, successful call — `accepted_count: 0`) |
| `subset` | `{"mode": "subset", "scenario_ids": ["..."]}` | accept only the ids you list |

**Output (complete response):**

```json
200 {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "user_id": "qa-user",
     "status": "completed",
     "accepted_count": 1}
```

`accepted_count` must equal the number of ids you sent. `status` always reads
`"completed"` on a successful call — that is a fact about the response, not
proof that this call was what finished the session (see below).

**How to test:**

1. Send the subset-accept with the `scenario_id` you regenerated in Test 4 (`b3fc2c96-...`).
2. Re-run Test 2: `session_status="completed"`. **`current_stage` stays `"REVIEW"`** — see the callout below; it never becomes `"APPROVED"`.
3. Re-run Test 3: only your chosen scenario shows `accepted: true`.
4. Call accept AGAIN with the same body → **`200` again**, `accepted_count: 1` again. This is not a conflict: `AcceptedAt`/`AcceptedBy` are coalesced (first decider wins), so a double-click or a retried request can never overwrite who actually decided, and can never manufacture a second ledger entry for a row that didn't change.
5. If time allows: on fresh sessions, also try `mode="all"` and `mode="none"`.

**The counterintuitive part — this is where the app changed the most.**
`SessionStatus` becomes `"completed"` the moment **generation** reaches the
REVIEW barrier (`app/pipeline/tasks.py::_send_to_review`), not when a human
accepts. The session's own lifecycle is "a generation request," not "a
review workstream" — it ends (and releases the asset) when generation ends,
while each *scenario* carries its own independent accept/reject decision for
as long as the reviewer needs. So by the time you can legally call this
endpoint, the session already reads `session_status="completed"` — that is
the expected, normal precondition for accept, not a state accept produces.
`CurrentStage` stays `"REVIEW"` forever after that: `APPROVED` still exists
in the stage enum but nothing writes it any more — it is pre-migration
history only, kept so old rows still parse. If you want "has every scenario
been decided", read `progress.overall` on Test 2 (`awaiting_review` until
every scenario has a decision, `complete` once they all do) — not
`current_stage`.

**This is the one place a human decision is recorded — in three event types, not two.**
A successful accept writes, all attributed to you with `ActorType='user'`:

1. `scenarios_accepted` — session-scoped. **Skipped entirely when `mode: "none"`**, because
   nothing was flipped.
2. `review_decision` — session-scoped, carrying `Decision` = `accept` / `partial` / `reject` to
   match your `mode`. Always written.
3. one `scenario_accepted` row per id that actually changed.

Both session-scoped rows land in the same commit; the guide's Part 3a table lists all three.
See Test 7a for how to read the trail back.

**Library promotion is no longer a side effect of accept.** In the current
app, accepting a scenario never touches the master threat library by itself —
promoting an AI-invented threat into `Threat_Type`/`Threat_Catalogue` is now
a separate, explicit call: `POST
/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library`, one
scenario at a time, recorded on its own in `Scenario_Audit`. That endpoint is
outside this test's scope, but do not expect accept alone to populate the
library, and do not go looking for a `Threat_Candidate_Review` table to
verify it — that table does not exist in the current schema at all.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Threat_Scenario` | Write | chosen rows get `Accepted=1`, `AcceptedAt`/`AcceptedBy` |
| `Subsystem_Stage_State` | Write (transient) | `_LOCK` row held for the call's duration, then released |
| `Scenario_Audit` | Write | the three events above, attributed to you |
| `Identified_Threat`, `Threat_Type`, `Threat_Catalogue` | Read | the liveness gate behind `master_inactive` |
| `Scenario_Session` | Read | loaded for the auth and review-gate checks, but **never written** — see the callout above; the session was already `completed` by generation before this call ran |
| `Prompt_Log` | — | **no row** — accept makes no AI call |

**Verify in the database:**

```sql
-- Only your chosen ids show Accepted=1; RejectedAt stays NULL on them (mutually exclusive):
SELECT ScenarioID, Accepted, RejectedAt, AcceptedAt, AcceptedBy FROM Threat_Scenario WHERE SessionID='<sid>';

-- CompletedAt reflects when GENERATION reached REVIEW, not when you clicked accept:
SELECT SessionStatus, CurrentStage, CompletedAt FROM Scenario_Session WHERE SessionID='<sid>';

-- The human decision, recorded (Decision = accept / partial / reject):
SELECT EventType, Decision, ActorUserID, ActorType, CreatedAt
FROM Scenario_Audit WHERE SessionID='<sid>'
  AND EventType IN ('review_decision','scenarios_accepted','scenario_accepted');
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Omit `mode`; or send `scenario_ids` with `mode` ≠ `"subset"`; or omit `scenario_ids` with `mode="subset"` | `422` |
| Accept a session that was cancelled | `409 accept_conflict` (`details.reason: "session_cancelled"`) |
| Accept while a worker genuinely still holds a live lease (generation truly in progress) | `409 accept_conflict` (`details.reason: "generation_in_progress"`) — the only reason worth polling on |
| Accept after a worker died/hung with no live lease, and automatic recovery couldn't park the session at REVIEW | `409 accept_conflict` (`details.reason: "generation_abandoned"`) — not retryable; cancel and start a new session |
| A `scenario_id` naming two different versions of the same scenario, or one that conflicts with a version already accepted on this session | `409 accept_conflict` (`details.reason: "duplicate_identity"`) |
| A `scenario_id` that isn't a decidable scenario of THIS session | `404 not_found` — and **nothing is accepted**, even the ids that were fine |
| A master threat type/catalogue was **soft-deleted** (`IsDeleted=1`) meanwhile | `409 master_inactive`. This gate is `IsDeleted`-only **by design**: setting `IsActive=0` does NOT trip it. A threat that `promote-to-library` (Test 9b) just minted starts `IsActive=0` pending curator review, and accepting a session containing it has to keep working. A tester who merely deactivates a row and expects a 409 will get a 200 |

**Reading that 404.** It names every bad id and why, so you don't have to hunt:

```json
404 {
  "error_code": "not_found",
  "message": "Nothing was accepted. 1 of the 3 scenarios you selected cannot be accepted: a341e4d1-... is not a scenario in this session. Get the current scenario ids from GET /v1/sessions/9aec52d8-.../results and try again.",
  "details": {
    "requested": 3,
    "matched": 2,
    "unacceptable": [{"scenario_id": "a341e4d1-...", "reason": "unknown"}]
  }
}
```

| `reason` | What it means | What to do |
|---|---|---|
| `unknown` | No such scenario in **this** session. | Check for a typo, or a copy-paste from a different session. An id belonging to someone else's session also reads `unknown` — on purpose, so this endpoint can't be used to probe whether an id exists. |
| `failure_card` | That scenario's generation failed (`scenario: null`). There is nothing to accept. | Regenerate it first, or leave it out. |
| `subsystem_not_awaiting_decision` | Its subsystem isn't at the review point yet. | Wait for the session to reach REVIEW. |
| `already_rejected` | You already rejected this scenario (Test 6a) — that decision stands. | Accept and reject are mutually exclusive per scenario; pick one. |

Note there is **no `superseded` reason any more** — naming an older, replaced
version is a legitimate accept (see Test 4's callout), not a refusal.

`message` names the first few offenders; `details.unacceptable` always lists all of them.

**Pass if:** the chosen scenarios show `accepted: true`, and a repeat accept with the same ids succeeds again without changing who decided first.

---

### Test 6a — Reject Scenarios ("I'll pass on these")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/reject` |
| **Why does this API exist?** | A pending scenario (nobody has looked at it) and a declined one (a reviewer said no) need to read differently on a risk register — pending sounds unfinished, declined is a decision made and signed. Accept alone can't express "no", only "not yet". |
| **What does it do?** | Records who declined which scenarios, and when. Nothing is deleted — the scenario keeps its content and stays visible in `GET /results`. There is no `mode` and no reject-all: declining everything is a click no reviewer should be one mis-tap away from, and leaving scenarios pending is already a valid resting state. |
| **When do you call it?** | Same review gate as accept — only while the session is at `REVIEW` / `AWAITING_DECISION`, which in practice means any time after generation finishes (see Test 6). Repeatable, and order-independent with accept — but the two are mutually exclusive per scenario. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/scenarios/reject" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>" \
  -d '{"scenario_ids": ["7c9e6679-7425-40de-944b-e07fc1f90ae7"]}'
```

**Output (complete response):**

```json
200 {"session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "user_id": "qa-user",
     "rejected_count": 1}
```

**How to test:**

1. From Test 3, pick a `scenario_id` you have **not** already accepted.
2. Send the reject.
3. Re-run Test 3: that scenario now shows `rejected_by`/`rejected_at` set — there is no plain `rejected` boolean, check those two fields — and `accepted: false`. Its `scenario`/`threat`/`controls` content is untouched.
4. Reject the SAME id again → same `200`, `rejected_count: 1` again. Idempotent: `RejectedAt`/`RejectedBy` are coalesced, so a second click never rewrites who actually declined it first.
5. Try to reject the `scenario_id` you accepted in Test 6 (`b3fc2c96-...`) → `404 not_found`, `details.unacceptable[].reason: "already_accepted"`.

**The mirror of accept, minus a session-level entry.** `decide_scenarios`
writes one `scenario_rejected` row per scenario, in the same call that flips
`RejectedAt`/`RejectedBy` — but unlike accept there is no session-scoped
`review_decision` pair, because rejecting a scenario is not a verdict on the
whole session, only on the scenarios you named.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Threat_Scenario` | Write | chosen rows get `RejectedAt`/`RejectedBy` |
| `Subsystem_Stage_State` | Write (transient) | same `_LOCK` acquire/release as accept, held only for the call |
| `Scenario_Audit` | Write | one `scenario_rejected` row per scenario, attributed to you |
| `Scenario_Session` | — | not touched, same reasoning as accept (Test 6) |

**Verify in the database:**

```sql
-- Rejected rows carry who/when; content is untouched:
SELECT ScenarioID, Accepted, RejectedAt, RejectedBy FROM Threat_Scenario WHERE SessionID='<sid>';

-- One ledger row per scenario, no session-level pair (compare with Test 6's review_decision):
SELECT EventType, ScenarioID, ActorUserID, ActorType, CreatedAt
FROM Scenario_Audit WHERE SessionID='<sid>' AND EventType='scenario_rejected';
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Empty `scenario_ids`, or more than 50 | `422` |
| Reject while the session is cancelled / still generating / generation abandoned | `409 accept_conflict` — the **same** error code family as accept; reject reuses accept's review gate and its `AcceptConflict` exception, there is no separate `reject_conflict` code |
| A `scenario_id` you already accepted | `404 not_found`, reason `already_accepted` |
| A `scenario_id` that's a failure card, unknown, or in a subsystem not yet at the review barrier | `404 not_found`, reason `failure_card` / `unknown` / `subsystem_not_awaiting_decision` |

**Pass if:** the named scenarios show `rejected_by`/`rejected_at`, everything else is untouched, and a repeat reject is a no-op that preserves the original decider.

---

### Test 7 — Cancel Session ("Forget it, stop the order")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/cancel` |
| **Why does this API exist?** | Sometimes the order was a mistake — wrong asset, or nobody will review it. Without cancel, an abandoned session would block its asset forever (one active session per asset). |
| **What does it do?** | Aborts a session before generation reaches the review barrier. |
| **When do you call it?** | Only on a session that is still `session_status="active"` — i.e. still in `THREAT_IDENTIFICATION` or `SCENARIO_GENERATION`. **Once generation reaches REVIEW the session is already `completed`** (see Test 6's callout) and cancel always `409`s from then on — there is no way to cancel a session sitting in front of a reviewer, even one nobody has decided on yet. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/<session_b_id>/cancel" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>"
```

(No body.)

**Output (complete response):**

```json
200 {"session_id": "<session_b_id>",
     "user_id": "qa-user",
     "status": "cancelled"}
```

**How to test:**

1. Session A (from Tests 4-6a) is already `completed` and can no longer be cancelled, so repeat Test 1 to create **Session B**.
2. Immediately cancel Session B, before generation has any chance to reach REVIEW.
3. Verify via Test 2: `session_status="cancelled"`, `current_stage="CANCELLED"`, `stage_status="CANCELLED"`; earlier per-stage history is preserved, not wiped.
4. Cancel the SAME session again → `409 cancel_conflict`.
5. Negative check: try cancelling Session A instead (already at REVIEW, nothing decided) → **also `409 cancel_conflict`** — see the callout below for why that is correct, not a bug.

**The counterintuitive part — and it changed from before.** Cancel's write is
CAS-fenced on `SessionStatus = 'active'`
(`app/db/dal.py::cancel_session`). Because `SessionStatus` now flips to
`completed` the instant generation reaches REVIEW (Test 6's callout) rather
than when a human decides, a session that reached REVIEW can never be
cancelled again — not by anyone, not even one second after it got there, and
regardless of whether a single scenario has been accepted or rejected. Cancel
is now strictly a "stop it before it's finished generating" action, not a
"give up on a review I don't want to do" action.

What's still true from before: cancel does NOT clean up the background work.
It flips the session row and writes an audit entry — nothing else. It does
not touch `Subsystem_Stage_State` at all: no lock released, no stage reset.
In-flight worker tasks notice the cancellation on their own next check, and
the reaper clears leftover stage/lock rows later. So right after cancelling
you may still see a stage as `RUNNING` in the DB. **That is expected — do not
report it as a bug.** Also `CompletedAt` stays NULL (cancelled ≠ completed).

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Write | `SessionStatus`→`cancelled`, `CurrentStage`/`StageStatus`→`CANCELLED`, `CancelledAt`/`CancelledBy` stamped; `CompletedAt` stays NULL |
| `Scenario_Audit` | Write | `session_cancelled` |
| `Subsystem_Stage_State` | — | **deliberately untouched** — the reaper cleans up |

**Verify in the database:**

```sql
-- Cancelled, but CompletedAt stays NULL; CancelledAt/CancelledBy record who and when:
SELECT SessionStatus, CurrentStage, StageStatus, CompletedAt, CancelledAt, CancelledBy
FROM Scenario_Session WHERE SessionID='<sid>';

-- A still-RUNNING stage or _LOCK row here is EXPECTED (the reaper clears it):
SELECT Level, Status, ActiveTaskID FROM Subsystem_Stage_State WHERE SessionID='<sid>';
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Cancel a session that already reached REVIEW (i.e. `session_status="completed"`) — decided or not | `409 cancel_conflict` |
| Cancel an already-cancelled session | `409 cancel_conflict` |
| Unknown `session_id` | `404` |
| Session belongs to a different entity | `403` |

**Pass if:** a still-cooking session cancels cleanly and shows cancelled everywhere on the board; a repeat cancel, and a cancel of any session that already reached REVIEW, both 409.

---

### Test 7a — Get the Session Audit Trail ("Who did what, and when")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/audit` |
| **Why does this API exist?** | Every step of every session has always been written to `Scenario_Audit`, but nothing ever read it back through the API. Part 3a showed you the raw table; this is the same trail through the API — a read path anyone holding `session_id` can use, with paging and filters, instead of a direct SQL query. |
| **What does it do?** | Returns the session's step-by-step history, oldest first — who did what, to what, and when. |
| **When do you call it?** | Any time — before, during, or after a session finishes. It is a plain read, not gated by session state. |

**Input (complete request):**

```bash
curl -s -G "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/audit" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>" \
  --data-urlencode "limit=100" \
  --data-urlencode "offset=0"
```

**Output (complete response):**

```json
200 {
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "limit": 100, "offset": 0,
  "events": [
    {"audit_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90", "at": "2026-08-31T09:00:00Z",
     "event": "session_started", "subject_type": "session", "scenario_id": null, "plan_id": null,
     "actor_user_id": "qa-user", "actor_type": "user", "stage": null, "subsystem_id": null,
     "decision": null, "detail": {}},
    {"audit_id": "2b3c4d5e-6f70-8899-8a9b-8c8d8e8f9091", "at": "2026-08-31T09:04:12Z",
     "event": "entered_review", "subject_type": "session", "scenario_id": null, "plan_id": null,
     "actor_user_id": null, "actor_type": "system", "stage": "REVIEW", "subsystem_id": null,
     "decision": null, "detail": {}},
    {"audit_id": "3c4d5e6f-7081-90aa-9bac-9d9e9fa0a1a2", "at": "2026-08-31T09:10:47Z",
     "event": "regeneration_completed", "subject_type": "session", "scenario_id": null, "plan_id": null,
     "actor_user_id": null, "actor_type": "system", "stage": "SCENARIO_GENERATION", "subsystem_id": 0,
     "decision": null,
     "detail": {"target_ids": ["9f8e7d6c-5b4a-3928-1706-f5e4d3c2b1a0"],
                "requested_ids": ["6ba7b810-9dad-11d1-80b4-00c04fd430c8"],
                "replacements": [{"old": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
                                  "new": "b3fc2c96-3f66-4562-8fa6-5717afa63f66"}],
                "failed_threat_ids": [], "rescored_threat_ids": [], "epoch": 2}},
    {"audit_id": "4d5e6f70-8192-a1bb-acbd-adaeafb0b1b2", "at": "2026-08-31T09:15:03Z",
     "event": "scenario_accepted", "subject_type": "scenario",
     "scenario_id": "b3fc2c96-3f66-4562-8fa6-5717afa63f66", "plan_id": null,
     "actor_user_id": "qa-user", "actor_type": "user", "stage": null, "subsystem_id": null,
     "decision": "accept", "detail": {}},
    {"audit_id": "5e6f7081-92a3-b2cc-bdce-bebfb0c1c2c3", "at": "2026-08-31T09:15:03Z",
     "event": "review_decision", "subject_type": "session", "scenario_id": null, "plan_id": null,
     "actor_user_id": "qa-user", "actor_type": "user", "stage": null, "subsystem_id": null,
     "decision": "partial", "detail": {"subset": ["b3fc2c96-3f66-4562-8fa6-5717afa63f66"]}},
    {"audit_id": "6f708192-a3b4-c3dd-cedf-cfd0d1e2e3e4", "at": "2026-08-31T09:18:29Z",
     "event": "scenario_rejected", "subject_type": "scenario",
     "scenario_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "plan_id": null,
     "actor_user_id": "qa-user", "actor_type": "user", "stage": null, "subsystem_id": null,
     "decision": "reject", "detail": {}}
  ]
}
```

**How to test:**

1. Run Tests 4-6a against one session, then read this endpoint back with no
   filters. You should see, in order: `session_started`, per-subsystem
   generation rows, `entered_review`, the `regeneration_completed` row from
   Test 4, a `next_set_outcome` row from Test 5, the `scenario_accepted` +
   `scenarios_accepted` + `review_decision` **trio** from Test 6, and a
   `scenario_rejected` row from Test 6a. Note `regeneration_completed` comes back
   `actor_user_id: null` / `actor_type: "system"` — the worker writes it, not you, even
   though you clicked the button.
2. Filter to one scenario with `?scenario_id=<id>` — only that scenario's own rows come back, never another scenario's.
3. Filter to one event type with `?event=scenario_rejected` (repeat `event=` for more than one type).
4. Filter to a time window with `since`/`until` (UTC), or to one human with `actor=qa-user` — `actor_user_id` is null on every pipeline-written row, so filtering by actor is how you isolate what a PERSON did versus what the system did.
5. Page through with `limit`/`offset` (`limit` is capped at 500).
6. Cross-check against Part 3a's raw query on the same session — same rows, same order:

```sql
SELECT AuditID, EventType, ScenarioID, PlanID, ActorUserID, ActorType, Decision, CreatedAt
FROM Scenario_Audit WHERE SessionID='<sid>' ORDER BY CreatedAt;
```

Part 3a showed you the raw table; this is the same trail through the API.
The one thing the API adds that the raw row doesn't carry is `subject_type` —
it's derived, not a column: a `plan_id` means the step concerned a treatment
plan, else a `scenario_id` means that scenario, else it concerned the session
as a whole.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Audit` | Read only | every row this session ever wrote, oldest first |
| `Scenario_Session` | Read only | `get_authorized_session`'s entity check |

**Verify in the database:** there is nothing to write-verify — this endpoint
has no write path — so "verify" means "matches the raw table it reads," which
is exactly step 6 above.

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| `event=` with a value that isn't a real event type | `422` |
| `limit` outside 1-500, or a negative `offset` | `422` |
| Unknown `session_id` | `404` |
| Session belongs to a different entity | `403` |

**Pass if:** events come back oldest-first, every row names its subject, each filter narrows correctly, and the count/order matches the raw `Scenario_Audit` query for the same session.

---
## Part 4b — Remediation / Treatment Plans (P1 if the risk module is enabled)

This whole area — all eleven routes in `app/api/treatment.py` — only exists if the risk module is turned on. `Settings.risk_module_enabled` (`app/core/config.py`, env var `RISK_MODULE_ENABLED` / `TSG_RISK_MODULE_ENABLED`, default **`False`**) gates whether `app/main.py` even mounts the router at all: `app/main.py`'s router block reads `if get_settings().risk_module_enabled: app.include_router(treatment_router)`. With the flag off, every path under this section is a plain 404 by *absence* — no route registered, no entry in `/openapi.json`, zero handler code running — not a 403, not a "feature disabled" error body. Before testing anything below, confirm the flag is on in the environment you're pointed at (ask ops, or just try `POST .../treatment-plan` once and see whether you get a 404 with no `error_code` body at all, which is FastAPI's own "no such route" page, vs. a real `ErrorResponse` envelope). The generator here is the **Mitigate** strategy only (`TreatmentStrategy.mitigate` in `app/core/enums.py`) — there's no strategy field on the wire, it's stamped server-side. And TSG reads **no risk-module tables** to build a plan: the register's own risk-scoring data (ratings, dates, existing controls) travels *in the request body* on first generation (see the module docstring of `app/api/treatment.py`); TSG supplies only its own scenario/threat/controls context.

Auth is the same header set as every other route in this guide — **not** the old `X-Dev-Entities`/`X-Dev-User` pair, which no longer exist anywhere in this app. `get_principal` (`app/api/deps.py`) requires `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`, all non-blank, or `401 unauthorized`; `X-Entity-Id` must equal the session's own `EntityID` (checked inside `get_authorized_session`, called first thing in every handler below) or `403 forbidden` (the wire `error_code`; `EntityForbidden` is only the Python exception class name) — and a session that doesn't exist at all 404s *before* that check runs, so an out-of-scope session id 404s rather than 403ing (no existence leak). Running-example values used throughout this section: `entity_id = "78"`, `user_id = "qa-user"`, `HOST = http://localhost:8000`. The session/scenario ids below (`5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e` / `1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90`) are the literal example values baked into `TreatmentPlanAccepted`/`TreatmentPlanStatus` in `app/api/schemas_treatment.py` (the treatment models live there, not in `schemas.py`, which only re-exports them) — substitute your own session's accepted `scenario_id` (from Test 3 / Test 6) when you actually run these.

---

### Test 7b — Request a Treatment Plan ("Order the fix")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` |
| **Why does this API exist?** | Accepting a scenario (Test 6) says "yes, this is a real risk" — it doesn't say what to do about it. This is where the register's risk-scoring numbers meet an AI-authored Mitigate plan. |
| **What does it do?** | Takes the register's risk data (ratings, dates, existing controls) **in the body** — TSG reads no risk-module tables — freezes it together with TSG's own scenario/threat/controls context into a snapshot, inserts a `RUNNING` plan row, and queues the actual generation on Celery. `202`, not `200`: this is the FIRST generation only. |
| **When do you call it?** | Once per scenario, and only after the scenario is **accepted** (`Accepted=1`, Test 6). If *any* plan row already exists for the scenario — whatever its status — this 409s; every version after the first goes through Test 7c instead. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>" \
  -d '{
    "existing_controls": ["annual patching", "network firewall"],
    "likelihood_rating": 4,
    "impact_rating": 5,
    "final_risk_rating": 20,
    "risk_level": "Critical",
    "risk_identification_date": "2026-06-14T08:31:00Z",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Water Treatment Operations",
    "existing_controls_all_subsystems": "No",
    "existing_controls_all_subsystems_justification": "Controls deployed on IT systems only.",
    "mitigation_start_date": "2026-07-01",
    "mitigation_end_date": "2026-09-30"
  }'
```

`TreatmentPlanBody` (`app/api/schemas_treatment.py`) is `extra="forbid"` — these 12 keys are the
ONLY ones accepted; anything else (including the retired `timeline_start_date`/`timeline_end_date`,
or `user_id`/`strategy`/`user_note`) 422s naming it.

**Five of the twelve are required**, not one: `existing_controls`, `likelihood_rating`,
`impact_rating`, `final_risk_rating` and `risk_level` are all declared with no default, so
omitting any of them is a `422` with `type: "missing"`. `existing_controls` may be `[]` — a risk
with no controls is legitimate — but the key itself must be present.

| Field | Required | Bounds |
|---|---|---|
| `existing_controls` | yes (may be `[]`) | at most 50 entries, each ≤ 500 chars. Blank entries and duplicates are silently dropped, order preserved |
| `likelihood_rating` | yes | integer 1–5 |
| `impact_rating` | yes | integer 1–5 |
| `final_risk_rating` | yes | integer 1–25 (the 5×5 matrix). Taken as-is, never re-derived |
| `risk_level` | yes | `Low` \| `Medium` \| `High` \| `Critical`. `""` here is a genuine 422 |
| `risk_identification_date` | no | datetime, normalized to UTC |
| `risk_owner` | no | ≤ 200 chars |
| `impacted_business_division` | no | ≤ 200 chars |
| `existing_controls_all_subsystems` | no | `Yes` \| `No` |
| `existing_controls_all_subsystems_justification` | no | ≤ 1000 chars |
| `mitigation_start_date` | no | `YYYY-MM-DD` |
| `mitigation_end_date` | no | `YYYY-MM-DD` |

On the seven OPTIONAL fields an empty string is silently treated as "not provided"
(`_blank_is_absent`), not a validation error — `risk_level` is deliberately excluded from that
rule precisely because it is required. `mitigation_start_date`/`mitigation_end_date` must be
given together or not at all, and end must not precede start.

**Output (complete response):**

```json
202 {
  "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
  "status": "RUNNING"
}
```

`202` means "accepted for async generation," not "done" — poll Test 7d (or 7e) until `status` is `COMPLETE` or `ERROR`. The worker also fires an advisory `treatment_plan_result` event on the session's SSE stream (`GET /v1/sessions/{id}/events`) for an instant hand-off, but keep polling regardless: several failure paths never publish that event.

**How to test:**

1. Accept a scenario first (Test 6) — you need its `scenario_id` with `Accepted=1`.
2. POST the body above. Save `plan_id`.
3. Poll Test 7d until `progress.overall` leaves `generating`.
4. POST here AGAIN with the same body → must get `409 plan_already_exists`, even though the first plan may still be `RUNNING`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Threat_Scenario` | Read | confirms `Accepted=1`; supplies threat/scenario context for the snapshot |
| `Scoped_Threat`, `Identified_Threat` | Read | threat identity joined into the snapshot's threat block |
| `Threat_Scenario_Control_Map`, `Control_Library`, `Control_Library_Standard_Map`, `Control_Standard` | Read | the scenario's Step-4 mapped controls, frozen into the snapshot |
| `Scenario_Session` | Read | session row (asset/subsystem context) — the board load inside `get_authorized_session` is deliberately re-read in full here |
| `Risk_Treatment_Plan` | Write | new row, `Status='RUNNING'`, `Superseded=0`, `InputSnapshotJSON` = the frozen context |
| `Scenario_Audit` | Write | `treatment_plan_requested` event, `ScenarioID` + `PlanID` stamped on the row |

**Verify in the database:**

```sql
SELECT PlanID, Status, RiskLevel, Superseded, CreatedAt
FROM Risk_Treatment_Plan WHERE ScenarioID='<scenario_id>' AND Superseded=0;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Scenario's `Accepted` flag isn't 1 | `409 treatment_conflict`, `details.reason="scenario_not_accepted"` — "treatment plans are generated for accepted scenarios only" |
| ANY plan already exists for this scenario (RUNNING, COMPLETE, or ERROR) | `409 treatment_conflict`, `details.reason="plan_already_exists"` — "...use POST .../treatment-plan/regenerate to create a new version" |
| **Two concurrent first-creates** for the same scenario | the loser gets `409 treatment_conflict`, `details.reason="generation_in_progress"` — not `plan_already_exists`. The filtered unique index `UX_TreatmentPlan_ActiveScenario` is the arbiter, not the preceding SELECT, so this can never be a false positive |
| A rating out of range, mismatched mitigation dates, or any key outside the 12 | `422` (`errors[].type=="extra_forbidden"` for an unknown key) |
| `scenario_id` isn't a scenario of THIS session | `404 not_found` — "scenario not found in this session" |
| `session_id` doesn't exist | `404 not_found` |
| `X-Entity-Id` doesn't own the session | `403 forbidden` |
| Celery broker unreachable when enqueuing | `503` — the row is already committed and parked `ERROR`/`enqueue_failed`; regenerate to retry |

**Pass if:** `202` with `status: "RUNNING"`, a `Superseded=0` row appears immediately, and a repeat POST before regenerating 409s `plan_already_exists`.

---

### Test 7c — Regenerate a Treatment Plan ("Try again, freshen it up")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/regenerate` |
| **Why does this API exist?** | The scenario's mapped controls (or the scenario text itself) can change after the first plan was written. Every version after the first is minted here — the first-create endpoint (7b) refuses once a plan exists at all. |
| **What does it do?** | Retires the current ACTIVE version (`Superseded=1`), inserts a new `RUNNING` row baselined on it, and re-enqueues generation. The register's risk data is **reused, not resent** — read back from the active version's own frozen `InputSnapshotJSON` — but the scenario/controls half is rebuilt fresh against whatever they are right now. |
| **When do you call it?** | Any time after a plan already exists (whatever its status). A fresh RUNNING generation already in flight, or a plan that changed under you between the read and the retire, blocks this with `409`. |

**Input (complete request)** — the body is empty, and must be sent as a literal `{}`:

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan/regenerate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>" \
  -d '{}'
```

`TreatmentPlanRegenerateBody` (`app/api/schemas_treatment.py`) is `extra="forbid"` with **zero declared fields** — the old `user_note` steering key was removed; sending it, or any key, 422s. Sending no body at all typically fails JSON parsing before the model even runs, so send `{}` explicitly.

**Output (complete response):**

```json
202 {
  "plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf",
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
  "status": "RUNNING"
}
```

Same `TreatmentPlanAccepted` shape as 7b, but a **new** `plan_id` — the old one is now `Superseded=1`, not deleted.

**How to test:**

1. Regenerate the scenario from Test 7b (needs an existing plan, any status).
2. Save the new `plan_id` — confirm it differs from the one in 7b.
3. Re-run the DB check below: the old row shows `Superseded=1`, the new one `Superseded=0`.
4. POST again immediately (before the new generation finishes) → `409 generation_in_progress`.

**Environment quirk:** if this scenario has **never** had a plan requested at all, you get `404 not_found` ("no treatment plan has been requested for this scenario") here — not `409 scenario_not_accepted`, even if the scenario also happens to be unaccepted. The baseline lookup runs *before* the accept check on purpose (`app/api/treatment.py`, the comment marked "ORDER MATTERS"), matching what the old two-transaction design enforced.

**Tables used:** same set as Test 7b's write path (`Risk_Treatment_Plan`, `Scenario_Audit`, plus the same `Threat_Scenario`/`Scoped_Threat`/`Identified_Threat`/`Threat_Scenario_Control_Map`/`Control_Library*` reads) — the only difference is the retire-then-insert instead of a bare insert, and `Scenario_Audit` still gets a `treatment_plan_requested` row (not a distinct "regenerated" event type).

**Verify in the database:**

```sql
SELECT PlanID, Status, Superseded, CreatedAt
FROM Risk_Treatment_Plan WHERE ScenarioID='<scenario_id>' ORDER BY CreatedAt DESC;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| No plan has ever been requested for this scenario | `404 not_found` — "no treatment plan has been requested for this scenario" |
| Scenario's `Accepted` flag isn't 1 (and a plan already exists) | `409 treatment_conflict`, `details.reason="scenario_not_accepted"` |
| A fresh RUNNING generation already in flight, or the active row changed underneath you (a concurrent regenerate/review-swap won the race) | `409 treatment_conflict`, `details.reason="generation_in_progress"` |
| Any key at all in the body | `422` (`extra_forbidden`) |
| Broker unreachable | `503` — row parked `ERROR`/`enqueue_failed`, retry with another regenerate |

**Pass if:** a new `plan_id` comes back `202 RUNNING`, the old row flips to `Superseded=1`, and a second regenerate before the first finishes 409s.

---

### Test 7d — Poll Treatment Plan Status ("Are we there yet?")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status` |
| **Why does this API exist?** | A plan poller hitting the full GET (Test 7e) on a timer would re-download tens of KB of `PlanJSON` every tick for three strings it actually reads. This is the cheap poll — lifecycle only, no plan content, no scenario, no threat. |
| **What does it do?** | Returns `status`, `progress` (the same `{generation, review, overall}` fold the board uses), `review_status`, and timestamps — nothing else. `dal.plan_status_row` selects plan-table columns only, deliberately never joining `PlanJSON`/`ScenarioJSON`/the threat tables. |
| **When do you call it?** | Right after 7b/7c's `202`, on a timer, until `progress.overall` leaves `generating`. Switch to Test 7e once you actually need the plan content. |

**Input (complete request)** — no body, no query params, path only:

```bash
curl -s "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan/status" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
  "plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf",
  "progress": {"generation": "COMPLETE", "review": "PENDING", "overall": "awaiting_review"},
  "status": "COMPLETE",
  "review_status": null,
  "reviewed_by": null,
  "reviewed_at": null,
  "created_by": "qa-user",
  "error_message": null,
  "reason": null,
  "created_at": "2026-08-31T09:14:00",
  "updated_at": "2026-08-31T09:16:42",
  "completed_at": "2026-08-31T09:16:42"
}
```

Switch the UI on `progress.overall` — it names the state AND the action it implies: `pending` → Generate, `generating` → spinner, `awaiting_review` → Review, `rejected` → Regenerate, `approved` → done, `error` → Retry. `pending` can **never** appear in a `200` body here — no plan row at all IS the pending state, and that's a `404`, not a `200` with `pending` inside it.

**How to test:**

1. Immediately after 7b's `202`, poll here → `status: "RUNNING"`, `progress.overall: "generating"`.
2. Keep polling until `status` flips to `COMPLETE` or `ERROR`.
3. Call this on a `scenario_id` that never had a plan requested → `404`.

**Environment quirk:** a `RUNNING` row whose progress clock hasn't moved in over `treatment_stale_seconds` is *presented* here as `status: "ERROR"`, `reason: "timed_out"` — the stored row is never rewritten (no reaper), so a late worker finish can still land and flip it back on a later poll. That's a read-time projection shared with Test 7e and the board (Test 7f); all three can never disagree about the same plan.

**Verify in the database:**

```sql
SELECT PlanID, Status, ReviewStatus, ReviewedBy, UpdatedAt, CompletedAt
FROM Risk_Treatment_Plan WHERE SessionID='<session_id>' AND ScenarioID='<scenario_id>' AND Superseded=0;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| No plan has ever been requested for this scenario | `404 not_found` — treat this as the `pending` state, not an error |
| `scenario_id` not a scenario of this session, or `session_id` unknown | `404 not_found` |
| `X-Entity-Id` doesn't own the session | `403 forbidden` |

**Pass if:** the poll tracks the same lifecycle Test 7e shows, without ever hauling `plan`/`scenario`/`threat` content.

---

### Test 7e — Get the Full Treatment Plan ("Show me the whole thing")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` |
| **Why does this API exist?** | Once Test 7d says `COMPLETE`, this is where you actually read the AI's plan — the recommended controls, the action plan, the timeline — plus the full scenario/threat/actor/controls context, so a reviewer never has to cross-reference the results screen. |
| **What does it do?** | Returns the scenario's one ACTIVE plan row: the same `scenario`/`threat`/`actors`/`controls` blocks `GET .../results` publishes (built by the identical function, so the two screens can never disagree), plus the AI-authored `plan` document itself. |
| **When do you call it?** | Once `status` is `COMPLETE` (works on `RUNNING`/`ERROR` too — `plan` is just `null`). Add `?include_superseded=true` to also pull every regenerated-away version. |

**Input (complete request)** — path params only; optional `?include_superseded=true|false` (default `false`):

```bash
curl -s "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {
  "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
  "progress": {"generation": "COMPLETE", "review": "PENDING", "overall": "awaiting_review"},
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
  "status": "COMPLETE",
  "treatment_strategy": "Mitigate",
  "scenario": {
    "threat_category": "Elevation of Privilege",
    "threat_type": "Credential Abuse",
    "threat_name": "Stolen RDP credentials",
    "scenario_title": "Ransomware via exposed RDP",
    "scenario_statement": "A ransomware operator gains access through...",
    "risk_statement": "Loss of treatment-plant availability...",
    "supporting_systems_involved": [
      {"supporting_system_id": 321, "supporting_system": "HMI Workstation", "is_entry_point": true, "justification": ""}
    ]
  },
  "threat": {
    "threat_id": "9c1e...", "threat_category": "Elevation of Privilege", "threat_category_id": 4,
    "threat_type": "Credential Abuse", "threat_name": "Stolen RDP credentials",
    "library_threat_type": "Credential Abuse", "library_threat_name": "Stolen RDP credentials",
    "grounding_status": "grounded", "is_threat_type_ai_generated": false, "is_threat_ai_generated": false
  },
  "actors": [
    {"actor_id": 12, "actor_name": "Nation-state/APT"},
    {"actor_id": 31, "actor_name": "Malicious insider"}
  ],
  "controls": [
    {"control_id": 70, "control_code": "CII-CID-070", "domain": "Configuration Management",
     "control_name": "Access Restriction For Change", "map_rank": 1, "score": 0.87,
     "standards": [{"standard_id": 4, "standard_name": "IEC 62443"}]}
  ],
  "controls_unavailable": false,
  "risk_level": "Critical",
  "review_status": null,
  "reviewed_by": null,
  "reviewed_at": null,
  "created_by": "qa-user",
  "cancelled_by": null,
  "cancelled_at": null,
  "risk_identification_date": "2026-06-14T08:31:00",
  "plan": {
    "title": "Remote Access Hardening",
    "treatment_plan": "Mitigate",
    "action_plan": "Harden remote access in three phases...",
    "applicable_to_all_subsystems": "No",
    "controls_to_be_implemented": {
      "control_coverage": "gaps",
      "controls": [
        {"control_type": "preventive", "control_name": "Access Restriction For Change",
         "description": "Enforce role-based access control and least-privilege...",
         "priority": "Critical", "control_code": "CII-CID-070", "control_library_id": 70,
         "domain": "Configuration Management"}
      ]
    },
    "remediation_action_plan": [
      {"action_id": "A1", "action": "Disable direct RDP exposure at the perimeter firewall.",
       "owner": "OT Security Team", "priority": "Critical", "dependencies": "None",
       "timeline": "2026-08-15",
       "success_criteria": "No inbound 3389 permitted from any untrusted zone."},
      {"action_id": "A2", "action": "Enforce MFA on every remote-access account.",
       "owner": "IAM Team", "priority": "High", "dependencies": "A1",
       "timeline": "2026-09-28",
       "success_criteria": "100% of remote accounts enrolled and verified."}
    ],
    "mitigation_timeline": "2026-09-28",
    "mitigation_owner": "OT Security Team",
    "risk_owner": "Head of OT Operations",
    "impacted_business_division": "Water Treatment Operations"
  },
  "warnings": [],
  "moderation_flagged": false,
  "error_message": null,
  "reason": null,
  "superseded": null
}
```

`plan` carries exactly the ten keys of `TreatmentPlanDocument` that the stored document
actually has — `treatment_presenter._VISIBLE_PLAN_KEYS` is derived from that model, so the
projection cannot drift from it. `remediation_action_plan` is the one to check first: it is
the numbered work itself, each row `{action_id, action, owner, priority, dependencies,
timeline, success_criteria}`, and generation refuses a plan whose
`remediation_action_plan` is **missing or not a list of objects**
(`TreatmentPlanInvalid: LLM plan is missing required table 'remediation_action_plan'`). An
**empty** array is NOT refused: the plan still reaches `COMPLETE`, carrying
`remediation_action_plan is empty — the prompt mandates at least one action...` in `warnings`.
So check `warnings` before treating a `COMPLETE` plan as actionable.
`action_plan` is the prose roll-up of those same rows, `mitigation_timeline` the latest date
among them. The prompt demands an absolute date for every `timeline`, but that is **not enforced**: a
non-date value is first tried as a duration ("30 days") and, failing that, recorded as a
warning — never rejected. A prose or duration `timeline` can therefore survive into a
`COMPLETE` plan, so validate it client-side rather than assuming a date. `priority` is drawn from
`Critical`/`High`/`Medium`/`Low`; a value outside that set is recorded in `warnings` rather
than rejected. Note the stored `risk_identification_date` is trimmed out of `plan` — it is
published as the sibling field of the same name instead, never in both places.

**Environment quirk:** `review_comment` is declared on `TreatmentPlanStatus` but marked `exclude=True` — populated in the DB, **never** on the wire. Same for `created_at`/`completed_at` — all three are `exclude=True` on `TreatmentPlanStatus` in `app/api/schemas_treatment.py` — a "presentation trim" applied 06-Aug-2026, still in effect. Don't be surprised when the model description mentions a field the JSON never shows.

**How to test:**

1. GET here on a `COMPLETE` scenario → `plan` is populated, `progress.overall` is `awaiting_review` (nobody's reviewed it yet).
2. GET with `?include_superseded=true` after regenerating (Test 7c) → `superseded` is a non-empty array, newest first. Each entry is a FULL one: its own `plan`, review verdict, `created_by`, `cancelled_by`/`cancelled_at`, `warnings` and `moderation_flagged`, plus the same `scenario`/`threat`/`actors`/`controls` as the top level (those four are version-independent, so they are read once and repeated rather than re-queried per version). Only `progress` is `null` on them — a retired version is history, not a live lifecycle. Use these entries to pick which `plan_id` to adopt in Test 7f. `controls_unavailable` is `false` on every entry on a healthy read; `true` means the control map could not be read this time — treat `controls` as unknown, not as a library gap.
3. GET on a scenario that never had a plan requested → `404`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Risk_Treatment_Plan` | Read | the active (`Superseded=0`) row, plus history rows if `?include_superseded=true` |
| `Threat_Scenario`, `Scoped_Threat`, `Identified_Threat` | Read | the `scenario`/`threat` blocks, same builder `/results` uses |
| `Threat_Scenario_Control_Map`, `Control_Library` | Read | the `controls` block — a failed read is what sets `controls_unavailable: true` |
| `Control_Library_Standard_Map`, `Control_Standard` | Read | the `standards[]` inside each control |
| `Threat_Actor` | Read | the `actors` block, on the legacy-name fallback path |

**Verify in the database:**

```sql
SELECT PlanID, Status, UpdatedAt, ReviewStatus, ErrorReason
FROM Risk_Treatment_Plan WHERE ScenarioID='<scenario_id>' AND Superseded=0;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| No plan has ever been requested for this scenario | `404 not_found` — "no treatment plan has been requested for this scenario" |
| `X-Entity-Id` doesn't own the session | `403 forbidden` |

**Pass if:** `plan` matches what 7b/7c's generation produced, `progress` agrees with what Test 7d showed for the same plan, and `?include_superseded=true` surfaces every regenerated-away version after Test 7c.

---

### Test 7f — Get a Session's Treatment-Plan Board ("Show me the whole board")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/treatment-plans` |
| **Why does this API exist?** | A reviewer doesn't poll one scenario at a time — this is every accepted scenario's plan state, and the session-wide progress rollup, in ONE call (replaces N per-scenario polls). |
| **What does it do?** | One row per accepted scenario (whichever version was accepted, even a superseded one), LEFT-joined to its active plan. `plan_id`/`status`/etc. are all `null` together for a scenario with no plan yet — the UI's "Generate" state — never a partial mix. |
| **When do you call it?** | Any time, including on a session with zero accepted scenarios — that's a normal `200` with `accepted_scenarios: 0`, `plans: []`, never a `404`. |

**Input (complete request)** — path param only; optional `?include_plan=true`, `?include_superseded=true` (both default `false`):

```bash
curl -s "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/treatment-plans" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "accepted_scenarios": 2,
  "progress": {"generation": "RUNNING", "review": "PENDING", "overall": "generating"},
  "plans": [
    {"scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90", "scenario_title": "Ransomware via exposed RDP",
     "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180", "status": "COMPLETE", "risk_level": "Critical",
     "review_status": "approved", "error_message": null, "reason": null,
     "plan": null, "superseded": null,
     "created_at": "2026-08-31T09:14:00", "completed_at": "2026-08-31T09:16:42"},
    {"scenario_id": "9f3c1e22-93a4-4f10-9a83-0f4c113b2a1e", "scenario_title": "Insider tampering with historian data",
     "plan_id": null, "status": null, "risk_level": null, "review_status": null,
     "error_message": null, "reason": null, "plan": null, "superseded": null,
     "created_at": null, "completed_at": null}
  ]
}
```

Note `progress` here is `RUNNING`/`generating`, not `COMPLETE`/`approved`, even though the first plan is done and approved — because the SECOND accepted scenario has **no plan requested at all**, and an unplanned accepted scenario counts against generation, not review. Read `progress` before you read `plans` if all you want is a one-line session status.

**How to test:**

1. GET here with one scenario planned+approved, one accepted-but-not-yet-planned → matches the shape above.
2. Add `?include_plan=true` → the first row's `plan` field fills in with the same trimmed object Test 7e serves; the second stays `null` (never requested).
3. Add `?include_superseded=true` after a regenerate → each row's `superseded` lists its replaced versions: the SAME full entries Test 7e's GET serves (scenario/threat/actors/controls, `created_by`, `warnings`, `moderation_flagged`, `controls_unavailable`; `progress` null). Without the flag `superseded` is `null` and the board query is unchanged.
4. GET on a session with nothing accepted → `200`, `accepted_scenarios: 0`, `plans: []` — not a `404`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Threat_Scenario` | Read | every row with `Accepted=1` for this session |
| `Risk_Treatment_Plan` | Read | LEFT-joined per accepted scenario on `Superseded=0` |

**Verify in the database:**

```sql
SELECT ts.ScenarioID, ts.Accepted, p.PlanID, p.Status
FROM Threat_Scenario ts LEFT JOIN Risk_Treatment_Plan p
  ON p.ScenarioID = ts.ScenarioID AND p.Superseded = 0
WHERE ts.SessionID = '<session_id>' AND ts.Accepted = 1;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| `session_id` doesn't exist | `404 not_found` |
| `X-Entity-Id` doesn't own the session | `403 forbidden` |

There is deliberately **no** 404 for "no accepted scenarios" or "no plans" — those are just empty results, not error conditions.

**Pass if:** every accepted scenario appears exactly once, `plan_id`/`status` fields are all-null or all-populated together (never partial), and `progress` matches what you'd derive by eye from the `plans` array.

---

### Test 7g — Cancel a Treatment Plan ("Forget it, stop the order")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/cancel` |
| **Why does this API exist?** | Same idea as Test 7's "the human decision is the whole point" — this is the stop button: flip a RUNNING generation to `ERROR` right now, instead of waiting out the staleness timeout after a mistaken click. |
| **What does it do?** | Flips the active RUNNING row to `ERROR` (`ErrorReason='cancelled'`, `CancelledBy`/`CancelledAt` stamped). Never deletes the row, and any LLM spend the worker already made stays on `Prompt_Log` untouched. |
| **When do you call it?** | Only while the plan is genuinely `RUNNING`. Race-safe: if the worker's own finish beat you to it, you get `409`, not a silent no-op. |

**Input (complete request)** — no body, no query params:

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan/cancel" \
  -H "X-API-Key: <X-API-Key>" \
  -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" \
  -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {
  "plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf",
  "status": "ERROR",
  "error_message": "cancelled by user"
}
```

**How to test:**

1. Kick off a generation (Test 7b or 7c) — you want to catch it while `status` is still `RUNNING`.
2. POST cancel immediately.
3. Re-run Test 7d: `status: "ERROR"`, `reason: "cancelled"` (not `timed_out` — that's a different reason, only for a dead worker).
4. Call cancel AGAIN on the same scenario → `409 not_in_progress` (it's already terminal).

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Risk_Treatment_Plan` | Write | `Status='ERROR'`, `ErrorReason='cancelled'`, `CancelledBy`/`CancelledAt` stamped — fenced by `ActiveTaskID` so a worker reclaiming the row between the SELECT and the UPDATE can't silently lose the cancel |
| `Scenario_Audit` | Write | `treatment_plan_cancelled` event |

**Verify in the database:**

```sql
SELECT PlanID, Status, ErrorReason, CancelledBy, CancelledAt
FROM Risk_Treatment_Plan WHERE ScenarioID='<scenario_id>' AND Superseded=0;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| No plan has ever been requested for this scenario | `404 not_found` — "no treatment plan has been requested for this scenario" |
| Plan isn't `RUNNING` (already `COMPLETE`/`ERROR`, including an already-cancelled one, or the worker's own finish just won the race) | `409 treatment_conflict`, `details.reason="not_in_progress"` — "no generation is in progress for this scenario" |

**Pass if:** the plan becomes `ERROR`/`cancelled by user`, `CancelledBy` matches your `X-User-Id`, and a repeat cancel 409s.

---

### Test 7h — Review a Treatment Plan ("The human says yea or nay.")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/review` |
| **Why does this API exist?** | Same principle as Accept Session — the AI writes a treatment plan, a person decides whether to run with it. This records that decision. |
| **What does it do?** | Stamps `approved` or `rejected` onto the **COMPLETE** plan version named by `plan_id`. Name the active version to decide on the current plan; name a historical one with `approved` and it is reinstated as the active plan in the same call — approving an older version IS choosing it. |
| **When do you call it?** | Once the plan's status is `COMPLETE`. A re-review overwrites the previous verdict — latest decision wins, and a regenerated plan always starts unreviewed. |

**Input (complete request)** — `plan_id` is REQUIRED and names the version being decided on:

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan/review" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>" \
  -d '{"decision": "approved", "plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180", "comment": "A3 timeline extended per operations."}'
```

| Field | Required | Meaning |
|---|---|---|
| `decision` | yes | `approved` or `rejected` |
| `comment` | no | free text, capped at 2000 chars, redacted like every other stored note |
| `plan_id` | **yes** | the version this decision applies to. Pass the ACTIVE version's own id to review the current plan; pass a HISTORICAL version's id (from `GET .../treatment-plan?include_superseded=true`) **with `decision: "approved"`** to make that version current AND approve it, atomically. Required on purpose — "whatever is active right now" would let a regeneration landing between your GET and this POST move the verdict onto a version nobody read. Omitting it is a `422`. |

**Output (complete response):**

```json
200 {"plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
     "review_status": "approved",
     "reviewed_by": "qa-user",
     "reviewed_at": "2026-08-31T09:14:02"}
```

`reviewed_by` always comes from `X-User-Id` — the body has no reviewer field, on purpose: nobody can review as someone else.

**How to test:**

1. Generate a plan and let it reach `COMPLETE`, then POST this review.
2. Re-run `GET .../treatment-plan`: `review_status` matches, `reviewed_by`/`reviewed_at` are stamped.
3. Review again with the opposite decision — the verdict overwrites; only the latest shows.
4. To exercise the version-switch branch: regenerate the plan once (a fresh active version, unreviewed), then POST here with `plan_id` set to the FIRST plan's id and `decision: "approved"`. The old plan becomes active again; the regenerated one becomes history — both keep their own verdicts.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Risk_Treatment_Plan` | Write | `ReviewStatus`/`ReviewComment`/`ReviewedBy`/`ReviewedAt` on the target row; on a version switch, the old active row's `Superseded` flips to 1 and the target's flips back to 0 |
| `Scenario_Audit` | Write | `treatment_plan_reviewed`; also `treatment_plan_version_restored` when a historical `plan_id` was supplied |

**Verify in the database:**

```sql
SELECT PlanID, ReviewStatus, ReviewComment, ReviewedBy, ReviewedAt, Superseded
FROM Risk_Treatment_Plan WHERE ScenarioID='1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90';

SELECT EventType, ActorUserID, ActorType, CreatedAt, DetailJSON
FROM Scenario_Audit
WHERE ScenarioID='1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90'
  AND EventType IN ('treatment_plan_reviewed','treatment_plan_version_restored')
ORDER BY CreatedAt;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Omit `decision`, or send anything other than `approved`/`rejected` | `422` |
| `plan_id` that isn't a valid GUID | `422` |
| No plan has ever been requested for this scenario | `404 not_found` |
| `plan_id` names a version that doesn't belong to this scenario at all | `404 not_found` — "no such plan version for this scenario" |
| Active plan is still `RUNNING` or ended `ERROR` (not `COMPLETE`) | `409 treatment_conflict` — `details.reason: "not_complete"` |
| A **historical** `plan_id` you tried to approve is itself not `COMPLETE` | `409 treatment_conflict` — `details.reason: "not_complete"` as well. The reinstate is CAS-fenced on `(Superseded=1, Status=COMPLETE)`, and a miss rolls the retire back, so the active version is left exactly as it was |
| Historical `plan_id` + `decision: "rejected"` | `409 treatment_conflict` — `details.reason: "version_not_active"` (it's already not the plan; rejecting it means nothing) |
| Historical `plan_id` while a fresh regeneration is `RUNNING` | `409 treatment_conflict` — `details.reason: "generation_in_progress"` |

**Pass if:** the plan's `review_status` matches what you sent, `reviewed_by` is your `X-User-Id`, and (on a version-switch request) the historical plan becomes the active one.

---

### Test 7i — Get an Entity's Treatment-Plan Register ("Every plan, one page, filterable.")

| | |
|---|---|
| **API** | `GET /v1/entities/{entity_id}/treatment-plans` |
| **Why does this API exist?** | "Which Critical risks still have no approved plan?" spans every asset an entity owns — this is the one page that answers it without a database ticket. |
| **What does it do?** | Lists every plan (across every session/scenario) belonging to the entity, newest first, filterable by status/review outcome/risk level. |
| **When do you call it?** | Any time — it's a read-only register view, not tied to any single session's lifecycle. |

**Input (complete request):**

```bash
curl -s -X GET "http://localhost:8000/v1/entities/78/treatment-plans?risk_level=Critical&status=COMPLETE&limit=100&offset=0" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

| Query param | Default | Meaning |
|---|---|---|
| `status` | none | `RUNNING` \| `COMPLETE` \| `ERROR` — a stale, timed-out `RUNNING` row is presented (and filtered) as `ERROR` |
| `review_status` | none | `approved` \| `rejected` |
| `risk_level` | none | `Low` \| `Medium` \| `High` \| `Critical` |
| `include_plan` | `false` | also return each plan's content — the same trimmed object the single-plan GET serves |
| `limit` | 100 | 1-500 |
| `offset` | 0 | 0+ |

**Output (complete response)** — default, `include_plan=false`:

```json
200 {"entity_id": "78", "limit": 100, "offset": 0,
     "plans": [
       {"plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
        "asset_name": "RTU-103", "scenario_title": "Ransomware via exposed RDP",
        "status": "COMPLETE", "risk_level": "Critical",
        "review_status": "approved", "reviewed_by": "qa-user",
        "error_message": null, "reason": null,
        "scenario": null, "threat": null, "actors": [], "controls": [], "controls_unavailable": false,
        "treatment_strategy": null, "risk_identification_date": null, "plan": null,
        "created_at": "2026-08-30T11:02:00", "completed_at": "2026-08-30T11:04:12"}
     ]}
```

Every key above is always present. With `include_plan=true`, `scenario`, `threat`, `actors`, `controls` (and `controls_unavailable` — `true` means the control map could not be read, not that the library has nothing), `treatment_strategy`, `risk_identification_date` and `plan` are populated instead of null/empty.

**How to test:**

1. Call with no filters — every plan for entity 78 comes back, newest first.
2. Add `risk_level=Critical` — only Critical rows remain.
3. Add `include_plan=true` — each COMPLETE row now carries a `plan` object; RUNNING/ERROR rows keep `plan: null`.
4. Call for an entity NOT in your `X-Entity-Id` — must 403, never leak a page for it.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Risk_Treatment_Plan` | Read | the register's rows, filtered/paged |
| `Scenario_Session` | Read | **always** — inner-joined; it is the `EntityID` authorization filter and the source of `asset_name` |
| `Threat_Scenario` | Read | **always** — outer-joined; supplies `scenario_title`, which the default `include_plan=false` response already shows |
| `Scoped_Threat`, `Identified_Threat` | Read | only when `include_plan=true` — the `scenario`/`threat` blocks |

**Verify in the database:**

```sql
SELECT TOP 100 PlanID, ScenarioID, Status, RiskLevel, ReviewStatus, CreatedAt
FROM Risk_Treatment_Plan WHERE EntityID='78' ORDER BY CreatedAt DESC;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| `status` set to anything other than `RUNNING`/`COMPLETE`/`ERROR` | `422` |
| `limit` outside 1-500, or `offset` negative | `422` |
| `entity_id` in the path ≠ your `X-Entity-Id` | `403 forbidden` |

**Pass if:** every returned row belongs to entity 78, every filter narrows the list correctly, and `include_plan=true` matches the single-plan GET byte-for-byte on the same plan.

---

### Test 7j — Get One Plan's Audit Trail ("This scenario's whole plan history, in order.")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/audit` |
| **Why does this API exist?** | A reviewer needs the full story for one scenario's plan — every version, who asked for it, what happened, who decided — not just the current snapshot. |
| **What does it do?** | Returns every treatment-plan event for this scenario across ALL versions, oldest first, plus synthesized `superseded` entries pulled straight from the version chain. |
| **When do you call it?** | Investigating a rejected plan, an audit request, a support ticket — the "why does this plan look like this" story. |

**Input (complete request):**

```bash
curl -s -X GET "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan/audit" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {"session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
     "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90",
     "events": [
       {"at": "2026-08-30T11:02:00", "event": "requested",
        "actor": "qa-user", "actor_type": "user", "session_id": null,
        "detail": {"plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf",
                    "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90"}},
       {"at": "2026-08-30T11:04:12", "event": "outcome",
        "actor": null, "actor_type": "system", "session_id": null,
        "detail": {"plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf", "status": "COMPLETE"}},
       {"at": "2026-08-30T14:10:00", "event": "superseded",
        "actor": null, "actor_type": null, "session_id": null,
        "detail": {"plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf"}},
       {"at": "2026-08-30T14:15:31", "event": "reviewed",
        "actor": "qa-user", "actor_type": "user", "session_id": null,
        "detail": {"plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180", "decision": "approved"}}
     ]}
```

`event` is a short verb — `requested` / `outcome` / `cancelled` / `reviewed` / `version restored` / `superseded`. The last one has no writer row at all: it's synthesized here from `Risk_Treatment_Plan.Superseded=1` rows in the version chain, not read from `Scenario_Audit`.

**How to test:**

1. Request a plan, let it complete, review it, regenerate it — then pull this trail and confirm every step shows up, oldest first.
2. Confirm a `superseded` entry appears for the version you regenerated away, even though no writer put that row there directly.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Audit` | Read | `requested`/`outcome`/`cancelled`/`reviewed`/`version restored` rows, filtered on `ScenarioID` |
| `Risk_Treatment_Plan` | Read | every version for this scenario — `Superseded=1` rows become the synthesized `superseded` entries |

**Verify in the database:**

```sql
SELECT EventType, ActorUserID, ActorType, CreatedAt, DetailJSON
FROM Scenario_Audit WHERE ScenarioID='1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90'
  AND EventType LIKE 'treatment_plan%' ORDER BY CreatedAt;

SELECT PlanID, Superseded, UpdatedAt FROM Risk_Treatment_Plan
WHERE ScenarioID='1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90' ORDER BY CreatedAt;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| No plan has ever been requested for this scenario | `404 not_found` |
| A `session_id`/`scenario_id` pair not authorized for your entity | `403 forbidden` (checked before the plan lookup) |

**Pass if:** events come back oldest-first, one `requested`/`outcome` pair per version, and every `Superseded=1` row shows a matching `superseded` entry.

---

### Test 7k — Get an Entity's Treatment-Plan Audit Trail ("All plan activity, entity-wide, newest first.")

| | |
|---|---|
| **API** | `GET /v1/entities/{entity_id}/treatment-plans/audit` |
| **Why does this API exist?** | The compliance feed: "every treatment-plan action across the entity in August" as one request instead of a database ticket. |
| **What does it do?** | Every treatment-plan event for the entity — across every session and scenario — newest first, filterable by date range and by who did it. |
| **When do you call it?** | Compliance reporting, investigating one actor's activity, or a periodic export. |

**Input (complete request):**

```bash
curl -s -X GET "http://localhost:8000/v1/entities/78/treatment-plans/audit?from=2026-08-01T00:00:00Z&to=2026-08-31T23:59:59Z&user_id=qa-user&limit=200&offset=0" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

| Query param | Default | Meaning |
|---|---|---|
| `from` | none | earliest `CreatedAt`, any UTC offset accepted (normalized to naive UTC before matching) |
| `to` | none | latest `CreatedAt`, same rule |
| `user_id` | none | filter to one actor |
| `limit` | 200 | 1-1000 |
| `offset` | 0 | 0+ |

**Output (complete response):**

```json
200 {"entity_id": "78", "limit": 200, "offset": 0,
     "events": [
       {"at": "2026-08-30T14:15:31", "event": "reviewed",
        "actor": "qa-user", "actor_type": "user",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "detail": {"plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180", "decision": "approved"}},
       {"at": "2026-08-30T11:02:00", "event": "requested",
        "actor": "qa-user", "actor_type": "user",
        "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
        "detail": {"plan_id": "442b4bd2-98ab-8ac4-b589-01a054d68dbf",
                    "scenario_id": "1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90"}}
     ]}
```

The one difference from Test 7j's per-scenario trail: every event here carries `session_id`, since a single page mixes events from many sessions.

**How to test:**

1. Call with no filters — every treatment-plan event for entity 78 comes back, newest first.
2. Narrow with `from`/`to` to a window you know contains exactly one event; confirm the count.
3. Narrow with `user_id` to your own actions only.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Audit` | Read | every treatment-plan event for the entity, date/actor filtered, paged |

**Verify in the database:**

```sql
SELECT TOP 200 EventType, ActorUserID, SessionID, CreatedAt, DetailJSON
FROM Scenario_Audit
WHERE EntityID='78' AND EventType LIKE 'treatment_plan%'
ORDER BY CreatedAt DESC;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| `limit` outside 1-1000, or `offset` negative | `422` |
| `from`/`to` not a parseable datetime | `422` |
| `entity_id` in the path ≠ your `X-Entity-Id` | `403 forbidden` |

**Pass if:** events are newest-first, every filter narrows correctly, and every row's `session_id` matches its own plan's session.

---

### Test 7l — Get a Plan's Evidence Bundle ("Exactly what the AI was shown, and exactly what it said back.")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/evidence` |
| **Why does this API exist?** | Reproducibility. If a plan is challenged, this is the receipt: the frozen input the AI actually saw, the validation record, and every raw AI call byte-for-byte — even for a version replaced long ago. |
| **What does it do?** | Returns one plan VERSION's evidence bundle. `status` here is the STORED value, deliberately unprojected — no staleness rewrite, unlike the poll GET. |
| **When do you call it?** | Auditing a specific plan version, or debugging why a generation produced what it did. |

**Input (complete request)** — `version` is required and names the exact `plan_id` to inspect (a superseded version is fine):

```bash
curl -s -X GET "http://localhost:8000/v1/sessions/5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e/scenarios/1a2b3c4d-5e6f-8788-898a-8b8c8d8e8f90/treatment-plan/evidence?version=0f0e0d0c-0b0a-8988-8786-858483828180" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {"plan_id": "0f0e0d0c-0b0a-8988-8786-858483828180", "status": "COMPLETE",
     "input_snapshot": {"asset": {"asset_id": 103, "asset_name": "RTU-103"},
                         "scenario": {"scenario_title": "Ransomware via exposed RDP"},
                         "risk_level": "Critical", "existing_controls": ["annual patching"]},
     "validation": {"warnings": [], "moderation": {"flagged": false}},
     "attempts": [
       {"at": "2026-08-30T11:03:40",
        "prompt": "You are generating a Mitigate treatment plan for…",
        "response": "{\"title\": \"Remote Access Hardening\", …}",
        "model_name": "gpt-4o", "model_version": "2024-08-06",
        "prompt_version": "treatment-v3", "parse_succeeded": true}
     ]}
```

`input_snapshot` is exactly what `build_treatment_input` froze at generation time — the register data from the POST body plus the session's own asset/scenario/controls context. `attempts` is every `Prompt_Log` row joined by `CorrelationID`; a call made before that column existed carries no linkage, so `attempts` can legitimately be `[]` on an old plan.

**How to test:**

1. Pull the evidence for the CURRENT `plan_id` — `status` should read `COMPLETE`, `attempts` non-empty.
2. Regenerate the plan, then pull evidence again with `?version=<old-plan-id>` — it must still return the OLD snapshot/attempts untouched.
3. Compare `input_snapshot.existing_controls` against what you sent in the original POST body — must match exactly (frozen, never re-derived).

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Risk_Treatment_Plan` | Read | the named version's `Status`, `InputSnapshotJSON`, `ValidationJSON` |
| `Prompt_Log` | Read | every row whose `CorrelationID` matches the `PlanID` |

**Verify in the database:**

```sql
SELECT PlanID, Status, InputSnapshotJSON, ValidationJSON
FROM Risk_Treatment_Plan WHERE PlanID='0f0e0d0c-0b0a-8988-8786-858483828180';

SELECT CreatedAt, Prompt, ResponseText, Model, ModelVersion, PromptVersion, ParseSucceeded
FROM Prompt_Log WHERE CorrelationID='0f0e0d0c-0b0a-8988-8786-858483828180'
ORDER BY CreatedAt;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Omit `version` | `422` (it's a required query param) |
| `version` names a `plan_id` that isn't any version of THIS scenario | `404 not_found` — "no such plan version for this scenario" |
| A `session_id`/`scenario_id` not authorized for your entity | `403 forbidden` |

**Pass if:** `input_snapshot` matches the exact register data you POSTed, and `status` here is the raw stored value even when the poll GET would present the same row as timed-out `ERROR`.

---
## Part 5 — Supplementary Tests (P2: if time permits)

### Test 8 — Live Session Events / SSE ("The live pizza tracker")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/events` (header `Accept: text/event-stream`) — no `response_model` (SSE); the 10 possible event bodies are typed via `responses=` for OpenAPI generation only |
| **Why does this API exist?** | Polling Test 2 in a loop is wasteful and laggy. A UI showing live progress needs the server to push updates the moment they happen. |
| **What does it do?** | Keeps the connection open and streams named events: a full snapshot on connect, then every state change, plus heartbeats. |
| **When do you call it?** | On any session id, active or terminal. Best opened before triggering Test 4/5, so you can watch them happen. |

**Input (complete request):**

```bash
curl -N -H "Accept: text/event-stream" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>" \
  "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/events"
```

**Not a browser `EventSource`.** This route requires the same `X-API-Key`/`X-User-Id`/
`X-Entity-Id`/`X-Tenant-Id` headers as every other route, and the native `EventSource` API cannot
set custom headers — it simply cannot authenticate against this endpoint. A UI must drive the
stream with `fetch()` and a `ReadableStream` reader instead (a worked example ships at
`app/static/sse_test.html`).

**Output (what the wire actually looks like)** — `200` with
`Content-Type: text/event-stream`. Each event is an `event:` line, a `data:`
line, then a blank line (the blank line ends one event):

```
event: reconcile
data: {"type":"reconcile","session_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","entity_id":"78","asset_id":103,"asset_name":"CAD Platform","user_id":"qa-user","session_status":"active","current_stage":"THREAT_IDENTIFICATION","stage_status":"RUNNING","progress":{"threats":"RUNNING","scenarios":"IDLE","overall":"in_progress","controls":"PENDING","error_message":{},"timings":{},"last_next_set":null,"last_regen":null,"coverage":null}}

event: stage_completed
data: {"type":"stage_completed","session_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","subsystem_id":0,"stage":"THREATS","status":"COMPLETE","generation_epoch":1,"ts":"2026-08-31T09:15:02.118427+00:00"}

event: session_entered_review
data: {"type":"session_entered_review","session_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","status":"SCENARIOS_AWAITING_DECISION","generation_epoch":1,"ts":"2026-08-31T09:18:44.902001+00:00"}

event: heartbeat
data: {"type":"heartbeat","session_id":"3fa85f64-5717-4562-b3fc-2c963f66afa6","ts":"2026-08-31T09:19:14.000000+00:00"}
```

`reconcile`'s payload is the exact `SessionBoard` shape GET `/v1/sessions/{session_id}` returns
(Test 2), with a `"type":"reconcile"` key stitched on — it is a snapshot, not a delta, and it does
**not** carry treatment-plan state.

**Every event type you can receive:**

| `type` | When it fires | Carries `subsystem_id`? |
|---|---|---|
| `reconcile` | Once, immediately on connect — the full board snapshot | no (whole board) |
| `subsystem_started` | Work began, before its stages run | yes |
| `stage_started` | One stage (`THREATS` or `SCENARIOS`) began | yes |
| `stage_completed` | That stage finished (`THREATS`→`COMPLETE`, `SCENARIOS`→`SCENARIOS_AWAITING_DECISION` — a failure routes to `error` instead) | yes |
| `session_entered_review` | Every subsystem hit its review barrier; session parked at REVIEW waiting on a human | no — session-wide |
| `next_set_result` | A "give me more" click finished | yes |
| `regen_result` | A "redo this one" click finished | yes |
| `treatment_plan_result` | One treatment plan reached a committed `COMPLETE`/`ERROR` — keyed by `scenario_id`, ADVISORY only (a dead worker, an autoretry, or a plain review verdict never publish one; keep a slow backstop poll of `GET .../treatment-plans`) | no — no `subsystem_id`, matches on `scenario_id` |
| `error` | A stage failed, or the whole session died | **both** — a `scope` field (`"stage"`/`"session"`) normally says which, so you never have to infer it from whether `subsystem_id` is present. One exception below |
| `session_cancelled` | Someone called `POST .../cancel` on this session (Test 7) | no — session-wide |
| `session_accepted` | An accept committed (Test 6); carries `status: "completed"` | no — session-wide |
| `scenarios_rejected` | A reject committed (Test 6a); carries `rejected_count` | no — session-wide |
| `heartbeat` | Periodically, proving the line is alive | no |

**Three things about this table that will bite a strict client.**

1. **Three event types are real but undeclared.** `session_cancelled` (from the cancel
   handler in `app/api/sessions.py`), `session_accepted` and `scenarios_rejected` (both from
   `app/pipeline/accept.py`) are all published on the session channel, so a Test 8 subscriber
   receives them. None of the three is a member of the `SSEEventType` enum, and none is in the
   route's declared response union — so they will NOT appear in types generated from
   `/openapi.json`, yet they arrive. Make your event switch tolerate an unrecognized `type`
   instead of throwing; do not treat the generated union as exhaustive.
2. **`error` from the reaper carries no `scope`.** The worker sets `scope` on the errors it
   publishes, but the background reaper's three publishes (lease expired, lock reclaimed,
   session reaped) omit the key entirely. `scope` is therefore optional on the wire: treat a
   missing one as "unknown", never default it to `"session"`.
3. **Epoch is on fewer events than you would expect, under two different names.** Only
   `stage_started`, `stage_completed`, `subsystem_started`, `session_entered_review` and the
   stage-scope `error` carry one, and they spell it **`generation_epoch`**. `next_set_result`
   carries one spelled **`epoch`**. Everything else carries none at all: `regen_result`,
   `treatment_plan_result`, the session-scope `error`, every reaper-published `error`, and the
   three undeclared events above. So there is nothing on a `regen_result` to match against your
   own click — which is exactly why Test 4 tells you to confirm on `progress.last_regen.epoch`
   from the board, a durable field that survives a dropped connection.

`embedding_job_update`/`grounding_job_update`/`intel_job_update` also exist on `SSEEventType` but
are **admin-scope only** — published on a per-job admin channel, never on a session channel — so
this endpoint can never emit them.

**Why did `next_set_result`/`regen_result` come back empty?** A fruitless
click (`no_new: true` on next-set, or `new_scenario_ids: []` on regen) is a valid outcome. Both events
carry a `reason` code plus `detail` (technical, for logs) and `message` (plain
English, safe to show the end user):

| `reason` | `message` (show this to the end user) |
|---|---|
| `no_new_threats_found` | "There's nothing new to add. We've already created a scenario for every threat we know about for this asset." |
| `new_threat_did_not_qualify` | "We found something new, but it didn't meet our criteria for this asset, so we didn't create a scenario for it." |
| `generation_failed` | "We hit a temporary problem generating the scenario(s). Nothing was lost — click 'generate next set' again to retry." (transient — the affected threat(s) stay selected and re-servable) |
| `no_target_ids` | (regenerate only) the request resolved to zero targets — normally rejected by the request schema itself. |
| `output_not_found_or_superseded` | "One or more of the scenarios you tried to regenerate have already been updated or no longer exist — refresh the results and try again with the current list." |
| `null` | A rare concurrent-click race — show a generic "That action couldn't be completed — please try again." |

**`reason` is not the same question as `outcome`.** `reason` says *why a click found
nothing new*; `outcome` (next-set only) says *what the click achieved overall*, and
is the field a UI should switch on. A click can carry a `reason` **and** still have
added scenarios — that happens when a candidate was found and rejected but the
variant fallback filled the batch anyway. `message` is populated **only** when the
click added nothing, because the wording says "nothing was added" and would
contradict a payload reporting new scenarios.

**A third group of codes exists that this table does not cover** — `ReviewGateReason`:
`session_completed`, `session_cancelled`, `generation_in_progress`, `generation_abandoned`, and
`asset_busy` (5 codes now, not 3). Those never appear on an event — they come back as
`details.reason` on a **409** from the accept/regenerate/next-set gate itself, meaning the request
never ran, rather than having run and found nothing. `generation_in_progress` is the only one
worth waiting on (the gate proves a live worker lease before returning it); `generation_abandoned`
means recovery already gave up — not retryable, start a new session for the asset.

**Don't transcribe any of these by hand.** All code sets, plus the event and
error payload shapes, are published in `/openapi.json` — generate your client types
from the spec so a renamed or added code is a compile error rather than a silent
mismatch.

**How to test:**

1. Open the stream → the `reconcile` event must arrive immediately.
2. In another tab, trigger Test 4 or 5 on the same session. Watch for
   `stage_started` / `stage_completed`, then `regen_result` or `next_set_result`.
3. Confirm periodic `heartbeat` events keep arriving.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session`, `Subsystem_Stage_State`, `Threat_Scenario`, `Scenario_Audit` | Read — **on connect only** | builds the `reconcile` snapshot (the same `build_board` query Test 2 uses) |
| (afterwards) | — | live stream is pure Redis pub/sub, no table touched |

**Verify in the database:** no new SQL — reuse Test 2's query and check the
`reconcile` payload matches those rows.

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Bad id / wrong entity | `404`/`403`, rejected before the stream opens |
| The server is already at its configured SSE concurrency cap | `503`, refused before the stream opens |

**Pass if:** `reconcile` fires on connect, state-change events match what Test 2 shows, and heartbeats keep coming.

---

### Test 9 — Get Accepted Scenarios by Session ("What did we keep?")

| | |
|---|---|
| **API** | `GET /v1/sessions/{session_id}/accepted-scenarios`, `response_model=AcceptedScenariosResponse` |
| **Why does this API exist?** | Downstream systems (risk registers, GRC tools) need a clean feed of ONLY what a human approved — never drafts, rejects, or superseded rows. |
| **What does it do?** | For one session, returns exactly the accepted scenarios. `session_id` is the only identifier — `asset_id`/`entity_id` are read off the session and returned. |
| **When do you call it?** | Anytime the session exists. Best right after Test 6 with the id it returned. |

**Input (complete request):**

```bash
curl -s "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/accepted-scenarios" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {
  "asset_id": 103,
  "entity_id": "78",
  "user_id": "qa-user",
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "completed_at": "2026-08-31T10:02:11+00:00",
  "scenarios": [
    {"scenario_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
     "accepted_by": "qa-user", "accepted_at": "2026-08-31T10:01:40+00:00",
     "rejected_by": null, "rejected_at": null,
     "controls_unavailable": false,
     "subsystem_id": 0,
     "scenario": {"threat_category": "Spoofing",
                  "threat_type": "Credential phishing",
                  "threat_name": "Stolen operator credentials",
                  "scenario_title": "Stolen operator credentials",
                  "scenario_statement": "An attacker phishes an operator into revealing their SCADA login, then uses it to reach the historian.",
                  "risk_statement": "Unauthorized control of the historian could corrupt production data used for billing and compliance reporting.",
                  "supporting_systems_involved": [
                    {"supporting_system_id": 321, "supporting_system": "OT Telecom Network",
                     "is_entry_point": true,
                     "justification": "The phished credential is used to log in through this network."}
                  ]},
     "threat": {"threat_id": "b6f9c2a0-1234-4a11-9c1e-abc123456789",
                "threat_category": "Spoofing", "threat_category_id": 1,
                "threat_type": "Credential phishing", "threat_name": "Stolen operator credentials",
                "threat_type_id": 3, "library_threat_type": "Credential phishing",
                "library_threat_name": null, "grounding_status": "verified",
                "threat_catalogue_id": 42, "is_threat_type_ai_generated": false,
                "is_threat_ai_generated": false, "grounding_score": 96.5,
                "score": 70.0, "scope_rank": 3},
     "actors": [{"actor_id": 12, "actor_name": "Nation-state/APT"},
                {"actor_id": 31, "actor_name": "Malicious insider"}],
     "controls": [{"control_id": 201, "control_code": "CII-CID-201",
                   "domain": "Identification & Authentication",
                   "control_name": "Multi-Factor Authentication", "map_rank": 1, "score": 93.0,
                   "standards": [{"standard_id": 3, "standard_name": "NIST SP 800-53 Rev. 5"},
                                 {"standard_id": 7, "standard_name": "ISO 27001:2022"}]}]}
  ]
}
```

(`completed_at` is `null` — and `scenarios` is `[]` — for a real session that
hasn't completed yet. That's a valid `200`, not an error. `rejected_by`/`rejected_at`
stay `null` by construction: this endpoint returns accepted rows only, and accept/reject
are mutually exclusive per scenario.)

**How to test:**

1. Call with the `session_id` from Test 6 → the scenario you accepted appears.
2. Call with an unknown `session_id` → `404`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Scenario_Session` | Read | the named session + auth check (same check as every other session route) |
| `Threat_Scenario` ⟕ `Scoped_Threat` ⟕ `Identified_Threat` | Read | rows with `Accepted=1` — **no `Superseded` filter**: an accepted scenario's flag is independent of which generation produced it |
| `Threat_Scenario_Control_Map` ⨝ `Control_Library` | Read | mapped controls for those scenarios, one batch query |
| `Control_Library_Standard_Map` ⨝ `Control_Standard` | Read | the `standards[]` inside each control |
| `Threat_Actor` | Read | actor names, on the legacy-name fallback path |

This API writes nothing.

**Verify in the database** — this SQL is literally the endpoint's own query,
so its output must match the response body exactly:

```sql
-- Step 1: the named session:
SELECT SessionID, AssetID, EntityID, CompletedAt FROM Scenario_Session
WHERE SessionID='<sid>';

-- Step 2: its accepted scenarios (NOT filtered on Superseded — Accepted is the
-- human's decision, decoupled from generation recency):
SELECT o.ScenarioID, o.SubsystemID, o.Accepted, o.AcceptedAt, o.AcceptedBy,
       i.ThreatTypeID, i.ThreatCatalogueID, i.ThreatType, i.ThreatName, o.ScenarioJSON
FROM Threat_Scenario o
LEFT JOIN Scoped_Threat s ON o.ScopedThreatID = s.ScopedThreatID
LEFT JOIN Identified_Threat i ON s.ThreatID = i.ThreatID
WHERE o.SessionID='<sid>' AND o.Accepted = 1 AND o.IdentityHash IS NOT NULL
ORDER BY i.ThreatID, o.ScenarioNumber, o.ScenarioID;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Unknown `session_id` | `404 not_found` |
| A session of an entity outside your `X-Entity-Id` | `403 forbidden` |
| A real session that just hasn't completed yet | `200` with `scenarios: []` (NOT an error) |

**Pass if:** only that session's accepted scenarios appear — pending and rejected ones never do.

---

### Test 9a — Cross-Session Scenario Reads ("Show me everything, not just one session")

| | |
|---|---|
| **APIs** | `GET /v1/users/{user_id}/scenarios` · `GET /v1/entities/{entity_id}/scenarios` (both `response_model=list[ScenarioListItem]`) · `GET /v1/sessions/{session_id}/scenarios/{scenario_id}` (`response_model=ScenarioListItem`) — all three live on a separate `scenarios_router` (its own Swagger group; same `/v1` URL prefix) |
| **Why do these APIs exist?** | Every other read needs a `session_id`. These answer "what has this USER produced?" and "what does this ENTITY have?" across all sessions — plus a direct fetch of one scenario by its id. |
| **What do they do?** | Same item shape for all three (`ScenarioListItem`): the full scenario (`scenario`, `threat`, `actors`, `controls`) plus context — `session_id`, `entity_id`, `user_id`, `session_status`, `scenario_number`, `accepted`, `superseded`, `created_at`, `accepted_by`/`accepted_at`, `rejected_by`/`rejected_at`. Newest first. |
| **When do you call them?** | Anytime — they're read-only. Best after Test 6 so there's something accepted to see. |

**Security in one sentence:** whatever `user_id` you ask about, you only ever
see scenarios from your one authorized entity (`X-Entity-Id`) — and naming a different
entity directly on route 2 gets a `403`.

**Input (complete requests):**

```bash
# 1) everything qa-user created (only the accepted ones, first page of 10):
curl -s "http://localhost:8000/v1/users/qa-user/scenarios?status=accepted&limit=10" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"

# 2) everything under entity 78, any user, completed sessions only:
curl -s "http://localhost:8000/v1/entities/78/scenarios?status=completed" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"

# 3) one specific scenario (user_id REQUIRED — must be the session owner):
curl -s "http://localhost:8000/v1/sessions/<session_id>/scenarios/<scenario_id>?user_id=qa-user" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Optional knobs on both list routes:** `status=active|completed|cancelled`
(the owning session's status) or `status=accepted` (only what a human accepted);
`include_superseded=true` to also see replaced versions; `limit` (default 100,
max 500) and `offset` for paging. Omit everything → all current scenarios.

**Output (complete response — list routes return a JSON array of these, the
item route returns one):**

```json
200 [
  {"scenario_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
   "subsystem_id": 0,
   "scenario": {"threat_category": "Spoofing",
                "threat_type": "Credential phishing",
                "threat_name": "Stolen operator credentials",
                "scenario_title": "Stolen operator credentials",
                "scenario_statement": "An attacker phishes an operator into revealing their SCADA login, then uses it to reach the historian.",
                "risk_statement": "Unauthorized control of the historian could corrupt production data used for billing and compliance reporting.",
                "supporting_systems_involved": [
                  {"supporting_system_id": 321, "supporting_system": "OT Telecom Network",
                   "is_entry_point": true,
                   "justification": "The phished credential is used to log in through this network."}
                ]},
   "threat": {"threat_id": "b6f9c2a0-1234-4a11-9c1e-abc123456789",
              "threat_category": "Spoofing", "threat_category_id": 1,
              "threat_type": "Credential phishing", "threat_name": "Stolen operator credentials",
              "threat_type_id": 3, "library_threat_type": "Credential phishing",
              "library_threat_name": null, "grounding_status": "verified",
              "threat_catalogue_id": 42, "is_threat_type_ai_generated": false,
              "is_threat_ai_generated": false, "grounding_score": 96.5,
              "score": 70.0, "scope_rank": 3},
   "actors": [{"actor_id": 12, "actor_name": "Nation-state/APT"}],
   "controls": [{"control_id": 201, "control_code": "CII-CID-201",
                 "domain": "Identification & Authentication",
                 "control_name": "Multi-Factor Authentication", "map_rank": 1, "score": 93.0,
                 "standards": [{"standard_id": 3, "standard_name": "NIST SP 800-53 Rev. 5"}]}],
   "accepted_by": "qa-user", "accepted_at": "2026-08-31T10:01:40+00:00",
   "rejected_by": null, "rejected_at": null, "controls_unavailable": false,
   "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
   "entity_id": "78", "user_id": "qa-user",
   "session_status": "completed", "scenario_number": 1,
   "accepted": true, "superseded": false,
   "created_at": "2026-08-31T09:20:11.123000+00:00"}
]
```

(An empty list is a valid `200 []` — a user or entity with no scenarios yet is
not an error. `scenario_id` — not `output_id`.)

**How to test:**

1. After Test 6, call route 1 with your user → the accepted scenario appears with `accepted: true`.
2. Call route 2 for entity 78 → the same rows appear (entity view spans all users).
3. Take any `scenario_id` from a list and fetch it via route 3 → same full payload.
4. Add `include_superseded=true` after a Test 4 regenerate → the replaced version appears with `superseded: true`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Threat_Scenario` ⨝ `Scenario_Session` | Read | scenario rows + the session's entity/user/status (the auth truth) |
| `Scoped_Threat` ⟕ `Identified_Threat` | Read | threat name/type per scenario |
| `Threat_Scenario_Control_Map` ⨝ `Control_Library` | Read | grounded controls, one batch query per page |

These APIs write nothing.

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| `GET /v1/entities/6/scenarios` while holding `X-Entity-Id: 78` | `403 forbidden` |
| Unknown or other-session `scenario_id` on the item route | `404 not_found` |
| `scenario_id` that isn't a GUID at all | `404 not_found` |
| Wrong `user_id` on the item route (not the session owner) | `404 not_found` |
| Item route without `user_id` | `422 validation_error` |
| `limit=501`, `offset=-1`, or `status=bogus` | `422 validation_error` |

**One exception to `include_superseded`, and it is deliberate.** With `status=accepted` the
recency filter is skipped entirely, so an accepted-but-superseded scenario comes back even
without the flag — same reasoning as Test 3's second query: the version a human accepted must
never be hidden by a later regeneration. For every other `status`, superseded rows stay hidden
until you ask for them.

**Pass if:** the lists never contain another entity's rows, never contain
failure cards, and hide superseded rows unless you ask for them — or unless you asked for
`status=accepted`, where an accepted older version is always returned.

---

### Test 9b — Promote a Scenario to the Library ("Teach the library what we found")

| | |
|---|---|
| **API** | `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library`, `response_model=LibraryPromotionResponse`, `409` conflicts share the same `ErrorResponse` envelope as accept/reject/regenerate |
| **Why does this API exist?** | Threat identification either RETRIEVES a threat already in the curated library (`grounding_status: "verified"`) or, when nothing matched well, has the model PROPOSE a new one (`grounding_status: "unverified"`). A proposed threat is scenario-specific and would otherwise disappear with the session — this is the only write path that adds it to `Threat_Type`/`Threat_Catalogue` (plus its category and actor links) so a future session on a similar asset profile can retrieve it instead of the model reinventing it from scratch. **Promotion does not make it retrievable on its own:** newly inserted rows are minted `IsActive=0`, pending curator review, and library retrieval filters `IsActive=1`. A curator has to activate the row before any session can match it. |
| **What does it do?** | Promotes ONE already-accepted scenario's threat type and threat. Nothing is duplicated: each item comes back `inserted` (a new master row), `existing` (reused), or `failed` (an actor with no stored id, a soft-deleted actor, or a link that did not take — the call still returns `200`, with `success: false` and an `error` on that item). Calling it twice creates nothing and returns the same ids. Controls are only reported here, never written — a mapped control is already curated `Control_Library` master data. |
| **When do you call it?** | After Test 6 accepts a scenario. Anyone holding `session_id` + `scenario_id` in their entity scope may call it — not owner-restricted, same posture as accept/reject. |

**Input (complete request):** no body.

```bash
curl -s -X POST "http://localhost:8000/v1/sessions/3fa85f64-5717-4562-b3fc-2c963f66afa6/scenarios/6ba7b810-9dad-11d1-80b4-00c04fd430c8/promote-to-library" \
  -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: <X-Tenant-Id>"
```

**Output (complete response):**

```json
200 {
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "scenario_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "success": true,
  "created_count": 1,
  "threat_type": {"id": 42, "name": "Credential phishing", "category_id": 1, "status": "existing"},
  "threat": {"id": 187, "name": "Stolen operator credentials",
             "type_id": 42, "category_id": 1, "status": "inserted"},
  "threat_actors": [{"id": 12, "name": "Nation-state/APT", "type_id": 42,
                     "status": "existing", "linked": true}],
  "controls": [{"control_id": 201, "control_code": "CII-CID-201",
                "domain": "Identification & Authentication",
                "control_name": "Multi-Factor Authentication", "map_rank": 1, "score": 93.0,
                "standards": [{"standard_id": 3, "standard_name": "NIST SP 800-53 Rev. 5"}]}],
  "controls_mapped": true
}
```

(`created_count: 0` and every item `"status": "existing"` is the expected, idempotent result of
calling this twice on the same scenario — that's a `200`, not an error.)

**How to test:**

1. Accept a scenario (Test 6), then `POST` this route on its `scenario_id` → `200`, each item's
   `status` is `inserted` or `existing`, and `threat.id`/`threat_type.id` are real primary keys.
2. Call it again on the same `scenario_id` → `200`, `created_count: 0`, every item now `existing`
   — nothing duplicated.
3. Call it on a `scenario_id` that was never accepted → `409`.

**Tables used:**

| Table | Read/Write | What happens |
|---|---|---|
| `Threat_Scenario` ⟕ `Scoped_Threat` ⟕ `Identified_Threat` | Read | loads the accepted scenario and the threat it was generated from — the promotion gate (`Status=complete`, `Accepted=1`, not superseded) |
| `Threat_Type` | Read/Write | resolves the threat's type, inserting one only if nothing matches by name. An inserted row is minted `IsActive=0` (pending curation) |
| `Threat_Catalogue`, `Threat_Catalogue_Category_Map` | Read/Write | resolves the threat itself and its category link, same insert-if-new rule |
| `Threat_Actor` | Read | the threat's already-stored actors. **Never written** — the AI never invents an adversary |
| `ThreatType_ThreatActor_Map` | Read/Write | links those actors to the type |
| `Identified_Threat` | Write | stamps the resolved `ThreatTypeID`/`ThreatCatalogueID` back onto the source threat row, fenced on `Superseded = 0` |
| `Threat_Scenario_Control_Map`, `Control_Library` | Read | controls already mapped to this scenario, reported read-only |
| `Scenario_Audit` | Write | one `library_promoted` row: who, when, and the per-item outcome |

**Verify in the database:**

```sql
-- the new/reused library rows this call touched:
SELECT ThreatTypeID, ThreatTypeName, ThreatCategoryID FROM Threat_Type WHERE ThreatTypeID=<type_id>;
SELECT ThreatCatalogueID, ThreatCatalogueName, ThreatTypeID FROM Threat_Catalogue WHERE ThreatCatalogueID=<catalogue_id>;

-- the audit trail this call always writes:
SELECT AuditID, EventType, ActorUserID, CreatedAt, DetailJSON FROM Scenario_Audit
WHERE SessionID='<sid>' AND EventType='library_promoted'
ORDER BY CreatedAt DESC;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Unknown `session_id`, or a `scenario_id` not in that session | `404 not_found` |
| Session outside your `X-Entity-Id` | `403 forbidden` |
| Scenario is a failure card (generation never produced content) | `409`, `details.reason: "failure_card"` |
| Scenario was superseded by a regeneration | `409`, `details.reason: "duplicate_identity"` |
| Scenario exists but is still pending (never decided) | `409`, `details.reason: "unknown"` |
| Scenario was rejected, not accepted | `409`, `details.reason: "already_rejected"` |
| Call it again on an already-promoted scenario | `200` — idempotent, `created_count: 0`, every item `"existing"` |

**Pass if:** the first call inserts the new library rows and records one `library_promoted` audit
event; every later call on the same scenario returns `200` with `created_count: 0` and changes
nothing in `Threat_Type`/`Threat_Catalogue`.

---

## Part 6 — Admin & Health (P3: skip first if short on time)

### Test 10 — Embeddings Admin ("Rebuild the AI's memory")

#### First: what is an "embedding"? (read this once — the whole test makes sense after it)

The AI does not compare words letter-by-letter. It turns a piece of text into
a long list of numbers called a **vector** (another word for it: **embedding**).
Texts with a similar *meaning* get similar numbers — even when the words are
completely different.

**Concrete example:** the library has a threat family named `"Spoofing"`.
The AI generates a threat called `"Impersonating the SCADA operator"`. Those
two share almost no letters — but their vectors are close, so TSG knows the
AI's threat belongs under the library's "Spoofing" family. That number-matching
is how every AI-to-library match in the app works.

Computing a vector costs time and money (each one is an AI model call), so TSG
computes each vector **once** and stores it in MongoDB
(`tsg_embeddings.embeddings`). That stored copy is the **vector cache**.
Four groups of master data have vectors:

| Group | What gets embedded | Source table | How many |
|---|---|---|---|
| `threat_type` | each threat family's **name** | `Threat_Type` | 27 |
| `threat_catalogue` | each exact threat's **name** | `Threat_Catalogue` | 75 |
| `control_library` | each control's **name + description** | `Control_Library` | 1,288 |
| `threat_actor` | each threat actor's **bare name** (no description column exists) | `Threat_Actor` | count directly — see the verify query below |

#### Why does the cache need admin APIs at all?

When you edit the library through the normal APIs (Tests 11, 14, 15), TSG
refreshes the affected vectors **automatically** — you never think about it.
The cache only goes stale when the SQL data changes **behind the app's back**:

| What happened behind the app's back | What's now wrong | Which action fixes it |
|---|---|---|
| Someone ran an `INSERT` script directly in SQL Server | the new rows have **no vector** — the AI can never match them | `create` |
| A fresh environment (e.g. new UAT) was set up from SQL scripts | **nothing** has vectors yet | `update` |
| Someone fixed a typo directly in SQL (`Spofing` → `Spoofing`) | the cache still holds the vector of the **old, wrong text** — the app never rewrites an existing vector on its own | `recreate` |
| A row was hard-`DELETE`d directly in SQL | its vector is an **orphan** that sits in Mongo forever | `delete` |

That's the entire purpose of this test's five endpoints: four repair actions +
one "is it done yet?" poll.

| | |
|---|---|
| **API** | `POST /v1/tsg/threat-library/embeddings/{create\|update\|recreate\|delete}` + `GET .../status/{job_id}` |
| **Why does this API exist?** | Direct SQL changes bypass the automatic vector refresh (table above). Without these endpoints, the only fix would be hand-editing MongoDB. |
| **What does it do?** | Repairs the vector cache. Every action answers immediately with a `job_id` and runs in the background (embedding 1,288 controls isn't instant) — you poll the status endpoint to see it finish. |
| **When do you call it?** | Only after data changed behind the app's back — normal library editing (Tests 11/14/15) needs none of this. |

**Auth on every one of these five endpoints (this is the part that changed):**
this whole router requires **two independent checks**, both on every request —
missing either one is a `401`:

1. `X-Admin-Key` — a shared secret, checked against `TSG_ADMIN_API_KEY`. Gates
   the entire embeddings router; there is no dev-mode bypass for it.
2. `X-API-Key` **and** `X-User-Id` — the same client-key auth every other
   endpoint in this guide uses (`X-API-Key` is verified against a stored
   `API_Client` secret hash; `X-User-Id` is the acting identity that lands in
   the audit log line). `X-Entity-Id` is **not** needed here — admin routes
   touch shared, cross-tenant master data, so there is no entity to scope to.
   `X-Tenant-Id` is accepted if you send it (bound into the log context) but
   never required.

There is no `X-Dev-Entities` / `X-Dev-User` dev-mode header pair — that mode
does not exist in this build.

#### Calling these from Swagger (instead of curl)

1. Open **`http://localhost:8000/docs`** in a browser (FastAPI's built-in Swagger UI).
2. Find the endpoint, click it, then click **Try it out**.
3. Every admin endpoint lists its headers as editable parameter fields. Fill in **all three**:
   - `X-Admin-Key` → the value of `TSG_ADMIN_API_KEY` (copy from `tsg/.env`)
   - `X-API-Key` → `<X-API-Key>` (any valid, active API client key — admin routes don't scope by client)
   - `X-User-Id` → `qa-user`
4. Paste the JSON body from the action you want (below) into the request-body box.
5. Click **Execute** — the response appears right underneath.

The JSON bodies below are exactly what goes in Swagger's body box. (curl users:
same bodies, with headers `X-Admin-Key: <X-Admin-Key>`, `X-API-Key: <X-API-Key>`,
`X-User-Id: qa-user`, `Content-Type: application/json` — one full example
at the end.)

Valid `group` values everywhere: `threat_type`, `threat_catalogue`, `control_library`, `threat_actor`.

#### Action 1 — `update`: "Fill in whatever is missing" (the safe default)

**Real situation:** you stood up a fresh UAT environment yesterday. SQL Server
has all 27 threat types, 75 catalogue entries and 1,288 controls — but MongoDB
is empty, because nothing ever computed their vectors. Until someone does, the
AI can match nothing.

**Endpoint:** `POST /v1/tsg/threat-library/embeddings/update`

**Swagger body** (empty object = "check every group, embed whatever has no vector"):

```json
{}
```

**Swagger body, scoped to one group** (optional):

```json
{"group": "control_library"}
```

**Response:**

```json
202 {"job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}
```

Anything that already has a vector is **skipped**, so re-running `update`
never costs anything extra. When unsure which action you need — use this one.

#### Action 2 — `create`: "I added these specific rows by hand — embed exactly them"

**Real situation:** a colleague bulk-inserted two new threat types straight
into SQL Server: `Living-off-the-Land` and `Supply Chain Compromise`. Adding
them through Test 14's API would have embedded them automatically — but a raw
SQL `INSERT` bypasses that. Right now the AI cannot match either name.

**Endpoint:** `POST /v1/tsg/threat-library/embeddings/create`

**Swagger body** (**both** `group` and `names` are required — `create` means
"embed exactly these", so you must say which; `names` takes at most 50 entries
per call):

```json
{"group": "threat_type", "names": ["Living-off-the-Land", "Supply Chain Compromise"]}
```

**Response:** `202 {"job_id": "..."}`

The other 25 threat types are untouched. A name that already has a vector is
skipped, not recomputed — so calling `create` twice is harmless.

#### Action 3 — `recreate`: "The text changed — throw the old vectors away, compute fresh ones"

**Real situation A (one name):** someone fixed a typo directly in SQL:
`Spofing` → `Spoofing`. The cache still holds the vector computed from the
old text `"Spofing"`. The app never rewrites an existing vector on its own, so
that wrong vector would sit there forever, quietly making matches worse.

**Swagger body:**

```json
{"group": "threat_type", "names": ["Spoofing"]}
```

**Real situation B (whole group):** the team switches to a different embedding
model. Every stored vector was computed by the OLD model, and vectors from two
different models cannot be compared. The whole group must be wiped and rebuilt.

**Swagger body** (no `names` = the whole group, orphans included):

```json
{"group": "control_library"}
```

**Endpoint:** `POST /v1/tsg/threat-library/embeddings/recreate` ·
**Response:** `202 {"job_id": "..."}`

**Why not just run `update` after a model switch?** `update` only ADDS missing
vectors — it never deletes anything. It would compute the new model's vectors
but leave the old model's vectors in Mongo too: two sets for the same items.
`recreate` = delete + re-embed as one step, so only fresh vectors remain.

Rule: `names` is only allowed together with `group` — enforced on `create`, `recreate` and
`delete`. `update` is the exception: it runs no such check and **ignores `names` entirely**, so
`{"names": [...]}` on `update` is accepted and then silently does a full missing-vector sweep.
Use `create` when you mean "embed exactly these".

#### Action 4 — `delete`: "Remove vectors, and do NOT recompute anything"

**Real situation:** months ago a threat type was hard-`DELETE`d straight in
SQL. The row is gone — but its vector still sits in MongoDB as an orphan.
Nothing will ever clean it up on its own.

**Endpoint:** `POST /v1/tsg/threat-library/embeddings/delete`

**Swagger body:**

```json
{"group": "threat_type", "names": ["Old Threat Name"]}
```

**Response:** `202 {"job_id": "..."}`

Rules that protect you:

- A bare `{}` is **rejected** (`422 admin_validation_error`) on purpose — so nobody wipes the
  whole cache by accident.
- `names` **without** `group` is also rejected (`422 admin_validation_error`, "names requires a
  specific group") — exactly like `recreate`. So `delete` effectively always needs `group`,
  optionally narrowed by `names`.
- Unlike `recreate`, nothing is recomputed afterwards. `delete` is for vectors
  that should be gone and STAY gone.
- It only touches Mongo — the SQL master tables are never changed.

#### Action 5 — `status/{job_id}`: "Is my job done yet?"

All four POSTs above answer immediately with a `job_id` — the real work runs
in the background. Poll this endpoint every few seconds until the state stops
being `PENDING`/`STARTED`.

**Endpoint:** `GET /v1/tsg/threat-library/embeddings/status/{job_id}`
(no body — in Swagger, paste the `job_id` into the path field; same three
headers as every action above)

**Responses you can get.** All four keys are present on every reply — the counts and
`error` are `null` until they apply, never absent, so only `state` is meaningful before the
job finishes. `rows_processed` and `vectors_deleted` are each keyed **by group**, never a
single bare number:

```json
// still working (state mirrors Celery's own AsyncResult states: PENDING, STARTED, ...)
200 {"rows_processed": null, "vectors_deleted": null, "state": "STARTED", "error": null}

// finished — create/update/recreate report counts per group
200 {"rows_processed": {"threat_type": 27, "threat_catalogue": 75, "control_library": 1288}, "vectors_deleted": null, "state": "SUCCESS", "error": null}

// finished — a delete job reports removals per group instead
200 {"rows_processed": null, "vectors_deleted": {"threat_type": 75}, "state": "SUCCESS", "error": null}

// failed — the error names the exact problem
200 {"rows_processed": null, "vectors_deleted": null, "state": "FAILURE", "error": "name matched nothing in group 'threat_type': 'Spofing'"}
```

#### One full curl example (the pattern is identical for all four actions)

```bash
curl -s -X POST "http://localhost:8000/v1/tsg/threat-library/embeddings/update" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -d '{}'

curl -s "http://localhost:8000/v1/tsg/threat-library/embeddings/status/<job_id>" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"
```

#### Body rules at a glance

| Action | Required in body | `422` if you… |
|---|---|---|
| `update` | nothing — `{}` is valid | — |
| `create` | `group` **and** `names` | omit either |
| `recreate` | `group` (`names` optional) | send `names` without `group` |
| `delete` | `group` (`names` optional) | send a bare `{}`, **or** send `names` without `group` |

`names`, whenever sent, is capped at 50 entries — over that is a plain
`422 validation_error` (the generic field-validation one, not
`admin_validation_error`) before any of the rules above are even checked.

**How to test:**

1. `update` with `{}` → `202 {"job_id": ...}`; poll status until `SUCCESS` with `rows_processed`.
2. Try the other actions, respecting each one's body rule (table above).

**Tables used:**

| Store | Read/Write | What happens |
|---|---|---|
| `Threat_Type`, `Threat_Catalogue`, `Control_Library`, `Threat_Actor` (SQL) | Read only | the names (or name+description, for controls) to embed |
| Mongo `tsg_embeddings.embeddings` | Write | where the vectors actually live |
| `Scenario_Audit` | — | **no row** — the admin audit trail is a structured log line |

**Verify in the database:**

```sql
-- SQL side: these are the names the job embeds:
SELECT ThreatTypeName FROM Threat_Type WHERE IsActive=1 AND IsDeleted=0;
SELECT ThreatActorName FROM Threat_Actor WHERE IsActive=1 AND IsDeleted=0;
```

```js
// Mongo side (mongosh): this count is what changes after create/recreate/delete:
use tsg_embeddings; db.embeddings.countDocuments({ group: "threat_type" });
db.embeddings.countDocuments({ group: "control_library" });  // 1288 once warmed
db.embeddings.countDocuments({ group: "threat_actor" });
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key` | `401` (`error_code: unauthorized`) |
| Missing/invalid `X-API-Key`, or missing `X-User-Id` | `401` (`error_code: unauthorized`) |
| `create` missing `group` or `names`; `recreate` with `names` but no `group`; `delete` with bare `{}` | `422` (`error_code: admin_validation_error`) |
| Unknown or expired `job_id` | `404` (`error_code: not_found`) |
| Named `delete` with a typo matching nothing anywhere | job ends `FAILURE`, naming it in `error` |
| Named `delete` of a real name whose vector is already gone | `SUCCESS` with 0 deleted (idempotent) |

**Pass if:** each job reaches `SUCCESS` (or a documented `FAILURE` with a non-empty `error`), and Mongo counts move accordingly.

---

### Test 10a — Embeddings Job Live Stream ("Watch the rebuild happen")

| | |
|---|---|
| **API** | `GET /v1/tsg/threat-library/embeddings/events/{job_id}` |
| **Why does this API exist?** | Polling Test 10's `status/{job_id}` in a loop works, but a UI watching a 1,288-control `recreate` job wants the server to push each step as it happens instead of guessing a poll interval. |
| **What does it do?** | Same auth boundary and same job as Test 10's status endpoint, but pushed live: a snapshot of the job's current state the instant you connect, then every state change the worker reports, plus heartbeats — until the job reaches a terminal state and the stream closes itself. |
| **When do you call it?** | Right after a Test 10 POST hands you a `job_id` — open this before (or instead of) polling status, especially for `recreate`/`update` on `control_library`, the one action slow enough to be worth watching. |

This route shares its headers with Test 10: `X-Admin-Key` **and** `X-API-Key`
**and** `X-User-Id`, all three, every time. Because those are custom headers,
the browser's native `EventSource` object cannot be used here (it cannot set
request headers) — use `curl -N`, or a `fetch()` + `ReadableStream` reader, the
same restriction as Test 8's session-events route when it needs non-default
headers.

**Input (complete request):**

```bash
curl -N \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  "http://localhost:8000/v1/tsg/threat-library/embeddings/events/6ba7b810-9dad-11d1-80b4-00c04fd430c8"
```

**Output (what the wire actually looks like)** — `200` with
`Content-Type: text/event-stream`. Each event is an `event:` line, a `data:`
line, then a blank line:

```
event: embedding_job_update
data: {"type":"embedding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"STARTED"}

event: embedding_job_update
data: {"type":"embedding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"STARTED","action":"recreate","group":"control_library","rows":1288}

event: heartbeat
data: {"type":"heartbeat","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","ts":"2026-08-31T09:19:14.000000+00:00"}

event: embedding_job_update
data: {"type":"embedding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"SUCCESS","action":"recreate","rows_processed":{"control_library":1288}}
```

(The stream closes right after that last frame — a terminal state is the end
of this job's story.)

**Every event you can receive:**

| Wire `event:` | When it fires | Extra fields carried on that frame |
|---|---|---|
| `embedding_job_update` | Immediately on connect — a snapshot of the job's state right now (re-reads the same `AsyncResult` Test 10's `status/{job_id}` polls) | `state` always; if already terminal: `rows_processed`/`vectors_deleted` (SUCCESS) or `error` (FAILURE) — same shape as the status endpoint |
| `embedding_job_update` | The worker picked the job up and started running it | `action` (`create`\|`update`\|`recreate`\|`delete`) |
| `embedding_job_update` | The worker finished one group. Fires once **per group processed, including a single-group call** — so the worked `recreate` on `control_library` below produces one | `action`, `group`, `rows` (rows processed for that one group) |
| `embedding_job_update` | An `LLMSlotUnavailable` autoretry was scheduled — **non-terminal**, the stream stays open and the job will run again | `state: "RETRY"`, `action`, `error` |
| `embedding_job_update` | Terminal — the job finished; the stream ends right after this frame | `action`, plus `rows_processed`/`vectors_deleted` (SUCCESS) or `error` (FAILURE) |
| `heartbeat` | Periodically, proving the line is alive | `job_id`, `ts` |

**Why can a snapshot frame be missing `action`/`group`/`rows`?** The on-connect
(and terminal-fallback) snapshot is built by re-reading Celery's own
`AsyncResult` directly — it only ever knows `state` plus, once terminal, the
job's result payload. `action`/`group`/`rows` are extra context only the
*worker itself* publishes as it works, so you only see them on frames that
arrived while the job was actually running, not on a snapshot taken after the
fact (e.g. connecting to an already-finished job).

**How to test:**

1. Fire a Test 10 `recreate` on `control_library` (the slowest one), grab its `job_id`.
2. Open this stream on that `job_id` → an `embedding_job_update` snapshot must arrive immediately.
3. Watch for further `embedding_job_update` frames as the worker starts and progresses, and confirm `heartbeat` frames keep arriving in between.
4. Confirm the terminal `embedding_job_update` frame matches what `GET status/{job_id}` (Test 10) reports, and that the connection then closes.
5. Reconnect to the same `job_id` after it's finished — you should get exactly one terminal `embedding_job_update` snapshot and an immediate close (no replay of the earlier progress frames).

**Tables used:**

| Store | Read/Write | What happens |
|---|---|---|
| — | — | this route itself touches no SQL/Mongo table — it re-reads Celery's result backend and subscribes to a Redis pub/sub channel. The job it is watching does the real reads/writes described in Test 10's table. |

**Verify in the database:** no new query — reuse Test 10's SQL/Mongo checks; the counts should already have moved by the time this stream's terminal frame arrives.

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key`, missing/invalid `X-API-Key`, or missing `X-User-Id` | `401`, rejected before the stream opens |
| Unknown or expired `job_id` (same family-scoped marker Test 10's status endpoint checks) | `404`, rejected before the stream opens |
| Connecting while the process is already at its shared SSE concurrency cap (every SSE route in the app shares one cap, session events included) | `503` (`error_code: sse_capacity_exceeded`), rejected before the stream opens |

**Pass if:** `embedding_job_update` fires immediately on connect with the job's current state, further frames arrive while the worker runs, the terminal frame matches Test 10's `status/{job_id}` response, the stream then closes on its own, and heartbeats keep arriving throughout.

---

## Part 6a — Grounding Calibration Admin (new since the last guide)

#### First: what is "grounding", and what does calibrating it do?

When the AI proposes a threat ("Impersonating the SCADA operator"), TSG has to decide
whether that maps to something already in the threat library (`Threat_Type` /
`Threat_Catalogue`) or is genuinely new. It does that the same way the library-embeddings
test does (Test 10): turn the proposed threat into a vector, compare it against the
library's vectors, and get back a similarity score. **Grounding** is the decision that score
drives — score at or above a cutoff, and the threat is `verified` (it's the same thing as a
real library entry); below it, `unverified` (stays session-local, never enters the shared
library).

That cutoff is the whole problem. It is not one universal number — a different
embedding+reranker model pair scores the exact same match differently, so a cutoff tuned for
one pair silently misjudges every match once the models change. **Calibration** is the fix:
it *measures* the right cutoff for whichever embedding+reranker pair is running right now,
by scoring two piles of known-answer pairs —

- **negatives** — real library entries scored against the library with themselves removed
  (i.e. "how similar do two genuinely different things look?" — the impostor case)
- **positives** — LLM paraphrases of library entries, scored against the full library (i.e.
  "how similar does the same thing, worded differently, look?" — the genuine-match case)

— and then finding the cutoff that best separates the two piles. How well it separates them
is reported as `quality` (Youden's J: 1.0 = perfect separation, 0.0 = no better than chance).
A sweep takes 10-15 minutes and makes ~100 billed LLM calls (the paraphrases), so nothing
ever queues one automatically — an admin has to ask for it, and the result is stored so every
grounding decision afterward reads it instead of re-measuring.

| | |
|---|---|
| **API** | `GET /threshold` · `POST /calibrate` · `GET /calibrations` · `GET /calibrate/status/{job_id}` · `GET /calibrate/events/{job_id}` — all under `/v1/tsg/grounding` |
| **Why does this API exist?** | Without it the match cutoff is a hardcoded guess that goes stale the moment the embedding or reranker model changes, and nobody can see whether the number in force was ever actually measured for the models running today. |
| **What does it do?** | Reports the cutoff currently in force, runs a sweep to measure a fresh one, and lets you watch or poll a sweep in progress. |
| **When do you call it?** | Any time `GET /threshold` reports `origin: "static_default"` or `"env_pinned"`, or after you swap the embedding/reranker model, or after curating the threat library (dedupe near-duplicate catalogue entries) and wanting a tighter number. |

**Auth on every route below** — the `grounding_router` is admin-gated two ways at once:
the router-level dependency requires `X-Admin-Key`, and each handler also resolves an admin
principal that requires `X-API-Key` + `X-User-Id` (`X-Tenant-Id` is accepted but optional,
and there is no `X-Entity-Id` — these routes touch shared, cross-tenant master data, not one
entity's). Missing or wrong `X-Admin-Key` → `401`; missing `X-API-Key` or `X-User-Id` → `401`
too. Every example below uses `X-User-Id: qa-user` as the acting admin.

---

### Test 10b — Get the Current Grounding Threshold ("What number is the AI grounding against, right now?")

| | |
|---|---|
| **API** | `GET /v1/tsg/grounding/threshold` |
| **Why does this API exist?** | The cutoff a session was graded against is otherwise invisible — you'd have to trust that someone calibrated it for the right models. |
| **What does it do?** | Reads the threshold `resolve_thresholds` would hand the pipeline right now, and says *where it came from*. Read-only and cheap — it never triggers a calibration, so it's safe to poll from a dashboard. |
| **When do you call it?** | Before trusting any grounding decision, and right after a model swap or a calibration sweep to confirm the new number took effect. |

**Input (complete request):**

```bash
curl -s "http://localhost:8000/v1/tsg/grounding/threshold" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"
```

**Output (complete response):**

```json
200
{
  "value": 86.25,
  "origin": "calibrated",
  "embedding_model": "multilingual-e5-large",
  "reranker_model": "bge-reranker-v2-m3"
}
```

**`origin` is the field that matters** — it says whether `value` can be trusted:

| `origin` | What it means |
|---|---|
| `calibrated` | Measured for this EXACT embedding+reranker pair by a successful sweep. Always wins when one is stored. |
| `env_pinned` | `TSG_GROUNDING_MATCH_THRESHOLD` bootstrapping — no calibration is stored for this pair yet. |
| `static_default` | The built-in fallback (`75.0`), tuned for a DIFFERENT model pair. Provisional — run Test 10c. |

**Verify in the database:**

```sql
-- The row resolve_thresholds reads when origin comes back "calibrated" for the current pair:
SELECT TOP 1 RunID, Status, EmbeddingModel, RerankerModel, MatchTh, Quality, FinishedAt
FROM Grounding_Calibration_Run
WHERE EmbeddingModel = 'multilingual-e5-large' AND RerankerModel = 'bge-reranker-v2-m3'
  AND Status = 'success' AND MatchTh IS NOT NULL
ORDER BY StartedAt DESC;
-- If origin came back "env_pinned" or "static_default" instead, this query returns no rows
-- for the current model pair — nothing has ever been calibrated for it.
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key` | `401` |
| Missing `X-API-Key` or `X-User-Id` | `401` |

**Pass if:** `value`/`origin` match whichever row (or lack of one) the SQL above shows for the current `embedding_model`/`reranker_model`.

---

### Test 10c — Start a Calibration Sweep ("Measure the new cutoff")

| | |
|---|---|
| **API** | `POST /v1/tsg/grounding/calibrate` |
| **Why does this API exist?** | It's the ONLY way a calibration ever starts — nothing queues one automatically, because a sweep costs 10-15 minutes and real LLM spend. |
| **What does it do?** | Opens a permanent ledger row (`Grounding_Calibration_Run`, `Status='running'`) for the current model pair, then queues the measurement in the background and answers immediately with a `job_id` + `run_id`. |
| **When do you call it?** | After `GET /threshold` shows `static_default`/`env_pinned`, after a model swap, or with `force: true` after curating the library (deduping near-duplicate catalogue entries) for a tighter cutoff. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/tsg/grounding/calibrate" \
  -H "Content-Type: application/json" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  -d '{"force": false}'
```

The body is optional — omitting it entirely, or sending `{}`, behaves the same as `{"force": false}`.

**Output (complete response):**

```json
202
{
  "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
  "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e"
}
```

`job_id` is the Celery task id — it expires with the result backend after about an hour.
`run_id` is `Grounding_Calibration_Run.RunID` — permanent, and what `GET /calibrations`
reports. Poll either Test 10e or watch Test 10f for the outcome.

**Without `force`, a pair that already has a successful run is a safe no-op** — and the sweep
does **not** run. The task looks up the newest successful run, closes its own ledger row as
`skipped`, publishes `SUCCESS` with `skipped: "already_calibrated"` and returns *before*
`grounding.calibrate` is ever called: no paraphrases, no LLM spend, no phase ticks, and it
finishes in seconds rather than 10-15 minutes. Send `force: true` to genuinely re-measure (e.g.
after curating the library). Note the ledger records this as `skipped`, never `success` — a
calibration that did not happen must not read as one.

**Why a `409` and not a queued-behind-it retry?** The ledger row is opened BEFORE the task is
queued, and a unique index (`UX_GroundingCalibration_Running`, filtered on `Status='running'`)
admits only one running row per model pair. A second concurrent `POST` for the same pair has
its `INSERT` refused by the database itself — not a racy "check then act" in Python — so this
can never be a false positive:

```json
409
{
  "error_code": "calibration_running",
  "message": "a calibration for this embedding+reranker pair is already running — poll it rather than starting a second 10-15 minute sweep",
  "details": {"run_id": "0f8fad5b-d9cb-469f-a165-70867728950e"}
}
```

**Verify in the database:**

```sql
SELECT RunID, JobID, Status, StartedBy, StartedByClient, StartedAt, Forced,
       EmbeddingModel, RerankerModel
FROM Grounding_Calibration_Run
WHERE RunID = '0f8fad5b-d9cb-469f-a165-70867728950e';
-- Status = 'running' immediately after the POST; becomes 'success' / 'no_signal' / 'failed'
-- once the sweep finishes (Test 10e / 10f tell you when).
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key`, or missing `X-API-Key`/`X-User-Id` | `401` |
| A calibration for this model pair is already running | `409 calibration_running`, `details.run_id` names the live run |
| `force` omitted/false on a pair with an existing successful run | still `202` — the job finishes `SUCCESS` with `skipped: "already_calibrated"`, not a failure |

**Pass if:** the ledger row appears immediately with `Status='running'`, then settles to
`success`/`no_signal`/`failed`, and a concurrent second `POST` for the same pair gets `409`
instead of a second row.

---

### Test 10d — List Calibration History ("The permanent record")

| | |
|---|---|
| **API** | `GET /v1/tsg/grounding/calibrations` |
| **Why does this API exist?** | Celery's own result backend expires after about an hour, so it can't answer "did last Tuesday's calibration pass, and who ran it?" — and before this table, a *failed* sweep wrote nothing anywhere at all. This ledger is permanent. |
| **What does it do?** | Lists calibration runs, newest first, each showing who ran it, when, and how it ended. |
| **When do you call it?** | Auditing who last calibrated, or checking a specific model pair's history before deciding whether to run Test 10c again. |

**Input (complete request):**

```bash
curl -s "http://localhost:8000/v1/tsg/grounding/calibrations?limit=10" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"
```

`limit` is optional, `1`-`200`, defaults to `50`.

**Output (complete response):**

```json
200
{
  "runs": [
    {
      "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
      "job_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
      "status": "success",
      "started_by": "qa-user",
      "started_by_client": "tsg-web",
      "started_at": "2026-08-31T10:14:02Z",
      "finished_at": "2026-08-31T10:29:41Z",
      "embedding_model": "multilingual-e5-large",
      "reranker_model": "bge-reranker-v2-m3",
      "forced": false,
      "match_th": 86.25,
      "quality": 0.94,
      "negatives": 100,
      "positives": 200,
      "highest_negative": 99.5,
      "lowest_positive": 71.2,
      "near_duplicates": [],
      "error": null
    }
  ]
}
```

**`status` is settled, not the raw column value:** a `running` row older than
`TSG_CALIBRATION_STALE_AFTER_SECONDS` (default 3600s / 1 hour) is reported here as `failed`
with a synthesized cause — it cannot genuinely still be running, and saying otherwise would
mislead anyone reading this table.

| `status` | Meaning |
|---|---|
| `running` | In flight right now (within the stale window) |
| `success` | Measured and stored — `match_th` is real |
| `no_signal` | Ran, but no cutoff beat chance for this model pair — not a crash, a finding: curate the library or change models |
| `skipped` | Declined to re-measure (`force` wasn't set and a successful run already existed) |
| `failed` | Raised an error, or a `running` row went stale |

**`started_by` vs `started_by_client`:** `started_by` is the claimed `X-User-Id` — trusted,
never verified, since admin routes share one `X-Admin-Key`. `started_by_client` is the
`API_Client` the request actually authenticated as via `X-API-Key` — that half is verified.

**Verify in the database:**

```sql
SELECT TOP 10 RunID, JobID, Status, StartedBy, StartedByClient, StartedAt, FinishedAt,
       EmbeddingModel, RerankerModel, Forced, MatchTh, Quality
FROM Grounding_Calibration_Run
ORDER BY StartedAt DESC;
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key`, or missing `X-API-Key`/`X-User-Id` | `401` |
| `limit` outside `1`-`200` | `422` |

**Pass if:** the response's rows and order match the SQL above, and any `running` row past
the stale window shows here as `failed`.

---

### Test 10e — Poll Calibration Status ("Is my sweep done yet?")

| | |
|---|---|
| **API** | `GET /v1/tsg/grounding/calibrate/status/{job_id}` |
| **Why does this API exist?** | Test 10c answers instantly with a `job_id`; the real 10-15 minute sweep runs in the background. This is how you find out it finished. |
| **What does it do?** | Answers from Celery's live `AsyncResult` while the job/marker is fresh, and falls back to the permanent ledger row once that expires — so a late poll (past the ~1 hour result TTL) still gets the real outcome instead of a stale 404. |
| **When do you call it?** | Right after Test 10c, in a loop, until `state` stops being `PENDING`/`STARTED`/`RETRY`. |

**Input (complete request):**

```bash
curl -s "http://localhost:8000/v1/tsg/grounding/calibrate/status/6ba7b810-9dad-11d1-80b4-00c04fd430c8" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"
```

**Responses you can get:**

Every reply carries all thirteen keys, in this order, with `null` standing in for whatever
does not yet apply — nothing is ever omitted:

```json
// still measuring — a worker has picked it up
200
{
  "state": "STARTED", "match_th": null, "quality": null, "negatives": null,
  "positives": null, "highest_negative": null, "lowest_positive": null,
  "near_duplicates": [], "run_id": null, "embedding_model": null,
  "reranker_model": null, "skipped": null, "error": null
}

// finished — a real cutoff was found
200
{
  "state": "SUCCESS",
  "match_th": 86.25,
  "quality": 0.94,
  "negatives": 100,
  "positives": 200,
  "highest_negative": 99.5,
  "lowest_positive": 71.2,
  "near_duplicates": [],
  "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "embedding_model": "multilingual-e5-large",
  "reranker_model": "bge-reranker-v2-m3",
  "skipped": null,
  "error": null
}

// finished — no cutoff beat chance for this model pair (still SUCCESS, not a failure)
200
{
  "state": "SUCCESS", "match_th": null, "quality": null, "negatives": 100,
  "positives": 200, "highest_negative": 99.5, "lowest_positive": 71.2,
  "near_duplicates": [], "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "embedding_model": "multilingual-e5-large", "reranker_model": "bge-reranker-v2-m3",
  "skipped": null, "error": null
}

// finished — declined to re-measure (a successful run already existed and force wasn't set)
200
{
  "state": "SUCCESS", "match_th": 86.25, "quality": null, "negatives": null,
  "positives": null, "highest_negative": null, "lowest_positive": null,
  "near_duplicates": [], "run_id": "0f8fad5b-d9cb-469f-a165-70867728950e",
  "embedding_model": "multilingual-e5-large", "reranker_model": "bge-reranker-v2-m3",
  "skipped": "already_calibrated", "error": null
}

// failed
200
{
  "state": "FAILURE", "match_th": null, "quality": null, "negatives": null,
  "positives": null, "highest_negative": null, "lowest_positive": null,
  "near_duplicates": [], "run_id": null, "embedding_model": null,
  "reranker_model": null, "skipped": null,
  "error": "LLMSlotUnavailable: no slot for the paraphrase batch after 3 retries"
}
```

**A FAILURE reply looks different depending on WHICH source answered it**, and the two are
mutually exclusive — do not expect a blend of the two. While the Celery job marker is still
alive (roughly the first hour) the reply comes from `AsyncResult` and carries only `state` and
`error`; `run_id`, `embedding_model` and `reranker_model` are all `null`, as above. Once the
marker expires the ledger fallback answers instead, and that reply carries `run_id` **and** both
model names, because those columns are written when the row is created.

`state == "SUCCESS"` with `match_th: null` is a real, meaningful outcome, not a bug: the
sweep ran and genuinely found that no cutoff separates real matches from impostors better
than chance under this model pair — a finding about the models/library, reported as a
successful measurement rather than a task failure. `quality` is what says whether to trust a
non-null `match_th` (1.0 = perfect separation, 0.0 = chance).

**Verify in the database:**

```sql
SELECT RunID, Status, MatchTh, Quality, NegativesCount, PositivesCount,
       HighestNegative, LowestPositive, NearDuplicatesJSON, ErrorMessage
FROM Grounding_Calibration_Run
WHERE JobID = '6ba7b810-9dad-11d1-80b4-00c04fd430c8';
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key`, or missing `X-API-Key`/`X-User-Id` | `401` |
| Unknown or fully-expired `job_id` (no live marker AND no matching ledger row) | `404` |

**Pass if:** `state` eventually reaches `SUCCESS`/`FAILURE`, and the fields it carries match
the ledger row from the SQL above — including after the ~1 hour Celery result TTL passes,
where this route must still answer from the ledger instead of `404`.

---

### Test 10f — Calibration Live Stream ("Watch the sweep happen")

| | |
|---|---|
| **API** | `GET /v1/tsg/grounding/calibrate/events/{job_id}` (SSE — `Accept: text/event-stream`) |
| **Why does this API exist?** | Polling Test 10e in a loop for a 10-15 minute sweep is wasteful and laggy. This keeps one connection open and pushes each progress tick the moment the worker reports it. |
| **What does it do?** | Sends a state snapshot immediately on connect, then live `grounding_job_update` events as the sweep progresses (`negatives` phase, then `positives` phase, then the terminal result), plus periodic `heartbeat`s. Closes itself the instant the job reaches a terminal state. |
| **When do you call it?** | Right after Test 10c, instead of polling Test 10e — best opened before or immediately after the `POST` so you don't miss the early ticks. |

**Input (complete request):**

```bash
curl -N -H "Accept: text/event-stream" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  "http://localhost:8000/v1/tsg/grounding/calibrate/events/6ba7b810-9dad-11d1-80b4-00c04fd430c8"
```

**A browser's native `EventSource` cannot open this stream** — `EventSource` can't set custom
headers, and this route needs the three admin headers above. Use `fetch()` with a
`ReadableStream` reader instead, or `curl -N` as above.

**Output (what the wire actually looks like)** — `200` with `Content-Type: text/event-stream`.
Each event is an `event:` line, a `data:` line, then a blank line:

```
event: grounding_job_update
data: {"type":"grounding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"STARTED","run_id":"0f8fad5b-d9cb-469f-a165-70867728950e","force":false}

event: grounding_job_update
data: {"type":"grounding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"STARTED","phase":"negatives","done":40,"total":100}

event: grounding_job_update
data: {"type":"grounding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"STARTED","phase":"positives","done":150,"total":200}

event: grounding_job_update
data: {"type":"grounding_job_update","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","state":"SUCCESS","run_id":"0f8fad5b-d9cb-469f-a165-70867728950e","match_th":86.25,"quality":0.94,"negatives":100,"positives":200,"highest_negative":99.5,"lowest_positive":71.2,"near_duplicates":[],"embedding_model":"multilingual-e5-large","reranker_model":"bge-reranker-v2-m3"}

event: heartbeat
data: {"type":"heartbeat","job_id":"6ba7b810-9dad-11d1-80b4-00c04fd430c8","ts":"2026-08-31T09:19:14.000000+00:00"}
```

**Every `state` you can see on a `grounding_job_update` event** (mirrors Celery's own
`AsyncResult.state` — same vocabulary Test 10e reports):

| `state` | When it fires | Terminal (stream closes)? |
|---|---|---|
| `PENDING` | Queued, not yet picked up by a worker | no |
| `STARTED` | A worker is executing it — carries `force` on the very first event, then `phase` (`"negatives"`/`"positives"`) + `done`/`total` on each progress tick | no |
| `RETRY` | Autoretry scheduled (e.g. an LLM slot was briefly unavailable) — it WILL run again | no |
| `SUCCESS` | Sweep finished — carries the measurement (`match_th`/`quality`/…) or `skipped: "already_calibrated"` | **yes** |
| `FAILURE` | Sweep raised — carries `error` | **yes** |
| `REVOKED` | Cancelled | **yes** |

The very first event on connect is always a snapshot read straight from Celery's
`AsyncResult` — if the job is already terminal by the time you connect (you opened this late),
that snapshot IS the terminal event and the stream closes right away instead of replaying
history. `heartbeat` events are unrelated pings (no `state`) proving the connection is still
alive; they don't affect whether the stream closes.

**How to test:**

1. Open the stream right after (or just before) firing Test 10c on the same `job_id`.
2. Confirm a `grounding_job_update` event with `state: "STARTED"` arrives first.
3. Watch `phase: "negatives"` ticks, then `phase: "positives"` ticks, `done` climbing toward `total`.
4. Confirm the stream ends right after a `SUCCESS`/`FAILURE`/`REVOKED` event — no more events after it.
5. Confirm periodic `heartbeat` events keep arriving while `STARTED` events are still spaced out.

**Verify in the database:** no new SQL — reuse Test 10e's query and confirm the terminal
event's `match_th`/`quality`/`error` match the ledger row it names.

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Missing/wrong `X-Admin-Key`, or missing `X-API-Key`/`X-User-Id` | `401`, rejected before the stream opens |
| Unknown or fully-expired `job_id` | `404`, rejected before the stream opens |
| The process is already at its SSE concurrency cap (shared by every SSE route, session streams included) | `503 sse_capacity_exceeded` with a `Retry-After` header, rejected before the stream opens |

**Pass if:** the snapshot event arrives immediately, progress ticks match what Test 10e shows
mid-sweep, the stream closes itself on the terminal event, and heartbeats keep coming while
it's still open.

---

### Test 13 — Threat Intel Feeds ("Is the news still fresh?")

| | |
|---|---|
| **API** | `GET /v1/tsg/threat-intel/feeds` · `POST /v1/tsg/threat-intel/feeds/refresh` · `POST /v1/tsg/threat-intel/feeds/{feed}/refresh` |
| **Why does this API exist?** | Threat libraries change monthly; live intel (actively exploited CVEs, fresh advisories) changes daily. The AI benefits from current context, and the operator needs to see feed freshness and force a pull instead of waiting for the timer. |
| **What does it do?** | Shows the state of every live feed (CISA KEV, CISA ICS advisories, OTX, URLhaus, TAXII) and refreshes them — each feed as its own background job, so a slow feed can't hold up the others and you can retry just the one that failed. |
| **When do you call it?** | Anytime for status; refresh when intel looks stale or after fixing a feed's config. |

**Auth:** every route on this router carries the router-level admin gate — `X-Admin-Key` must exactly match the server's configured admin key — plus `get_admin_principal`: `X-API-Key` (a valid, hashed client key) and `X-User-Id` (required, non-blank — it becomes the audited actor in logs and the Celery shadow label). `X-Entity-Id` is not read at all here (no admin route scopes to an entity); `X-Tenant-Id` is accepted and bound to the log context if sent, but never required and never read by any admin handler — the intel cache is shared, cross-tenant data.

**Prerequisites.** The refresh endpoints below work on their own and need no scheduler. There
is **no scheduled refresh at all by default**: the beat entry is registered only when
`TSG_INTEL_REFRESH_INTERVAL_SECONDS > 0`, which defaults to `0` (and values between 1 and 899
are rejected outright), so you also need `celery beat` running and an interval of at least 900.
Nothing is "daily" unless you set `86400`. **`TSG_INTEL_ENABLED` does not gate any of this** —
despite the name, it controls only whether intel is injected into the AI's prompts, and never
whether feeds refresh.

**Input (complete requests):**

```bash
# 1) See the state of every feed
curl -s "http://localhost:8000/v1/tsg/threat-intel/feeds" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"

# 2) Refresh ALL enabled feeds now (one background job per feed)
curl -s -X POST "http://localhost:8000/v1/tsg/threat-intel/feeds/refresh" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"

# 3) Refresh just ONE feed — the targeted retry after a failure
curl -s -X POST "http://localhost:8000/v1/tsg/threat-intel/feeds/cisa_kev/refresh" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"
```

No bodies. Valid feed names for command 3: `cisa_kev`, `cisa_ics`, `otx`, `urlhaus`, `taxii`.

**Fields added 2026-09-02:** `stale` = an ENABLED feed with no successful refresh inside `TSG_INTEL_STALE_AFTER_SECONDS` (48 h default) — the SDD's SOURCE_STALE signal, also logged by `tsg.self_check` as `intel.feed_stale`; `source_version` = the release the last refresh synced (KEV `catalogVersion`, the CSAF mirror's newest change date). Set `TSG_INTEL_REFRESH_INTERVAL_SECONDS` (e.g. 86400) to run this refresh on the Celery beat schedule instead of by hand.

**Output (complete responses):**

```json
// GET /feeds
200 {"feeds": [
  {"feed": "cisa_kev", "enabled": true,  "item_count": 1653, "kinds": {"cve": 1653},
   "prompted": true,  "last_fetched_at": "2026-08-31T03:00:00Z",
   "last_attempt_at": "2026-08-31T03:00:00Z", "last_success_at": "2026-08-31T03:00:00Z",
   "last_error": null, "source_version": "2026.08.31", "stale": false},
  {"feed": "urlhaus",  "enabled": false, "item_count": 0, "kinds": {},
   "prompted": false, "last_fetched_at": null, "last_attempt_at": null,
   "last_success_at": null, "last_error": null, "source_version": null, "stale": false},
  {"feed": "otx",      "enabled": true,  "item_count": 0, "kinds": {},
   "prompted": true,  "last_fetched_at": null,
   "last_attempt_at": "2026-08-31T03:00:00Z", "last_success_at": null,
   "last_error": "HTTPError: 401 unauthorized — check OTX_API_KEY",
   "source_version": null, "stale": true}
]}

// POST /feeds/refresh — one job id PER ENABLED FEED (the fan-out; 0 keys if nothing is enabled)
202 {"jobs": {"cisa_kev": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
              "cisa_ics": "7c1d2e93-1f4b-42aa-9c31-0b7e5a2d8f10"}}

// POST /feeds/cisa_kev/refresh — exactly one
202 {"jobs": {"cisa_kev": "9f2a5b17-8c40-4d6e-a1b2-3c4d5e6f7a8b"}}
```

**How to test:**

1. `GET /feeds` — every known feed is listed, *including switched-off ones*.
2. `POST /feeds/refresh` → `202` with one job id **per enabled feed** — never a fixed 5; `otx` only shows up if an OTX key is configured, `taxii` only if a TAXII server is configured, `urlhaus` is off by default.
3. `POST /feeds/cisa_kev/refresh` → `202` with a single job.
4. `POST /feeds/phishtank/refresh` → `404` (not a feed TSG knows).
5. `GET /feeds` again — `last_success_at` has moved forward.

You must be able to tell three states apart:

| What you see | What it means |
|---|---|
| `"enabled": false` | switched off in configuration |
| `"enabled": true`, `"last_success_at": null` | on, but has never run |
| `"last_error": "..."` | it ran and failed — with the reason |

**Two things that look like bugs but aren't:**

- **A successful refresh can add 0 items.** The ICS feed only downloads
  advisories it doesn't already have — judge health by `last_success_at`, not
  by the count moving.
- **`urlhaus` shows `"prompted": false`.** Deliberate: raw malicious-URL data
  is cached for analysts but never sent to the AI.

**Tables used:** none in SQL — intel lives in **MongoDB**:

| Collection | Read/Write | What happens |
|---|---|---|
| `threat_intel` | Write | the cached intel items |
| `intel_feed_status` | Write | per-feed last attempt / success / error |

**Verify in the database (mongosh):**

```js
use tsg_embeddings; db.threat_intel.countDocuments({ source: "cisa_kev" });
db.intel_feed_status.find({}, { _id: 0 });   // last attempt / success / error per feed
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Unknown feed name | `404` |
| Known-but-disabled feed refresh | `404` naming it as disabled |
| Missing/wrong `X-Admin-Key` | `401` |
| Missing/wrong `X-API-Key`, or blank `X-User-Id` | `401` |

**Pass if:** the three feed states are distinguishable and a refresh advances `last_success_at`.

---

### Test 13a — List Live Intel Items ("Browse what the feeds actually caught")

| | |
|---|---|
| **API** | `GET /v1/tsg/threat-intel/items` |
| **Why does this API exist?** | `GET /feeds` in Test 13 only tells you a feed is healthy — it doesn't show what it actually pulled. An analyst (or anyone tracing where a scenario's cited intel came from) needs to browse the cached KEV CVEs, ICS advisories, OTX pulses and IOCs themselves. |
| **What does it do?** | Pages through the cached intel items, newest first, optionally filtered to one feed with `?source=`. |
| **When do you call it?** | Spot-checking a feed right after a refresh, or tracing a scenario's cited intel back to its source item. |

**Auth:** same as Test 13 — `X-Admin-Key` + `X-API-Key` + `X-User-Id`.

**Input (complete requests):**

```bash
# Every feed interleaved, first page
curl -s "http://localhost:8000/v1/tsg/threat-intel/items?limit=50&offset=0" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"

# Filtered to one feed
curl -s "http://localhost:8000/v1/tsg/threat-intel/items?source=otx&limit=50&offset=0" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user"
```

No body. `source` is optional — one of `cisa_kev`, `cisa_ics`, `otx`, `urlhaus`, `taxii`; omit it for every feed interleaved. `limit` defaults to 50 (1–500), `offset` defaults to 0.

Four of the fourteen fields are sparse by source, not optional on the wire — every item
carries all fourteen. `scope_tags` holds canonical scope keys the source tagged
(`sector:energy`, `country:united arab emirates`) and is what the prompt's scope tier
matches on by equality. `summary` is the source's own one-line summary and is emitted into
the prompt for CISA-authored kinds only. `severity` is the max CVSS base score, published
by ICS advisories only. `cwes` lists the weakness ids the source names. An OTX pulse
legitimately shows `[]`/`""`/`null` for all four.

**Output (complete response):**

```json
200 {
  "items": [
    {
      "source": "otx", "kind": "pulse",
      "external_id": "6a6c1a2b3c4d5e6f7a8b9c0d",
      "title": "[Armored Likho] Armored Likho's new weapon: BusySnake Stealer",
      "adversary": "Armored Likho",
      "description": "BusySnake is a new stealer attributed to ...",
      "url": "https://otx.alienvault.com/pulse/6a6c1a2b3c4d5e6f7a8b9c0d",
      "tags": ["armored likho", "stealer"],
      "fetched_at": "2026-08-31T07:44:27Z",
      "published_at": "2026-08-30T21:10:00Z",
      "scope_tags": [],
      "summary": "",
      "severity": null,
      "cwes": []
    },
    {
      "source": "cisa_kev", "kind": "cve",
      "external_id": "CVE-2026-31337",
      "title": "Example Corp Gateway — Improper Authentication",
      "adversary": null,
      "description": "Actively exploited authentication bypass ...",
      "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      "tags": [],
      "fetched_at": "2026-08-31T03:00:00Z",
      "published_at": "2026-08-29T00:00:00Z",
      "scope_tags": ["sector:energy", "country:united arab emirates"],
      "summary": "Improper authentication in Example Corp Gateway allows remote takeover.",
      "severity": 9.8,
      "cwes": ["CWE-287"]
    }
  ],
  "total": 1655,
  "limit": 50,
  "offset": 0
}
```

**How to test:**

1. `GET /items` with no `source` — items from every feed; `total` matches the sum of every feed's `item_count` from Test 13.
2. `GET /items?source=cisa_kev` — every returned item's `source` is `cisa_kev`; `total` matches that feed's `item_count`.
3. `GET /items?source=phishtank` → `404` (not a feed TSG knows — same allowlist as the refresh routes).
4. `GET /items?limit=500&offset=1500` on a feed with fewer than 1500 items → `200` with an empty `items` array and the real `total`, **not** a `404`.

**Tables used:** none in SQL — reads the same MongoDB collection Test 13 writes to:

| Collection | Read/Write | What happens |
|---|---|---|
| `threat_intel` | Read | paged newest-first by `published_at`, `external_id` as a tiebreak |

**Verify in the database (mongosh):**

```js
use tsg_embeddings;
db.threat_intel.find({ source: "otx" }, { raw: 0 })
  .sort({ published_at: -1, external_id: 1 }).skip(0).limit(50);
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| `?source=` an unknown feed name | `404` naming the valid feeds |
| Missing/wrong `X-Admin-Key` or `X-API-Key`, or blank `X-User-Id` | `401` |
| Mongo-backed intel store unreachable | `503` — **never** a `200` with an empty page standing in for an outage |

**Pass if:** filtering by `source` narrows both `items` and `total` correctly, and an empty result page is distinguishable from a store outage (`200` vs `503`).

---

### Test 13b — Feed Refresh Live Stream ("Watch a refresh happen instead of polling for it")

| | |
|---|---|
| **API** | `GET /v1/tsg/threat-intel/feeds/events/{job_id}` (header `Accept: text/event-stream`) |
| **Why does this API exist?** | Polling `GET /feeds` in a loop after a refresh is the same waste Test 8 solves for sessions — a job id from either refresh route in Test 13 can be watched live instead of re-polled. |
| **What does it do?** | Streams one queued per-feed refresh job's progress: a state snapshot on connect, then `STARTED`, then a terminal `SUCCESS`/`FAILURE` (or a non-terminal `RETRY` that keeps the stream open for another attempt). |
| **When do you call it?** | Right after `POST /feeds/refresh` or `POST /feeds/{feed}/refresh`, using one of the job ids from the `jobs` map in the response. |

**Input (complete request):**

```bash
curl -N -H "Accept: text/event-stream" \
  -H "X-Admin-Key: <X-Admin-Key>" -H "X-API-Key: <X-API-Key>" -H "X-User-Id: qa-user" \
  "http://localhost:8000/v1/tsg/threat-intel/feeds/events/9f2a5b17-8c40-4d6e-a1b2-3c4d5e6f7a8b"
```

These must be real HTTP headers, not query params — the browser's native `EventSource` API cannot set custom headers, so it cannot consume this stream. A browser client needs `fetch()` + a `ReadableStream` reader, same requirement Test 8 calls out for the session-events route.

**Output (what the wire actually looks like)** — `200` with `Content-Type: text/event-stream`. Every event on this route shares one event name, `intel_job_update`; the `state` field inside `data:` is what actually changes:

```
event: intel_job_update
data: {"type":"intel_job_update","job_id":"9f2a5b17-8c40-4d6e-a1b2-3c4d5e6f7a8b","state":"PENDING"}

event: intel_job_update
data: {"type":"intel_job_update","job_id":"9f2a5b17-8c40-4d6e-a1b2-3c4d5e6f7a8b","state":"STARTED","feed":"cisa_kev"}

event: intel_job_update
data: {"type":"intel_job_update","job_id":"9f2a5b17-8c40-4d6e-a1b2-3c4d5e6f7a8b","state":"SUCCESS","feed":"cisa_kev","item_count":12}
```

The first frame is always a connect-time snapshot read straight from the Celery result backend — even a client that connects after the job already finished gets that terminal state immediately, never silence. That snapshot never carries `feed`; `feed` only shows up once the worker itself has started and published a live update.

**Every `state` you can receive:**

| `state` | When it fires | Carries `feed`? | Extra fields |
|---|---|---|---|
| `PENDING` | connect-time snapshot only — queued, not yet picked up by a worker | no | — |
| `STARTED` | snapshot if a worker is already running it; otherwise a live event once one picks it up | snapshot: no · live: yes | — |
| `RETRY` | live only — a transient fetch error; autoretry **will** run again (non-terminal, stream stays open) | yes | `error` |
| `SUCCESS` | terminal — the refresh finished | **live: yes · snapshot: no** | `item_count` |
| `FAILURE` | terminal — retries exhausted | **live: yes · snapshot: no** | `error` |

`item_count` and `error` are present only on the event that actually carries them for that `state` — there's no `null` placeholder for the field that doesn't apply.

**`feed` is absent on every connect-time snapshot, terminal ones included.** The snapshot is
built from Celery's result backend, which knows the state and the result payload but not which
feed the job was for. So the "connect to an already-finished job" case in step 2 below gives you
a `SUCCESS` frame with `item_count` and **no `feed`**. Only frames the worker itself published
while running carry `feed`.

**How to test:**

1. `POST /feeds/refresh`, take one job id from `jobs`, open its stream immediately → snapshot arrives first (often `PENDING` or `STARTED` with no `feed` yet), then a live `STARTED` with `feed` set, then a terminal `SUCCESS` or `FAILURE` that closes the stream.
2. Open the stream for a job id that already finished (from a refresh run a minute earlier) → the snapshot itself is already the terminal event; the stream ends right there.
3. `GET .../events/not-a-real-job-id` → `404`.

**Tables used:** none in SQL/Mongo directly — this route reads Redis:

| Store | Read/Write | What happens |
|---|---|---|
| Redis admin job marker (`mark_admin_job`, same TTL as the Celery result backend) | Read | is `job_id` known and not expired — `404` if not |
| Redis (Celery result backend) | Read | the connect-time state snapshot |
| Redis (pub/sub bus) | Read | live `STARTED`/`RETRY`/`SUCCESS`/`FAILURE` hints as the worker publishes them |
| `intel_feed_status` (Mongo) | — | not touched by this route — Test 13's `GET /feeds` is the durable truth once the stream reports a terminal event |

**Verify in the database:** no new query — once the stream reports a terminal event, confirm it landed durably the same way Test 13 does:

```js
use tsg_embeddings; db.intel_feed_status.findOne({ feed: "cisa_kev" });
```

**Must-fail checks:**

| You do this | App must answer |
|---|---|
| Unknown or expired `job_id` | `404` |
| Missing/wrong `X-Admin-Key` or `X-API-Key`, or blank `X-User-Id` | `401`, rejected before the stream opens |
| SSE concurrency cap already hit (`sse_max_concurrent_streams`, shared across every SSE route in the process) | `503` with `Retry-After` |

**Pass if:** the connect-time snapshot always arrives first (even for an already-finished job), `feed` shows up once a live event fires, and the stream closes itself on `SUCCESS`/`FAILURE` but stays open through `RETRY`.

---

### What happened to Tests 11, 12, 14 and 15?

If you used an earlier version of this guide: those four tests walked through APIs for
importing threat-intel sources, checking library inventory, and hand-editing threat/control
library rows with PATCH and DELETE. **Those APIs are gone.** There is no import endpoint, no
inventory endpoint, and — checked directly against the source, not assumed —
**zero PATCH, PUT or DELETE routes anywhere in the app**:

```bash
grep -rn '@router\.\(patch\|put\|delete\)(' app/api/*.py
# (no output)
```

Library content is now curated two different ways, for two different kinds of content.

**1. The curated library is edited as SQL, not through the API.**

`Threat_Category`, `Threat_Type`, `Threat_Catalogue`, `Threat_Actor`, `Control_Library` and
`Control_Standard` are edited by hand in `scripts/eyshield_handoff/3. Seed_to_Threat_library.sql`
(27 threat-type names, 75 catalogue names, 13 actor names) and
`5. Seed_to_Control_library.sql` (30 standards, 1288 controls, 6105 control-standard links), then
a DBA re-runs the deployment pipeline documented in `scripts/eyshield_handoff/readme.txt`:

```
0. TSG_Preflight.sql            read-only — run FIRST, send the result set back, any FAIL is a stop
1. TSG_Core.sql                 TSG's own session/pipeline tables
2. Threat_library.sql           threat-library master tables
3. Seed_to_Threat_library.sql   curated threat library data
4. Control_library.sql          control library tables + Step-4 control mapping
5. Seed_to_Control_library.sql  curated control library data
6. TSG_Verify.sql               read-only — run LAST, send the result set back, do not sign off on a FAIL
```

All five middle scripts are idempotent and safe to re-run. There's nothing to smoke-test here
with `curl` — the verification step **is** running `6. TSG_Verify.sql` and confirming every row
PASSes.

**2. A threat the AI discovers mid-session becomes a library entry through Test 9b, not a
bulk-edit endpoint.**

When a session accepts a scenario whose threat wasn't already in the catalogue,
`POST /v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library` (Test 9b, above) is
the one live-traffic path that can insert a new `Threat_Type` / `Threat_Catalogue` row. It's
deliberately narrow — one threat, one caller, fully audited — not a general CRUD surface.

**Duplicate protection, if you're wondering:** dedup is the *application's* guarantee, not the
database's. `app/core/naming.py::normalize_name()` casefolds, Unicode-normalizes and collapses
separators (`"APT41"` / `"APT-41"` / `"APT 41"` are one identity), and `app/db/dal.py`'s upsert
functions check for an existing row by that key **before** ever inserting. Two writers racing
each other is the one case that check can't catch — the loser's `INSERT` hits a real unique
index (`UX_ThreatType_NaturalKey`, `UX_ThreatCatalogue_NaturalKey`) and raises `IntegrityError`,
but `dal.py` catches it and returns the WINNER's row instead of the error. So a race resolves
silently to `created: false` on whichever caller lost — you will not see a raw SQL error from
this, by design.

---

### Test 16 — Health Checks ("Is anyone home?")

| | |
|---|---|
| **API** | `GET /health` · `GET /ready` — **no auth on either** |
| **Why does this API exist?** | Orchestrators (Kubernetes/OpenShift) and load balancers need two different answers: "should I restart this process?" (liveness) and "should I send it traffic?" (readiness). |
| **What does it do?** | `/health` = liveness: "is the process running at all?" Always `200` if up — it does not touch the database, Redis, or Mongo, that's `/ready`'s job. `/ready` = readiness: "can it reach the database, Redis, and Mongo (when this deployment uses it), and does it see a live Celery worker?" |
| **When do you call it?** | `/health` first thing in setup; `/ready` whenever you suspect a dependency. |

**Input (complete requests):**

```bash
curl -s "http://localhost:8000/health"
curl -s "http://localhost:8000/ready"
```

**Output (complete responses):**

```json
// /health — always, as long as the process is up:
200 {"status": "ok"}

// /ready, everything running:
200 {"status": "ready", "checks": {"database": "ok", "redis": "ok", "mongo": "ok", "workers": "ok"}}

// /ready, a dependency down — honest degradation:
503 {"status": "not_ready", "checks": {"database": "error", "redis": "ok", "mongo": "ok", "workers": "ok"}}
```

`mongo` may say `"skipped"` instead of `"ok"` — that happens when `TSG_EMBEDDING_STORE` is not
`mongo` (i.e. this deployment uses the in-memory embedding cache) and is fine, not a failure.

`workers` is **advisory only**: it's a broadcast ping for a live Celery worker over the broker,
and it's reported in `checks` for visibility — but by itself it never flips `status` to
`not_ready` or the HTTP code to 503. With no workers the API still serves every synchronous
route; queued jobs simply wait instead of the whole pod being pulled from rotation.

**How to test:**

1. `GET /health` → `200 {"status": "ok"}` always.
2. `GET /ready` with everything running → `200 ready`, all four checks `"ok"` (or `mongo:
   "skipped"` if this deployment doesn't use Mongo).
3. Stop the DB (or Redis) and call `/ready` again → `503 not_ready` naming the dead dependency.
4. Stop the Celery worker (leave everything else up) and call `/ready` again → still `200 ready`,
   with `checks.workers: "error"` — confirms `workers` really is advisory and doesn't drag the
   whole probe down.

**Tables used:** none. Connectivity pings only — `SELECT 1` (MSSQL), `PING` (Redis), `ping`
(Mongo, skipped when the embedding store isn't `mongo`), and a Celery broadcast ping (workers,
1-second timeout so a healthy check never waits it out). No application table is ever queried.

**Security note:** the error response never leaks exception details — just `"error"` per
dependency; each failure is logged server-side instead.

**Pass if:** `/ready` honestly reports both the healthy and degraded state, and a dead `workers`
check alone never brings the whole probe down.

---

## Part 6c — API Clients Admin (new since the last guide)

Every other test in this guide assumes you already have an `X-API-Key` — Part 2's setup just says
"get an admin key from someone who already has one." These three tests are how that key actually
gets minted, listed, and killed. You'll want them if you're the one issuing keys to a new
integration, rotating a leaked key, or just proving during a smoke test that key lifecycle
management still works end to end.

All three routes live under `/v1/tsg/api-clients` and are gated at the router level by
`X-Admin-Key` alone (`require_admin`, not `get_principal`) — deliberately not part of the entity/
tenant model, since minting a client key can't itself require already having one, and these
routes manage cross-tenant client keys rather than one entity's data. Create and revoke also
require `X-User-Id` (checked in the handler, `400` if blank) so every provisioning/revocation
action is attributable in the audit trail; list does not.

### Test 16a — Create an API Client ("Mint me a key, just the one time")

| | |
|---|---|
| **API** | `POST /v1/tsg/api-clients` — requires `X-Admin-Key` + `X-User-Id` |
| **Why does this API exist?** | Every other endpoint in this whole guide needs an `X-API-Key`. Something has to hand one out in the first place — this is that something. |
| **What does it do?** | Generates a 32-byte secret server-side, stores only its SHA-256 hash, and returns the raw secret in the response. `module` is free-text (`tsg`, `chatbot`, ...) — a key only authenticates for its own module. |
| **When do you call it?** | Onboarding a new integration, or rotating a key (create the replacement before revoking the old one). |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/tsg/api-clients" \
  -H "X-Admin-Key: <X-Admin-Key>" \
  -H "X-User-Id: qa-user" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "qa-smoke-client",
    "name": "QA Smoke Test Client",
    "module": "tsg"
  }'
```

**Output (complete response):**

```json
// 201 Created
{
  "client_id": "qa-smoke-client",
  "module": "tsg",
  "secret": "9f3a1c7e2b5d8f0164a7c3e9b2d5f8a1046c9e2b7d4f1a8c5e0b3d6f9a2c7e4b"
}
```

**This response is the only time the raw secret is ever shown.** Reading the handler
(`app/api/api_clients.py`) confirms it: the secret is generated with `secrets.token_hex(32)`,
hashed with SHA-256 before the `INSERT`, and only the hash (`KeyHash`) is ever persisted — the
plaintext secret exists nowhere but this one response body, and the create-time log line
(`api_client.created`) deliberately omits it too. Copy it now. If it's lost, there is no recovery
path — revoke this client and create a new one.

**How to test:**

1. Create a client with a fresh `client_id` → `201`, response includes `secret`.
2. Repeat with the same `client_id` → `409 Conflict` ("client_id '...' already exists").
3. Omit `X-User-Id` (or send it blank) → `400` ("X-User-Id header is required").
4. Omit or send a wrong `X-Admin-Key` → `401`.
5. Violate a length bound → plain `422 validation_error`: `client_id` is 1–100 chars, `name`
   1–200, `module` 1–50. All three are required.

**Verify in the database:**

```sql
SELECT ClientID, Name, Module, Active, CreatedBy, CreatedAt
FROM API_Client
WHERE ClientID = 'qa-smoke-client';
-- Active = 1, CreatedBy = 'qa-user'. Note: KeyHash is NOT the secret you got back —
-- it's the SHA-256 of it. There is no column anywhere holding the plaintext secret.
```

**Security note:** `client_id`/`name`/`module` are logged; the secret never is, in the log or
anywhere else after this response.

**Pass if:** the secret appears exactly once, in this response, and never again in any later
call (including Test 16b's list) or in the database.

---

### Test 16b — List API Clients ("Who's got a key to the building?")

| | |
|---|---|
| **API** | `GET /v1/tsg/api-clients` — requires `X-Admin-Key` |
| **Why does this API exist?** | An admin needs to audit who has keys, which are still active, and who provisioned/revoked each one — without touching the database directly. |
| **What does it do?** | Returns every API client's metadata, newest-created first. Never returns `KeyHash` or the secret. Optional `?module=` filters to one module. |
| **When do you call it?** | Auditing active keys, or confirming Test 16a's create / Test 16c's revoke actually landed. |

**Input (complete requests):**

```bash
curl -s "http://localhost:8000/v1/tsg/api-clients" \
  -H "X-Admin-Key: <X-Admin-Key>"

# optionally scoped to one module:
curl -s "http://localhost:8000/v1/tsg/api-clients?module=tsg" \
  -H "X-Admin-Key: <X-Admin-Key>"
```

**Output (complete response):**

```json
// 200 OK
[
  {
    "client_id": "qa-smoke-client",
    "name": "QA Smoke Test Client",
    "module": "tsg",
    "active": true,
    "created_at": "2026-08-31T10:15:00Z",
    "created_by": "qa-user",
    "revoked_at": null,
    "revoked_by": null
  }
]
```

**How to test:**

1. List with no filter after Test 16a → the array includes `qa-smoke-client` with `active: true`
   and no `secret`/`key_hash` field anywhere in the payload.
2. List with `?module=chatbot` (or any module you didn't create a client for) → `qa-smoke-client`
   does not appear.
3. Omit or send a wrong `X-Admin-Key` → `401`. No `X-User-Id` is required for this one — it's a
   read.

**Verify in the database:**

```sql
SELECT ClientID, Name, Module, Active FROM API_Client ORDER BY CreatedAt DESC;
-- Same set the API returned, minus KeyHash which the API never exposes.
```

**Pass if:** the listing matches what create/revoke did, and `KeyHash`/`secret` never appear in
the response body under any field name.

---

### Test 16c — Revoke an API Client ("Cutting up the key card")

| | |
|---|---|
| **API** | `POST /v1/tsg/api-clients/{client_id}/revoke` — requires `X-Admin-Key` + `X-User-Id` |
| **Why does this API exist?** | A leaked or retired key has to stop working immediately, and someone has to be on record for having pulled it. |
| **What does it do?** | Flips `Active` to `false` and stamps `RevokedAt`/`RevokedBy` on the one active client row matching `client_id`. The key stops authenticating on its very next use — there's no update route, no un-revoke; rotation is create-new + revoke-old. |
| **When do you call it?** | Offboarding an integration, or immediately after a key leak. |

**Input (complete request):**

```bash
curl -s -X POST "http://localhost:8000/v1/tsg/api-clients/qa-smoke-client/revoke" \
  -H "X-Admin-Key: <X-Admin-Key>" \
  -H "X-User-Id: qa-user"
```

**Output (complete response):**

```json
// 200 OK
{
  "client_id": "qa-smoke-client",
  "status": "revoked"
}
```

**How to test:**

1. Revoke `qa-smoke-client` from Test 16a → `200`, `status: "revoked"`.
2. Revoke the same `client_id` again → `404` ("no active API client '...'") — it's no longer
   active, so a second revoke finds nothing to act on.
3. Revoke a `client_id` that never existed → `404`, same message.
4. Omit `X-User-Id` → `400` ("X-User-Id header is required").
5. Try to use the just-revoked client's secret as `X-API-Key` on any normal endpoint (e.g. Test
   16b's list, swapping to a route that uses `get_principal`) → `401` — a revoked key stops
   authenticating immediately.

**Verify in the database:**

```sql
SELECT ClientID, Active, RevokedAt, RevokedBy
FROM API_Client
WHERE ClientID = 'qa-smoke-client';
-- Active = 0, RevokedBy = 'qa-user', RevokedAt populated.
```

**Security note:** revocation is a soft delete (`Active=0`) — the row and its audit trail
(`CreatedBy`/`RevokedBy`) stay in the table forever. There's no hard-delete path for `API_Client`.

**Pass if:** the revoked key immediately stops authenticating, and revoking twice (or revoking a
client that doesn't exist) both return a clean `404` instead of a 500.

---

## Part 7 — Cheat Sheet (keep this open while testing)

### The journey in one line

> create (1) → poll (2) → read results (3) → redo one (4) → get more (5) → accept (6) or pass on it (6a) → request a fix (7b) → poll it (7d) → review it (7h) → check the trail (7a / 7j) — then create a throwaway session and cancel it (7).

### The four rules (again — they explain most "weird" behavior)

1. **`202` = "working on it", not "done."** Only the board (Test 2) says it finished.
2. **Nothing is ever deleted.** Filter `Superseded=0` for scenarios — but `(Superseded=0 OR Accepted=1)` whenever accepted rows matter, since an accept survives a later regenerate (Test 3). `IsDeleted=0` for library rows.
3. **The reaper acts alone.** State changes with no API call = the janitor, not a bug.
4. **`ActorUserID` = who's accountable, `ActorType` = who pressed the button — but only on rows a human actually caused.** Everything the pipeline writes on its own has `ActorUserID = NULL` and `ActorType = 'system'`. A `NULL` here is information ("the pipeline did this"), not a gap.

### Error code quick reference

Verified against every exception handler in `app/api/errors.py`, the one error raised ahead of
them by middleware, and the codes derived from a bare `HTTPException` status — this is the
complete list, not a sample. The derived ones (`bad_request`, `conflict`, `method_not_allowed`,
`service_unavailable`) come from the HTTP status phrase rather than a typed handler, so they
never carry `details`.

| error_code | HTTP | When you'll see it |
|---|---|---|
| `unauthorized` | 401 | bad, missing, or expired `X-API-Key` / `X-Admin-Key` |
| `forbidden` | 403 | authenticated, but not entitled to this entity's data. This is the wire value; `EntityForbidden` is only the Python class name |
| `bad_request` | 400 | creating or revoking an API client without `X-User-Id`. Note it is a `400`, not a `401` — the header is for attribution there, not authentication |
| `not_found` | 404 | unknown session / scenario / job / client id, or a row you can't see |
| `method_not_allowed` | 405 | right path, wrong verb. Derived from the HTTP status itself, and the reply carries an `Allow` header naming the verbs that do work |
| `active_session_exists` | 409 | creating a second session for an asset that already has one active (`details.active_session_id`) |
| `idempotency_key_conflict` | 409 | reusing an `Idempotency-Key` with a different body |
| `regenerate_conflict` | 409 | regenerate/next-set at the wrong stage, or on a bad `scenario_id` (`details.reason`) |
| `accept_conflict` | 409 | accept/reject at the wrong stage (`details.reason` says why) |
| `master_inactive` | 409 | accepting when a needed master threat type/catalogue was deactivated |
| `cancel_conflict` | 409 | cancelling a session that's already terminal (including "already reached REVIEW") |
| `treatment_conflict` | 409 | any treatment-plan gate refusal (`details.reason` is a `TreatmentGateReason`) |
| `embedding_busy` | 409 | a concurrent admin recreate/delete already holds this embedding group's lock |
| `calibration_running` | 409 | a grounding calibration for this model pair is already running (`details.run_id`) |
| `conflict` | 409 | creating an API client whose `client_id` already exists. Status-derived, so no `details` — distinct from the typed 409s above |
| `admin_validation_error` | 422 | a structurally-valid but business-rule-invalid admin body |
| `validation_error` | 422 | plain request-shape validation failure (missing/malformed field); `details.errors` lists every offending field |
| `payload_too_large` | 413 | request body over 16 MB. Raised by `BodySizeLimitMiddleware` **before** the error handlers run, so it is the one error that never carries a `details` key. A chunked upload with no declared length slips past it |
| `capacity_exceeded` / `llm_slot_unavailable` / `sse_capacity_exceeded` | 503 | the pipeline, the LLM slot pool, or the SSE stream pool is at its configured limit — retry after the `Retry-After` header |
| `service_unavailable` | 503 | a dependency the handler needed was unreachable: the Celery broker when enqueuing a session, regeneration or treatment plan, or the intel store on `GET /v1/tsg/threat-intel/items`. Status-derived, so no `details` and **no `Retry-After`**, unlike the three above |
| `internal_error` | 500 | unhandled exception — always logged server-side with a `request_id` you can grep for |

Two error codes from earlier guides no longer exist: `library_conflict` (belonged to the manual-editing API, which is gone — see "What happened to Tests 11, 12, 14 and 15?") and `reject_conflict` (reject reuses `accept_conflict`, it never had its own code).

### Which header set does each test need?

| Tests | Headers |
|---|---|
| 1–9b (everything under `/v1/sessions`, `/v1/users`, `/v1/entities/{id}/scenarios`) | `X-API-Key` + `X-User-Id` + `X-Entity-Id` + `X-Tenant-Id` (all four, via `get_principal`) |
| 7b–7l (treatment plans) | Same four — treatment routes sit on the same `/v1` auth, gated additionally by `settings.risk_module_enabled` |
| 10, 10a (embeddings), 10b–10f (grounding), 13/13a/13b (intel) | `X-Admin-Key` (router-level) **plus** `X-API-Key` + `X-User-Id` (`get_admin_principal`) — no `X-Entity-Id` needed |
| 16a, 16c (create / revoke an API client) | `X-Admin-Key` (router-level) **plus** `X-User-Id`, which is for attribution, not authentication — blank gives `400`, not `401` |
| 16b (list API clients) | `X-Admin-Key` only — it is a read, and takes no `X-User-Id` at all |
| 16 (health) | none |

### Results checklist (fill in as you go)

| # | Test | Priority | Pass/Fail | Notes |
|---|---|---|---|---|
| 1 | Create Session (+ idempotency) | P1 | | Session A id: |
| 2 | Get Session Board (+ 404/403) | P1 | | |
| 3 | Get Session Results | P1 | | saved scenario_id: |
| 4 | Regenerate Scenarios | P1 | | |
| 5 | Generate Next Set | P1 | | |
| 6 | Accept Session (repeatable now, not one-shot) | P1 | | |
| 6a | Reject Scenarios | P1 | | |
| 7 | Cancel Session (+ repeat-409) | P1 | | Session B id: |
| 7a | Get the Session Audit Trail | P1 | | |
| 7b | Request a Treatment Plan | P1* | | *if risk module enabled |
| 7c | Regenerate a Treatment Plan | P1* | | |
| 7d | Poll Treatment Plan Status | P1* | | |
| 7e | Get the Full Treatment Plan | P1* | | |
| 7f | Get a Session's Treatment-Plan Board | P1* | | |
| 7g | Cancel a Treatment Plan | P1* | | |
| 7h | Review a Treatment Plan | P1* | | |
| 7i | Get an Entity's Treatment-Plan Register | P1* | | |
| 7j | Get One Plan's Audit Trail | P1* | | |
| 7k | Get an Entity's Treatment-Plan Audit Trail | P1* | | |
| 7l | Get a Plan's Evidence Bundle | P1* | | |
| 8 | Live Session Events / SSE | P2 | | |
| 9 | Get Accepted Scenarios by Session | P2 | | |
| 9a | Cross-Session Scenario Reads | P2 | | |
| 9b | Promote a Scenario to the Library | P2 | | |
| 10 | Embeddings Admin (all 4 actions) | P3 | | |
| 10a | Embeddings Job Live Stream | P3 | | |
| 10b | Get the Current Grounding Threshold | P3 | | |
| 10c | Start a Calibration Sweep | P3 | | |
| 10d | List Calibration History | P3 | | |
| 10e | Poll Calibration Status | P3 | | |
| 10f | Calibration Live Stream | P3 | | |
| 13 | Threat Intel Feeds | P3 | | |
| 13a | List Live Intel Items | P3 | | |
| 13b | Feed Refresh Live Stream | P3 | | |
| 16 | Health Checks (`/health`, `/ready`, incl. degraded) | P3 | | |
| 16a | Create an API Client | P3 | | |
| 16b | List API Clients | P3 | | |
| 16c | Revoke an API Client | P3 | | |

*Tests 11, 12, 14 and 15 from earlier versions of this guide are intentionally absent — see
"What happened to Tests 11, 12, 14 and 15?" in Part 6.*
