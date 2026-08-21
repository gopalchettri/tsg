# TSG API Integration Guide (for UI Developers)

Audience: UI developers consuming the **Threat Scenario Generator (TSG)** backend (FastAPI, API version `1.1`).
Everything below is generated from the actual backend code. Anything not determinable from code is marked `<TO_BE_CONFIRMED>`.

---

## 1. API Base URL

```text
<API_BASE_URL>
```

UI environment variable:

```text
VITE_API_BASE_URL=<API_BASE_URL>
```

The server listens on port **8000** (`http://<host>:8000`); every endpoint path already includes its full prefix (`/v1/...`), so the base URL is just scheme + host + port with **no extra path segment**. The deployed UAT/prod hostname is `<TO_BE_CONFIRMED>` — configure it per environment via `VITE_API_BASE_URL`, never hard-code it.

Interactive API docs are served at `<API_BASE_URL>/docs` (Swagger UI) and the machine-readable spec at `<API_BASE_URL>/openapi.json` — useful for trying calls and generating client types.

---

## 2. API Key Configuration

There is **no `Authorization: Bearer`** mechanism. TSG authenticates every call with custom headers.

UI environment variables:

```text
VITE_API_KEY=<API_KEY>
VITE_ADMIN_API_KEY=<ADMIN_API_KEY>   # only if the UI includes admin screens
```

> Store keys in environment/configuration only — never hard-code them in source. The backend's own guidance (docs/TSG_API_AUTHENTICATION_GUIDE.md §13) is that the API key must not live in browser code at all in production: calls should go browser → your BFF/server → TSG.

### 2.1 User header set — required on all Sessions / Scenarios / Treatment Plans endpoints

All four are required; a missing one returns `401`.

```text
X-API-Key: <API_KEY>
X-User-Id: <USER_ID>
X-Entity-Id: <ENTITY_ID>
X-Tenant-Id: <TENANT_ID>
Content-Type: application/json      # on requests with a body
```

The `X-User-Id` / `X-Entity-Id` / `X-Tenant-Id` values come from your host platform's authentication/tenancy context — TSG trusts them as sent (it can optionally verify user↔entity membership server-side). Which values to send per environment: `<TO_BE_CONFIRMED>` with the platform team (the server's configured fallback tenant is `DESC`, but the header must still be sent).

### 2.2 Admin header set — required on all `/v1/tsg/...` admin endpoints

```text
X-Admin-Key: <ADMIN_API_KEY>
X-API-Key: <API_KEY>
X-User-Id: <USER_ID>
Content-Type: application/json      # on requests with a body
```

(`X-Tenant-Id` is optional here; `X-Entity-Id` is ignored.)
**Exception:** the API Clients module (§5.6) needs only `X-Admin-Key` (+ `X-User-Id` on create/revoke).

### 2.3 Notes

- The `X-API-Key` value is issued by an administrator via `POST /v1/tsg/api-clients` (§5.6) — the secret is shown **once** at creation and cannot be recovered.
- Optional headers: `Idempotency-Key` (only on `POST /v1/sessions`, max 200 chars) and `X-Request-Id` (echoed back on every response; include it in bug reports).
- **CORS:** the server's allowed-origins list is empty by default (`TSG_CORS_ALLOWED_ORIGINS`). Browsers are blocked at preflight until your UI origin is added — per-environment value `<TO_BE_CONFIRMED>`. Allowed methods: GET, POST, PATCH, DELETE.
- **Timestamps:** all datetimes are UTC (ISO-8601).
- **Pagination:** list endpoints take `limit`/`offset`. Only some responses carry a `total` (intel items, promotions, candidates) — the scenario lists, treatment register and audit feeds do **not**; page until a response comes back shorter than `limit`.

### 2.4 Recommended fetch wrapper

One wrapper keeps every call correct:

```js
const api = (path, { admin = false, ...init } = {}) =>
  fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "X-API-Key": API_KEY,
      "X-User-Id": ctx.userId,
      "X-Entity-Id": ctx.entityId,
      "X-Tenant-Id": ctx.tenantId,
      ...(admin ? { "X-Admin-Key": ADMIN_KEY } : {}),
      ...(init.body ? { "Content-Type": "application/json" } : {}),
      ...init.headers,
    },
  });
```

### 2.5 Handling auth failures

- `401 unauthorized` — key or identity headers missing/invalid; the body is deliberately
  generic, so check which header you dropped. A revoked key also lands here. Never retry
  as-is.
- `403 forbidden` — authenticated, but this user/entity may not touch this resource. Show
  "no access"; do not retry. Everything is entity-scoped: a session created under entity 78
  is a `404` under entity 79.

---

## 3. Common Error Responses

Every error (unless noted per endpoint) uses one envelope:

```json
{ "error_code": "not_found", "message": "human-readable text", "details": { } }
```

`details` is present only when there is machine-readable context (e.g. a conflict `reason`).

| Status | `error_code` | Meaning |
|---|---|---|
| 401 | `unauthorized` | Missing/invalid key or identity headers (body is deliberately generic) |
| 403 | `forbidden` | Authenticated, but not authorized for this entity/session |
| 404 | `not_found` | Resource does not exist (or is filtered from your view) |
| 409 | `active_session_exists` | Asset already has an active session (`details.active_session_id`) |
| 409 | `idempotency_key_conflict` | Same `Idempotency-Key`, different body (`details.existing_session_id`) |
| 409 | `accept_conflict` / `regenerate_conflict` / `cancel_conflict` / `treatment_conflict` | Action refused; switch on `details.reason` |
| 409 | `library_conflict` | Duplicate library row (`details.existing_id`) |
| 413 | `payload_too_large` | Request body over the configured limit (default 128 MB) |
| 422 | `validation_error` | Invalid body/params; `details.errors` is the field-error list |
| 422 | `admin_validation_error` / `threat_library_import_error` | Domain validation on admin/import endpoints |
| 503 | `capacity_exceeded` / `llm_slot_unavailable` / `sse_capacity_exceeded` | Busy — retry after the `Retry-After` header (seconds) |
| 500 | `internal_error` | Unexpected; response carries `X-Request-Id` for support |

Exceptions to the envelope — these return FastAPI's plain `{"detail": "..."}` instead:

- All **API Clients** errors (400/404/409, §5.6).
- `POST /v1/sessions`: `422` invalid server tuning config, and `503` "could not be queued" (the session is auto-cancelled — safe to retry).
- `POST .../regenerate/scenarios` and `POST .../scenarios/next-set`: `503` "could not queue the request".
- `GET /v1/tsg/threat-intel/items`: `503` "intel store unavailable".

`GET /ready` has its own shape (§5.1). Error handlers should therefore accept **either** `error_code` or `detail`.

---

## 4. Async Jobs & SSE Streams (conventions)

Long-running work returns **202 + an id**; you then poll a GET and/or subscribe to a Server-Sent-Events stream:

| Start (202) | Poll | SSE stream |
|---|---|---|
| `POST /v1/sessions` → `session_id` | `GET /v1/sessions/{id}` | `GET /v1/sessions/{id}/events` |
| `POST .../regenerate/scenarios`, `POST .../scenarios/next-set` → `epoch` | `GET /v1/sessions/{id}` (`progress.last_regen` / `progress.last_next_set`) | same stream |
| `POST .../treatment-plan` → `plan_id` | `GET` on the same path | same stream (`treatment_plan_result`, advisory) |
| Embedding actions → `job_id` | `GET .../embeddings/status/{job_id}` | `GET .../embeddings/events/{job_id}` |
| Library import → `job_id` | `GET .../imports/{job_id}` | `GET .../imports/events/{job_id}` |
| Intel refresh → `jobs{feed: job_id}` | `GET .../threat-intel/feeds` (no per-job GET) | `GET .../feeds/events/{job_id}` |

**The main user flow, step by step** (each endpoint's full detail + sample response is in §5):

1. **Preflight** — `GET /health` → `200 {"status":"ok"}` (no auth). Optional: `GET /ready`
   for a per-dependency status badge.
2. **Create the session** — `POST /v1/sessions` (§5.2) with the asset/supporting-system ids
   from your host platform, plus an `Idempotency-Key` so a network retry is safe → `202
   session_id`. Branch on `409 active_session_exists` (offer to open
   `details.active_session_id`) and `503 capacity_exceeded` (honor `Retry-After`).
3. **Watch progress** — open `GET /v1/sessions/{id}/events` (SSE) immediately AND poll
   `GET /v1/sessions/{id}` as backstop. Render from the `reconcile` snapshot; drive the whole
   UI state from `progress.overall`.
4. **Render the review screen** — when `progress.overall` = `awaiting_review` →
   `GET .../results`: threats + scenario cards (a failed card has `scenario: null` and
   `validation_errors` — show it as a failure card, don't hide it). Excel: `.../results.xlsx`.
5. **Optional loops** — "Generate more": `POST .../scenarios/next-set` (no body) → match the
   returned `epoch` against `progress.last_next_set.epoch` (or the `next_set_result` event),
   then re-fetch `/results`; on `outcome: "exhausted"` disable the button, on
   `"partial_retryable"` offer a retry. "Regenerate selected": `POST
   .../regenerate/scenarios` with `output_ids` (+ optional `user_note`) — same epoch-matching
   pattern via `last_regen`. Both `409 regenerate_conflict` while another generation runs —
   disable the buttons while one is in flight.
6. **Accept (terminal — confirm with the user first)** — `POST .../accept` with
   `{"mode":"all"}`, `{"mode":"none"}`, or `{"mode":"subset","output_ids":[…]}` → session
   `completed`. Then render the permanent record: `GET .../accepted-scenarios`.
   (`POST .../cancel` is the terminal abandon action.)
7. **Treatment plans (optional module)** — per accepted scenario: `POST .../treatment-plan`
   (first version) or `.../treatment-plan/regenerate` (later versions) → `202`; watch the
   same session SSE stream for `treatment_plan_result` (advisory) and poll the GET on the
   same path; `POST .../treatment-plan/review` records the decision (optionally with
   `plan_id` to adopt an older version). Board: `GET .../treatment-plans`; entity register:
   `GET /v1/entities/{id}/treatment-plans`.
8. **Admin screens (optional)** — the curation queue (§5.8): list pending cards
   (`?kind=threat|actor`), the rejected blacklist (`?status=rejected`), approve (mints with
   the original proposer credited) or reject (identity stays suppressed); a concurrent
   resolve returns `409` — refresh the queue. Promotions monitor + retry: §5.7.

**Golden rules:** all four user headers on every non-admin call, key server-side in
production (§2); SSE via `fetch()` streaming, never `EventSource`, always with the polling
backstop; drive state from `progress.overall`, treat events as acceleration; match `epoch`
to pair a click with its result and disable in-flight buttons; switch on `details.reason`
for every 409; accept/cancel are terminal — confirm first.

**SSE rules (UI-critical):**
- Streams require the auth headers, so the browser `EventSource` API **cannot** be used. Use `fetch()` + `ReadableStream` parsing. A working reference client ships with the backend at `app/static/sse_test.html` (served at `/dev/sse-test` in dev environments only).
- Content type is `text/event-stream`. Each stream sends a snapshot on connect and closes itself when the underlying work is terminal.
- Events are **best-effort with no replay** — always keep a polling backstop.
- At the per-process stream cap you get `503 sse_capacity_exceeded` — fall back to polling and retry after `Retry-After`.

---

## 5. Module-wise API Documentation

Modules: Health · Sessions · Scenarios · Treatment Plans · Embeddings Admin · API Clients Admin · Session Admin (Promotions) · Threat Library Candidates · Threat Library Import · Threat Library CRUD · Control Library CRUD · Threat Intel Admin.

---

## 5.1 Health

No authentication headers required.

### Health Check

**Method:** `GET`
**Endpoint:** `/health`
**Purpose:** Liveness probe; always returns 200.
**When to call:** Connectivity check (e.g. at app start).
**Headers:** none
**Response:** `200`

```json
{ "status": "ok" }
```

### Readiness Check

**Method:** `GET`
**Endpoint:** `/ready`
**Purpose:** Reports whether the backend's dependencies (database, Redis, Mongo, workers) are up.
**When to call:** Ops dashboards, or before enabling app features after a deploy.
**Headers:** none
**Response:** `200` ready / `503` not ready (own shape, not the error envelope):

```json
{ "status": "ready", "checks": { "database": "ok", "redis": "ok", "mongo": "skipped", "workers": "ok" } }
```

---

## 5.2 Sessions

Headers for **every** endpoint in this module (§2.1):

```text
X-API-Key: <API_KEY>
X-User-Id: <USER_ID>
X-Entity-Id: <ENTITY_ID>
X-Tenant-Id: <TENANT_ID>
```

Add `Content-Type: application/json` on POSTs with a body.

### Create Session

**Method:** `POST`
**Endpoint:** `/v1/sessions`
**Purpose:** Creates a threat-scenario session for one asset and starts the AI pipeline.
**When to call:** When the user clicks "Generate threat scenarios" for an asset.
**Extra header (optional):** `Idempotency-Key: <unique-string>` — safe retry; replaying the same key + same body returns `200` with the existing session.
**Request:**

```json
{
  "entity_id": "78",
  "service_id": 335,
  "sector_id": 95,
  "subsector_id": 111,
  "asset_id": 103,
  "supporting_system_id": [321, 322, 323, 324]
}
```

- `asset_id` (int, required) — asset to analyze.
- `entity_id` (string, required) — must match `X-Entity-Id` scope.
- `supporting_system_id` (int[], required) — 1–50 ids, **no duplicates**.
- `subsector_id` (int, optional) — the sub-sector (child) id; **preferred**. `sector_id` (int, optional) is the parent sector, cross-check only.
- `service_id` (int, optional).
- Do **not** send `user_id` — the initiating user is taken from `X-User-Id`.

> **Where these ids come from:** TSG exposes **no lookup endpoints** for assets, services, sectors/sub-sectors, or supporting systems — it validates the ids against the shared onboarding data server-side. The UI must source them from the host platform's onboarding/asset screens or APIs: `<TO_BE_CONFIRMED>`.

**Response:** `202` (`200` on idempotent replay)

```json
{ "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "user_id": "jsmith" }
```

**Errors:** `409 active_session_exists` (`details.active_session_id`) · `409 idempotency_key_conflict` (`details.existing_session_id`) · `503 capacity_exceeded`.

### Get Session Board

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}`
**Purpose:** Current status of the session and its pipeline stages — the polling endpoint.
**When to call:** After creating a session and periodically as the SSE backstop; also to read `progress.last_next_set` / `progress.last_regen` after those actions.
**Response:** `200`

```json
{
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "entity_id": "78",
  "asset_id": 103,
  "asset_name": "SCADA Server",
  "user_id": "jsmith",
  "session_status": "active",
  "current_stage": "SCENARIO_GENERATION",
  "stage_status": "RUNNING",
  "progress": {
    "threats": "COMPLETE",
    "scenarios": "RUNNING",
    "overall": "in_progress",
    "error_message": {},
    "last_next_set": null,
    "last_regen": null
  }
}
```

- `session_status`: `active | completed | cancelled`.
- `current_stage`: `THREAT_IDENTIFICATION | SCENARIO_GENERATION | REVIEW | APPROVED | CANCELLED`.
- `progress.threats` / `progress.scenarios`: `IDLE | RUNNING | SCENARIOS_AWAITING_DECISION | COMPLETE | ERROR | CANCELLED`.
- `progress.overall`: `pending | in_progress | awaiting_review | complete | error | cancelled` — drive the main UI state from this.
- `progress.error_message`: object keyed by stage name (empty object = no errors).
- `progress.last_next_set`: `{ outcome: "complete"|"partial_retryable"|"exhausted", requested, delivered, variants, reason, epoch }`.
- `progress.last_regen`: `{ target_ids, requested_ids, replacements, failed_threat_ids, rescored_threat_ids, epoch, user_note }`.

**Errors:** `404`, `403`.

### Get Session Results

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/results`
**Purpose:** The session's threats and generated scenarios (current versions).
**When to call:** When `progress.overall` reaches `awaiting_review` (and again after regenerate/next-set/accept).
**Query:** `include_replaced` (bool, default `false`) — nests superseded versions under each card's `replaced_scenarios`.
**Response:** `200`

```json
{
  "session_id": "…", "entity_id": "78", "asset_id": 103, "asset_name": "SCADA Server",
  "user_id": "jsmith",
  "progress": { "…": "same shape as the board" },
  "threats": [
    {
      "threat_id": "…", "threat_type": "Spoofing", "threat_name": "PLC identity spoofing",
      "grounding_status": "verified", "threat_catalogue_id": 42, "threat_actors": ["APT33"],
      "grounding_score": 87.5, "score": 12.0, "scope_rank": 1
    }
  ],
  "scenarios": [
    {
      "output_id": "…", "threat_id": "…", "accepted": false,
      "moderation_checked": true, "moderation_flagged": false, "moderation_categories": [],
      "validation_status": "ok", "validation_errors": [],
      "generation_epoch": 1, "scenario_number": 1, "controls_mapped": true,
      "replaced_scenarios": [],
      "scenario": {
        "scenario_title": "…", "scenario_statement": "…", "risk_statement": "…",
        "threat_category": "Spoofing", "threat_type": "…", "threat_name": "…",
        "threat_actors": ["…"],
        "controls": [
          { "control_library_id": 9, "control_code": "AC-2", "domain": "Access Control",
            "control_name": "…", "rank": 1, "score": 0.91,
            "suggested_control": null, "suggested_why": null, "standards": ["…"] }
        ],
        "suggested_controls": [ { "name": "…", "why": "…" } ],
        "unmatched_suggestions": [],
        "supporting_system_applicability": [
          { "supporting_system": "…", "applicable": true, "justification": "…" }
        ]
      }
    }
  ]
}
```

- `scenario` is `null` on a failure card (`validation_status`/`validation_errors` say why).
- The `scenario` object allows extra keys beyond those listed (the narrative is AI-produced); `scenario_title`, `scenario_statement`, `risk_statement` are the display fields. Full narrative key set beyond these: `<TO_BE_CONFIRMED>`.

**Errors:** `404`, `403`.

### Download Session Results (Excel)

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/results.xlsx`
**Purpose:** Same data as `/results` as an `.xlsx` workbook.
**When to call:** "Export to Excel" button.
**Query:** `include_replaced` (bool, default `false`).
**Response:** `200`, `Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet`, `Content-Disposition: attachment; filename="session_{session_id}_results.xlsx"`. Fetch as a blob and trigger a download.
**Errors:** `404`, `403`.

### Accept Scenarios

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/accept`
**Purpose:** Records the review decision and completes the session (terminal).
**When to call:** When the user finishes reviewing (`progress.overall` = `awaiting_review`).
**Request:** one of

```json
{ "mode": "all" }
{ "mode": "none" }
{ "mode": "subset", "output_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"] }
```

- `mode` (required): `all` accepts everything, `none` accepts nothing (session still completes), `subset` accepts only `output_ids`.
- `output_ids` (string[]): required non-empty (max 50) when `mode="subset"`; **must be omitted otherwise**.

**Response:** `200`

```json
{ "session_id": "…", "user_id": "jsmith", "status": "completed", "accepted_count": 7 }
```

**Errors:** `409 accept_conflict` with `details.reason` ∈ `session_completed | session_cancelled | generation_in_progress` · `404` (on a partial subset, `details` names each unacceptable output id).

### Regenerate Scenarios

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/regenerate/scenarios`
**Purpose:** Rebuilds the narratives of the named scenarios (new versions supersede the old).
**When to call:** User selects scenarios and clicks "Regenerate".
**Request:**

```json
{ "output_ids": ["3fa85f64-5717-4562-b3fc-2c963f66afa6"], "user_note": "Please emphasize the insider-threat vector." }
```

- `output_ids` (string[], required, 1–50) · `user_note` (string, optional).

**Response:** `202`

```json
{ "session_id": "…", "user_id": "jsmith", "status": "regenerating", "epoch": 3 }
```

Match `epoch` against `progress.last_regen.epoch` on the board (or the `regen_result` SSE event) to know when *this* click finished.
**Errors:** `409 regenerate_conflict` (`details.reason`) · `503` (queue unreachable).

### Generate Next Scenario Set

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/next-set`
**Purpose:** Generates the next batch of scenarios (accumulating; nothing is replaced).
**When to call:** "Generate more" button during review.
**Request:** no body.
**Response:** `202` — same shape as Regenerate with `"status": "generating"`:

```json
{ "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "user_id": "jsmith", "status": "generating", "epoch": 2 }
```

Match `epoch` against `progress.last_next_set.epoch`. `last_next_set.outcome` tells you what happened: `complete` (full set), `partial_retryable` (click again to retry failures), `exhausted` (nothing further exists — disable the button).
**Errors:** `409 regenerate_conflict` · `503`.

### Cancel Session

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/cancel`
**Purpose:** Cancels an active session (terminal).
**When to call:** User abandons the session.
**Request:** no body.
**Response:** `200`

```json
{ "session_id": "…", "user_id": "jsmith", "status": "cancelled" }
```

**Errors:** `409 cancel_conflict` (already completed/cancelled).

### Session Events (SSE)

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/events`
**Purpose:** Live progress stream for the session (stage starts/completions, review gate, regen/next-set results, treatment-plan results, errors, heartbeats).
**When to call:** Open right after creating a session; reopen on reconnect. See §4 — **`EventSource` will not work**; use `fetch()` + `ReadableStream`.
**Response:** `200`, `text/event-stream`. Event types (`event:` field / `type` key):

| Event | Payload keys |
|---|---|
| `reconcile` (sent once per connect) | full Session Board + `type` |
| `stage_started` / `stage_completed` | `session_id, subsystem_id, stage, status, generation_epoch, ts` |
| `subsystem_started` | `session_id, subsystem_id, generation_epoch, ts` |
| `session_entered_review` | `session_id, status, generation_epoch, ts` |
| `next_set_result` | `subsystem_id, outcome, requested, new_scenarios, new_variants, no_new, epoch, reason, detail, message, ts` |
| `regen_result` | `subsystem_id, requested_output_ids, new_output_ids, replacements, failed_threat_ids, rescored_threat_ids, reason, detail, message, ts` |
| `treatment_plan_result` | `output_id, plan_id, status, reason, ts` |
| `error` | `scope ("stage"\|"session"\|null), subsystem_id, message, generation_epoch, ts` — **not necessarily terminal; do not tear the UI down on it** |
| `heartbeat` | `session_id, ts` |

Example frames:

```text
event: stage_completed
data: {"type":"stage_completed","session_id":"5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e","subsystem_id":321,"stage":"SCENARIO_GENERATION","status":"COMPLETE","generation_epoch":1,"ts":"2026-08-15T02:04:11Z"}

event: session_entered_review
data: {"type":"session_entered_review","session_id":"5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e","status":"SCENARIOS_AWAITING_DECISION","generation_epoch":1,"ts":"2026-08-15T02:04:12Z"}

event: heartbeat
data: {"type":"heartbeat","session_id":"5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e","ts":"2026-08-15T02:04:27Z"}
```

The stream closes itself when the session leaves `active`.
**Errors:** `503 sse_capacity_exceeded` (fall back to polling) · `404` · `403`.

### Get Accepted Scenarios

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/accepted-scenarios`
**Purpose:** The final accepted record of a completed session.
**When to call:** Rendering a completed session's outcome.
**Response:** `200`

```json
{
  "asset_id": 103, "entity_id": "78", "user_id": "jsmith", "session_id": "…",
  "completed_at": "2026-08-01T10:15:00",
  "scenarios": [
    { "output_id": "…", "supporting_system_id": 321, "threat_type_id": 5, "threat_catalogue_id": 42,
      "threat_type": "Spoofing", "threat_name": "…", "threat_actors": ["…"], "scenario": { "…": "narrative object as in /results" } }
  ]
}
```

**Errors:** `404`, `403`.

---

## 5.3 Scenarios (cross-session reads)

Same headers as §5.2 (all four user headers).

### List a User's Scenarios

**Method:** `GET`
**Endpoint:** `/v1/users/{user_id}/scenarios`
**Purpose:** Scenario history filtered by initiating user (always restricted to entities the caller is authorized for — the path is a filter, not an identity claim).
**When to call:** "My scenarios" screen.
**Query:** `status` (`active | completed | cancelled | accepted`, optional) · `include_superseded` (bool, default `false`) · `limit` (int, default 100, max 500) · `offset` (int, default 0).
**Response:** `200` — array of scenario list items:

```json
[
  { "output_id": "…", "supporting_system_id": 321, "threat_type_id": 5, "threat_catalogue_id": 42,
    "threat_type": "Spoofing", "threat_name": "…", "threat_actors": ["…"], "scenario": { "…": "…" },
    "session_id": "…", "entity_id": "78", "user_id": "jsmith", "session_status": "completed",
    "scenario_number": 1, "accepted": true, "superseded": false, "created_at": "2026-08-01T10:15:00" }
]
```

### List an Entity's Scenarios

**Method:** `GET`
**Endpoint:** `/v1/entities/{entity_id}/scenarios`
**Purpose:** Scenario history for one entity.
**When to call:** Entity-level register screen.
**Query & response:** identical to the user listing above:

```json
[
  { "output_id": "9d4e8c2a-77b1-4b3a-9f6e-2c1d0a5b7e33", "supporting_system_id": 321, "threat_type_id": 5,
    "threat_catalogue_id": 42, "threat_type": "Spoofing", "threat_name": "PLC identity spoofing",
    "threat_actors": ["APT33"], "scenario": { "scenario_title": "…", "scenario_statement": "…", "risk_statement": "…" },
    "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "entity_id": "78", "user_id": "jsmith",
    "session_status": "completed", "scenario_number": 1, "accepted": true, "superseded": false,
    "created_at": "2026-08-01T10:15:00" }
]
```

**Errors:** `403` if the entity is not in the caller's authorized set.

### Get One Scenario

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}`
**Purpose:** One scenario row regardless of its flags — use it to inspect superseded versions or failure cards (`scenario` is `null` on those).
**When to call:** Scenario detail view / history drill-down.
**Query:** `user_id` (string, **required**) — mismatch returns `404`.
**Response:** `200` — one scenario list item (same shape as above):

```json
{ "output_id": "9d4e8c2a-77b1-4b3a-9f6e-2c1d0a5b7e33", "supporting_system_id": 321, "threat_type_id": 5,
  "threat_catalogue_id": 42, "threat_type": "Spoofing", "threat_name": "PLC identity spoofing",
  "threat_actors": ["APT33"], "scenario": { "scenario_title": "…", "scenario_statement": "…", "risk_statement": "…" },
  "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "entity_id": "78", "user_id": "jsmith",
  "session_status": "completed", "scenario_number": 1, "accepted": true, "superseded": false,
  "created_at": "2026-08-01T10:15:00" }
```

**Errors:** `404`, `403`, `422` (missing `user_id`).

---

## 5.4 Treatment Plans

> ⚠️ This module is mounted **only when the backend runs with `RISK_MODULE_ENABLED=true`** (code default is `false` — the endpoints 404 when disabled). Whether it is enabled in your target environment: `<TO_BE_CONFIRMED>`.

Same headers as §5.2 (all four user headers). Treatment plans apply to **accepted** scenarios of **completed** sessions.

### Generate Treatment Plan (first generation only — BREAKING CHANGE)

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan`
**Purpose:** Starts AI generation of a Mitigate treatment plan for one accepted scenario, using the risk-register data you supply. **First generation only** — if any plan already exists for the scenario (whatever its status), this returns `409` with `details.reason = plan_already_exists`; every later version is minted by the dedicated `/regenerate` route below. (Previously re-POSTing here regenerated — clients must switch.)
**When to call:** "Generate treatment plan" — the first time only.
**Request:**

```json
{
  "existing_controls": ["annual patching", "network firewall"],
  "likelihood_rating": 4,
  "impact_rating": 5,
  "final_risk_rating": 20,
  "risk_level": "Critical",
  "risk_identification_date": "2026-06-14T08:31:00Z",
  "risk_owner": "Head of OT Operations",
  "impacted_business_division": "Water Treatment Operations",
  "existing_controls_all_subsystems": "No",
  "existing_controls_all_subsystems_justification": "Controls deployed on IT systems only."
}
```

- `existing_controls` (string[], **key required**, may be `[]`; max 50 items, each ≤ 500 chars).
- `likelihood_rating` / `impact_rating` (int, required, 1–5) · `final_risk_rating` (int, required, 1–25).
- `risk_level` (required): `Low | Medium | High | Critical`.
- Optional: `risk_identification_date` (ISO datetime), `risk_owner` (≤200), `impacted_business_division` (≤200), `existing_controls_all_subsystems` (`Yes | No`), `existing_controls_all_subsystems_justification` (≤1000), `user_note` (≤1000, steering for the first generation).
- No strategy field (server stamps `Mitigate`); no `user_id` field (comes from `X-User-Id`).

**Response:** `202`

```json
{ "plan_id": "…", "session_id": "…", "output_id": "…", "status": "RUNNING" }
```

**Errors:** `409 treatment_conflict` with `details.reason` ∈ `scenario_not_accepted | plan_already_exists | generation_in_progress` · `404` · `500` (enqueue failure; plan parked in ERROR).

### Regenerate Treatment Plan (new route)

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/regenerate`
**Purpose:** Mints a new plan version: retires the ACTIVE version to history, generates a fresh one. The register risk data is **reused from the active version's frozen snapshot** — never resent (changed register data cannot be resubmitted after first generation). The baseline is the ACTIVE version (the one a human last chose via approve-switch), never simply the newest.
**When to call:** "Regenerate" — every generation after the first.
**Request:**

```json
{ "user_note": "focus on database encryption; vendor owns the network" }
```

- `user_note` (optional, ≤1000): steering for this regeneration; **replaces** the previous version's note entirely (omit for none). This is the only field.

**Response:** `202` — same shape as Generate:

```json
{ "plan_id": "…", "session_id": "…", "output_id": "…", "status": "RUNNING" }
```

**Errors:** `409 treatment_conflict` with `details.reason` ∈ `scenario_not_accepted | generation_in_progress` · `404` (no plan ever generated — use Generate first) · `500` (enqueue failure; plan parked in ERROR).

### Get Treatment Plan (poll)

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan`
**Purpose:** The plan's current state — this GET **is** the poll endpoint and also serves the finished plan.
**When to call:** Poll after the POST until `status` is `COMPLETE` or `ERROR` (the `treatment_plan_result` SSE event is an advisory fast-path — keep polling; some outcomes never publish).
**Query:** `include_superseded` (bool, default `false`) — previous versions in `superseded[]`.
**Response:** `200`

```json
{
  "plan_id": "…", "session_id": "…", "output_id": "…",
  "status": "COMPLETE",
  "treatment_strategy": "Mitigate",
  "scenario": { "scenario_title": "…", "scenario_statement": "…", "risk_statement": "…",
                "threat_category": "…", "threat_type": "…", "threat_name": "…", "threat_actors": ["…"] },
  "risk_level": "Critical",
  "review_status": null,
  "risk_identification_date": "2026-06-14T08:31:00",
  "plan": {
    "title": "…", "treatment_plan": "…", "action_plan": "…",
    "applicable_to_all_subsystems": "No",
    "controls_to_be_implemented": { "control_coverage": "gaps",
      "controls": [
        { "control_type": "preventive", "control_name": "Account Management",
          "description": "…", "priority": "Critical",
          "control_code": "AC-2", "control_library_id": 9 }
      ] },
    "remediation_action_plan": "…", "mitigation_timeline": "…", "mitigation_owner": "…",
    "risk_owner": "…", "impacted_business_division": "…"
  },
  "error_message": null,
  "reason": null,
  "superseded": null
}
```

- `status`: `RUNNING | COMPLETE | ERROR`. `plan` is `null` until COMPLETE.
- On ERROR, switch on `reason`: `generation_failed | invalid_plan | content_blocked | cancelled | timed_out | enqueue_failed`.
- `review_status`: `null` (unreviewed) | `approved` | `rejected`.

**Errors:** `404` (never requested for this scenario) · `403`.

### Get Session Treatment Board

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/treatment-plans`
**Purpose:** One row per accepted scenario with its plan state — replaces N per-scenario polls.
**When to call:** Rendering the session's treatment-plan list screen.
**Query:** `include_plan` (bool, default `false`) · `include_superseded` (bool, default `false`).
**Response:** `200`

```json
{
  "session_id": "…", "accepted_scenarios": 7,
  "plans": [
    { "output_id": "…", "scenario_title": "…", "plan_id": null, "status": null,
      "risk_level": null, "review_status": null, "error_message": null, "reason": null,
      "plan": null, "superseded": null, "created_at": null, "completed_at": null }
  ]
}
```

`plan_id: null` = never requested → show a "Generate" button.
**Errors:** `404`, `403`.

### Download Treatment Plans (Excel)

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/treatment-plans.xlsx`
**Purpose:** The session's treatment plans as an `.xlsx` workbook.
**When to call:** "Export" button on the treatment board.
**Response:** `200`, xlsx media type, `Content-Disposition: attachment; filename="session_{session_id}_treatment_plans.xlsx"`.
**Errors:** `404`, `403`.

### Cancel Treatment Plan Generation

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/cancel`
**Purpose:** Stops a RUNNING generation.
**When to call:** User cancels while the plan is generating.
**Request:** no body.
**Response:** `200`

```json
{ "plan_id": "…", "status": "ERROR", "error_message": "cancelled by user" }
```

**Errors:** `409 treatment_conflict`, `details.reason = not_in_progress` · `404` · `403`.

### Review Treatment Plan (now also the version selector)

**Method:** `POST`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/review`
**Purpose:** Records the human adoption decision (a re-review overwrites; a regenerate resets the new version to unreviewed). With the optional `plan_id`, **approving a HISTORICAL COMPLETE version makes it the current plan and approves it, atomically** — approving an older version IS choosing it (last human decision wins; the displaced version keeps its own verdict in history; every switch is audited and emits a `treatment_plan_result` SSE event).
**When to call:** Approve / Reject on the current plan; or Approve on an older version in the history list (its `plan_id` comes from `GET .../treatment-plan?include_superseded=true`).
**Request:**

```json
{ "decision": "approved", "comment": "Proceed with Q4 remediation.", "plan_id": "…" }
```

- `decision` (required): `approved | rejected` · `comment` (optional, ≤ 2000).
- `plan_id` (optional): omit — or pass the active version's id — to review the current plan; pass a historical version's id with `decision=approved` to switch to it. Note: the entity register lists plans by original creation date, so a switched-to older version keeps its original position.

**Response:** `200`

```json
{ "plan_id": "…", "review_status": "approved", "reviewed_by": "jsmith", "reviewed_at": "2026-08-15T09:00:00" }
```

**Errors:** `409 treatment_conflict`, `details.reason` ∈ `not_complete` (target still generating, or the historical version never finished) `| version_not_active` (rejecting a historical version — meaningless, it is already not the plan) `| generation_in_progress` (a running regeneration blocks the switch) · `404` (unknown/foreign `plan_id`) · `403`.

### Entity Treatment-Plan Register

**Method:** `GET`
**Endpoint:** `/v1/entities/{entity_id}/treatment-plans`
**Purpose:** Entity-wide remediation register across all sessions.
**When to call:** Entity register / compliance screen.
**Query:** `status` (`RUNNING | COMPLETE | ERROR`) · `review_status` (`approved | rejected`) · `risk_level` (`Low | Medium | High | Critical`) · `include_plan` (bool, default `false`) · `limit` (default 100, max 500) · `offset` (default 0) — all optional.
**Response:** `200`

```json
{
  "entity_id": "78", "limit": 100, "offset": 0,
  "plans": [
    { "plan_id": "…", "session_id": "…", "output_id": "…", "asset_name": "…", "scenario_title": "…",
      "status": "COMPLETE", "risk_level": "Critical", "review_status": "approved", "reviewed_by": "jsmith",
      "error_message": null, "reason": null, "scenario": null, "treatment_strategy": "Mitigate",
      "risk_identification_date": "…", "plan": null, "created_at": "…", "completed_at": "…" }
  ]
}
```

(`scenario`/`plan` are populated only with `include_plan=true`.)
**Errors:** `403` · `422` (bad enum value).

### Treatment Plan Audit Trail (one scenario)

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/audit`
**Purpose:** Full event history of one scenario's plans (oldest first): `requested | outcome | cancelled | reviewed | version restored | superseded`.
**When to call:** Audit/history panel of a plan.
**Response:** `200`

```json
{
  "session_id": "…", "output_id": "…",
  "events": [
    { "at": "2026-08-15T08:59:00", "event": "requested", "actor": "jsmith", "actor_type": "user",
      "session_id": null, "detail": { } }
  ]
}
```

**Errors:** `404`, `403`.

### Entity Treatment Audit Feed

**Method:** `GET`
**Endpoint:** `/v1/entities/{entity_id}/treatment-plans/audit`
**Purpose:** Entity-wide treatment audit events, newest first.
**When to call:** Compliance/audit feed screen.
**Query:** `from` / `to` (ISO datetime, optional) · `user_id` (optional) · `limit` (default 200, max 1000) · `offset` (default 0).
**Response:** `200` — same event shape as above, with `session_id` populated:

```json
{
  "entity_id": "78", "limit": 200, "offset": 0,
  "events": [
    { "at": "2026-08-15T09:00:00", "event": "reviewed", "actor": "jsmith", "actor_type": "user",
      "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "detail": { } },
    { "at": "2026-08-15T08:59:00", "event": "requested", "actor": "jsmith", "actor_type": "user",
      "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "detail": { } }
  ]
}
```

**Errors:** `403`.

### Treatment Plan Evidence

**Method:** `GET`
**Endpoint:** `/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/evidence`
**Purpose:** Reproducibility bundle for one plan version (input snapshot, validation, per-attempt prompt/response/model metadata).
**When to call:** Evidence/inspection view (superseded versions allowed).
**Query:** `version` (string, **required**) — the `plan_id` to inspect.
**Response:** `200`

```json
{
  "plan_id": "…", "status": "COMPLETE",
  "input_snapshot": { }, "validation": { },
  "attempts": [
    { "at": "…", "prompt": "…", "response": "…", "model_name": "…", "model_version": "…",
      "prompt_version": "…", "parse_succeeded": true }
  ]
}
```

**Errors:** `404` · `403` · `422` (missing `version`).

---

## 5.5 Embeddings Admin

Headers for this module (§2.2):

```text
X-Admin-Key: <ADMIN_API_KEY>
X-API-Key: <API_KEY>
X-User-Id: <USER_ID>
```

All four action endpoints share the same body and return `202` with a `job_id`:

```json
{ "group": "threat_type", "names": ["Spoofing", "Denial of Service"] }
```

- `group` (optional): `threat_type | threat_catalogue | control_library`; omit = every group.
- `names` (string[], optional, max 50): scopes to named items; **requires `group`**.

### Create Embeddings

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/embeddings/create`
**Purpose:** Embed specific newly added items. **Both `group` and `names` are required here** (422 otherwise).
**When to call:** After adding named library items outside the CRUD API.
**Response:** `202`

```json
{ "job_id": "b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18" }
```

### Update Embeddings

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/embeddings/update`
**Purpose:** Whole-group sync — embeds whatever is missing. Body may be `{}`.
**When to call:** Routine sync, or after a CRUD write returned a null `embeddings_job_id` warning.
**Response:** `202`

```json
{ "job_id": "b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18" }
```

### Recreate Embeddings

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/embeddings/recreate`
**Purpose:** Wipe then re-embed. `names` without `group` → 422.
**When to call:** After model/config changes that invalidate stored vectors.
**Response:** `202`

```json
{ "job_id": "b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18" }
```

### Delete Embeddings

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/embeddings/delete`
**Purpose:** Wipe vectors without re-embedding. `group` and `names` cannot both be omitted (422).
**When to call:** Cleanup only.
**Response:** `202`

```json
{ "job_id": "b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18" }
```

### Get Embedding Job Status

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/embeddings/status/{job_id}`
**Purpose:** Poll an embedding job (also used for `embeddings_job_id` returned by library CRUD writes).
**When to call:** After any 202 above, until `state` is terminal.
**Response:** `200`

```json
{ "state": "SUCCESS", "error": null, "rows_processed": { "threat_type": 12 }, "vectors_deleted": null }
```

`state`: `PENDING | RECEIVED | STARTED | RETRY | SUCCESS | FAILURE | REVOKED | REJECTED | IGNORED` (terminal: SUCCESS/FAILURE/REVOKED). `rows_processed` (create/update/recreate) and `vectors_deleted` (delete) are keyed by group; exact inner keys beyond the group names: `<TO_BE_CONFIRMED>`.
**Errors:** `404` (unknown/expired job id).

### Embedding Job Events (SSE)

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/embeddings/events/{job_id}`
**Purpose:** Live updates for one embedding job (event type `embedding_job_update`; snapshot on connect; closes when terminal).
**When to call:** Instead of tight polling, per §4's SSE rules.
**Response:** `200`, `text/event-stream`. Example frames:

```text
event: embedding_job_update
data: {"type":"embedding_job_update","job_id":"b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18","state":"STARTED"}

event: embedding_job_update
data: {"type":"embedding_job_update","job_id":"b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18","state":"SUCCESS","rows_processed":{"threat_type":12},"vectors_deleted":null}
```

**Errors:** `404` · `503 sse_capacity_exceeded`.

---

## 5.6 API Clients Admin

**Different header rule than other admin modules** — only:

```text
X-Admin-Key: <ADMIN_API_KEY>
X-User-Id: <USER_ID>        # required on create/revoke only
```

Errors here use FastAPI's plain shape: `{"detail": "..."}`.

### Create API Client (mint a key)

**Method:** `POST`
**Endpoint:** `/v1/tsg/api-clients`
**Purpose:** Creates an API client and returns its secret key — **shown once, never recoverable**.
**When to call:** Provisioning a new consumer (e.g. the UI's BFF).
**Request:**

```json
{ "client_id": "ui-bff", "name": "TSG Web UI BFF", "module": "tsg" }
```

- `client_id` (1–100) · `name` (1–200) · `module` (1–50) — all required. A key only authenticates against its own module; use `tsg` for this API.

**Response:** `201`

```json
{ "client_id": "ui-bff", "module": "tsg", "secret": "<the API key — store it now>" }
```

**Errors:** `400` (missing `X-User-Id`) · `409` (duplicate `client_id`).

### List API Clients

**Method:** `GET`
**Endpoint:** `/v1/tsg/api-clients`
**Purpose:** Lists clients (never secrets or hashes).
**When to call:** Admin key-management screen.
**Query:** `module` (optional filter).
**Response:** `200`

```json
[ { "client_id": "ui-bff", "name": "TSG Web UI BFF", "module": "tsg", "active": true,
    "created_at": "…", "created_by": "admin1", "revoked_at": null, "revoked_by": null } ]
```

### Revoke API Client

**Method:** `POST`
**Endpoint:** `/v1/tsg/api-clients/{client_id}/revoke`
**Purpose:** Deactivates a client's key immediately.
**When to call:** Key rotation or compromise.
**Request:** no body (`X-User-Id` required).
**Response:** `200`

```json
{ "client_id": "ui-bff", "status": "revoked" }
```

**Errors:** `400` · `404` (no active client with that id).

---

## 5.7 Session Admin (Promotions)

Admin headers (§2.2). "Promotions" are post-completion library-promotion attempts that failed and await retry.

### List Pending Promotions

**Method:** `GET`
**Endpoint:** `/v1/tsg/sessions/promotions`
**Purpose:** Sessions whose library promotion failed.
**When to call:** Admin ops screen.
**Query:** `limit` (default 100) · `include_exhausted` (bool, default `true`).
**Response:** `200`

```json
{
  "promotions": [
    { "session_id": "…", "entity_id": "78", "asset_id": "103", "asset_name": "…",
      "failed_at": "2026-08-15T02:00:00Z", "attempts": 2, "max_attempts": 5, "exhausted": false,
      "error": "…", "user_id": "jsmith", "completed_at": "…" }
  ],
  "total": 1,
  "auto_retry_enabled": true
}
```

### Get One Pending Promotion

**Method:** `GET`
**Endpoint:** `/v1/tsg/sessions/promotions/{session_id}`
**Purpose:** One promotion's detail (same row shape as above).
**When to call:** Drill-down from the list.
**Response:** `200`

```json
{ "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "entity_id": "78", "asset_id": "103",
  "asset_name": "SCADA Server", "failed_at": "2026-08-15T02:00:00Z", "attempts": 2, "max_attempts": 5,
  "exhausted": false, "error": "promotion transaction deadlocked", "user_id": "jsmith",
  "completed_at": "2026-08-15T01:58:40Z" }
```

**Errors:** `404`.

### Retry Promotion

**Method:** `POST`
**Endpoint:** `/v1/tsg/sessions/promotions/{session_id}/retry`
**Purpose:** Retries the promotion **synchronously** (not a job).
**When to call:** Admin clicks "Retry".
**Request:** no body.
**Response:** `200` — `outcome`: `succeeded | failed | skipped`.

```json
{ "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "outcome": "succeeded" }
```

**Errors:** `404`.

### Dismiss Promotion

**Method:** `DELETE`
**Endpoint:** `/v1/tsg/sessions/promotions/{session_id}`
**Purpose:** Removes the pending promotion without retrying.
**When to call:** Admin clicks "Dismiss".
**Response:** `200` — same `PromotionRetryResult` shape:

```json
{ "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e", "outcome": "succeeded" }
```

**Errors:** `404`.

---

## 5.8 Threat Library Candidates

Admin headers (§2.2). The queue holds EVERYTHING new the AI pipeline proposes — threats
(`kind: "threat"` — a type+name pair) **and actors** (`kind: "actor"` — the actor name, with
`proposed_type` showing which threat TYPE the actor was proposed for, so the reviewer sees the
association approval will create; `proposed_category` is `null` on actor rows). With
`promotion_auto_approve_enabled` off (the default), nothing enters the shared library without
an approval here (previously novel types auto-minted and novel actors were silently dropped).

### List Candidates

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/candidates`
**Purpose:** Pending AI-proposed threats AND actors — or the standing rejected blacklist.
**When to call:** Curation screen; blacklist view.
**Query:** `limit` (default 100) · `kind` (`threat` | `actor`, optional — omit for both) ·
`status` (`pending` default | `rejected` — rejected identities never re-queue and never
auto-mint, so this view is the audit trail of every standing "no").
**Response:** `200`

```json
{
  "candidates": [
    { "candidate_id": "…", "session_id": "…", "entity_id": "78",
      "kind": "threat", "created_by": "sara",
      "proposed_category": "Tampering", "proposed_type": "…", "proposed_name": "…",
      "proposed_generic_name": null, "threat_type_id": null,
      "status": "pending", "created_at": "2026-08-15T02:00:00Z" },
    { "candidate_id": "…", "session_id": "…", "entity_id": "78",
      "kind": "actor", "created_by": "sara",
      "proposed_category": null, "proposed_type": "Firmware Tampering",
      "proposed_name": "State-sponsored group APT-X",
      "proposed_generic_name": null, "threat_type_id": 210,
      "status": "pending", "created_at": "2026-08-15T02:01:00Z" }
  ],
  "total": 2
}
```

`created_by` is the ORIGINAL proposer (the user whose accept raised the card); on approval the
minted master row's `CreatedBy` credits that user — the approving admin lands on the card's
reviewer fields and the audit trail.

### Get One Candidate

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/candidates/{candidate_id}`
**Purpose:** One candidate's detail (same row shape).
**When to call:** Drill-down.
**Response:** `200`

```json
{ "candidate_id": "c9a8b7c6-d5e4-4f3a-9b1c-0d9e8f7a6b5c", "session_id": "5b7c9d21-93a4-4f10-9a83-0f4c113b2a1e",
  "entity_id": "78", "kind": "threat", "created_by": "sara",
  "proposed_category": "Tampering", "proposed_type": "Firmware Tampering",
  "proposed_name": "Firmware supply-chain tampering", "proposed_generic_name": null,
  "threat_type_id": null, "status": "pending", "created_at": "2026-08-15T02:00:00Z" }
```

**Errors:** `404`.

### Approve Candidate

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/candidates/{candidate_id}/approve`
**Purpose:** Accepts the candidate into the library — a threat card mints its type+catalogue
entry (reusing the card's `threat_type_id` while that type is still active, else creating one);
an actor card mints the `Threat_Actor` row and links it to the type the card names, resolved
at approval time in two steps: the card's `threat_type_id` is used FIRST when that type is
still active and not deleted; a null or dead id falls back to matching the `proposed_type`
text (approve the sibling threat card first and the link lands on its freshly minted type; if
no active type — or more than one — matches, the actor is created UNLINKED,
`threat_type_id: null` in the response AND on the resolved card, and the skip is audited).
Minted rows credit the ORIGINAL proposer.
**When to call:** Curator approves.
**Request:** no body.
**Response:** `200` (actor cards: `threat_catalogue_id` is null; `threat_type_id` is the linked type or null)

```json
{ "candidate_id": "c9a8b7c6-d5e4-4f3a-9b1c-0d9e8f7a6b5c", "status": "accepted", "threat_type_id": 5, "threat_catalogue_id": 42 }
```
**Errors:** `404` · `409 accept_conflict` (already reviewed — a losing concurrent approve/reject is rolled back whole, leaving no library rows behind).

### Reject Candidate

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/candidates/{candidate_id}/reject`
**Purpose:** Rejects the candidate.
**When to call:** Curator rejects.
**Request:** no body.
**Response:** `200` — same shape with `"status": "rejected"` (ids null):

```json
{ "candidate_id": "c9a8b7c6-d5e4-4f3a-9b1c-0d9e8f7a6b5c", "status": "rejected", "threat_type_id": null, "threat_catalogue_id": null }
```

**Errors:** `404` · `409`.

---

## 5.9 Threat Library Import

Admin headers (§2.2). Bulk-imports external threat libraries (MITRE ATT&CK, MISP actors, …).

### List Import Sources

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/sources`
**Purpose:** Known sources and their load state.
**When to call:** Import screen load.
**Response:** `200`

```json
{
  "sources": [
    { "source": "attack_ics", "source_tag": "mitre_attack_ics", "loaded": true,
      "type_count": 12, "threat_count": 95, "actor_count": null,
      "last_run": { "status": "success", "dry_run": false,
                    "started_at": "2026-07-27T09:14:00Z", "finished_at": "2026-07-27T09:16:12Z",
                    "error": null, "types_imported": 12, "threats_imported": 95,
                    "started_by": "jsmith" } }
  ]
}
```

(`last_run` is null if the source was never attempted; keys: `status, dry_run, started_at, finished_at, error, types_imported, threats_imported, actors_upserted` (misp_actors only), `started_by` — null for CLI-driven runs. `actor_count` is populated for `misp_actors` only.)

### Start Import

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-library/sources/{source}/import`
**Purpose:** Runs one source's import as a background job. `{source}` must be a known source (404 otherwise).
**When to call:** Admin clicks "Import" (use `dry_run: true` for a preview).
**Request:** all fields optional; `{}` = download from upstream and import:

```json
{ "dry_run": true, "via_taxii": false, "max_actors": 40, "file_content": null }
```

- `dry_run` (bool, default `false`) — parse and report only, writes nothing.
- `via_taxii` (bool, default `false`) — ATT&CK sources only; incompatible with `file_content`.
- `max_actors` (int, default 40, min 1) — `misp_actors` only.
- `file_content` (string) — **the "uploaded" file as JSON text inside this JSON body** (no multipart upload anywhere in this API). Size-capped by the server (422 if over; 413 if the whole request exceeds the body limit).

**Response:** `202`

```json
{ "job_id": "e4f1a2b3-6c7d-4e8f-9a0b-1c2d3e4f5a6b" }
```

**Errors:** `404` (unknown source) · `422 threat_library_import_error` (bad flag combination, oversized/unparseable content) · `413`.

### Get Import Job Status

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/imports/{job_id}`
**Purpose:** Poll an import job.
**When to call:** After the 202, until `state` is terminal.
**Response:** `200` — `state` as in §5.5; `result` holds run stats on SUCCESS. Every source reports `source, dry_run, skipped_count, skipped`; catalogue sources add `types, threats, new_category_links, before_count, after_count, ot_rules` (`ot_rules` non-empty for OT sources only); `misp_actors` adds `actors_upserted` instead; real (non-dry) runs also carry `embeddings_job_id`.

```json
{
  "state": "SUCCESS",
  "result": { "source": "attack", "dry_run": false, "skipped_count": 3, "skipped": [],
              "types": 14, "threats": 800, "new_category_links": 2,
              "before_count": 0, "after_count": 800, "ot_rules": [],
              "embeddings_job_id": "b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18" },
  "error": null
}
```

**Errors:** `404`.

### Import Job Events (SSE)

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-library/imports/events/{job_id}`
**Purpose:** Live updates for one import job (event type `import_job_update`).
**When to call:** Instead of tight polling (§4 SSE rules apply).
**Response:** `200`, `text/event-stream`. Example frames:

```text
event: import_job_update
data: {"type":"import_job_update","job_id":"e4f1a2b3-6c7d-4e8f-9a0b-1c2d3e4f5a6b","state":"STARTED","source":"attack"}

event: import_job_update
data: {"type":"import_job_update","job_id":"e4f1a2b3-6c7d-4e8f-9a0b-1c2d3e4f5a6b","state":"SUCCESS","source":"attack","dry_run":false,"skipped_count":3,"skipped":[],"types":14,"threats":800,"new_category_links":2,"before_count":0,"after_count":800,"ot_rules":[],"embeddings_job_id":"b7e2c9a4-1f35-4c8e-9d21-7a6f0b3c5d18"}
```

**Errors:** `404` · `503`.

---

## 5.10 Threat Library CRUD

Admin headers (§2.2). Five resources, one pattern:

- **List** endpoints share query params: `limit` (default 100, max 500) · `offset` (default 0) · `include_deleted` (bool, default `false`).
- **DELETE is a soft delete** — the row is hidden, not destroyed, and the deleted row is returned.
- Row responses include an audit block: `is_active, is_deleted, source, created_at, created_by, updated_at, updated_by`, plus `embeddings_job_id` — non-null only on a write that queued re-embedding (poll it via §5.5 status); always null on GET. (Threat-rule rows have no `source`/`embeddings_job_id`.)
- PATCH bodies are partial — send only what changes; an empty PATCH body is a 422.
- Duplicate natural keys → `409 library_conflict` (`details.existing_id`).
- Referencing a missing/deleted parent (e.g. `threat_category_id`, `threat_type_id`) → `404`.

### Threat Categories — `/v1/tsg/threat-library/threat-categories`

| Method | Endpoint | Purpose / When |
|---|---|---|
| `GET` | `/v1/tsg/threat-library/threat-categories` | List (shared query params) — category admin screen |
| `POST` | `/v1/tsg/threat-library/threat-categories` | Create → `201` — admin adds a category |
| `PATCH` | `/v1/tsg/threat-library/threat-categories/{threat_category_id}` | Partial update — admin edits |
| `DELETE` | `/v1/tsg/threat-library/threat-categories/{threat_category_id}` | Soft delete — admin removes |

**Create request** (note: the id is **caller-supplied**, this table's PK is not auto-generated):

```json
{ "threat_category_id": 7, "threat_category_name": "Elevation of Privilege",
  "threat_category_code": "EOP", "security_objective": "Authorization", "is_active": true }
```

Required: `threat_category_id` (int ≥ 1), `threat_category_name` (1–200). Optional: `threat_category_code` (≤20), `security_objective` (≤200), `is_active` (default `true`). PATCH accepts the same fields minus the id.
**Row response:** the fields above + audit block:

```json
{ "threat_category_id": 7, "threat_category_name": "Elevation of Privilege",
  "threat_category_code": "EOP", "security_objective": "Authorization",
  "is_active": true, "is_deleted": false, "source": null,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1",
  "updated_at": null, "updated_by": null, "embeddings_job_id": null }
```

### Threat Types — `/v1/tsg/threat-library/threat-types`

| Method | Endpoint |
|---|---|
| `GET` / `POST` | `/v1/tsg/threat-library/threat-types` |
| `PATCH` / `DELETE` | `/v1/tsg/threat-library/threat-types/{threat_type_id}` |

**Create request:**

```json
{ "threat_type_name": "Ransomware", "description": "…", "sector_id": 95,
  "threat_category_id": 7, "is_active": true, "actor_names": ["FIN7"] }
```

Required: `threat_type_name` (1–300). Optional: `description`, `sector_id` (≥1), `threat_category_id` (≥1, must be a live category → else 404), `is_active`, `actor_names` (linked best-effort). On PATCH, `actor_names` links **additively** (never removes); an actors-only PATCH is legal. A rename queues re-embedding → non-null `embeddings_job_id`.
**Row response:** `threat_type_id, threat_type_name, description, sector_id, threat_category_id` + audit block:

```json
{ "threat_type_id": 5, "threat_type_name": "Ransomware", "description": "Malware that encrypts data for extortion.",
  "sector_id": 95, "threat_category_id": 7,
  "is_active": true, "is_deleted": false, "source": null,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1",
  "updated_at": null, "updated_by": null, "embeddings_job_id": null }
```

### Threat Catalogue — `/v1/tsg/threat-library/threat-catalogue`

| Method | Endpoint |
|---|---|
| `GET` / `POST` | `/v1/tsg/threat-library/threat-catalogue` |
| `PATCH` / `DELETE` | `/v1/tsg/threat-library/threat-catalogue/{threat_catalogue_id}` |

**Create request:**

```json
{ "threat_type_id": 5, "threat_name": "Ransomware on historian server", "description": "…",
  "sector_id": 95, "is_active": true }
```

Required: `threat_type_id` (≥1, live), `threat_name` (1–500). Optional: `description`, `sector_id`, `is_active`.
**Row response:** `threat_catalogue_id, threat_type_id, threat_name, description, sector_id` + audit block:

```json
{ "threat_catalogue_id": 42, "threat_type_id": 5, "threat_name": "Ransomware on historian server",
  "description": "Encryption of the OT historian database for extortion.", "sector_id": 95,
  "is_active": true, "is_deleted": false, "source": null,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1",
  "updated_at": null, "updated_by": null, "embeddings_job_id": null }
```

### Threat Actors — `/v1/tsg/threat-library/threat-actors`

| Method | Endpoint |
|---|---|
| `GET` / `POST` | `/v1/tsg/threat-library/threat-actors` |
| `PATCH` / `DELETE` | `/v1/tsg/threat-library/threat-actors/{threat_actor_id}` |

**Create request:** `{ "threat_actor_name": "FIN7", "is_capable": 1, "is_active": true }` — required: `threat_actor_name` (1–200). Actors are not embedded → `embeddings_job_id` always null.
**Row response:** `threat_actor_id, threat_actor_name, is_capable` + audit block:

```json
{ "threat_actor_id": 61, "threat_actor_name": "FIN7", "is_capable": 1,
  "is_active": true, "is_deleted": false, "source": null,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1",
  "updated_at": null, "updated_by": null, "embeddings_job_id": null }
```

### Threat Rules — `/v1/tsg/threat-library/threat-rules`

| Method | Endpoint |
|---|---|
| `GET` / `POST` | `/v1/tsg/threat-library/threat-rules` |
| `PATCH` / `DELETE` | `/v1/tsg/threat-library/threat-rules/{threat_rule_id}` |

Scoping rules that gate/weight threat families. **List** adds one extra query param: `threat_type_id` (optional filter).

**Create request:**

```json
{ "rule_type": "relevance_flag", "threat_type_id": 12, "rule_key": "asset_type",
  "rule_value": "Operational Technology (OT)", "weight": 10.0, "is_active": true }
```

- `rule_type` (required): `tech_gate | relevance_flag | relevance_context_value`.
- `threat_type_id` (required, ≥1, live family).
- `rule_key` (required, 1–200) — must be in the allowlist: `criticality, subsystem_name, asset_type, past_incidents`.
- `rule_value` (optional, ≤450) · `weight` (optional; **forbidden on `tech_gate`**) · `is_active` (default `true`).
- **PATCH:** only `rule_value`, `weight`, `is_active` are mutable (`rule_type`/`rule_key`/`threat_type_id` are immutable — retire and recreate instead). An explicit `"weight": null` clears the override.

**Row response:** `threat_rule_id, rule_type, threat_type_id, rule_key, rule_value, weight, is_active, is_deleted, created_at, created_by, updated_at, updated_by`:

```json
{ "threat_rule_id": 3, "rule_type": "relevance_flag", "threat_type_id": 12, "rule_key": "asset_type",
  "rule_value": "Operational Technology (OT)", "weight": 10.0, "is_active": true, "is_deleted": false,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1", "updated_at": null, "updated_by": null }
```
**Errors:** `422 admin_validation_error` (bad `rule_type`/`rule_key`, weight on a tech_gate, empty PATCH).

---

## 5.11 Control Library CRUD

Admin headers (§2.2). Same shared pattern as §5.10 (list params, soft delete, audit block + `embeddings_job_id`).

### Control Standards — `/v1/tsg/control-library/standards`

| Method | Endpoint |
|---|---|
| `GET` / `POST` | `/v1/tsg/control-library/standards` |
| `PATCH` / `DELETE` | `/v1/tsg/control-library/standards/{standard_id}` |

**Create request:** `{ "standard_name": "ISO 27001", "is_active": true }` — required: `standard_name` (1–200). Standards are not embedded.
**Row response:** `standard_id, standard_name` + audit block:

```json
{ "standard_id": 1, "standard_name": "ISO 27001",
  "is_active": true, "is_deleted": false, "source": null,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1",
  "updated_at": null, "updated_by": null, "embeddings_job_id": null }
```

### Controls — `/v1/tsg/control-library/controls`

| Method | Endpoint |
|---|---|
| `GET` / `POST` | `/v1/tsg/control-library/controls` |
| `PATCH` / `DELETE` | `/v1/tsg/control-library/controls/{control_id}` |

**Create request:**

```json
{ "control_code": "AC-2", "itot": "IT", "domain": "Access Control",
  "control_name": "Account Management", "control_description": "…",
  "sample_evidence": null, "is_active": true }
```

Required: `control_code` (1–20, the natural key), `itot` (`IT`/`OT`), `domain` (1–200), `control_name` (1–500), `control_description` (min 1). Optional: `sample_evidence`, `is_active`. Editing `control_name` **or** `control_description` queues re-embedding.
**Row response:** `control_library_id, control_code, itot, domain, control_name, control_description, sample_evidence` + audit block. (URL segment is `{control_id}`; the response field is `control_library_id`.)

```json
{ "control_library_id": 9, "control_code": "AC-2", "itot": "IT", "domain": "Access Control",
  "control_name": "Account Management", "control_description": "Manage system accounts, group memberships, and access authorizations.",
  "sample_evidence": null,
  "is_active": true, "is_deleted": false, "source": null,
  "created_at": "2026-08-15T02:00:00Z", "created_by": "admin1",
  "updated_at": null, "updated_by": null, "embeddings_job_id": null }
```

### Link Control ↔ Standard

**Method:** `POST`
**Endpoint:** `/v1/tsg/control-library/controls/{control_id}/standards/{standard_id}`
**Purpose:** Tags a control with a standard. Idempotent — re-linking an existing pair returns `201` unchanged, never 409.
**When to call:** Admin assigns standards on the control editor.
**Request:** no body.
**Response:** `201`

```json
{ "control_library_id": 9, "standard_ids": [1, 2], "standards": ["ISO 27001", "NIST CSF"] }
```

**Errors:** `404` (control or standard missing/deleted).

### Unlink Control ↔ Standard

**Method:** `DELETE`
**Endpoint:** `/v1/tsg/control-library/controls/{control_id}/standards/{standard_id}`
**Purpose:** Removes the tag — **hard delete** (the only one in this API).
**When to call:** Admin removes a standard tag.
**Response:** `200` — same shape as Link:

```json
{ "control_library_id": 9, "standard_ids": [1], "standards": ["ISO 27001"] }
```

**Errors:** `404` (pair was not linked).

---

## 5.12 Threat Intel Admin

Admin headers (§2.2). External threat-intelligence feeds that inform generation.

### List Intel Feeds

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-intel/feeds`
**Purpose:** Every configured feed's state (disabled ones included) — also the **durable status source after a refresh** (there is no per-job GET in this module).
**When to call:** Intel screen load, and to confirm refresh outcomes.
**Response:** `200`

```json
{
  "feeds": [
    { "feed": "…", "enabled": true, "item_count": 120, "kinds": { "report": 80, "actor": 40 },
      "prompted": true, "last_fetched_at": "…", "last_attempt_at": "…", "last_success_at": "…",
      "last_error": null }
  ]
}
```

### List Intel Items

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-intel/items`
**Purpose:** Fetched intel items, newest published first.
**When to call:** Intel browsing screen.
**Query:** `source` (optional; unknown feed → 404) · `limit` (default 50, max 500) · `offset` (default 0).
**Response:** `200`

```json
{
  "items": [
    { "source": "…", "kind": "report", "external_id": "…", "title": "…", "adversary": "…",
      "description": "…", "url": "…", "tags": ["…"], "fetched_at": "…", "published_at": "…" }
  ],
  "total": 1, "limit": 50, "offset": 0
}
```

**Errors:** `404` (unknown source) · `503` (intel store unavailable — never an empty page).

### Refresh All Feeds

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-intel/feeds/refresh`
**Purpose:** Queues a refresh of every enabled feed — one job per feed.
**When to call:** Admin clicks "Refresh all".
**Request:** no body.
**Response:** `202`

```json
{ "jobs": { "cisa_kev": "f0e1d2c3-b4a5-4968-8776-655443322110", "otx": "a1b2c3d4-e5f6-4708-9a0b-c1d2e3f4a5b6" } }
```

### Refresh One Feed

**Method:** `POST`
**Endpoint:** `/v1/tsg/threat-intel/feeds/{feed}/refresh`
**Purpose:** Queues a refresh of one feed.
**When to call:** Per-feed "Refresh" button.
**Request:** no body.
**Response:** `202` — same shape (one entry):

```json
{ "jobs": { "otx": "a1b2c3d4-e5f6-4708-9a0b-c1d2e3f4a5b6" } }
```

**Errors:** `404` — unknown feed **or a known-but-disabled feed**.

### Intel Job Events (SSE)

**Method:** `GET`
**Endpoint:** `/v1/tsg/threat-intel/feeds/events/{job_id}`
**Purpose:** Live updates for one refresh job (event type `intel_job_update`; note `RETRY` is non-terminal here).
**When to call:** After a refresh, per §4's SSE rules; confirm final state via `GET /feeds`.
**Response:** `200`, `text/event-stream`. Example frames:

```text
event: intel_job_update
data: {"type":"intel_job_update","job_id":"a1b2c3d4-e5f6-4708-9a0b-c1d2e3f4a5b6","state":"STARTED","feed":"otx"}

event: intel_job_update
data: {"type":"intel_job_update","job_id":"a1b2c3d4-e5f6-4708-9a0b-c1d2e3f4a5b6","state":"SUCCESS","feed":"otx","item_count":120}
```

**Errors:** `404` · `503`.
