# Session-Progress SSE Contract Guide

For developers building a client against `GET /v1/sessions/{session_id}/events` and its polling
twin `GET /v1/sessions/{session_id}`. Every payload shape below is taken from the current code
(`app/api/sessions.py`, `app/api/schemas.py`, `app/core/enums.py`, `app/pipeline/tasks.py`,
`app/pipeline/cascade.py`, `app/pipeline/reaper.py`, `app/sse/bus.py`) â€” this file is the wire
contract and its gaps, not a design rationale. Design rationale lives in
`docs/SSE_PRODUCTION_READINESS_PLAN.md`.

**The one rule that matters more than any payload shape below: SSE is a hint layer, the DB is the
source of truth.** Every event on this stream is best-effort, none are replayed, and a publish
failure can silence an entire worker process for a cooldown window. `GET
/v1/sessions/{session_id}` (the *board*) is designed to agree with the stream at all times â€” poll
it as your backstop regardless of whether the stream looks healthy.

---

## 0. Connecting

**Native browser `EventSource` cannot consume this stream.** This API requires three custom
headers on every request â€” `X-API-Key`, `X-User-Id`, `X-Entity-Id` (see
`docs/TSG_API_AUTHENTICATION_GUIDE.md`) â€” and `EventSource` has no way to set custom headers.
Use `fetch()` with a `ReadableStream` reader instead:

```javascript
const resp = await fetch(`/v1/sessions/${sessionId}/events`, {
  headers: { "X-API-Key": apiKey, "X-User-Id": userId, "X-Entity-Id": entityId },
});
const reader = resp.body.getReader();
const decoder = new TextDecoder();
let buf = "";
while (true) {
  const { value, done } = await reader.read();
  if (done) break;
  buf += decoder.decode(value, { stream: true });
  // Split on the SSE record separator ("\n\n"); parse "event:"/"data:" lines per record.
  // Continuation `data:` lines must be JOINED WITH "\n" and only one leading space stripped â€”
  // do not `.trim()` each line (that corrupts any future multi-line JSON payload). See
  // app/static/sse_test.html for a worked parser.
}
```

`app/static/sse_test.html` is the shipped reference client â€” a working example, not a library.

**Content-type on the wire:** `text/event-stream`. Each record is `event: <kind>\ndata: <json>\n\n`
â€” the event *name* (`event:`) always matches the JSON body's own `"type"` key; a client may switch
on either, but the JSON `"type"` field is what this guide documents field-by-field.

---

## 1. The ten event kinds, at a glance

| `type` | Scope | Durable mirror (poll this if you missed it) | Typed model |
|---|---|---|---|
| `reconcile` | session (full snapshot) | â€” it *is* the durable snapshot | `SessionBoard` (+ injected `type`) |
| `stage_started` | stage | `progress.threats`/`scenarios` == `RUNNING` | `StageStartedEvent` |
| `stage_completed` | stage | `progress.threats`/`scenarios` == `COMPLETE`/`AWAITING_DECISION` | `StageCompletedEvent` |
| `subsystem_started` | subsystem | `current_stage`/`stage_status` (only one subsystem exists today) | `SubsystemStartedEvent` |
| `session_entered_review` | session | `current_stage == "REVIEW"` | `SessionEnteredReviewEvent` |
| `error` | stage **or** session (see `scope`) | `progress.error_message[stage]` (stage-scoped) / `session_status == "cancelled"` (session-scoped) | `ErrorEvent` |
| `next_set_result` | subsystem | `progress.last_next_set` | `NextSetResultEvent` |
| `regen_result` | subsystem | `progress.last_regen` | `RegenResultEvent` |
| `treatment_plan_result` | plan (no subsystem) | **NONE on this board** â€” poll `GET /v1/sessions/{id}/treatment-plans` | `TreatmentPlanResultEvent` |
| `heartbeat` | none (keep-alive) | n/a â€” carries no state | `HeartbeatEvent` |

All ten are registered in `/openapi.json` on `GET /v1/sessions/{session_id}/events` as one
Pydantic union (`app/api/sessions.py::_EVENT_STREAM_RESPONSES`) â€” generate a typed client from the
spec instead of hand-copying the shapes below.

**One subsystem today.** `subsystem_id` is always `0` (`ASSET_UNIT_ID`) â€” the pipeline tracks one
asset as a single unit of work. The field exists for a future multi-subsystem pipeline; do not
special-case the value `0`.

---

## 2. Payload shapes, field by field

### 2.1 `reconcile`

Sent exactly once per connect/reconnect, **before** any live event, as the full current
`SessionBoard` â€” the same body `GET /v1/sessions/{session_id}` returns, plus one injected key:

```json
{
  "type": "reconcile",
  "session_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "entity_id": "ENT-001",
  "asset_id": 12345, "asset_name": "SCADA Historian",
  "user_id": "qa-user",
  "session_status": "active",
  "current_stage": "SCENARIO_GENERATION",
  "stage_status": "AWAITING_DECISION",
  "progress": {
    "threats": "COMPLETE", "scenarios": "AWAITING_DECISION",
    "overall": "awaiting_review",
    "error_message": {},
    "last_next_set": {"outcome": "partial_retryable", "requested": 5, "delivered": 3,
                    "variants": 0, "reason": null, "epoch": 4},
    "last_regen": null
  }
}
```

`"type": "reconcile"` is stitched onto the streamed payload by `stream_events()`
(`app/api/sessions.py`) â€” it is **not** part of the `SessionBoard` model itself (that model is
shared with the polling GET, which never sends a `type` key), so `/openapi.json`'s schema for this
union member cannot express `type` as a `Literal` the way every other event does. Treat the `type`
key as guaranteed on the wire for this event regardless of what the generated schema shows.

**It is a snapshot, not a delta**, and it does **not** carry treatment-plan state â€” fetch
`GET /v1/sessions/{session_id}/treatment-plans` separately on connect and on every reconnect (see
Â§4.3).

### 2.2 `stage_started`

```json
{"type": "stage_started", "session_id": "3fa85f64-â€¦", "subsystem_id": 0,
 "stage": "THREATS", "status": "RUNNING", "generation_epoch": 1,
 "ts": "2026-08-12T09:00:00+00:00"}
```

`stage`: `"THREATS"` or `"SCENARIOS"`. `status` is always `"RUNNING"` â€” this event fires only at
claim time.

### 2.3 `stage_completed`

```json
{"type": "stage_completed", "session_id": "3fa85f64-â€¦", "subsystem_id": 0,
 "stage": "SCENARIOS", "status": "SCENARIOS_AWAITING_DECISION", "generation_epoch": 1,
 "ts": "2026-08-12T09:02:14+00:00"}
```

**`status` has exactly two real values, not one** â€” both published from the same call site
(`tasks.py::_send_live_update`): THREATS finishes `"COMPLETE"`; SCENARIOS finishes
`"SCENARIOS_AWAITING_DECISION"` (`StageStatus.AWAITING_DECISION`'s wire value) â€” reaching
AWAITING_DECISION for SCENARIOS *is* the review barrier, not an unfinished state. A failed stage
never emits this event â€” it routes to `error` instead.

### 2.4 `subsystem_started`

```json
{"type": "subsystem_started", "session_id": "3fa85f64-â€¦", "subsystem_id": 0,
 "generation_epoch": 1, "ts": "2026-08-12T08:59:59+00:00"}
```

Fires **before** this subsystem's stages run. No `stage` field â€” it precedes both THREATS and
SCENARIOS. **Advisory, not guaranteed**: `_announce_generation_started` only publishes when there
is pending work (`dal.subsystem_has_pending_work`); an idempotent redelivery that finds nothing
left to do publishes nothing.

### 2.5 `session_entered_review`

```json
{"type": "session_entered_review", "session_id": "3fa85f64-â€¦",
 "status": "SCENARIOS_AWAITING_DECISION", "generation_epoch": 1,
 "ts": "2026-08-12T09:02:15+00:00"}
```

Fires once, when every subsystem has hit its review barrier. Session-wide â€” never carries
`subsystem_id`. **This is one of the two signals a client may use to tear down a "generatingâ€¦"
UI state** (the other being a terminal `session_status` from a poll/reconcile) â€” see Â§2.6.

### 2.6 `error` â€” read this one carefully

```json
// scope="stage" â€” tasks.py::_record_failure
{"type": "error", "session_id": "3fa85f64-â€¦", "scope": "stage", "subsystem_id": 0,
 "message": "the AI service is temporarily unavailable â€” please retry",
 "generation_epoch": 1, "ts": "2026-08-12T09:01:40+00:00"}

// scope="session" â€” tasks.py::_mark_session_failed
{"type": "error", "session_id": "3fa85f64-â€¦", "scope": "session",
 "message": "session failed: all subsystems errored", "ts": "2026-08-12T09:01:41+00:00"}
```

- **`scope="stage"`**: one subsystem's stage errored. `subsystem_id`/`generation_epoch` are
  present. The session is **not necessarily done** â€” other subsystems can still finish, or the
  reviewer can regenerate once the session reaches REVIEW.
- **`scope="session"`**: every subsystem errored; the session was marked `cancelled`
  server-side. `subsystem_id`/`generation_epoch` are absent â€” terminal.
- **`scope` is absent (`null`)** on the **three** `error` events `app/pipeline/reaper.py`'s
  dead-worker sweep publishes (two stage-scoped with `subsystem_id`, one session-scoped without)
  â€” a known gap, not closed by this contract; see Â§4.1. Fall back to "`subsystem_id` present" for
  those specifically.

**Do not tear down UI on `error` alone.** A stage-scoped `error` can be followed by more progress
on other subsystems, or by a human regenerating. Wait for `session_entered_review`, or a terminal
`session_status` (`completed`/`cancelled`) from a `reconcile` event or a
`GET /v1/sessions/{session_id}` poll, before treating the session as finished.

**Durable mirror**: unlike `next_set_result`/`regen_result`, `error` has no separate summary
field â€” the board's own `progress.threats`/`progress.scenarios` status (`ERROR`) plus
`progress.error_message[stage]` (item 7 â€” see Â§5) already carry the same information durably. A
missed `error` event costs nothing beyond the client not being told the instant it happened.

### 2.7 `next_set_result` (unchanged by this phase â€” documented for completeness)

```json
{"type": "next_set_result", "session_id": "3fa85f64-â€¦", "subsystem_id": 0,
 "outcome": "partial_retryable", "requested": 5, "new_scenarios": 3, "new_variants": 0,
 "no_new": false, "epoch": 4, "reason": null, "detail": null, "message": null,
 "ts": "2026-08-12T09:05:00+00:00"}
```

`reason`/`detail`/`message` are populated **only** when `no_new` is true (see
`ClickOutcomeReason` in `app/core/enums.py` and `cascade.py::_REASON_INFO` for the fixed
reasonâ†’sentence table). **Durable mirror: `progress.last_next_set`** â€” compare `.epoch` against
the `epoch` your `POST .../scenarios/next-set` call returned.

### 2.8 `regen_result` (unchanged by this phase â€” documented for completeness)

```json
{"type": "regen_result", "session_id": "3fa85f64-â€¦", "subsystem_id": 0,
 "requested_output_ids": ["6ba7b810-â€¦"], "new_output_ids": ["b3fc2c96-â€¦"],
 "replacements": [{"old": "6ba7b810-â€¦", "new": "b3fc2c96-â€¦"}],
 "failed_threat_ids": [], "rescored_threat_ids": [], "reason": null, "detail": null,
 "message": null, "ts": "2026-08-12T09:06:30+00:00"}
```

**Durable mirror: `progress.last_regen`** (new this phase â€” see Â§5). Compare `.epoch` against the
`epoch` your `POST .../regenerate/scenarios` call returned. Note the field names differ slightly
from `regen_result`'s own (`last_regen.target_ids`/`requested_ids` vs. this event's
`requested_output_ids`/`new_output_ids`) â€” `last_regen` is built straight from the
`regeneration_completed` audit row, not from this event, so the two are not byte-identical.

### 2.9 `treatment_plan_result` (unchanged by this phase â€” documented for completeness)

```json
{"type": "treatment_plan_result", "session_id": "3fa85f64-â€¦",
 "output_id": "1a2b3c4d-â€¦", "plan_id": "b9fe2c07-â€¦", "status": "COMPLETE",
 "reason": null, "ts": "2026-08-12T09:14:02+00:00"}
```

**Match on `output_id`, never `plan_id`** â€” a regeneration mints a new `plan_id` for the same
scenario. **No durable mirror on this board at all** â€” see Â§4.3, and
`docs/TREATMENT_PLAN_API_TEST_GUIDE.md` Â§3.2 for the full contract.

### 2.10 `heartbeat`

```json
{"type": "heartbeat", "session_id": "3fa85f64-â€¦", "ts": "2026-08-12T09:00:15+00:00"}
```

Sent every `sse_ping_seconds` (default 15s) when nothing else was published, so proxies don't
drop an idle connection. Carries no state â€” use its arrival only to reset your own idle timer.

---

## 3. What never publishes

| Situation | What actually happens | Why |
|---|---|---|
| A worker is SIGKILLed mid-stage | **Nothing**, for up to `stage_lease_seconds` (default 300s, or auto-derived from `llm_timeout_seconds`/`llm_max_retries`) + `reaper_interval_seconds` (default 60s) â€” the board shows a frozen `RUNNING` the whole time, then the reaper's sweep publishes `error` once it reclaims the lease | Detection is lease-based by design (no heartbeat-per-stage exists); see Â§4.2 |
| A treatment plan's worker dies mid-generation | Never â€” the `Risk_Treatment_Plan` row stays `RUNNING` forever; there is no reaper for it | `docs/TREATMENT_PLAN_API_TEST_GUIDE.md` Â§3.2's "Never publishes" table |
| A treatment plan hits an LLM-capacity autoretry | Never â€” the retry keeps bumping the row's progress clock, so it never even goes stale | ibid |
| A treatment plan is cancelled or reviewed | Never â€” cancel/review run in the API process; only the worker publishes | ibid |
| Any `bus.publish` call fails (Redis down/slow) | **Every** event from that worker process is silenced for `sse_breaker_cooldown_seconds` (default 30s) â€” not just the one that failed | Process-global circuit breaker (`app/sse/bus.py`); see Â§4.4 |
| A client connects between the `reconcile` snapshot and the live subscription actually starting | An event published in that narrow window is dropped â€” never delivered, never replayed | Known, accepted race; see Â§4.5 |
| `verify_membership` revokes a user mid-stream | No event fires for it â€” the stream simply **closes** (server-initiated) on the next tick | Not a publish gap â€” this is the re-authorization check (item 30), working as designed |

---

## 4. Recovery path for every gap this plan left open

Section headers below match the finding numbers in `docs/SSE_PRODUCTION_READINESS_PLAN.md` so you
can cross-reference the rationale for *why* each one was left advisory-only rather than
structurally closed.

### 4.1 `error`'s `scope` is absent on 3 of 5 real publish sites (item 27, partial)

`tasks.py`'s two `error` sites (`_record_failure`, `_mark_session_failed`) always set `scope`.
`reaper.py`'s three `error` sites (the dead-worker sweep, a different phase â€” item 5) do not yet.

**Recovery:** treat `scope == null` as "derive it yourself" â€” `subsystem_id` present means
stage-scoped, absent means session-scoped. This is exactly the rule item 27 retired for the two
`tasks.py` sites; it still holds for `reaper.py`'s until a follow-up adds `scope` there too.

### 4.2 Frozen board during a SIGKILL (item 6, not structurally closed)

The plan's own text calls for exposing `lease_expires_at` on the board so a client can show
"checkingâ€¦" instead of a silent frozen status once staleness is expected. **That field does not
exist on `SessionBoard` as of this guide** â€” it was never scheduled into an implementation phase.

**Recovery:** there is no live signal for this window. A client-side heuristic â€” no
`stage_started`/`stage_completed`-adjacent progress for longer than your own configured "this is
taking too long" threshold â€” is the only available mitigation today. Once the reaper's sweep runs
(`reaper_interval_seconds`, default 60s, after the lease itself expires), an `error` event (scope
absent â€” see Â§4.1) or a `reconcile`-visible status change follows.

### 4.3 `treatment_plan_result` has no durable board mirror (item 8's one genuine gap)

Every other advisory event in this guide has a durable counterpart on `SessionProgress`
(`last_next_set`, `last_regen`, or the stage status itself for `error`). `treatment_plan_result`
does not â€” plan state lives entirely outside `SessionBoard`.

**Recovery:** `GET /v1/sessions/{session_id}/treatment-plans` (the treatment-plan board) on
connect and on every reconnect, plus a slow backstop poll while any plan is `RUNNING`. Match on
`output_id`. Full detail: `docs/TREATMENT_PLAN_API_TEST_GUIDE.md` Â§3.2.

### 4.4 A publish failure silences a whole worker process (item 9, log-only fix)

The circuit breaker (`app/sse/bus.py`) is process-global: one failed publish stops **every**
session's events from that worker process for the cooldown window, not just the session that
failed. The only planned fix is a log line naming which breaker opened (operational
diagnosability), not a client-visible signal â€” this is not something a client can detect on the
wire at all.

**Recovery:** this is exactly why every event in this guide has (or should have â€” see Â§4.3) a
durable mirror on the board. **Always keep a backstop poll of `GET /v1/sessions/{session_id}`**
regardless of whether the SSE connection looks healthy; do not treat "stream open, no events" as
"nothing happened."

### 4.5 Reconcile-to-subscribe race (structural, not scheduled for a fix)

`stream_events()` loads the board (the `reconcile` snapshot) and only then subscribes to the live
channel. An event published in that gap is never delivered on this connection and is never
replayed (no replay log exists by design for a hint layer).

**Recovery:** the same backstop poll as Â§4.4 covers this â€” the missed event's underlying state
change is always visible on the next `GET /v1/sessions/{session_id}`. The periodic
`SUBSCRIBE_TICK` inside `stream_events()` (once per `sse_ping_seconds`) also re-reads the board's
session status on every tick independent of any published event, so a terminal transition is
never missed for longer than one tick even if the triggering event itself was.

### 4.6 No `Last-Event-ID` / replay on reconnect (item 8, structurally closed for 8 of 10 kinds)

There is deliberately no replay log â€” `reconcile` plus the durable mirrors above cover
`stage_started`/`stage_completed`/`subsystem_started`/`session_entered_review`/`error`/
`next_set_result`/`regen_result`/`heartbeat` in full on every reconnect. The two exceptions are
`treatment_plan_result` (Â§4.3) and the reconcile-to-subscribe race window itself (Â§4.5), both
covered by the same backstop-poll recovery.

### 4.7 `session_entered_review`'s `generation_epoch` is not always correct (not structurally closed)

`_send_to_review` (`app/pipeline/tasks.py`) defaults `generation_epoch` to `1` and its only caller,
`decide_session_outcome`, never overrides it â€” including on the path a regenerate takes back into
review. `Scenario_Session` has no session-level epoch column to read a real value from at that call
site; the value lives per subsystem/stage on `Subsystem_Stage_State` only. Threading a correct value
through would mean adding an `epoch` parameter to `decide_session_outcome` and updating every one of
its callers (several sites in `cascade.py`, plus `reaper.py` and `sessions.py`) â€” out of scope for
the current implementation.

**Recovery:** never trust `session_entered_review.generation_epoch` to detect which regenerate/
next-set round put the session back in review. Use `progress.last_regen.epoch` /
`progress.last_next_set.epoch` from `GET /v1/sessions/{session_id}` instead â€” both are written from
the correct per-subsystem epoch and are the durable, authoritative signal this event's field was
meant to mirror.

---

## 5. Breaking change: `SessionProgress.error_message` (item 7)

**This changes `GET /v1/sessions/{session_id}`'s response shape, not just the SSE stream** â€” both
read from the same `build_board()` function.

| | Before | After |
|---|---|---|
| Type | `str \| None` | `dict[str, str]` |
| Default / "no error" | `null` | `{}` |
| Two simultaneous stage failures | Last-row-wins â€” one message silently overwrote the other | Both survive, keyed by stage |

```json
// before
{"progress": {"error_message": "the AI service is temporarily unavailable â€” please retry"}}

// after
{"progress": {"error_message": {"threats": "the AI service is temporarily unavailable â€” please retry"}}}
```

Keys are `"threats"`/`"scenarios"` (lowercased `SubsystemLevel` values), matching the sibling
`progress.threats`/`progress.scenarios` field names. An empty dict means no stage currently
carries an error message â€” check `progress.threats == "ERROR"` /
`progress.scenarios == "ERROR"` for which stage(s), and index into `error_message` with that same
lowercase key.

**Any existing typed consumer that deserializes `error_message` as `Optional[str]` will fail to
parse the response the moment this ships.** There is no dual-write/versioning transition â€” this
guide is the coordination point. If you maintain such a consumer, update it before this deploys.

---

## 6. Config knobs that shape stream behavior

| Setting | Default | Effect |
|---|---|---|
| `sse_ping_seconds` | 15 | `heartbeat` cadence, and the SUBSCRIBE_TICK status-recheck cadence (terminal-state detection, re-auth check) |
| `sse_send_timeout_seconds` | 30 | A stalled consumer (not reading the response) is force-closed within this long |
| `sse_shutdown_grace_seconds` | 25 | Open streams get this long to drain on a graceful API shutdown/rollout |
| `sse_max_concurrent_streams` | 180 | Per-process cap on open SSE connections; exceeding it returns `503` with `Retry-After`, never a raw connection error |
| `sse_breaker_cooldown_seconds` | 30 | How long a worker process silences ALL publishes after one failure (Â§4.4) |
| `sse_subscriber_socket_timeout_seconds` | 10 | How fast a dead Redis connection is detected under an open subscription |
| `verify_membership` | `False` | When `True`, a revoked (user, entity) pair closes the stream within one `sse_ping_seconds` tick |

---

## 7. Quick reference

| Event `type` | Scope | Terminal-ish? | Durable mirror |
|---|---|---|---|
| `reconcile` | session | n/a (snapshot) | itself |
| `stage_started` | stage | no | `progress.{threats,scenarios}` |
| `stage_completed` | stage | no (SCENARIOSâ†’AWAITING_DECISION *is* the review gate) | `progress.{threats,scenarios}` |
| `subsystem_started` | subsystem | no | `current_stage`/`stage_status` |
| `session_entered_review` | session | **yes-ish** (safe to stop a "generating" spinner) | `current_stage == "REVIEW"` |
| `error` | stage or session (`scope`) | only when `scope="session"` | `progress.error_message[stage]` / `session_status` |
| `next_set_result` | subsystem | no | `progress.last_next_set` |
| `regen_result` | subsystem | no | `progress.last_regen` |
| `treatment_plan_result` | plan | no | **none â€” poll `/treatment-plans`** |
| `heartbeat` | none | no | n/a |
