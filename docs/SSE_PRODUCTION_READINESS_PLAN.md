# SSE production-readiness plan — all 38 confirmed findings

## Context

A 6-dimension audit (wire format, connection lifecycle, delivery semantics, auth/security,
infrastructure, contract) of `GET /v1/sessions/{session_id}/events`, with every finding
independently adversarially re-verified. Result: **37 confirmed** (6 major, 29 minor, 2 cosmetic),
12 refuted (real mechanisms that turned out to be deliberate, documented, already-mitigated
tradeoffs — the "SSE is a hint layer, DB is truth, keep a backstop poll" pattern this codebase
applies consistently). A 38th finding, originally rated blocker, was retracted after review — see
below.

**Retracted: the earlier "JWT never invoked" blocker finding.** A prior pass flagged, at blocker
severity, that `deps.py`'s header-based auth (`X-API-Key` + `X-User-Id` + `X-Entity-Id`,
[deps.py:66-97](../app/api/deps.py)) contradicted `TSG_SDD.md`'s claim that "TSG validates the
platform's JWT." That framing was backwards. `docs/TSG_API_AUTHENTICATION_GUIDE.md` is the
authoritative, purpose-built guide for TSG's auth model, and it documents — in full detail, with a
response-code table, key-rotation procedure, and the `TSG_VERIFY_MEMBERSHIP` switch — exactly the
header-based model `deps.py` implements. This is TSG's real, intentional, fully-documented
authentication design, not a gap. The only real residual: `TSG_SDD.md` and `deps.py`'s own module
docstring still describe a JWT model this guide has since superseded — a low-priority
documentation-accuracy cleanup (point both at `TSG_API_AUTHENTICATION_GUIDE.md` instead), not a
security or SSE defect, and not blocking anything below. No item in this plan (1-32) depended on
the retracted finding.

Target: every confirmed SSE finding gets a concrete fix. Scope is "everything confirmed" per
direction — including cosmetic/low-impact items.

This plan was itself adversarially re-audited after the first draft (33 candidate gaps found in
the plan's own reasoning, 26 confirmed) — every correction below marked **Correction:** was added
during that second pass, where an originally-proposed fix was found to be non-functional,
order-dependent on another fix, or misattributed. A third pass then checked the plan for build
sequencing — the Implementation Order below is its output.

---

## Implementation order

Sections A-F below are grouped by *root cause*, not *build sequence*. Several items touch the same
function and are only safe to land in this order — building them in item-number order, or in
parallel by different people, will produce exactly the "one fix silently undoes another" failures
the second audit pass caught. All new settings get concrete defaults here so no phase is blocked on
picking a number mid-implementation.

**Phase 0 — Config surface (no behavior change).** Add every new setting up front:
`sse_max_concurrent_streams` (default 180 — sizes both item 11's pool and item 12's semaphore, one
value, not two), `sse_send_timeout_seconds` (30), `sse_shutdown_grace_seconds` (25),
`sse_subscriber_socket_timeout_seconds` (10), `sse_subscriber_health_check_interval_seconds` (30),
`cors_allowed_origins` (empty by default, set per environment). Validate `sse_ping_seconds` with
`Field(gt=0)` (item 16). *Done when:* config-loading tests pass, including the `sse_ping_seconds`
rejection cases (verification 7).

**Phase 1 — `app/sse/bus.py`: one redesign, four items, in this sub-order.**
1. Item 11 — shared `redis.asyncio.ConnectionPool`, sized by `sse_max_concurrent_streams`.
2. Item 14 — `socket_timeout`/`health_check_interval` **on the pool's construction**, not the
   per-call client (passing them to `Redis(connection_pool=...)` is silently dropped).
3. Item 15 — wrap the `finally` cleanup in `anyio.CancelScope(shield=True)`; do not reorder instead.
4. Item 1's polling primitive — replace `async for msg in pub.listen()` with a loop calling
   `get_message(timeout=sse_ping_seconds)`, yielding a sentinel on timeout so the caller in
   `stream_events()` gets control back periodically without the subscription itself dying.
5. Item 10 — fix the "WORKER-ONLY" docstring; add a timeout to the non-prober wait for the
   API-process call path.
*Done when:* a subscription receives no message for `sse_ping_seconds` and the sentinel is observed
— proves the loop no longer blocks indefinitely (folds into verification 6).

**Phase 2 — `app/api/sessions.py`: `stream_events()` rewrite.** Consumes Phase 1's sentinel:
- Item 1's logic — on every sentinel, re-read the board's session status; break the generator on a
  terminal state. Publish on accept (`accept.py:94`) and cancel
  (`sessions.py:801-814`) as the fast path — the sentinel-driven check is the guarantee that doesn't
  depend on either publish succeeding.
- Item 30 — same sentinel tick: if `verify_membership` is on, re-check the (user, entity) pair;
  close the stream if it no longer resolves. One handler, not two.
- Item 2 — `send_timeout=sse_send_timeout_seconds` on `EventSourceResponse`.
- Item 20 — `shutdown_grace_period=sse_shutdown_grace_seconds` on the same construction.
- Item 12 — gate `session_events()` behind an `sse_max_concurrent_streams` semaphore, before the
  `run_in_threadpool` board load; 503 with `Retry-After` (reuse `errors.py:105-118`) at the cap.
*Done when:* verification 1 (including the stubbed-publish run), 5, and 11 pass.

**Phase 3 — Publish completeness.** Item 5 (reaper's three write sites) and item 4 (`generation_epoch`
on all three publish call sites `_record_failure`/`_send_to_review`/`_announce_generation_started`
touch). *Done when:* verification 3 and 4 pass, exercising every site each item touches, not just
the first.

**Phase 4 — Contract and data model.** Land together — one OpenAPI union and its payloads:
items 26 (`reconcile` enum member + `"type"` key on `build_board()`'s payload + `SessionBoard`
binding), 25 (typed models for the remaining 6 events, including the two-value `stage_completed`
Literal), 27 (`scope` on `error`), 28 (don't-tear-down-UI doc note), 24 (EventSource limitation
sentence), 3 (`last_regen`), then **item 7 last, and only after confirming any known external
consumer of `GET /v1/sessions/{id}` has been told** — it changes that endpoint's response shape, not
just SSE. Item 29 (the contract doc) is written last in this phase, once the shapes above are final.
*Done when:* verification 2 and 9 pass; a generated client has typed models for all 10 event kinds.

**Phase 5 — Infra and ops.** Item 22 (`stop_grace_period: 40s` on the `api` Compose service),
item 31 (`CORSMiddleware` with `cors_allowed_origins` **and** `allow_headers` for the three auth
headers — the allowlist alone fails preflight), item 17 (`RequestIDMiddleware` content-type check),
item 21 (startup assertion against `_get_uvicorn_server()`'s live signal-handler introspection, not
an `uvicorn`-importable check, which would pass even after the worker class drifts away from
uvicorn), item 9 (breaker log line), item 19 (no code — comment only). *Done when:* verification 8,
12, and 13 pass.

**Phase 6 — Reference client.** Item 18 (data-line join fix) and item 32 (stale comment **and** the
actual headers `sse_test.html` sends — add `X-API-Key`, rename the two dev-header fields to
`X-User-Id`/`X-Entity-Id`, or the client still 401s after every other phase lands). *Done when:*
`sse_test.html` opens a live stream against a real session end-to-end.

**Phase 7 — Full verification pass.** Run all 13 verification checks in order; `pytest` green
(verification 10).

---

## A. Delivery guarantees — the stream must reach a correct terminal state

Root cause common to most of these: publishing is scattered and best-effort with no fallback when
it's skipped. Fix is not "add more publishes everywhere" — it's to make the *board* (already the
documented source of truth) do the work event delivery can't guarantee, and stop treating publish
gaps as exceptional.

1. **Stream never ends** (major) — `stream_events()` has no exit condition; accept/cancel publish
   nothing. **Correction: "piggyback on the heartbeat tick" as originally written is not
   implementable** — sse_starlette's ping runs as a sibling anyio task
   ([sse.py:479-499](../app/.venv/Lib/site-packages/sse_starlette/sse.py)) with no way to reach into
   or cancel the generator `stream_events()` actually drives. The real fix: rewrite
   `stream_events()`'s inner loop to stop blocking indefinitely on `pub.listen()`
   ([bus.py:121](../app/sse/bus.py)) — wrap the read in a timed wait (`anyio.move_on_after` per
   iteration, or redis-py's `get_message(timeout=...)`) so the generator itself wakes on a fixed
   interval, checks the board's session status, and breaks on a terminal state. Publish on accept
   ([accept.py:94](../app/pipeline/accept.py)) and cancel
   ([sessions.py:801-814](../app/api/sessions.py)) as the fast path; the timed-wake status check is
   the guarantee that doesn't depend on the publish succeeding. Item 30 reuses this same timed-wake
   loop for its re-authorization check — implement both checks in one consolidated per-tick handler,
   not two independent patches to the same function.
2. **No `send_timeout`** (major) — add `send_timeout` to the `EventSourceResponse` construction
   ([sessions.py:885](../app/api/sessions.py)) via a new setting `sse_send_timeout_seconds`, default
   30s (2× the 15s ping interval), so a stalled consumer is force-closed in seconds, not ~15 minutes.
3. **Regenerate has no durable board mirror** (major) — add `last_regen` to `SessionProgress`
   (mirroring `last_next_set`), written by `build_board`
   ([sessions.py:121-139](../app/api/sessions.py)) from the `regeneration_completed` audit row. Fix
   `RegenerateResponse`'s docstring ([schemas.py:744-751](../app/api/schemas.py)), which currently
   tells clients to poll a field that can never hold regen data.
4. **`_record_failure` drops `epoch`** — add `generation_epoch` to the publish at
   [tasks.py:1459-1460](../app/pipeline/tasks.py) (it's already a parameter); same for
   `_send_to_review` ([tasks.py:1495-1496](../app/pipeline/tasks.py)) and
   `_announce_generation_started` ([tasks.py:1532-1533](../app/pipeline/tasks.py)).
5. **Reaper's stage→ERROR transitions are silent** — reaper.py has zero `bus.publish` calls. Add
   one at each of the three write sites ([reaper.py:73-78, 81-86, 152-159](../app/pipeline/reaper.py))
   so a client watching live doesn't need to wait for the next board refetch to see it.
6. **Worker SIGKILL: frozen board for lease + 60s** — no fix to the detection latency (it's a
   deliberate lease-based design); the fix is transparency: expose `lease_expires_at` on the board
   so a client can show "checking..." instead of a silent frozen "RUNNING" past the point staleness
   is expected.
7. **`progress.error_message` is last-row-wins, no stage attribution** — change
   `SessionProgress.error_message` to a `dict[str, str]` keyed by stage
   ([sessions.py:112-118](../app/api/sessions.py), [schemas.py:259-266](../app/api/schemas.py)), so two
   simultaneous failures don't silently drop one message. **This is a breaking REST API change, not
   an SSE-only tweak** — `SessionProgress` is also `SessionBoard`'s field, served by the *polling*
   `GET /v1/sessions/{session_id}` ([sessions.py:243-249](../app/api/sessions.py)), which
   [TSG_SDD.md:205](TSG_SDD.md) documents as "designed to agree" with the SSE stream. Any
   existing typed consumer reading `error_message` as `Optional[str]` hard-fails to parse the
   response the moment this ships. Needs a verification step (add to item 9's contract check) and,
   if any external consumer already depends on the string shape, a coordinated rollout rather than a
   silent type change.
8. **No `id:` / `Last-Event-ID`** — not fixed as "add replay" (no replay log exists by design and
   shouldn't for a hint layer); fixed by making reconnect cost nothing instead: `reconcile` already
   covers 7 of 9 event types fully, and items 3 closes the 8th. `treatment_plan_result` is the one
   genuine gap — call out that treatment-plan clients specifically must poll
   ([treatment.py](../app/pipeline/treatment.py) already documents this; make it load-bearing, not
   optional, in the reference client).
9. **Circuit breaker is process-global** — no code fix (splitting it per-session would need a
   Redis-backed breaker, disproportionate to the actual impact once items 1-8 remove the "stuck
   forever" failure modes). Add a log line naming which breaker (worker/API) opened, for
   diagnosability.
10. **`bus.publish`'s "WORKER-ONLY" docstring is contradicted by a live API-process call path** —
    fix the docstring to describe both cases accurately
    ([bus.py:80-82](../app/sse/bus.py)), and give the non-prober wait in the API-process case a
    timeout, since [bus.py:90-93](../app/sse/bus.py)'s "must be untimed" reasoning was written for the
    worker-only case that no longer holds.

## B. Redis connection budget — protects the pipeline, not just SSE

**Items 11, 14, and 15 are one redesign of `bus.subscribe()`'s connection lifecycle, not three
independent patches** — implementing them separately or out of order breaks the later ones:

11. **Unbounded, unpooled Redis connection per stream** ([bus.py:115](../app/sse/bus.py)) — switch to
    a shared connection pool for subscribers via `redis.asyncio.ConnectionPool`, sized by
    **one** new setting, `sse_max_concurrent_streams` (default 180). **Do this first**; items 12, 14
    and 15 depend on its shape.
12. **No concurrency/rate limit on SSE connections** — add a per-process semaphore gating
    `session_events()` ([sessions.py:854](../app/api/sessions.py)), limited to the **same**
    `sse_max_concurrent_streams` value item 11's pool uses — one setting drives both, so the
    semaphore can never admit more streams than the pool has connections for, and a race between two
    independently-sized caps (which could otherwise surface a raw Redis `ConnectionError` instead of
    a clean 503) is structurally impossible rather than merely coordinated. Return 503 at the cap
    using the codebase's existing capacity-503 convention (`Retry-After`,
    [errors.py:105-118](../app/api/errors.py)) rather than a bare 503 — add `app/api/errors.py` to
    Files Touched for this item.
13. **`/ready` shares the same Redis, cascading to a full outage** — item 12's cap closes the
    SSE-attributable path to this. No separate code fix; add a metric so an approaching cap is
    visible before `/ready` would ever trip.
14. **Subscriber has no read timeout / health check** — add `socket_timeout` (new setting
    `sse_subscriber_socket_timeout_seconds`, default 10s) and `health_check_interval` (new setting
    `sse_subscriber_health_check_interval_seconds`, default 30s). **Correction: the fix site moves
    once item 11 lands.** Passing these kwargs to the per-call `Redis()` constructor is silently
    dropped by redis-py whenever `connection_pool=` is set
    ([redis/asyncio/client.py:280-322](../app/.venv/Lib/site-packages/redis/asyncio/client.py))
    — set them on the shared `ConnectionPool`'s own construction instead, not on
    [bus.py:115-116](../app/sse/bus.py).
15. **`await r.aclose()` never runs on disconnect** — **correction: only one of the two originally
    proposed fixes actually works.** "Reorder the finally" does not guarantee cleanup completes under
    cancellation; wrap the cleanup in `anyio.CancelScope(shield=True)` — that is the only fix,
    not an alternative to reordering. This matters more than it did before item 11: under a shared,
    capped pool, a skipped cleanup permanently consumes one slot of the cap per occurrence, which is
    the exact connection-exhaustion cascade items 12/13 exist to prevent — now self-inflicted by a
    missed cleanup instead of unbounded connection growth.

## C. Wire protocol / library configuration

16. **`sse_ping_seconds` unvalidated** — add `Field(gt=0)` in
    [config.py:488](../app/core/config.py); 0 floods, negative 500s every connect.
17. **RequestIDMiddleware's SSE branch is dead code** (two duplicate findings, wire-format +
    infrastructure dimensions) — fix the check at
    [middleware.py:70](../app/core/middleware.py) to test `response.headers.get("content-type", "")`
    instead of the always-`None` `response.media_type`.
18. **The only shipped SSE client violates the data-line join rule** — fix
    [sse_test.html:168](../app/static/sse_test.html) to join continuation `data:` lines with `\n` and
    strip only one leading space, not `.trim()`. Dormant today (no multi-line JSON is ever
    produced) but this file is the copy-paste source for future clients — fix it before someone
    copies the bug forward.
19. **`Connection: keep-alive` unconditional** (cosmetic, unreachable under uvicorn/HTTP1.1) — no
    fix; note in the reference client's comments that this becomes relevant only if the ASGI server
    is ever swapped for one that speaks HTTP/2.

## D. Lifecycle / shutdown

20. **`shutdown_grace_period` defaults to 0** — pass an explicit `shutdown_grace_period` to
    `EventSourceResponse` ([sessions.py:885](../app/api/sessions.py)) via a new setting
    `sse_shutdown_grace_seconds`, default 25s — 5s under gunicorn's `graceful-timeout`
    (30s, [Dockerfile:40-41](../Dockerfile)), so open streams get a bounded drain window instead of
    an instant cut on every rollout.
21. **Graceful shutdown survives only via introspection fallback** — no fix to the mechanism itself
    (it's sse_starlette's own, already correct given the current server); add a startup-time
    assertion that the ASGI server is uvicorn (the one case this depends on), so the fragility is
    loud instead of silent if that ever changes.
22. **`api` container gets Docker's 10s default stop grace vs. worker's explicit 300s** — add
    `stop_grace_period: 40s` to the `api` service in
    [compose.prod.yml](../docker/compose.prod.yml) — above gunicorn's 30s `graceful-timeout` with
    margin, so Docker never SIGKILLs before gunicorn's own grace period completes.
23. **Reconnect stampede after rollout burns the shared threadpool + DB pool** — **correction: item 2
    does not mitigate this.** `send_timeout` only bounds an already-open stream's write path; the
    stampede's actual cost is a burst of concurrent `Depends(get_principal)` DB lookups
    ([deps.py:66-97](../app/api/deps.py)) plus `run_in_threadpool(_load_events_board, ...)`
    ([sessions.py:865](../app/api/sessions.py)) from brand-new connections, which `send_timeout` never
    touches. **Item 12's semaphore is the actual mitigation** — it gates `session_events()` before
    the threadpool call, so it caps concurrent reconnect load, not just steady-state stream count.
    Item 20 (bounded drain) still helps by smoothing the timing of the stampede.

## E. Contract / typing — what an external team needs to build correctly

24. **Native `EventSource` cannot consume this stream, undocumented in the contract** — add one
    sentence to `_EVENT_STREAM_RESPONSES`'s description
    ([sessions.py:840-848](../app/api/sessions.py)) stating this explicitly and pointing at the
    fetch()+ReadableStream pattern.
25. **Only 3 of 9 event names have a typed schema** — declare models for the remaining 6
    (`stage_started`/`stage_completed`/`subsystem_started`/`session_entered_review`/`error`/
    `heartbeat`) and add them to the `_EVENT_STREAM_RESPONSES` union
    ([sessions.py:837-851](../app/api/sessions.py)). **`stage_completed` needs a two-value Literal, not
    one**: it publishes `StageStatus.COMPLETE` for THREATS ([tasks.py:668](../app/pipeline/tasks.py))
    and `StageStatus.AWAITING_DECISION` for SCENARIOS ([tasks.py:1327](../app/pipeline/tasks.py)) via
    the same `_send_live_update` call — a naive single-value Literal (matching this file's own
    convention elsewhere) would reject half its real traffic.
26. **`reconcile` isn't a member of `SSEEventType`** — add it to the enum
    ([enums.py:218-243](../app/core/enums.py)) and bind it to `SessionBoard` in the response union.
    **Also add a `"type": "reconcile"` key to the payload** `build_board()` returns when streamed
    ([sessions.py:874](../app/api/sessions.py)) — binding the model without it leaves `reconcile` the
    only union member with no discriminator field, defeating the exact design rule
    [schemas.py:817-819](../app/api/schemas.py) states for every other event ("a field typed as the
    whole SSEEventType gives the union no discriminator").
27. **`error`'s dual-scope rule lives only in an internal doc** — add an explicit `scope` field
    (`"stage"` | `"session"`) to both payloads ([tasks.py:1459-1460, 1517-1518](../app/pipeline/tasks.py))
    instead of relying on key-presence, and document it in the typed model from item 25.
28. **Stage-scoped `error` isn't necessarily terminal** — document explicitly, next to the typed
    `error` model, that clients must not tear down UI on `error` alone; wait for
    `session_entered_review` or a terminal session status.
29. **No client-facing contract doc comparable to the treatment-plan guide** — write one covering
    the session-progress stream at the same depth: field-by-field payload shapes, a "what never
    publishes" table, and the recovery path for each gap this plan didn't structurally close.

## F. Auth/security (SSE-scoped only — see Context for the retracted JWT finding)

30. **SSE authorization checked once at connect, never re-validated** — add a periodic
    re-authorization check that closes the stream if `verify_membership` is on and the (user,
    entity) pair no longer resolves. **Correction: reuses item 1's sentinel-driven loop, not "the
    heartbeat tick"** — sse_starlette's ping is a separate task that can't close the stream (see item
    1's correction); this must run in the same per-tick handler item 1 adds inside
    `stream_events()`, not a second independent mechanism. Low urgency given only status metadata
    flows, not content, but cheap to add to the same tick.
31. **No CORS middleware** — add `CORSMiddleware` with a configured origin allowlist
    ([main.py](../app/main.py)), needed for any browser-based external consumer regardless of the
    documented backend-to-backend model, since that model may not be the only one going forward.
    **Must also set `allow_headers` for the three custom auth headers** (`X-API-Key`, `X-User-Id`,
    `X-Entity-Id`, required per [deps.py:66-69](../app/api/deps.py)) — these are non-simple headers
    that trigger a CORS preflight, which Starlette's `CORSMiddleware` rejects by default unless they
    are explicitly listed. An origin allowlist alone leaves a browser consumer blocked at the
    preflight stage, not connected. New setting belongs in
    [config.py](../app/core/config.py) alongside item 11/20's — add that row to Files Touched.
32. **`sse_test.html`'s comment misstates prod auth as "bearer token"** (cosmetic) — fix the comment
    at [sse_test.html:74](../app/static/sse_test.html) to name the real header set. **Also fix the
    actual request the page sends**: `headers()` ([sse_test.html:119](../app/static/sse_test.html))
    sends `X-Dev-User`/`X-Dev-Entities`, which `get_principal` never reads and which omits
    `X-API-Key` entirely — leftover from the retired dev-auth model
    ([config.py:36-53](../app/core/config.py) `_RETIRED_SETTINGS`). As written, items 18+32 fix this
    file's parser bug and one comment but leave it 401ing on every connection — add an `X-API-Key`
    field and rename the two header keys to `X-User-Id`/`X-Entity-Id`, so the repo's one shipped SSE
    client can actually connect after this plan lands.

---

## Files touched

| File | Findings addressed |
|---|---|
| [app/api/sessions.py](../app/api/sessions.py) | 1, 2, 3, 7, 8, 24, 25, 26, 30, plus event models |
| [app/sse/bus.py](../app/sse/bus.py) | 1 (polling primitive), 10, 11, 14, 15 |
| [app/pipeline/tasks.py](../app/pipeline/tasks.py) | 4, 27 |
| [app/pipeline/reaper.py](../app/pipeline/reaper.py) | 5 |
| [app/pipeline/accept.py](../app/pipeline/accept.py) | 1 (accept publish) |
| [app/api/schemas.py](../app/api/schemas.py) | 3, 7, 25, 27 |
| [app/core/enums.py](../app/core/enums.py) | 26 |
| [app/core/config.py](../app/core/config.py) | 12, 16, 31, plus new settings for 11, 20 |
| [app/core/middleware.py](../app/core/middleware.py) | 17 |
| [app/main.py](../app/main.py) | 31 |
| [docker/compose.prod.yml](../docker/compose.prod.yml) | 22 |
| [app/api/errors.py](../app/api/errors.py) | 12 (reuse existing Retry-After 503 pattern) |
| `app/static/sse_test.html` | 18, 32 |
| New: session-progress contract doc | 29 |
| `docs/TSG_SDD.md`, `app/api/deps.py` (docstring only) | low-priority cleanup: retire the superseded JWT references, point at `TSG_API_AUTHENTICATION_GUIDE.md` |

---

## Verification

1. **Terminal state (1, 2):** accept a session while streaming from a second client — stream closes
   within one heartbeat tick. Stall a consumer (don't read the response) — connection force-closed
   within `send_timeout`, not 15 minutes. **Also stub `bus.publish` to a no-op and repeat the accept
   test — the stream must still close via the timed-wake status check.** The publish-on-accept path
   alone does not prove item 1's stated guarantee ("doesn't depend on the publish succeeding"); only
   this stubbed run does.
2. **Regen mirror (3):** regenerate, disconnect before the result event, reconnect — `reconcile`
   shows the regen outcome via `last_regen`.
3. **Epoch (4):** trigger a stage failure during an active regen — the `error` event carries the
   current epoch, not the default. **Repeat for all three publish sites item 4 touches**, not just
   `_record_failure`: also drive a session to `session_entered_review` and to a fresh
   `subsystem_started` and confirm both carry the current epoch too.
4. **Reaper (5):** kill a worker mid-stage, wait for the reaper sweep — an `error` event fires
   without waiting for a manual board refetch.
5. **Redis budget (11, 12, 13):** open streams past the configured cap — clean 503, not a Redis
   connection error; `/ready` stays green throughout.
6. **Subscriber health (14, 15):** kill the Redis connection under a live subscriber — the stream
   detects it within `socket_timeout`, not indefinitely; confirm the finally-block cleanup actually
   runs on client disconnect (repeat the earlier repro).
7. **Ping validation (16):** set `TSG_SSE_PING_SECONDS=0` and `=-1` — both rejected at config load,
   not at connect time.
8. **Shutdown (20, 22):** SIGTERM the API container mid-stream — client gets a clean close within
   the grace window, not an instant cut.
9. **Contract (24-28):** generate a client from the OpenAPI spec — it has typed models for all 9
   event kinds plus `reconcile`, and the generated docs state the EventSource limitation, the
   `error` scope rule, and item 28's "don't tear down UI on a stage-scoped error" guidance. **Also
   assert runtime behavior, not just schema text**: force a single-subsystem failure and confirm the
   emitted `error` event actually carries `scope: "stage"`; force a total-session failure and confirm
   `scope: "session"` — a schema description alone doesn't prove the field is emitted correctly.
10. `pytest` green, including new tests for: terminal-state stream closure (including the stubbed-
    publish case above), epoch presence on error events, the reconcile-after-subscribe ordering
    (already-known race), and the connection cap returning 503 with `Retry-After`.
11. **Re-auth (30):** with `verify_membership` on, revoke a user's entity access mid-stream — the
    connection closes within one timed-wake tick, not indefinitely.
12. **CORS (31):** a cross-origin preflight from a non-allowlisted origin is rejected; from an
    allowlisted origin, the preflight succeeds and the three custom auth headers are accepted (not
    just the origin check).
13. **Startup assertion (21):** boot the app under a non-uvicorn ASGI server (or confirm the
    assertion actually inspects `_get_uvicorn_server()`'s live signal-handler introspection, not just
    whether the `uvicorn` package is importable, which is always true given it's a hard dependency
    regardless of the configured worker class) — the assertion must fail loudly, not pass by
    accident.
