# Reaper & Library-Promotion — Developer Guide

Quick reference. Source of truth for defaults/validation is always `app/core/config.py`.

---

## 1. Session Reaper

**What it is:** a periodic cleanup pass (`app/pipeline/reaper.py::clean_up_abandoned_sessions`)
that reclaims CAS locks/leases left dangling by a crashed worker or an undelivered task, and
cancels sessions that are genuinely stuck (not just between stages).

**When you need it:** always, in any environment where the pipeline runs. Without it, a crashed
worker leaves a session's lock permanently `RUNNING` and it can never be worked on again.

**How it runs:** automatically. `celery beat` fires task `tsg.reap` on a schedule — you don't
call it directly. Start everything (API + worker + beat) with:

```powershell
.\start.ps1
```

**Manual trigger** (for testing, without waiting for the schedule):
```powershell
.venv\Scripts\celery.exe -A app.pipeline.celery_app.celery_app call tsg.reap
```

There is no HTTP/admin endpoint to trigger a pass on demand — beat and the manual command above
are the only two ways to run one.

**What one pass does, in order:**
1. Expired `RUNNING` stage rows → marked `ERROR`.
2. Expired `RUNNING` `_LOCK` rows → reset to `IDLE` (reclaimable again).
3. Sessions with no live lease → cancelled, in two groups: (a) a session whose lock/lease was
   just proven expired in steps 1-2 **this same pass** — reaped immediately, no grace wait; (b)
   a session that was never touched at all (never enqueued, or a reserved epoch whose task never
   ran) — only reaped once `UpdatedAt` is older than the grace window. A session sitting at
   `REVIEW`, or one any worker still holds a live lease on, is never touched — the former is a
   legitimate human wait, the latter means someone is still actively working on it.

Two real call sites deliberately route around waiting for this: `app/api/sessions.py:230` cancels
a session immediately on an accept-flow crash rather than leaving it for the reaper's stale-grace
window, and `:653` notes the same window is why a bare re-raise there would otherwise wedge a
session out of `REVIEW`. The reaper is the backstop of last resort, not the first line of defense.

Scope note: this reaper is specific to the scenario-generation pipeline. Treatment plans have no
reaper of their own (`app/api/treatment.py:175`) — a stale plan there is just presented as
timed-out, and the next `POST` supersedes it instead.

### Configuration

| Setting | Default | What it controls | Change it when... |
|---|---|---|---|
| `TSG_REAPER_INTERVAL_SECONDS` | `60.0` | How often the sweep runs (beat schedule for `tsg.reap`). | Lower for faster crash recovery (more DB polling); raise to reduce load. Rarely needs touching. |
| `TSG_REAPER_STALE_GRACE_SECONDS` | derived — **follows `TSG_STAGE_LEASE_SECONDS`** (300s) if unset | How long a lease-less session must sit untouched before it's called "abandoned." | Raise if legitimate stages sometimes run longer than one lease window (avoids false-positive cancellations). Leave unset otherwise — it's designed to track the lease duration automatically. |
| `TSG_STAGE_LEASE_SECONDS` | `300` | How long a CAS lock/lease is held before it's considered expired. | Only if a single pipeline stage genuinely needs longer than 5 minutes. |
| `TSG_STAGE_MAX_ATTEMPTS` | `5` | Retry cap for a single stage before it's abandoned. | Rarely. |

---

## 2. Library Promotion (retry + auto-approve)

**What it is:** after `POST /v1/sessions/{id}/accept`, Phase 1 (core accept) commits immediately.
Phase 2 — "promotion" — runs right after, isolated: it dedupes each accepted threat against the
shared `Threat_Catalogue`, mints or links it, and eager-embeds it. Phase 2 can fail on its own
(LLM hiccup, embedder timeout) **without undoing the accept** — the session stays `completed`
either way. This is the mechanism that tracks and retries that specific failure.

**When you need it:** any environment where accept runs against a live library — i.e. always
outside pure dev smoke-testing. Without it, a Phase-2 failure just silently never happens again.

### How a threat is triaged (per threat, every accept)

Cosine similarity of the threat's generic name vs. the nearest active catalogue entry:

```
cosine >= TRIAGE_AUTO_REJECT_COSINE (0.95)   -> auto_reject : link to the existing entry
cosine <  TRIAGE_AUTO_APPROVE_COSINE (0.80)  -> auto_approve: genuinely novel
otherwise                                     -> review      : curator queue
```

`auto_approve` only mints immediately if `TSG_PROMOTION_AUTO_APPROVE_ENABLED=true`; otherwise it's
downgraded to `review` too. `review` threats land in `Threat_Candidate_Review`
(`GET /v1/tsg/threat-library/candidates`) for a human to approve/reject.

**`auto_reject` is never gated** — a near-duplicate always auto-links to the existing catalogue
entry, with no toggle to route it to a human instead. Only the `auto_approve` band is
configurable; there is no "review everything, including duplicates" mode.

### If Phase 2 fails

The session gets `PromotionFailedAt` / `PromotionError` / `PromotionUserID` / `PromotionAttempts`
stamped on it. From there:

- **Automatic:** if `TSG_PROMOTION_AUTO_RETRY_ENABLED=true` (default), `celery beat`'s
  `tsg.retry_promotions` task retries it on its own interval, up to `TSG_PROMOTION_MAX_ATTEMPTS`,
  after which it's "exhausted" (the sweep stops touching it, but...)
- **Manual, always available regardless of exhaustion:**

| Action | Endpoint | Auth |
|---|---|---|
| List all pending/failed promotions | `GET /v1/tsg/sessions/promotions` | `X-Admin-Key` |
| One session's failure detail | `GET /v1/tsg/sessions/promotions/{session_id}` | `X-Admin-Key` |
| Force a retry now | `POST /v1/tsg/sessions/promotions/{session_id}/retry` | `X-Admin-Key` |
| Give up on it — its threats are never promoted after this | `DELETE /v1/tsg/sessions/promotions/{session_id}` | `X-Admin-Key` |

`list_promotions` takes `?include_exhausted=false` to hide sessions the sweep has given up on
(they're still manually retryable either way).

Both retry and dismiss return one of **3** outcomes, not 2 — `outcome: "succeeded"`,
`"failed"` (genuinely broken, safe to retry again or dismiss), or **`"skipped"`** (someone else —
the sweep, or another admin — is touching this session's lock right this second; nothing changed,
no attempt was burned, just try again). Dismiss is permanent: it clears the failure state without
re-running promotion, so that session's accepted threats simply never make it into the shared
library unless a human calls retry first.

**Manual sweep trigger** (for testing, without waiting for the schedule):
```powershell
.venv\Scripts\celery.exe -A app.pipeline.celery_app.celery_app call tsg.retry_promotions
```

### Curator review queue (the `review` band)

| Action | Endpoint | Auth |
|---|---|---|
| List pending candidates | `GET /v1/tsg/threat-library/candidates` | `X-Admin-Key` |
| One candidate's detail | `GET /v1/tsg/threat-library/candidates/{candidate_id}` | `X-Admin-Key` |
| Approve → mints into the catalogue | `POST /v1/tsg/threat-library/candidates/{candidate_id}/approve` | `X-Admin-Key` |
| Reject → discarded, catalogue untouched | `POST /v1/tsg/threat-library/candidates/{candidate_id}/reject` | `X-Admin-Key` |

CAS-guarded: a candidate already resolved (by anyone) returns `409` on a second approve/reject —
it never re-mints or double-processes.

### Configuration

| Setting | Default | What it controls | Change it when... |
|---|---|---|---|
| `TSG_PROMOTION_AUTO_APPROVE_ENABLED` | `false` | Whether an `auto_approve`-band threat mints straight into the catalogue, or is downgraded to `review`. | Turn on only after `TRIAGE_AUTO_APPROVE_COSINE`/`TRIAGE_AUTO_REJECT_COSINE` are calibrated for your embedding model — a wrong threshold pollutes the shared library with unreviewed entries. |
| `TSG_PROMOTION_AUTO_RETRY_ENABLED` | `true` | Whether the periodic sweep retries failed promotions automatically, vs. waiting for an admin. | Turn off if every promotion failure must be a human decision. |
| `TSG_PROMOTION_RETRY_INTERVAL_SECONDS` | `60.0` | How often the sweep checks for failed promotions. | Rarely. |
| `TSG_PROMOTION_MAX_ATTEMPTS` | `5` | Attempts before the sweep marks a promotion "exhausted" (manual retry still works past this). | Raise if transient failures (e.g. LLM rate limits) need more automatic tries before a human is expected to step in. |
| `TSG_PROMOTION_SWEEP_BATCH_LIMIT` | `200` | Max sessions retried in one sweep pass. | Raise only if the interval is too short to drain a real backlog. |
| `TSG_PROMOTION_LIST_MAX_LIMIT` | `500` | Page-size cap on `GET /v1/tsg/sessions/promotions`. | Rarely. |
| `TSG_TRIAGE_AUTO_APPROVE_COSINE` | `0.80` | Cosine below which a threat is "genuinely novel." | Recalibrate from `promotion_triage` audit rows after any embedding-model change. Must stay **below** the reject band. |
| `TSG_TRIAGE_AUTO_REJECT_COSINE` | `0.95` | Cosine at/above which a threat is treated as a duplicate of an existing entry. | Same as above — recalibrate together. |
| `TSG_LIBRARY_PROMOTION_THRESHOLD` | `75.0` | Grounding-match cutoff: a threat scoring below this is eligible for promotion at all. Must not exceed `TSG_GROUNDING_MATCH_THRESHOLD` (enforced at startup). | Only alongside a grounding-threshold retune — the two are coupled. |

### Quick recipes

- **"I want everything reviewed by a human, nothing auto-minted"** — leave
  `TSG_PROMOTION_AUTO_APPROVE_ENABLED` unset/`false` (the default). Every novel threat lands in
  the curator queue.
- **"I want novel threats minted immediately, no review step"** — set
  `TSG_PROMOTION_AUTO_APPROVE_ENABLED=true`, but only after confirming the cosine bands are
  calibrated (check recent `promotion_triage` audit rows for false auto-approves first).
- **"A promotion is stuck and I need it fixed now"** — `POST .../retry`; if it's genuinely broken
  (e.g. bad data), `DELETE .../{session_id}` to stop the sweep from retrying it forever.
