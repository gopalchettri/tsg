# Reaper & Library-Promotion — Developer Guide

Quick reference. Source of truth for defaults/validation is always `app/core/config.py`.

---

## 1. Session Reaper

**What it is:** a periodic cleanup pass (`app/pipeline/reaper.py::clean_up_abandoned_sessions`)
that reclaims CAS locks/leases left dangling by a crashed worker or an undelivered task, and
cancels sessions that are genuinely stuck (not just between stages).

**When you need it:** always, in any environment where the pipeline runs. Without it, a crashed
worker leaves a session's lock permanently `RUNNING` and it can never be worked on again.

**How it runs:** automatically. `celery beat` enqueues task `tsg.reap` on a schedule — you don't
call it directly. The task executes ON the worker (beat only schedules it): with no live worker,
the ticks queue up in the broker and nothing is reaped until the next worker boots and drains them. Start everything (API + worker + beat) with:

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
shared `Threat_Catalogue`, then — depending on the `TSG_PROMOTION_AUTO_APPROVE_ENABLED` master
switch — either queues every novelty for admin review (OFF, the default) or mints/links it
directly and eager-embeds it (ON). Phase 2 can fail on its own (LLM hiccup, embedder timeout)
**without undoing the accept** — the session stays `completed` either way. This is the mechanism
that tracks and retries that specific failure.

**When you need it:** any environment where accept runs against a live library — i.e. always
outside pure dev smoke-testing. Without it, a Phase-2 failure just silently never happens again.

### How a threat is triaged (per threat, every accept)

Cosine similarity of the threat's generic name vs. the nearest active catalogue entry:

```
cosine >= TRIAGE_AUTO_REJECT_COSINE (0.95)   -> auto_reject : link to the existing entry
cosine <  TRIAGE_AUTO_APPROVE_COSINE (0.80)  -> auto_approve: genuinely novel
otherwise                                     -> review      : curator queue
```

`TSG_PROMOTION_AUTO_APPROVE_ENABLED` is the **master switch for every kind of library growth**,
not just the `auto_approve` band:

- **OFF (default — admin-gated):** `auto_approve` is downgraded to `review`; a novel threat
  **type** is *not* minted at accept (the card keeps `ThreatTypeID` NULL until approval); each
  unknown **actor** queues as its own card (kind `actor`, with the proposing threat's type text
  shown in `proposed_type`); actor→type **links** are written only when an admin approves.
- **ON (full auto):** types, clearly-novel generic names, clearly-novel actors (junk-gated), and
  links are all created at accept, stamped `ai_auto_promoted` — links only ever seed a type
  minted in that same accept, never a curated type's actor set.

**Actor names get the same three lanes** — adapted for short text labels. A **duplicate** is a
spelling variant of an existing actor by normalized identity ONLY ("APT X" = "APT-X" = "apt
nova"→"APT-Nova"): the existing row is reused, no card. Merging is deliberately NOT
similarity-based — a character ratio at 0.95 would merge near-opposites like "Authorized
third-party user" / "Unauthorized third-party user", so anything merely similar queues for
**review** under BOTH switch positions (similarity = character ratio OR shared-word overlap,
so "Terrorist" vs "Terrorist/Extremist" is review, never novel; the knob is
`TSG_TRIAGE_AUTO_APPROVE_COSINE`), and only names clearly unlike everything are **novel**.
Identity is Unicode-aware ("Fáncy Bear" = "Fancy Bear", "APT41" = "APT-41" = "APT 41", and a
Cyrillic or CJK name is a name, not junk); filler like "Unknown"/"N/A" is dropped at parsing
with a log.

**Scales past a small actor library**: a novel-looking name is scored against a shortlisted
candidate set, not the whole active actor table
(`app/pipeline/accept_actors.py::_triage_actor_name`) — narrowed by TWO indices built
together, a trigram index (`_build_trigram_index`, shared 3-character runs — narrows the
character-ratio signal) and a token index (`_build_token_index`, shared whole words —
narrows the token-containment signal). Both are required: a shared word of only 1-2
characters can cross zero shared trigrams with a candidate when it sits next to different
neighbors in each name (confirmed empirically — "AQ PK" vs "PK Brigade AQ" shares no
trigram despite 1.0 token containment), so trigram overlap ALONE can silently miss a real
duplicate; the token index closes that gap by matching on the exact shared word regardless
of context. The union of both can never hide a match either signal would have scored above
the floor. Measured at 5K-20K synthetic actors: tens-to-low-hundred-millisecond build for
both indices together, a consistent 1.4x-4.3x per-query speedup over a full scan. Rebuilt
fresh every accept (not cached across accepts, unlike the Stage-1 vocabulary hint below) —
a mid-accept mint could otherwise leak into a shared cache and be matched against by a
later, unrelated accept after its own transaction rolled back.

The Stage-1 PROMPT's actor vocabulary (what the AI is shown as preferred spellings, see
`docs/HOW_THREATS_ARE_GENERATED.md`) is a separate, smaller concern: capped at
`TSG_ACTOR_VOCABULARY_CAP` (default 300) and cached `TSG_ACTOR_VOCABULARY_CACHE_SECONDS`
(default 30s) — a hint list, not a gate, so capping/caching it changes nothing about which
actors this triage recognizes.

Actor candidacy is deliberately independent of the threat's own grounding score:
a brand-new actor proposed on a perfectly-matched threat still reaches the queue. An admin's
**reject sticks under BOTH switch positions**: a rejected identity is neither re-queued nor
auto-minted by later sessions — for actors AND for threat names (re-opening is a deliberate
curator action, not an accept side-effect).

`review` cards land in `Threat_Candidate_Review` (`GET /v1/tsg/threat-library/candidates`,
filterable with `?kind=threat|actor`; `?status=rejected` lists the blacklist instead) for a
human to approve/reject. Approval credits the
**original proposing user** as `CreatedBy` on the minted master rows; the admin is recorded on
`ReviewedBy` and in the audit.

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
| List all pending/failed promotions | `GET /v1/tsg/sessions/promotions` | Admin headers † |
| One session's failure detail | `GET /v1/tsg/sessions/promotions/{session_id}` | Admin headers † |
| Force a retry now | `POST /v1/tsg/sessions/promotions/{session_id}/retry` | Admin headers † |
| Give up on it — its threats are never promoted after this | `DELETE /v1/tsg/sessions/promotions/{session_id}` | Admin headers † |

† **Admin headers** = `X-Admin-Key` + `X-API-Key` + `X-User-Id` + `X-Tenant-Id`. No `X-Entity-Id` —
admin routes are not entity-scoped (see docs/TSG_API_AUTHENTICATION_GUIDE.md §8).

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
| List candidates — `?status=pending` (default) for the review queue, `?status=rejected` for the standing identity blacklist | `GET /v1/tsg/threat-library/candidates` | Admin headers † |
| One candidate's detail | `GET /v1/tsg/threat-library/candidates/{candidate_id}` | Admin headers † |
| Approve → mints into the library (threat card: type + generic name; actor card: actor + its link to the type named on the card) | `POST /v1/tsg/threat-library/candidates/{candidate_id}/approve` | Admin headers † |
| Reject → discarded, library untouched | `POST /v1/tsg/threat-library/candidates/{candidate_id}/reject` | Admin headers † |

† Same admin headers as above — `X-Admin-Key` + `X-API-Key` + `X-User-Id` + `X-Tenant-Id`.

CAS-guarded: a candidate already resolved (by anyone) returns `409` on a second approve/reject —
the losing request is rolled back whole, so it never mints, links, or double-processes anything.
An actor card's link resolves at approval time, in two steps: the card's grounded type id is
used FIRST when that type is still active and not deleted; a null or dead id falls back to the
card's type text (one unambiguous active match). When neither resolves, the actor is created
**unlinked** and the skip is logged/audited — approve the sibling threat card first if the type
is part of the same proposal.

### Configuration

| Setting | Default | What it controls | Change it when... |
|---|---|---|---|
| `TSG_PROMOTION_AUTO_APPROVE_ENABLED` | `false` | THE master switch for AI-driven library growth: OFF routes every novel type/name/actor (and every actor→type link) through the admin candidate queue; ON lets accept mint and link all of it directly. Read live — a flip applies to every promotion from that moment, including retries. | Turn on only after `TRIAGE_AUTO_APPROVE_COSINE`/`TRIAGE_AUTO_REJECT_COSINE` are calibrated for your embedding model — a wrong threshold pollutes the shared library with unreviewed entries. |
| `TSG_PROMOTION_AUTO_RETRY_ENABLED` | `true` | Whether the periodic sweep retries failed promotions automatically, vs. waiting for an admin. | Turn off if every promotion failure must be a human decision. |
| `TSG_PROMOTION_RETRY_INTERVAL_SECONDS` | `60.0` | How often the sweep checks for failed promotions. | Rarely. |
| `TSG_PROMOTION_MAX_ATTEMPTS` | `5` | Attempts before the sweep marks a promotion "exhausted" (manual retry still works past this). | Raise if transient failures (e.g. LLM rate limits) need more automatic tries before a human is expected to step in. |
| `TSG_PROMOTION_SWEEP_BATCH_LIMIT` | `200` | Max sessions retried in one sweep pass. | Raise only if the interval is too short to drain a real backlog. |
| `TSG_PROMOTION_LIST_MAX_LIMIT` | `500` | Page-size cap on `GET /v1/tsg/sessions/promotions`. | Rarely. |
| `TSG_TRIAGE_AUTO_APPROVE_COSINE` | `0.80` | Similarity below which a proposal is "genuinely novel" — governs BOTH kinds: catalogue names (embedding cosine) and actor names (string ratio, novel-vs-review split only). | Recalibrate from `promotion_triage` audit rows (`candidates` = threats, `actors` = actor names) after any embedding-model change. Must stay **below** the reject band. |
| `TSG_TRIAGE_AUTO_REJECT_COSINE` | `0.95` | Cosine at/above which a CATALOGUE name is treated as a duplicate of an existing entry (existing row reused, nothing created). Actor duplicates never use it — they merge on normalized spelling identity only. | Same as above — recalibrate together. |
| `TSG_LIBRARY_PROMOTION_THRESHOLD` | `75.0` | Grounding-match cutoff: a THREAT scoring below this is eligible for type/name promotion. Actor candidacy is independent of it — actors on any accepted threat are always triaged. Must not exceed `TSG_GROUNDING_MATCH_THRESHOLD` (enforced at startup). | Only alongside a grounding-threshold retune — the two are coupled. |

### Quick recipes

- **"I want everything reviewed by a human, nothing auto-minted"** — leave
  `TSG_PROMOTION_AUTO_APPROVE_ENABLED` unset/`false` (the default). Every novel threat type,
  name, and actor lands in the curator queue; nothing enters the shared library, and no
  actor→type link is written, without an admin approval.
- **"I want novel threats, actors, and links minted immediately, no review step"** — set
  `TSG_PROMOTION_AUTO_APPROVE_ENABLED=true`, but only after confirming the cosine bands are
  calibrated (check recent `promotion_triage` audit rows for false auto-approves first).
- **"A promotion is stuck and I need it fixed now"** — `POST .../retry`; if it's genuinely broken
  (e.g. bad data), `DELETE .../{session_id}` to stop the sweep from retrying it forever.
