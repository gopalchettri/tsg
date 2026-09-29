# TSG — decisions needed, found while syncing SDD v2.1

**Companion to `Threat_Scenario_Generator_SDD_V2.docx` v2.1**

| Attribute | Value |
|---|---|
| Document type | Decision register (no fixes applied) |
| Subject system | Threat Scenario Generator (TSG) |
| Produced by | The SDD v2.0 → v2.1 synchronisation audit |
| Codebase audited | `tsg/app`, working tree at 20 September 2026 |
| Date | 2026-09-20 |
| Status | For decision |

---

## Why this document exists

Syncing the SDD to the code traced roughly 150 of the document's factual claims to source. Most
mismatches were ordinary documentation drift, and those were corrected in the SDD itself as
tracked changes.

The six items below are different. In each one the SDD described the *safer* or *more complete*
behaviour, and the code is the thing that looks wrong — so amending the document would have
recorded the weaker behaviour as the intended design. **Nothing here has been changed.** The SDD
now describes what the code actually does; these are the places where somebody should decide
whether that is what it *should* do.

Ordered by consequence, not by effort.

---

## 1. The prompt leak guard is disabled in production

`app/pipeline/llm.py:248-253`

`_assert_no_db_keys` is the last line of defence before a prompt leaves the process: it re-scans
the outgoing message for database identifiers that redaction should already have stripped. Outside
production a hit **raises** and the call never happens. In production the same hit is logged as
`prompt.db_key_leak` and **the call proceeds**.

Every other environment fails closed; the one environment holding real CII asset data fails open.
A leak in prod produces a log line that nothing blocks on, and the identifiers still reach the
model provider.

**Decide:** raise in production too, or keep the current behaviour and route
`prompt.db_key_leak` to alerting so it is not merely recorded.

---

## 2. Control mapping can exhaust permanently, with no way to retry it

`app/pipeline/control_mapping.py:159-170`, `app/core/config.py:438-446`,
`app/core/enums.py:85-93`

`control_map_max_attempts` (5) is not a backoff — it is a permanent cutoff. A scenario past it is
excluded from every future mapping pass, shows `ControlMappingStatus.ERROR` on the session board,
and there is **no API route that can re-queue it**. The only recovery is regenerating the
scenario, which produces a new version and therefore a new review decision.

A reranker outage lasting longer than five sweep ticks converts into permanently empty control
lists for every scenario caught in it.

**Decide:** add an admin route to reset the attempt counter, make the cutoff time-based rather
than count-based, or accept the regenerate-only recovery and document it for operators.

---

## 3. The control-mapping sweep silently skips older sessions

`app/pipeline/control_mapping.py:522-530`

`CONTROL_MAP_SWEEP_FROM = 2026-08-25` is a hard date floor: sessions created before it are never
swept, whatever their state. The constant presumably marked a migration boundary, but it is now a
permanent, silent exclusion — an affected session reports control mapping as pending forever and
nothing explains why.

**Decide:** remove the floor now that the migration is past, or keep it and surface the exclusion
explicitly rather than as indefinite pending.

---

## 4. The body-size limit does not apply to chunked uploads

`app/core/middleware.py:23-50`

`BodySizeLimitMiddleware` rejects on `Content-Length` before the body is read. A chunked
transfer-encoded request declares no length, so it passes the check and is buffered in full.

The middleware is correctly ordered (added last, runs first) and the 16 MB constant is right; the
gap is only the header it depends on. Note the limit is a hardcoded class constant with no
setting, which is deliberate.

**Decide:** count bytes as the stream is consumed, or accept the gap on the grounds that the
upstream ingress already caps request size — in which case the guarantee belongs to the ingress,
not to this middleware.

---

## 5. The active-session ceilings ship disabled

`app/core/config.py:531,533`

`max_active_sessions` and `max_active_sessions_per_entity` both default to `0`, which disables
them. The capacity check, the `503` and the `Retry-After` header are all implemented and correct
— they simply never fire unless an operator sets a value.

The SDD described the ceilings as an operating control. That is now qualified in v2.1, but a
protection that is off by default is only a protection if deployment sets it.

**Decide:** pick non-zero defaults, or confirm that the deployment configuration sets them and
treat the code default as intentionally inert.

---

## 6. Scheduled threat-intel refresh is off by default

`app/core/config.py:146`, `app/pipeline/celery_app.py:92-94`

`intel_refresh_interval_seconds` defaults to `0`, which removes the `intel-refresh` beat entry
entirely. Feeds then refresh only when an administrator posts to the refresh route. The
self-check does warn on stale feeds (`intel.feed_stale`), so the condition is visible — but in the
default posture, scenario prompts are grounded on whatever intel was last fetched by hand.

**Decide:** enable a default interval, or confirm that manual refresh is the intended operating
model and that the staleness warning is monitored.

---

## Not in this list

Two things were checked and are **correct as they stand**, despite looking like defects:

- **The lease keeper replacing per-call lease renewal** (`app/pipeline/lease_keeper.py:3-8`). The
  SDD described the old design. The change was deliberate: renewing only before an AI call meant a
  long non-LLM step was reaped while still alive. The SDD was corrected, not the code.
- **`verify_membership` defaulting off** (`app/core/config.py:628`). This is the accepted auth
  model, not a pending remediation. It used to be stated at INFO on every boot by
  `assert_security_posture`, at INFO rather than WARN precisely so it would not be mistaken for a
  pending remediation. **That function was removed on 2026-09-29 at the owner's instruction**, so
  the posture is no longer announced anywhere at boot: it is now documented here and nowhere else.
