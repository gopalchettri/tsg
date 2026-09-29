# Remediation log — 2026-09-29

**Branch:** `tsg/hybrid_search_tsg`
**Range:** `8891afe..d480826` — one checkpoint plus 15 commits of work, all on 2026-09-29
**Suite at the end:** 1705 passed, 0 failed
**Schema:** 2 new tables, 4 new indexes. No data migration, nothing rewritten.

**What started it.** Session `6174F288-222C-890E-98C1-01A0EC098CBD` (entity 78, Ejari / Dubai REST)
was cancelled on 2026-09-29 07:23:59Z. One `litellm.rerank` call read-timed out at 120s while
grounding the first gap proposal. Session `9BC8AA90-EC29-81DE-B52D-01A0EC08E754` died identically
76 seconds later on the same entity — a reranker outage, not bad data.

Investigating that one timeout surfaced 32 defects. They are listed below against the commit that
fixed each, so any one can be traced or reverted on its own.

---

## How to revert

Every commit below reverts cleanly on its own:

```bash
git revert <sha>
```

**Order matters in one place only.** `2bc06e6` → `5161de5` → `b392d03` → `14ce326` → `d480826` are
the diagnostics stack and build on each other. Reverting the whole feature means newest-first:

```bash
git revert d480826 14ce326 b392d03 5161de5 2bc06e6
```

**Rolling back the deployment** is a plain redeploy of the prior build. No schema change needs
undoing — the two tables and four indexes are additive and unreferenced by older code. The one
change to a persisted write is `9818757`, which alters statement *order* inside an existing
transaction; nothing is stored differently.

---

## 1. Data loss or silently wrong output

| # | Issue | Commit | Where |
|---|---|---|---|
| 1 | **A regeneration could destroy a subsystem's threats.** `dal.supersede` committed before the replacement insert; any failure in between left **zero active threats** | `9818757` | `app/pipeline/threat_identification.py` |
| 2 | **Same hole on a lost CAS** — the rollback discarded the new rows and left the supersede committed. Nobody had noticed this one | `9818757` | same |
| 3 | **A sixth control-reference key was silently dropped.** The shape was hand-listed in two places, so the AI judged control coverage without data the shipped prompt tells it it has | `203e19e` | `app/api/library_references.py` |

## 2. The reported incident, and its real cause

| # | Issue | Commit | Where |
|---|---|---|---|
| 4 | **A rerank timeout cancelled the session.** Retryability was an open-ended allowlist: unknown ⇒ destroy the work. **Inverted the rule** — transient unless provably permanent | `7e9167d` | `app/pipeline/llm.py` |
| 5 | **Embeddings had the identical hole** — same chokepoint, coin-flip which one the outage hit first | `7e9167d` | same |
| 6 | **Two embedding-heavy jobs would have survived the fix unfixed** — they carry their own shorter retry list | `7e9167d` | `app/pipeline/celery_app.py` |
| 7 | **"Every call is wrapped" was a comment.** Its docstring claimed four call paths; there were six | `7e9167d` | `tests/test_transient_provider_retry.py` |
| 8 | **408 and 425 are transient 4xx** — the first draft of the inversion would have filed a gateway timeout as permanent, reintroducing the exact bug | `7e9167d` | `app/pipeline/llm.py` |
| 9 | **`num_retries` was silently ignored for embed and rerank.** Config said 3 attempts; reality was 1 | `5dfa0c0` | `app/pipeline/llm.py` |

## 3. Configuration that could not be trusted

| # | Issue | Commit | Where |
|---|---|---|---|
| 10 | **A pinned stage lease exactly equal to the worst case was accepted** (`<` should have been `<=`) | `2400277` | `app/core/config.py` |
| 11 | **The lease floor ignored the embedding and reranker budgets** — derived from only one of three | `5dfa0c0` | `app/core/config.py` |
| 12 | **The retry window did not outlast the control-map sweep on defaults** (both 300s). A deployment on defaults had the race the test exists to prevent | `9818757` | `app/core/config.py` |
| 13 | **A deprecated setting was still silently obeyed**, and the boot validator bounding it had been deleted | `a688ff9` | `app/core/env_selfcheck.py` |

## 4. Misleading to operators and clients

| # | Issue | Commit | Where |
|---|---|---|---|
| 14 | **The published OpenAPI stated something false** — `existing_controls` documented as 422-ing on duplicates; it silently collapses them | `203e19e` | `app/api/schemas_treatment.py` |
| 15 | **The worker logged `succeeded: None` one second after `pipeline.failed`** — the true answer was computed and thrown away | `a688ff9` | `app/pipeline/tasks.py` |
| 16 | **A treatment failure told the operator "a database issue"** after an LLM outage | `7e9167d` | `app/pipeline/celery_app.py` |
| 17 | **The prompt version hash had been deleted**, so prompt changes stopped invalidating anything | `a2bab7b` | `app/pipeline/prompts.py` |
| 18 | **A rerank timeout was filed as `database_transient`** — sending whoever read the dashboard to the wrong system | `7e9167d` | `app/pipeline/pipeline_common.py` |

## 5. Test-suite defects — the safety net itself

| # | Issue | Commit | Where |
|---|---|---|---|
| 19 | **The whole suite read the developer's `.env`.** CI green, this machine red — and worse, a test could pass locally *for the wrong reason* | `cc9b34e` | `tests/conftest.py` |
| 20 | **Five tests read and wrote a real SQL Server during `pytest`** without declaring it | `cc9b34e`, `2709227` | `tests/conftest.py` |
| 21 | **Tests pinned to private helpers** broke when a rule moved between two functions while behaviour stayed correct | `cc9b34e` | `tests/test_control_topup_provenance.py` |
| 22 | **Docs tests hardcoded filenames**, yielding `FileNotFoundError` from a test whose job is "docs match code" | `a2bab7b` | `tests/test_remediation_reference_resolution.py` |
| 23 | **Whole-dict equality assertions** broke on any added field | `a2bab7b` | same |
| 24 | **Two retry tests asserted a log line that is not emitted** under isolated settings | `191d11f` | `tests/test_library_first_identification.py` |
| 25 | **A hardcoded `31 indexes` tripwire.** It exists to catch a regex that stopped matching, but as a literal it also fails on every legitimate index — teaching the next reader the number is noise to bump | `b392d03` | `tests/test_tsg_script_package.py` |

## 6. Diagnosability — the original complaint

| # | Issue | Commit | Where |
|---|---|---|---|
| 26 | **A UAT failure was undiagnosable without shell access.** All three durable surfaces carried `"stage processing failed"`; the truth lived only in container stdout | `2bc06e6`, `5161de5`, `b392d03` | `app/core/diagnostics.py`, `app/api/diagnostics.py` |
| 27 | **No metrics, APM or error aggregation of any kind** | `14ce326` | `app/core/diagnostic_backends.py` |
| 28 | **Retries made outages invisible.** The symptom that made people notice disappeared — and there was no *aggregate* to alert on | `d480826` | `app/core/diagnostics.py` |

## 7. Defects introduced while building the fix, and caught before shipping

Recorded rather than left implied.

| # | Issue | Commit | Where |
|---|---|---|---|
| 29 | **The writer cached its engine across a DSN change** — silently writing to the *old* database. It surfaced as diagnostics landing in a real SQL Server during a test run | `5161de5` | `app/core/diagnostic_writer.py` |
| 30 | **Log capture defaulted on for the test suite**, so ordinary unit tests wrote log rows to whatever database was configured | `5161de5` | `tests/conftest.py` |
| 31 | **The operator guide documented five categories; the code had three and the API rejected the other two** | `14ce326` | `app/core/diagnostic_backends.py` |
| 32 | **`slow` would have been documented and permanently dead** — `trace_step` measures nothing unless a trace sink is live, and all three are off by default everywhere | `14ce326` | `app/core/tracing.py` |

---

## The shape underneath almost all of them

**Two things that must relate, with nothing enforcing it.** Retry window vs sweep interval (both
300). Pinned lease vs worst case (both 400). Config saying 3 attempts vs an actual 1. Producer keys
vs consumer keys. Documentation vs behaviour. Test premise vs the developer's machine.

That is why the fixes enforce the relationship at **boot** — three new validators — or through
**tests that grow themselves**, parametrised over the source of truth rather than a copied literal.
Issue 25 is the same lesson applied to a test that had itself become the stale copy.

---

## Deployment

**Schema first, before the code:**

```bash
sqlcmd -S <uat-host> -d <db> -i "scripts/tsg_script/TSG_Deploy_All.sql"
```

Re-runnable; every statement checks first. Post-deployment validation must report **24 tables,
319 columns, 36 indexes**.

**New settings**, all with safe defaults — none is required for boot:

| Setting | Default |
|---|---|
| `TSG_EMBEDDING_MAX_RETRIES`, `TSG_RERANKER_MAX_RETRIES` | follow `TSG_LLM_MAX_RETRIES` |
| `TSG_DIAGNOSTIC_DB_CATEGORIES` | `all` |
| `TSG_DIAGNOSTIC_PUBLIC_DETAIL` | `false` |
| `TSG_DIAGNOSTIC_RETENTION_DAYS` / `TSG_APPLICATION_LOG_RETENTION_DAYS` | 30 / 7 |
| `TSG_DIAGNOSTIC_QUEUE_MAX` | 10000 |
| `TSG_DIAGNOSTIC_SLOW_STEP_MS` | 5000 |
| `TSG_DIAGNOSTIC_BACKENDS_DISABLED` | *(empty)* |
| `TSG_INFRA_DEGRADED_THRESHOLD` / `_WINDOW_SECONDS` | 20 / 300 |

**The stage lease derives itself** from the retry budget, so the retry change cannot outrun it.
Verified against `.env`: worst case 360s, lease 720s. With a fallback model configured: 720s and
1440s. Boot refuses if a pinned lease is ever set at or below the floor.

**Read a failure afterwards:** `GET /v1/tsg/diagnostics?session_id=...` — no key required. Full
operator guide in [`DIAGNOSTICS_CONFIGURATION.md`](DIAGNOSTICS_CONFIGURATION.md).

---

## Open, not fixed

Stated so the list above is not read as complete.

- **UAT's own `TSG_LLM_*` values were never verified** against the running environment. The
  reconciliation was done against the repo's `.env` and `.env.uat`.
- **Celery `retry_jitter` was never confirmed** in this deployment. It defaults true; with every
  session retrying the same dead endpoint, unjittered retries arrive in lockstep.
- **Whether `6174F288` was a regeneration** is still unanswered. It decides whether issue 1 already
  cost threats on 29 Sep, and is one query against the UAT database.
- **No rate limiting** on the public diagnostics reads. Each request is bounded server-side by a
  time window and a row cap, but request volume is not throttled; that belongs at the gateway.
- **The post-cap limbo window**: when `AttemptCount` reaches `stage_max_attempts`, the session sits
  RUNNING until the reaper's lease sweep rather than settling immediately.
