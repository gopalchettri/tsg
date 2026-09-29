# TSG End-to-End API Testing Guide

**What this is.** One document that takes you from a brand-new environment to a finished, reviewed
remediation plan — in the order the application actually works, with nothing left to guess.

**Who it is for.** Developers, QA/test engineers, integration engineers, support engineers, and
anyone non-technical who needs to run or understand a test. Section 14 is written for readers who
do not want to read the rest.

**Source of truth.** The code in this repository. Every request, response and status code below was
either taken from the implementation or observed on a running stack. Where something could not be
confirmed, it says **"Not confirmed from implementation."** rather than guessing.

**Companion document.** [`API_Reference.md`](API_Reference.md) lists **all 62 routes**. This guide
covers only the ~18 on the main path, in depth.

---

## 0. Before you test — the order to run everything in

**Read this first.** The threat-scenario and remediation APIs do **not** fail on an unprepared
platform. They succeed and return **weak or empty results**: every threat marked "unverified",
scenarios with `controls: []`, remediation plans with no library controls. A green test run can
therefore still be wrong. Run the blocks below **in order**, once per environment.

The same numbers appear in **Swagger** (`/docs`). The groups are listed in this order, and every
API title starts with its step, for example **"2.1 · Import an open-source threat library"**.
Titles marked **As needed**, **Curation** or **Recovery** are not part of the first-time setup.

### 0.1 The blocks at a glance

| Order | Block | What it does | Why it must come here | If you skip it |
|---:|---|---|---|---|
| — | **Outside the API** | Database, seed data, `.env`, services (0.2) | Nothing works without tables, libraries and running workers | Boot fails, or silent empty results |
| 0 | **Health** | Is everything up? | Cheapest check first | — |
| 1 | **API Clients Admin** | Creates your `X-API-Key` | Every other call needs it | 401 on everything |
| 2 | **Threat Intel Admin** | Loads **content**: extra threats, ATT&CK/CAPEC techniques, live intel | Blocks 3 and 4 work on the library, so it must be complete first | Smaller library; no technique or intel references in scenarios |
| 3 | **Embeddings Admin** | Makes the "meaning fingerprints" of every threat, actor and control | Matching threats and controls uses these. It must see block 2's additions | First sessions slow; approved/imported threats not matched |
| 4 | **Grounding Admin** | Measures the "is this really a match?" cutoff for your models | It **samples the library and uses the fingerprints**, so it must run **last** | A generic cutoff is used — the `TSG_GROUNDING_MATCH_THRESHOLD` default, 75.0 today, tuned for different models |
| 6 | **Threat Scenario Generation** | Run → review → **accept** scenarios | Remediation only works on accepted scenarios | — |
| 7 | **Scenarios** | Read scenarios across sessions | Only has data after block 6 | Empty lists |
| 8 | **Remediation Plans** | Build, read and approve plans | Needs accepted scenarios (6) with mapped controls | 409 `scenario_not_accepted` |
| 5 | **Control Mapping Admin** | Recovery only | Use it if accepted scenarios show `controls: []` | — |

> **Why not Grounding first?** Calibration looks at library entries and their fingerprints. Run
> before blocks 2 and 3 and it measures an incomplete library, then you pay for it again
> (about 10-15 minutes and ~100 AI calls).

### 0.2 Outside the API (DBA, platform team, ops)

| # | Task | Why | If skipped |
|---:|---|---|---|
| a | Platform tables filled: assets, owners, sectors, supporting systems, `option`/`option_value` (platform team) | TSG looks up the asset you are modelling there | `POST /v1/sessions` returns 403/404 |
| b | `scripts/tsg_script/TSG_Deploy_All.sql` ends with `FINAL SIGN-OFF` | Creates and repairs every TSG table | App will not start |
| c | Seed `3. Seed_to_Threat_library.sql` and `5. Seed_to_Control_library.sql` (expected: 6 categories, 27 types, 75 threats; 30 standards, 1288 controls) | The threat library is what threats are matched against; the control library is what gets recommended | **Silent:** unverified threats, `controls: []`, plans without library controls |
| d | `.env`: `TSG_ADMIN_API_KEY`, `TSG_RISK_MODULE_ENABLED=true`, model endpoints | Admin routes need the key; remediation routes only exist when the risk module is on | 401 on admin routes; 404 on remediation |
| e | Start the API, **worker `-Q celery`**, **worker `-Q admin`** and beat (`run.ps1`) | Blocks 2, 3 and 4 run **only** on the admin worker | Admin jobs wait forever, while `/ready` still says 200 |

### 0.3 Each block, and each API inside it, in order

Headers used below. **Admin** = `X-Admin-Key` + `X-API-Key` + `X-User-Id`. Block 1 needs only
`X-Admin-Key` + `X-User-Id`.

```bash
ADMIN="<TSG_ADMIN_API_KEY>"; KEY="<secret from 1.1>"; USER="1138"; BASE="http://localhost:8000"
```

**Block 0 — Health** (no login)

| Step | API | Why |
|---|---|---|
| 0.1 | `GET /health` | The process is alive |
| 0.2 | `GET /ready` | Database, cache and broker are reachable. **It does not check that any data is loaded** |

**Block 1 — API Clients Admin**

| Step | API | Why |
|---|---|---|
| 1.1 | `POST /v1/tsg/api-clients` | Creates the key. **The secret is shown once** — save it as `KEY` |
| 1.2 | `GET /v1/tsg/api-clients` | Confirms the key is listed and active |
| As needed | `POST /v1/tsg/api-clients/{client_id}/revoke` | Retire a key |

```bash
curl -s -X POST "$BASE/v1/tsg/api-clients" -H "X-Admin-Key: $ADMIN" -H "X-User-Id: $USER" \
  -H "Content-Type: application/json" -d '{"client_id":"qa-smoke","name":"QA smoke","module":"tsg"}'
```

**Block 2 — Threat Intel Admin** (content first)

| Step | API | Why | Optional? |
|---|---|---|---|
| 2.1 | `POST /v1/tsg/threat-intel/library/import/{source}` — one per source: `pytm`, `emb3d`, `atlas`, `misp_actors` | Adds threats from public libraries to the seeded ones. Needs step 0.2c's categories. Queues an embeddings update by itself | Optional |
| 2.2 | `GET /v1/tsg/threat-intel/library/import/status/{job_id}` | Wait until the import says it finished | With 2.1 |
| 2.3 | `POST /v1/tsg/threat-intel/techniques/rebuild` | Loads MITRE ATT&CK / ATT&CK-ICS / CAPEC so scenarios can cite real attack techniques | Recommended |
| 2.4 | `GET /v1/tsg/threat-intel/techniques` | Wait for `warm: true`. Until then, no technique references are used | With 2.3 |
| 2.5 | `POST /v1/tsg/threat-intel/feeds/refresh` | Loads recent real-world intel (e.g. CISA KEV) that scenario prompts can cite | Recommended |
| 2.6 | `GET /v1/tsg/threat-intel/feeds` | Each feed reports healthy | With 2.5 |
| 2.7 | `GET /v1/tsg/threat-intel/items` | Intel items are actually cached | With 2.5 |

```bash
curl -s -X POST "$BASE/v1/tsg/threat-intel/library/import/pytm" -H "X-Admin-Key: $ADMIN" -H "X-API-Key: $KEY" \
  -H "X-User-Id: $USER" -H "Content-Type: application/json" -d '{"dry_run":false,"activate":true}'
curl -s -X POST "$BASE/v1/tsg/threat-intel/techniques/rebuild" -H "X-Admin-Key: $ADMIN" -H "X-API-Key: $KEY" \
  -H "X-User-Id: $USER" -H "Content-Type: application/json" -d '{"sources":["attack","attack_ics","capec"]}'
curl -s -X POST "$BASE/v1/tsg/threat-intel/feeds/refresh" -H "X-Admin-Key: $ADMIN" -H "X-API-Key: $KEY" -H "X-User-Id: $USER"
```

**Block 3 — Embeddings Admin** (fingerprint the final library)

| Step | API | Why |
|---|---|---|
| 3.1 | `POST /v1/tsg/threat-library/embeddings/update` with `{}` | Fills in fingerprints for every threat type, threat, actor and control that has none. Safe to repeat |
| 3.2 | `GET /v1/tsg/threat-library/embeddings/status/{job_id}` | Wait until it finishes |
| As needed | `/create` (named items), `/recreate` (after changing the embedding model), `/delete` | Not part of first-time setup. `{}` on `recreate` means **every group** — slow and billed, but it rebuilds what it removes. `{}` on `delete` is **refused** (422 `admin_validation_error`); `/create` needs both `group` and `names` |

```bash
curl -s -X POST "$BASE/v1/tsg/threat-library/embeddings/update" -H "X-Admin-Key: $ADMIN" -H "X-API-Key: $KEY" \
  -H "X-User-Id: $USER" -H "Content-Type: application/json" -d '{}'
```

**Block 4 — Grounding Admin** (last)

| Step | API | Why |
|---|---|---|
| 4.1 | `GET /v1/tsg/grounding/threshold` | See the current cutoff and where it came from (`origin`) |
| 4.2 | `POST /v1/tsg/grounding/calibrate` with `{}` | Measures the cutoff for your models. About 10-15 minutes. If this model pair is already calibrated it is skipped; `{"force":true}` re-measures |
| 4.3 | `GET /v1/tsg/grounding/calibrate/status/{job_id}` | Wait until it finishes |
| 4.4 | `GET /v1/tsg/grounding/threshold` again | `origin` should now be `calibrated` |
| 4.5 | `GET /v1/tsg/grounding/calibrations` | History of every calibration |
| 4.6 | `POST /v1/tsg/control-map/calibrate` | Measures a **second, separate** cutoff: the score a control must reach to be attached to a scenario. 4.2 measured threats against short labels; this measures a scenario paragraph against control text, which scores on a different scale. Minutes of reranking; `limit` (default 50) bounds the sample |
| 4.7 | `GET /v1/tsg/control-map/calibrate/status/{job_id}` | Wait until `state` stops being `STARTED`, then read `cutoff`. **The measurement is stored and control mapping applies it by itself, from the next mapping pass** — a stored cutoff out-votes `TSG_CONTROL_MAP_MIN_SCORE` (§7.3 lists the three sources in order), so do **not** edit or comment out that line to make this take effect; it is the bootstrap that answers only until a measurement exists. Confirm with `cutoff_origin`: `calibrated_for_control_mapping` means this run is what runs. `SUCCESS` with `cutoff: null` is a real answer: retrieval found nothing, so nothing was stored and the previous cutoff still stands |

```bash
curl -s -X POST "$BASE/v1/tsg/grounding/calibrate" -H "X-Admin-Key: $ADMIN" -H "X-API-Key: $KEY" \
  -H "X-User-Id: $USER" -H "Content-Type: application/json" -d '{}'
```

**Block 6 — Threat Scenario Generation** (business headers: `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id`)

| Step | API | Why | Details |
|---|---|---|---|
| 6.1 | `POST /v1/sessions` | Starts the AI run for one asset | §7.1 |
| 6.2 | `GET /v1/sessions/{id}/events` (live) **or** poll `GET /v1/sessions/{id}` | Wait until it reaches review (several minutes) | §7.2 |
| 6.3 | `GET /v1/sessions/{id}/results` | Read the generated scenarios | §7.3 |
| 6.4 | *Optional:* `POST …/regenerate/scenarios`, `POST …/scenarios/next-set`, `POST …/scenarios/reject` | Rewrite, add more, or decline scenarios before accepting | — |
| 6.5 | `POST /v1/sessions/{id}/accept` | **Remediation only works on accepted scenarios** | §7.4 |
| 6.6 | `GET /v1/sessions/{id}/accepted-scenarios` | Confirm what was accepted | — |
| 6.7 | *Optional:* `POST …/scenarios/{scenario_id}/promote-to-library` | Proposes a new threat for the library → then **Curation** below | — |
| As needed | `…/unaccept`, `…/cancel`, `GET …/audit` | Undo, stop, or read history | — |

**Block 7 — Scenarios** (read-only, after block 6)

| Step | API | Why |
|---|---|---|
| 7.1 | `GET /v1/sessions/{id}/scenarios/{scenario_id}` | One scenario in full |
| 7.2 | `GET /v1/users/{user_id}/scenarios` | Everything one user created |
| 7.3 | `GET /v1/entities/{entity_id}/scenarios` | Everything under one entity |

**Block 8 — Remediation Plans** (after block 6 has accepted scenarios)

| Step | API | Why | Details |
|---|---|---|---|
| 8.1 | `POST …/scenarios/{scenario_id}/treatment-plan` **or** `POST /v1/remediation-plans` (any scenario, or a hand-written one with `is_manual=true`) | Starts writing the plan from the scenario's mapped controls | §8 |
| 8.2 | `GET …/treatment-plan/status` | Wait until it reaches `awaiting_review` | §9.1 |
| 8.3 | `GET …/treatment-plan` | Read the plan | §9.2 |
| 8.4 | `GET …/treatment-plan/evidence?plan_id=…` | Exactly what the AI was given | §9.3 |
| 8.5 | `POST …/treatment-plan/review` | Approve or decline | §10.1 |
| 8.6 | *Optional:* `POST …/treatment-plan/regenerate` | Rewrite the plan (then back to 8.2) | — |
| 8.7 | `GET /v1/sessions/{id}/treatment-plans`, `GET /v1/entities/{entity_id}/treatment-plans` | The plan registers | §10.2 |
| 8.8 | `GET …/treatment-plan/audit`, `GET /v1/entities/{entity_id}/treatment-plans/audit` | Plan history | — |
| As needed | `POST …/treatment-plan/cancel` | Stop a plan being written | — |

> In Swagger, 8.3 is listed directly under 8.1 because they share one address (POST to request,
> GET to read). Run it after 8.2 as shown here.

**Ongoing — Curation** (after step 6.7 or a manual plan proposed new threat names)

| Step | API | Why |
|---|---|---|
| Curation 1 | `GET /v1/tsg/threat-intel/library/pending` | See the proposed threats |
| Curation 2 | `POST /v1/tsg/threat-intel/library/threats/approve` (or `/reject`) | Add them to the library, or discard them |
| then | **3.1 again** | Approving does not fingerprint the new threats. Until 3.1 runs they are never matched |

**Recovery — Control Mapping Admin**

| Step | API | When |
|---|---|---|
| Recovery | `POST /v1/tsg/control-map/sweep` | Accepted scenarios show `controls: []` (e.g. after an outage). Beat also runs it on a schedule |

**Full order:** outside-the-API → **0 → 1 → 2 → 3 → 4 → 6 → 7 → 8**, with Curation and Recovery
only when needed.

---

## 1. The complete flow

```
PHASE 0   OUTSIDE THE API  -- database, seed data, asset records      (SQL + platform team)
                |
PHASE 1   READINESS        -- GET /health . GET /ready                (no login needed)
                |
PHASE 2   CREDENTIALS      -- POST /v1/tsg/api-clients                (admin key -> API key)
                |
PHASE 3   ONE-TIME CONFIG  -- embeddings . grounding threshold        (admin key)
                |
        +-------+----------------------------------------+
        |                                                |
PHASE 4a  AI PATH                                  PHASE 4b  MANUAL PATH
  POST /v1/sessions                                  POST /v1/remediation-plans
  poll  GET /v1/sessions/{id}                          is_manual = true
  GET   .../results                                    (TSG creates the session AND
  POST  .../accept                                      the scenario for you)
  POST  /v1/remediation-plans
        is_manual = false
        |                                                |
        +-------+----------------------------------------+
                |   both paths now hold the same three ids
PHASE 5   THE PLAN   -- poll .../treatment-plan/status -> GET .../treatment-plan -> .../evidence
                |
PHASE 6   FINISH     -- POST .../treatment-plan/review . entity register . unaccept + reject
```

**The important idea:** the AI path and the hand-written path join at Phase 5. From there they use
the *same* endpoints. One door, two kinds of scenario.

---

## 2. Execution sequence table

| Step | Phase | API | Method | Endpoint | Purpose | Prerequisite | Output used by |
|---:|---|---|---|---|---|---|---|
| 0 | Setup | *(no API)* | — | SQL scripts | Create tables + seed the threat and control libraries | Database access | Everything |
| 0b | Setup | *(no API)* | — | Platform tables | Asset, entity and supporting-system records | Platform team | Steps 5, 9M |
| 1 | Readiness | Health | GET | `/health` | Is the API process alive? | Step 0 | — |
| 2 | Readiness | Ready | GET | `/ready` | Are DB, Redis and Mongo up? Workers are reported but never fail it, and **no data is checked** | Step 1 | — |
| 3 | Credentials | Create API client | POST | `/v1/tsg/api-clients` | Mint the `X-API-Key` every later call needs | Admin key | Steps 5-18 |
| 4 | Config | Embeddings update | POST | `/v1/tsg/threat-library/embeddings/update` | Vectorise library rows inserted by SQL (Swagger 3.1) | Step 0 | Steps 4b, 5 quality |
| 4b | Config | Grounding threshold / calibrate | GET / POST | `/v1/tsg/grounding/threshold`, `/calibrate` | Check / measure the match cutoff — **after** embeddings (Swagger 4.1-4.4) | Step 4 | Step 5 quality |
| 5 | Business (AI) | Create session | POST | `/v1/sessions` | Start an AI threat-scenario run | Steps 0b, 3 | Steps 6-9 |
| 6 | Processing | Session board | GET | `/v1/sessions/{session_id}` | Poll until the run reaches review | Step 5 | Step 7 |
| 7 | Result | Results | GET | `/v1/sessions/{session_id}/results` | Read the generated scenarios | Step 6 | Step 8 |
| 8 | Business | Accept | POST | `/v1/sessions/{session_id}/accept` | Keep the scenarios you want | Step 7 | Step 9 |
| 9 | Business | Remediation plan (AI) | POST | `/v1/remediation-plans` | Ask for a plan, `is_manual=false` | Step 8 | Steps 11-15 |
| 9M | Business | Remediation plan (manual) | POST | `/v1/remediation-plans` | Save a hand-written scenario **and** plan it, `is_manual=true` | Steps 0b, 3 | Steps 11-15 |
| 11 | Processing | Plan status | GET | `.../treatment-plan/status` | Poll until the AI finishes writing | Step 9 or 9M | Step 12 |
| 12 | Result | Get plan | GET | `.../treatment-plan` | Read the finished plan | Step 11 | Step 13 |
| 13 | Result | Evidence | GET | `.../treatment-plan/evidence` | Proof of exactly what the AI was given | Step 12 | Audit |
| 14 | Finalisation | Review | POST | `.../treatment-plan/review` | Approve or decline the plan | Step 12 | Step 15 |
| 15 | Result | Entity register | GET | `/v1/entities/{entity_id}/treatment-plans` | The GRC page: all plans for an entity | Step 14 | Reporting |
| 16 | Curation | Pending library | GET | `/v1/tsg/threat-intel/library/pending` | Review names a manual scenario proposed | Step 9M | Step 17 |
| 17 | Curation | Approve / reject | POST | `.../library/threats/approve` or `/reject` | Accept or refuse those names | Step 16 | Future saves |
| 18 | Cleanup | Unaccept + reject | POST | `.../unaccept`, `.../scenarios/reject` | Remove a test scenario from the register | Step 14 | — |

Steps 5-8 are the **AI path only**. Step 9M replaces steps 5-9 entirely for a hand-written scenario.

---

## 3. Environment and platform setup

### 3.1 Required before ANY testing

| Item | How it is provided | Notes |
|---|---|---|
| SQL Server database | DBA | `ALTER DATABASE <db> SET READ_COMMITTED_SNAPSHOT ON;` is mandatory (`SETUP_AND_RUN_GUIDE.md`) |
| TSG tables + libraries | SQL scripts, in order (3.2) | No Alembic. Re-running `1. TSG_Core.sql` **is** the migration |
| Asset / entity records | **Platform team** | TSG only reads these — see 3.3 |
| Redis | Infrastructure | Celery broker + results |
| MongoDB | Infrastructure | Stores embeddings, the threat-intel cache and the ATT&CK/CAPEC technique corpus |
| Celery workers | `start.ps1` | **Two** are needed: default queue (`-Q celery`) and admin (`-Q admin`) |
| Celery beat | `start.ps1` | Runs the reaper, self-check and control-map sweep |
| LLM + embedding + reranker | litellm endpoint / local models | `.env` |
| `TSG_ADMIN_API_KEY` | `.env` | **If blank, all 31 admin routes return 401 by design** |
| `TSG_RISK_MODULE_ENABLED=true` | `.env` | **If false, all 12 remediation-plan routes do not exist (404)** |

### 3.2 Database scripts — run in this order

From `scripts/eyshield_handoff/`:

| Order | File | Creates |
|---:|---|---|
| 0 | `0. TSG_Preflight.sql` | Read-only check. Any FAIL = stop |
| 1 | `1. TSG_Core.sql` | TSG's own 13 tables |
| 2 | `2. Threat_library.sql` | Threat category / type / catalogue / actor tables |
| 3 | `3. Seed_to_Threat_library.sql` | The curated threat library **data** |
| 4 | `4. Control_library.sql` | Control Library tables + the scenario-to-control map |
| 5 | `5. Seed_to_Control_library.sql` | 30 standards, 1288 controls, 6105 links |
| 6 | `6. TSG_Verify.sql` | Read-only proof the install worked |

> **Never run `scripts/TSG_Core_Drop.sql` against UAT or production.** It drops the 13 core tables
> including `API_Client`, and the app will not boot until a client row is re-inserted.

### 3.3 The one thing you cannot do through the API

**TSG cannot create assets.** These four tables belong to the platform, are read-only to TSG, and
are written by neither a TSG script nor a TSG endpoint:

```
ctm_scan_entity                       the asset itself
ctm_scan_entity_bu                    links asset -> entity   (group_id IS the entity id)
ctm_scan_entity_supporting_system     links asset -> its supporting systems
onboarding_supporting_systems         the supporting systems
```

**This step is performed outside the API layer.** Ask the platform team, or read the ids out of the
platform database. You need: `entity_id`, an `asset_id` that entity owns, and its
`supporting_system_id` list. Without rows here, step 5 cannot resolve an asset and returns **403**.

If data already exists, `GET /v1/users/{user_id}/scenarios` is a useful way to discover usable ids
from past runs.

### 3.4 Sample data used throughout this guide

| Field | Value |
|---|---|
| Base URL | `http://localhost:8000` |
| `entity_id` | `78` |
| `asset_id` | `99` |
| `supporting_system_id` | `[306, 307, 308]` |
| `subsector_id` | `110` |
| Threat category / type / threat | `Tampering` / `Malware/Ransomware` / `Ransomware on OT support systems` |
| Control codes | `CII-CID-213, 242, 377, 369, 210, 195, 533, 017, 019, 311` |

Every example below uses these same values.

### 3.5 Authentication — exactly which headers

| Route group | Headers required |
|---|---|
| 28 business routes | `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id` |
| 28 admin routes (`admin.py`, `threat_intel.py`) | `X-Admin-Key`, `X-API-Key`, `X-User-Id` (`X-Tenant-Id` optional) |
| 3 api-client routes | `X-Admin-Key` only (+ `X-User-Id` on create/revoke) |
| `/health`, `/ready` | none |

A missing or wrong header returns **401** with the same opaque message, on purpose — it never tells
an attacker which part was wrong.

> **Security note.** `X-API-Key` is the credential. `X-User-Id` and `X-Entity-Id` are *input* that
> the calling service is trusted to populate. One key therefore reaches every entity, so keys are
> **server-side only** — never ship one to a browser or mobile app.

---

## 4. STEP 1-2 — Readiness

### 4.1 API information

| | |
|---|---|
| Step | 1 and 2 |
| Phase | Readiness |
| Type | **Retrieval** |
| Method / Endpoint | `GET /health`, `GET /ready` |
| Auth | None |
| Previous | Phase 0 (SQL) |
| Next | Step 3 |

### 4.2 Why this API is needed

`/health` says the web process is alive. `/ready` says its dependencies are, and it is the only call
that **reports** on both Celery workers — per queue, in `checks.workers_celery` and
`checks.workers_admin`. It does not enforce them: the worker check is advisory and is excluded from
the failing set, so `/ready` answers **200 with no workers at all**. Read those two keys yourself.
Without the default-queue worker, plans are queued and never written, and nothing in the status code
will tell you.

### 4.3 Prerequisites

| Prerequisite | Created by | Required? |
|---|---|---|
| API running | `start.ps1` | Yes |
| Database, Redis, Mongo | Infrastructure | Yes for `/ready` — any one unreachable is a 503 |
| Celery workers | `start.ps1` | **Reported, never enforced.** `/ready` is 200 without them — read `checks.workers_celery` and `checks.workers_admin`. Required for any job to actually run |

### 4.4 Request

```bash
curl -s http://localhost:8000/health
curl -s http://localhost:8000/ready
```

No body, no parameters.

### 4.5 Response

```json
{"status":"ready",
 "checks":{"database":"ok","redis":"ok","mongo":"ok",
           "workers":"ok","workers_celery":"ok","workers_admin":"ok"}}
```

| Parameter | Type | Always present | Example | Description |
|---|---|---|---|---|
| `status` | string | Yes | `ready` | Overall verdict |
| `checks.database` | string | Yes | `ok` | SQL Server reachable |
| `checks.redis` | string | Yes | `ok` | Broker reachable |
| `checks.mongo` | string | Yes | `ok` | Vector store reachable |
| `checks.workers_celery` | string | Yes | `ok` | **Default-queue worker present** |
| `checks.workers_admin` | string | Yes | `ok` | Admin-queue worker present |

### 4.6 Errors

| Status | Cause | Tester action |
|---|---|---|
| Connection refused | API not running | Start it |
| 503 | A dependency is down | Read which `checks` entry is not `ok` |

### 4.7 Test cases

| ID | Scenario | Expected |
|---|---|---|
| H-1 | API up | `/health` returns 200 |
| H-2 | All dependencies up | `/ready` returns 200, every check `ok` |
| H-3 | Stop the default worker | `workers_celery` is not `ok` — and `/ready` still returns **200** with `status: ready`. That is correct, not a probe bug: the worker check is advisory, so a 503 here would evict a pod that can still serve every synchronous route |

---

## 5. STEP 3 — Create an API client  *(Prerequisite API)*

### 5.1 API information

| | |
|---|---|
| Step | 3 |
| Phase | Credentials |
| Type | **Configuration** — one-time per consumer |
| Method / Endpoint | `POST /v1/tsg/api-clients` |
| Auth | `X-Admin-Key` + `X-User-Id` |
| Previous | Step 2 |
| Next | Step 4 |

### 5.2 Why this API is needed

Every business route needs `X-API-Key`. This is the only endpoint that creates one. It deliberately
does **not** require an existing API key — you cannot be asked for a key in order to get a key.

### 5.3 Prerequisites

| Prerequisite | Created by | Required? |
|---|---|---|
| `TSG_ADMIN_API_KEY` configured | `.env` | Yes — blank always denies |
| `API_Client` table | `1. TSG_Core.sql` | Yes |

### 5.4 Request

```json
{ "client_id": "qa-smoke", "name": "QA smoke", "module": "tsg" }
```

| Parameter | Type | Required | Nullable | Example | Description |
|---|---|---|---|---|---|
| `client_id` | string (1-100) | Yes | No | `qa-smoke` | Your id for this key. Must be unique (a duplicate is 409) |
| `name` | string (1-200) | Yes | No | `QA smoke` | Label shown in the client list |
| `module` | string (1-50) | Yes | No | `tsg` | The key authenticates only for this module |

```bash
curl -s -X POST http://localhost:8000/v1/tsg/api-clients \
  -H "X-Admin-Key: <admin key>" \
  -H "X-User-Id: 1138" \
  -H "Content-Type: application/json" \
  -d '{"client_id":"qa-smoke","name":"QA smoke","module":"tsg"}'
```

### 5.5 Internal processing

1. `X-Admin-Key` is compared in constant time. A blank configured key always denies.
2. A 64-character secret is generated server-side.
3. Only the **SHA-256 hash** is stored — the plain secret is never written to the database.
4. The row is inserted into `API_Client`.
5. The secret is returned **once**.

### 5.6 Database

This API does not execute hand-written SQL. Data is accessed through SQLAlchemy.

| Table | Operation | Purpose |
|---|---|---|
| `API_Client` | INSERT | Stores name, module, key hash, created-by |

### 5.7 Response

```json
{ "client_id": "qa-smoke", "module": "tsg", "secret": "a6748c88..." }
```

| Parameter | Type | Always present | Description |
|---|---|---|---|
| `client_id` | string | Yes | Use it to revoke later |
| `secret` | string | **Only on create** | The `X-API-Key` value |

**Important output for the next API:**

```
secret    -> X-API-Key header on steps 5-18
client_id -> POST /v1/tsg/api-clients/{client_id}/revoke
```

> **Save the secret now.** It is never shown again. Lost it? Create a new client and revoke the old.

### 5.8 Errors

| Status | Cause | Tester action |
|---|---|---|
| 401 | Missing/wrong `X-Admin-Key`, or the key is not configured | Check `.env` |
| 400 | `X-User-Id` blank | Add the header |
| 409 | `client_id` already exists | Pick another `client_id` |
| 422 | Missing `client_id`, `name` or `module` | Fix the body |

### 5.9 Test cases

| ID | Scenario | Expected |
|---|---|---|
| C-1 | Valid create | 201 with `secret` |
| C-2 | No admin key | 401 |
| C-3 | Blank `X-User-Id` | 400 |
| C-4 | Use the secret on `/v1/sessions` | Accepted |
| C-5 | Revoke, then reuse the key | 401 |

---

## 6. STEP 4 — Configuration checks *(Configuration APIs)*

These are **one-time per environment**, not per test. The full block order (Threat Intel →
Embeddings → Grounding) and the reasons are in **§0**. Run 6.1 before 6.2.

### 6.1 Embeddings — `POST /v1/tsg/threat-library/embeddings/update` *(Swagger 3.1)*

Because the library was loaded by SQL, its rows have no vectors yet. `update` fills only what is
missing and is safe to repeat. Run it **before** calibration: calibration uses these vectors.

> **Warning — the two routes differ.** `recreate` with an empty body `{}` targets **every group**:
> it deletes and re-embeds the whole cross-tenant cache, which is slow and costs real AI calls.
> Nothing refuses it, so always name a `group`. `delete` with `{}` is **refused** — 422
> `admin_validation_error`, "delete requires group and/or names — refusing to wipe the entire cache
> with an empty request" — because `delete` does not rebuild and so cannot self-heal. On both routes,
> `names` without a `group` is refused too.

### 6.2 Grounding threshold — `GET /v1/tsg/grounding/threshold` *(Swagger 4.1)*

Tells you how confidently TSG matches an AI-proposed threat to a library entry.

```bash
curl -s http://localhost:8000/v1/tsg/grounding/threshold \
  -H "X-Admin-Key: <admin key>" -H "X-API-Key: <api key>" -H "X-User-Id: 1138"
```

| `origin` value | Meaning | Action |
|---|---|---|
| `calibrated` | Measured for the models in use | Nothing |
| `env_pinned` | Set by `TSG_GROUNDING_MATCH_THRESHOLD`, because no successful calibration exists for these models yet | A calibration, once it succeeds, takes precedence over this value |
| `static_default` | The built-in value, tuned for **different** models | Calibrate (6.3) |

### 6.3 Calibrate — `POST /v1/tsg/grounding/calibrate` *(Swagger 4.2)*

Expensive. Returns `202` with `job_id` and `run_id`; poll
`GET /v1/tsg/grounding/calibrate/status/{job_id}` (Swagger 4.3), then read the threshold again
(Swagger 4.4): `origin` should be `calibrated`.

> **Warning.** `force: true` runs roughly 10-15 minutes of billed LLM calls and overwrites the live
> threshold with no undo. Leave `force` out unless you mean it.

### 6.4 If configuration is missing

| Missing | Effect |
|---|---|
| Embeddings | Library matching is weak; threats appear `unverified` more often |
| Calibration | A default threshold is used and the worker logs a warning at boot |
| `TSG_ADMIN_API_KEY` | Every admin route returns 401 |
| `TSG_RISK_MODULE_ENABLED` | All remediation-plan routes return 404 |

---

## 7. STEP 5-8 — The AI path

### 7.1 Step 5 — `POST /v1/sessions`  *(Business)*

**Why:** starts the AI run that identifies threats and writes scenarios for one asset.

**Prerequisites**

| Prerequisite | Created by | Required? |
|---|---|---|
| API key | Step 3 | Yes |
| Asset + entity rows | Platform team (3.3) | Yes |
| No other active session for the asset | — | Yes — one run per asset |

**Request**

```json
{ "entity_id": "78", "asset_id": 99, "supporting_system_id": [306, 307, 308] }
```

| Parameter | Type | Required | Nullable | Example | Description |
|---|---|---|---|---|---|
| `entity_id` | string | Yes | No | `"78"` | Must match `X-Entity-Id` |
| `asset_id` | integer | Yes | No | `99` | Must be owned by that entity |
| `supporting_system_id` | array of integer | Yes | No | `[306,307,308]` | Systems in scope |
| `subsector_id` | integer | No | Yes | `110` | Send the **child**, not `sector_id` |

```bash
curl -s -X POST http://localhost:8000/v1/sessions \
  -H "X-API-Key: <api key>" -H "X-User-Id: 1138" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC" \
  -H "Idempotency-Key: run-001" -H "Content-Type: application/json" \
  -d '{"entity_id":"78","asset_id":99,"supporting_system_id":[306,307,308]}'
```

**Response (202)**

```json
{ "session_id": "bc345a7d-2e3c-82a5-88cc-01a0ce0e866b", "user_id": "1138" }
```

**Important output for the next API:** `session_id -> steps 6, 7, 8, 9`

**Errors**

| Status | Cause | Action |
|---|---|---|
| 401 | Bad or missing headers | Check 3.5 |
| 403 | Asset not owned by that entity | Confirm with the platform team |
| 409 `active_session_exists` | A run is already going for this asset | Wait or cancel |
| 409 `idempotency_key_conflict` | Key reused with a different body | Use a new key |
| 503 | Broker down | Check `/ready` |

### 7.2 Step 6 — `GET /v1/sessions/{session_id}`  *(Processing / poll)*

Poll every 5-10 seconds until `progress.overall` is `awaiting_review`.

| `progress.overall` | Meaning |
|---|---|
| `in_progress` | Still working |
| `awaiting_review` | Scenarios ready for you |
| `complete` | Decisions already made |
| `error` | Read `progress.error_message` |

A live run observed: `THREAT_IDENTIFICATION` for about 4 minutes, then `SCENARIO_GENERATION`,
reaching `awaiting_review` in roughly 8 minutes total.

**Alternative:** stream `GET /v1/sessions/{session_id}/events` instead of polling. See
`docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md`.

### 7.3 Step 7 — `GET /v1/sessions/{session_id}/results`  *(Result)*

Returns the generated scenario cards.

| Field | Type | Meaning |
|---|---|---|
| `scenarios[].scenario_id` | string | **Needed for accept and for the plan** |
| `scenarios[].scenario_source` | string | `generated` (AI) or `manual` (a person) |
| `scenarios[].threat.score` | number or null | Relevance score — `null` for hand-written threats |
| `scenarios[].controls[]` | array | Controls matched from the Control Library, in `map_rank` order (see below — that is not the same as score order) |
| `scenarios[].controls_mapped` | boolean | `false` = mapping has not been attempted yet, so an empty list means nothing about the library |
| `scenarios[].controls_unavailable` | boolean | `true` = this response could not read the mapping. Retry; do not read the empty list as a library gap |
| `scenarios[].controls_mapping_exhausted` | boolean | `true` = this scenario used up its mapping attempts. Permanent — only a regenerate gets a fresh attempt, so read the sibling field below before you spend one |
| `scenarios[].controls_mapping_exhaustion_reason` | string or null | **Why** the flag is set — `null` unless it is. Switch on this, not on English text. The values are the members of `ControlMappingExhaustionReason` (`app/core/enums.py`), which today defines exactly one: `retry_budget_exhausted` — the mapping attempts ran out with no `ControlsMappedAt` stamp. More members may be added to distinguish causes without a wire break, so read the enum rather than assuming the single value |
| `scenarios[].library` | object or null | What a hand-written scenario did to the library; `null` for AI |

**Important output:** `scenario_id -> steps 8, 9`

**What each control now carries.** Read one entry of `controls[]`:

```json
{
  "control_id": 201,
  "control_code": "CII-CID-201",
  "itot": "OT",
  "domain": "Identification & Authentication",
  "control_name": "Multi-Factor Authentication",
  "control_description": "Require a second authentication factor for all remote and privileged access to control-system assets.",
  "map_rank": 1,
  "score": 93.0,
  "mapping_relevance": 93.0,
  "standards": [{ "standard_id": 3, "standard_name": "NIST SP 800-53 Rev. 5" }]
}
```

| Field | New? | What to check |
|---|---|---|
| `control_code`, `control_name` | No | A real Control Library code. The AI never invents one |
| `itot` | **New** | `IT` or `OT`, the library's own label. There is no "both" value in the library, so treat it as context, not as proof a control does not apply |
| `domain` | No | One of the 97 domains in the library. Every control has one |
| `control_description` | **New** | What the control does, in the library's words. This is what the plan's AI reads to judge whether the risk is already covered |
| `map_rank` | No | `1` on the first entry and rising by one in the order returned. It reflects the **composite** order in "IT/OT and domain" below — IT/OT compatibility, then score, then domain — so do **not** expect it to track the score. A gap in the run means a mapped control has since been retired from the library |
| `score` | No | 0-100, **or `null`** — `null` only for controls a **person chose** (never scored), and for rows mapped before scoring existed. Controls TSG mapped carry the scorer's number even on a hand-written scenario, so `null` is the mark of a person's own pick and not of a manual scenario. A number below the cutoff means the entry was a backfill or a top-up (see below) |
| `mapping_relevance` | **New** | Always the **same value** as `score`, `null` included. Both are published on purpose — `score` stays for clients that already read it. If they ever differ, raise it |

**How many controls to expect.** The Control Library holds **1288 active controls**: 731 labelled
`IT` and 557 `OT`. Mapping runs in two rounds — a fast search shortlists
`TSG_CONTROL_MAP_SHORTLIST_K` controls, then an accurate scorer scores only those, 0-100. A control
that is not shortlisted is never scored and can never appear here.

| Setting | Value here | Meaning for what you see |
|---|---|---|
| `TSG_CONTROL_MAP_SHORTLIST_K` | 60 | 60 of the 1288 controls are scored per scenario. It used to be 20, about 1.6% of the library, and that was the single biggest cause of thin control lists |
| `TSG_CONTROL_MAP_MIN_SCORE` | 50, and set | The relevance cutoff — but only **one of three** ways it resolves, and no longer the first (next table). A stored control-map measurement for the models in use wins over it; this line is the bootstrap, in force here only because no such measurement exists yet. With neither, the cutoff is the borrowed threat-grounding threshold |
| `TSG_CONTROL_MAP_MIN_COUNT` | 5 (default) | A **minimum to aim for**, not a cap |
| `TSG_CONTROL_MAP_MAX_COUNT` | 25 (default) | A runaway guard. Nothing is padded up to it |
| `TSG_CONTROL_MAP_BACKFILL_RATIO` | 0.42 (default) | The backfill/top-up floor as a **fraction of the cutoff in force**, not an absolute. Nothing below `ratio × cutoff` may be added to reach the minimum. Here that is **0.42 × 50 = 21.0** |
| `TSG_CONTROL_MAP_BACKFILL_MIN_SCORE` | **unset** — commented out in `.env` and `.env.uat` | Deprecated absolute override. Honoured only if the name is present in the environment *and* the number is strictly below the cutoff in force; otherwise it is ignored with a `controls.backfill_floor_override_ignored` log line and the ratio is used. Its field default of 25.0 is **not** any deployment's floor |

**The cutoff resolves from three sources, in this order** (`control_mapping._min_score`), and every
`controls_mapped` audit entry names which one answered. **The order was INVERTED on 2026-09-25** by
the repo owner's decision — the database has the final say, the env file is what runs until the
database has an answer — because the env value is a guess written before anyone measured this
deployment, while the measurement is the answer got by scoring real scenarios against the real
control library. Do not re-order this table back:

| # | Source | Audit `effective_min_score_origin` |
|---|---|---|
| 1 | The newest successful control-map measurement stored for **this exact embedding + reranker pair** — what step 4.6 writes, and the only number ever measured for the question this stage asks, so it out-votes the env file. A measurement taken under different models is invisible; a stored `0.0` counts as measured, not missing | `calibrated_for_control_mapping` |
| 2 | `TSG_CONTROL_MAP_MIN_SCORE`, only while that name is present in the environment. The **bootstrap**: it is the branch in force in this deployment, at 50, only because no control-map measurement has been stored for the models in use yet, and it stops deciding the moment one is | `env_pinned` |
| 3 | The threat-grounding threshold, borrowed. It was measured label-against-label while this stage asks paragraph-against-control-text, so it is the wrong scale — relabelled precisely so you can see that in the audit | `borrowed_from_threat_grounding_uncalibrated` |

So step 4.6 is never inert: branch 1 picks the measurement up on the next mapping pass, with no
restart and with the env line exactly as it is. **Do not pin, edit or comment out
`TSG_CONTROL_MAP_MIN_SCORE` in order to apply a measurement** — that was the old instruction and it
is now backwards. What does still prevent pickup is a run that **stored nothing** (`SUCCESS` with a
null `cutoff`: retrieval faulted, so the previous cutoff stands) or a **change to either model**,
since branch 1 is keyed on the pair. To overrule a measurement, take another one for the same pair —
the newest wins — or clear `ControlMapTh` on the row that is winning and let branch 2 answer again.

**Read the two derived numbers back, never recompute them.** Both the cutoff and the floor it
resolved to are published on every `controls_mapped` audit entry, as `effective_min_score`,
`effective_min_score_origin` and `effective_backfill_min_score`. Use those when grading a run — they
are the only record of what was actually applied, and they move when the cutoff moves.

**What the application refuses at boot** (`Settings._validate_control_map_counts`,
`app/core/config.py`) is the count relationships only: the shortlist must be **at least** the ceiling
(`TSG_CONTROL_MAP_SHORTLIST_K` ≥ `TSG_CONTROL_MAP_MAX_COUNT`, 60 ≥ 25 here), and the minimum must be
**at or below** the ceiling (`TSG_CONTROL_MAP_MIN_COUNT` ≤ `TSG_CONTROL_MAP_MAX_COUNT`, 5 ≤ 25 here).
`TSG_CONTROL_MAP_TOP_K` used to make the second one easy to trip by accident, because it aliased the
**ceiling** — a name meaning "top 5" quietly supplying the 25-control cap. It is now **RETIRED** and
aliases nothing: an inherited `TSG_CONTROL_MAP_TOP_K=5` line **refuses the boot outright**, naming
`TSG_CONTROL_MAP_MAX_COUNT` as its replacement, rather than pinning the ceiling back to 5. Delete the
line and set the ceiling you want. The same applies to `TSG_REMEDIATION_CONTROL_MIN_COUNT`, which is
retired in favour of `TSG_CONTROL_MAP_MIN_COUNT` (`RETIRED_ENV_NAMES` in `app/core/config.py` holds
both, and the boot error names the replacement for each).

**The floor is not checked at boot, and a bad floor does not fail loudly.** That validator was
deleted on purpose — it could only ever compare against a *pinned* cutoff, which is one of the three
sources above, so it read like a guarantee while a stored measurement could move the cutoff under it.
What guarantees the band now is structural: the ratio is bounded `0 < r < 1`, so a fraction of any
positive cutoff is strictly below that cutoff. If you pin the deprecated absolute at or above the
cutoff in force, the application **boots green** and the floor silently reverts to the ratio. The only
signal is the log event `controls.backfill_floor_override_ignored` — look for it there, not in a boot
failure.

**Two mechanisms, two names — keep them apart.** This guide uses:

| Name | When it runs | Where it is described |
|---|---|---|
| **Backfill** | While a scenario is being mapped, to reach the minimum from controls already scored in the same pass | Here, and the setting `TSG_CONTROL_MAP_BACKFILL_RATIO` |
| **Top-up** | Later, on the first plan request for **any** scenario still short of the minimum — either plan route, generated or hand-written; the one scenario it never touches is a hand-written one carrying the person's own controls | §8.6A |

Both stop at the same floor — each resolves `ratio × the cutoff its own pass is using` — and both can
leave a scenario legitimately short. Only the top-up writes an audit entry marked
`"source": "remediation_top_up"`, which is the only way to tell after the fact which of the two
produced a below-cutoff score.

**Worked examples.** Three scenarios in the same session can legitimately return three different
counts:

Below, **C** is the cutoff in force (50 in this deployment) and **F** is the floor it resolves to
(`0.42 × 50 = 21.0` here). Read both off the run's `controls_mapped` audit entry rather than assuming
these values — if the cutoff moves, every number in this table moves with it.

| Scenario | Scored at or above C | Between F and C | You should see | Why |
|---|---|---|---|---|
| A | 8 | — | **8 controls**, every `score` at or above C | Everything that clears the cutoff is kept. Before this change the list was cut to 5 and the three lost controls were recorded nowhere |
| B | 2 | 6 more | **5 controls** — the 2 that cleared, then the 3 best of the 6, in that order | The minimum is a target. The backfill takes the next best already-scored controls, only from above the floor, and always places them after every control that cleared |
| C | 0 | 0 | **0 controls**, with `controls_mapped: true` | Nothing relevant exists, so nothing is invented. A short list is the honest answer. Earlier builds padded a case like this with controls scoring 13.55, 10.21 and 9.53 against a cutoff of 50 |

A fourth case to recognise: a scenario with **4 controls** where only 4 cleared the floor. That is
correct, not a shortfall — the minimum is never reached with filler.

**How to verify it.** Do step 5 **first** if you want the real C and F; every check below is stated
against them rather than against a literal, because both are derived.

1. Read `/results` and, for each scenario, **count `controls[]`**. This is the only place a
   per-scenario count exists on the API — see step 5.
2. Any list **longer than 5** proves the old truncation is gone. Check no `score` is below C.
3. Any list where some `score` is **between F and C** was filled by a backfill or a top-up.
   Check that every such entry sits **after** all the ones at or above C, that none is below F,
   and that the list stops at 5.
4. Any list **shorter than 5** must have no candidate left above F. (At this deployment's F of 21.0,
   a list short of 5 while candidates sit at 23 **is** a defect — do not excuse it against the
   deprecated 25.0 absolute, which is unset and is not the floor.)
5. `GET /v1/sessions/{session_id}/audit` and read the `controls_mapped` entry. **It is one entry
   per mapping pass, not per scenario:** every number in it is a total across every scenario that
   pass handled, and it names no scenario. Use it to explain the counts you got in step 1, not to
   look one up. It records how many controls cleared the cutoff, how many were mapped, how many
   were backfilled, how many the ceiling dropped, how many were demoted for IT/OT, the IT/OT
   labels used and where they came from, whether the pool filter was applied and with which
   labels, the domain affinity, and — the two you need above — `effective_min_score` with
   `effective_min_score_origin` (that is **C**, and which of the three sources produced it) and
   `effective_backfill_min_score` (that is **F**, the floor the ratio resolved to). Those numbers are
   how "the library had five good controls" is told apart from "the library had forty and a cap
   kept five". The one `controls_mapped` entry that *does* name a scenario is the top-up's, marked
   `"source": "remediation_top_up"` (§8.6A).
6. `map_rank` must read `1, 2, 3 …` in the order returned. **Do not expect the scores to descend** —
   read the next paragraph for why, and use the SQL below to see the order's real reason.
7. For a scenario's own numbers straight from the database, use the SQL below: it is the count, the
   order and the reason for that order in one result.

**IT/OT and domain — two different things.** IT/OT acts twice, and only one of them is an ordering
rule:

| Level | What happens | Can it remove a control? |
|---|---|---|
| The candidate pool, per **session** | Before anything is scored, the pool is cut to the labels every one of the session's asset and supporting-system categories resolves to. It is all-or-nothing: if **any** category cannot be resolved, no filter is applied and the whole library is in the pool. An unlabelled control is always in the pool either way | **Yes.** A control outside the pool is never scored and cannot appear in any list. The audit entry says whether the filter was applied and with which labels |
| The ordering, per **scenario** | The asset plus the supporting systems *that scenario* names decide its own IT/OT context. A control outside it sorts behind every compatible one, whatever either scored | **No.** It is only pushed down |

So for an OT scenario, one `IT` control lower down the list is **not** a defect — the library has no
"applies to both" label, so a genuinely universal control still arrives as one or the other. What
*would* be a defect is an `IT` control sitting **above** a comparable `OT` one. And because
compatibility outranks the score, a compatible control scoring 55 correctly sits above an
incompatible one scoring 90: that is why `map_rank` is not the score in disguise.

Domain is the last and weakest key. It only breaks a tie between controls the first two keys cannot
separate, and can never lift a control that failed the cutoff into the list.

```sql
-- The order, the scores, and the two things that decide the order
SELECT map.MapRank, map.Score, lib.ITOT, lib.Domain, lib.ControlCode
FROM   Threat_Scenario_Control_Map map
JOIN   Control_Library lib ON lib.ControlLibraryID = map.ControlLibraryID
WHERE  map.ScenarioID = '<scenario_id>'
ORDER BY map.MapRank;
```

### 7.4 Step 8 — `POST /v1/sessions/{session_id}/accept`  *(Business)*

**Why:** a plan can only be written for an **accepted** scenario.

```json
{ "mode": "subset", "scenario_ids": ["bcbf72ed-..."] }
```

| Parameter | Type | Required | Allowed values | Description |
|---|---|---|---|---|
| `mode` | string | Yes | `all`, `none`, `subset` | `subset` requires `scenario_ids` |
| `scenario_ids` | array of string | With `subset` | — | Which scenarios to keep |

**Response (200):** `{"accepted_count": 1, "status": "completed", "replaced": []}`

---

## 8. STEP 9 / 9M — `POST /v1/remediation-plans`  (the main endpoint)

One endpoint, two kinds of scenario. **This route is not in the older HTML guidebook.**

### 8.1 API information

| | |
|---|---|
| Step | 9 (AI) and 9M (manual) |
| Phase | Business + Processing |
| Type | **Business** |
| Method / Endpoint | `POST /v1/remediation-plans` |
| Auth | `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id` |
| Extra header | `Idempotency-Key` — **required when `is_manual=true`** |
| Previous | Step 8 (AI) or Step 3 (manual) |
| Next | Step 11 |

### 8.2 Why this API is needed

For an AI scenario it starts the plan. For a hand-written scenario it does everything in one call:
saves the scenario, accepts it, and starts the plan — so a person's risk is treated exactly like a
generated one from here on.

### 8.3 Prerequisites

| Prerequisite | Created by | Required for |
|---|---|---|
| `TSG_RISK_MODULE_ENABLED=true` | `.env` | Both — otherwise 404 |
| Accepted scenario | Step 8 | `is_manual=false` |
| Asset + entity rows | Platform team | `is_manual=true` |
| Threat library values | Seed SQL | `is_manual=true` |
| Control Library codes | Seed SQL | `is_manual=true` |
| `Idempotency-Key` header | You | `is_manual=true` |
| `TSG_REMEDIATION_CONTROL_TOP_UP_ENABLED` (default `true`), `TSG_CONTROL_MAP_MIN_COUNT` (default `5`), `TSG_CONTROL_MAP_MAX_COUNT` (default `25`), `TSG_CONTROL_MAP_BACKFILL_RATIO` (default `0.42`) | `.env` | Both kinds — the control top-up in 8.6A runs on every first plan request. Optional: off simply skips it. The ratio sets the floor as a fraction of the cutoff in force (21.0 here). The older name `TSG_REMEDIATION_CONTROL_MIN_COUNT` is **RETIRED** and supplies nothing: leaving it set **refuses the boot**, naming `TSG_CONTROL_MAP_MIN_COUNT` |

### 8.4A Request — AI scenario (`is_manual=false`)

```json
{
  "is_manual": false,
  "session_id": "bc345a7d-...",
  "scenario_id": "bcbf72ed-...",
  "existing_controls": ["Perimeter firewall between IT and OT"],
  "likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 20,
  "risk_level": "Critical",
  "risk_identification_date": "2026-09-15T09:30:00Z",
  "risk_owner": "Head of OT Operations",
  "impacted_business_division": "Water Treatment Operations",
  "existing_controls_all_subsystems": "No",
  "existing_controls_all_subsystems_justification": "Corporate IT only.",
  "mitigation_start_date": "2026-10-01", "mitigation_end_date": "2026-12-31"
}
```

### 8.4B Request — hand-written scenario (`is_manual=true`)

```json
{
  "is_manual": true,
  "manual_scenario": {
    "entity_id": 142, "asset_id": 1200, "sector_id": 183, "subsector_id": 198,
    "service_id": 1707,
    "supporting_system_id": [1550, 1551],
    "threat_category_id": 5, "threat_category_name": "Tampering",
    "threat_type_id": 42, "threat_type_name": "Engineering Workstation Compromise",
    "threat_id": 126, "threat_name": "Engineering workstation compromise",
    "threat_scenario": "Threat actors compromise an engineering workstation, programming laptop or project repository through phishing, malware, portable media, stolen laptop or weak endpoint controls ...",
    "risk_statement": "Compromise of engineering workstations can expose controller logic and enable trusted changes to devices ...",
    "mapped_controls": [
      {"control_id": 1483, "control_code": "CII-CID-195",
       "control_name": "Malicious Code Protection (Anti-Malware)"},
      {"control_id": 1486, "control_code": "CII-CID-198", "control_name": "Mobile Code"},
      {"control_id": 1490, "control_code": "CII-CID-202",
       "control_name": "Malicious Link & File Protections"},
      {"control_id": 1501, "control_code": "CII-CID-213",
       "control_name": "Phishing & Spam Protection"},
      {"control_id": 1508, "control_code": "CII-CID-220", "control_name": "User Awareness"}]
  },
  "existing_controls": [{"control_code": "CII-CID-195"},
                        "Perimeter firewall between IT and OT"],
  "likelihood_rating": 4, "impact_rating": 5, "final_risk_rating": 20,
  "risk_level": "Critical",
  "risk_identification_date": "2026-09-15T09:30:00Z",
  "risk_owner": "Head of OT Operations",
  "impacted_business_division": "Water Treatment Operations",
  "existing_controls_all_subsystems": "No",
  "existing_controls_all_subsystems_justification": "Corporate IT only.",
  "mitigation_start_date": "2026-10-01", "mitigation_end_date": "2026-12-31"
}
```

Four things about that body have changed since the earlier drafts of this guide, and each is a 422
or a surprise if you copy an old one (`app/api/schemas_treatment.py::ManualScenarioIn`):

- **There is no `scenario_title`.** It was removed in 2026-09 and the model forbids extras, so
  sending one is a 422 naming it — deliberately, rather than letting you believe TSG stored it.
- **The threat is named by id, by name, or both** — `threat_category_id`/`_name`,
  `threat_type_id`/`_name`, `threat_id`/`_name` — never by the bare `threat_category` /
  `threat_type` / `threat` keys the old body used. Send both halves of a pair and they must agree,
  or it is a 422 quoting the library's value. `threat_id` is the **library** threat's integer id
  (126), not a session's scenario uuid, and when you send it the library's spelling wins over your
  `threat_name` everywhere downstream.
- **The category pair is optional.** Omit both and TSG derives the category from the resolved threat
  type, or saves the scenario without one when the library records none. The type and the threat must
  each still be named somehow.
- **`mapped_controls` is optional**, and each entry may be an object naming a library row by
  `control_id`, `control_code`, `control_name` or any mix, or a plain code string like
  `"CII-CID-195"`. `existing_controls` takes the same two forms plus free text.

### 8.5 Every parameter

**Routing fields**

| Parameter | Type | Required | Nullable | Allowed | Description |
|---|---|---|---|---|---|
| `is_manual` | boolean | Yes | No | `true` / `false` | Which kind of scenario |
| `session_id` | string | If `false` | Yes | max 38 chars | Existing session. **Must be absent when `true`** |
| `scenario_id` | string | If `false` | Yes | max 38 chars | Accepted scenario. **Must be absent when `true`** |
| `manual_scenario` | object | If `true` | Yes | — | **Must be absent when `false`** |

**`manual_scenario` fields**

| Parameter | Type | Required | Length | Description |
|---|---|---|---|---|
| `entity_id` | string or integer | Yes | — | Must match `X-Entity-Id` |
| `asset_id` | integer | Yes | — | Owned by that entity |
| `supporting_system_id` | array of integer | Yes | 1-50 ids | Systems in scope; a single id may be sent bare |
| `subsector_id` | integer | No | — | Child, not parent |
| `sector_id` | integer | No | — | Cross-check only — must be the parent of `subsector_id` |
| `service_id` | integer | No | — | Critical service the asset delivers; with `entity_id` it resolves the sub-sector server-side |
| `threat_scenario` | string | Yes | 1-4000 | What happens |
| `risk_statement` | string | Yes | 1-4000 | Business impact |
| `threat_category_id` / `threat_category_name` | integer / string | **No** | — / 1-200 | One of the six STRIDE rows, by id, name or both; **never created**. Omit both and TSG derives the category from the threat type, or saves without one. `scenario_title` is **gone** — sending it is a 422 |
| `threat_type_id` / `threat_type_name` | integer / string | Yes (one of the two) | — / 1-300 | Library type; proposed as a pending curator row if new — which needs a name, so propose by name |
| `threat_id` / `threat_name` | integer / string | Yes (one of the two) | — / 1-500 | Library threat (`threat_id` = `Threat_Catalogue.ThreatCatalogueID`, e.g. 126 — not a scenario uuid); proposed as pending if new. Send an id and the library's spelling overrides your name |
| `mapped_controls` | array of object or string | **No** | up to 50 entries | The controls this plan may recommend, **in your order of relevance** — each entry a library row named by `control_id`, `control_code`, `control_name` or any mix, or a plain code string. TSG never re-maps or replaces controls **you** send, however few. Every entry must resolve to an active library row (unknown or retired is a 422, all named) and naming one control twice is a 422 — including across keys (id 1483 and its own code in the same list). **Optional:** omitted, `null`, `""` and `[]` all mean "I chose none", and TSG then maps 5-25 library controls to the scenario itself before planning, with the same matching an AI scenario gets (8.6A) |

Sending both halves of an id/name pair that disagree is a 422 quoting the library's value. Blank or
punctuation-only values are rejected (422). Duplicate control codes are rejected (422).

**Register fields (both modes)**

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `existing_controls` | array of object or string | No | The register's baseline for gap analysis. Each entry either names a Control Library row (`control_id`, `control_code`, `control_name` or any mix — an object, or a plain code string) or is free text such as `"Quarterly phishing simulation"`, kept verbatim and never rejected. An entry that names a library row the scenario is also mapped to is matched **by TSG in code** (its name, domain and description fetched from the library and shown to the AI), marks that mapped control `covered_by_register`, and the plan may never recommend it; free text is judged by the AI by meaning. Optional: omitted, `null`, `""` and `[]` all mean a risk with no recorded controls. At most 50 entries; naming one control twice is a 422 |
| `likelihood_rating`, `impact_rating`, `final_risk_rating` | number | No | 0 or more, up to 4 decimal places |
| `risk_level` | string | No | `Low`, `Medium`, `High`, `Critical` are the toolkit's own values; any other non-empty label your register uses is accepted and echoed back unchanged |
| `risk_identification_date` | string (date-time) | No | ISO 8601 |
| `risk_owner` | string | No | — |
| `impacted_business_division` | string | No | — |
| `existing_controls_all_subsystems` | string | No | `Yes` or `No` |
| `existing_controls_all_subsystems_justification` | string | No | Up to 1000 characters |
| `mitigation_start_date`, `mitigation_end_date` | string (date) | No | `YYYY-MM-DD`. Send **both or neither**; end on or after start. Omitted, `null` or `""` = no window. A bad date or a number is 422. With the pair, TSG dates every action from the start date; without it, actions carry durations only (see 9.2) |

```bash
curl -s -X POST http://localhost:8000/v1/remediation-plans \
  -H "X-API-Key: <api key>" -H "X-User-Id: 1138" \
  -H "X-Entity-Id: 78" -H "X-Tenant-Id: DESC" \
  -H "Idempotency-Key: smoke-1790157403" \
  -H "Content-Type: application/json" \
  -d @manual_body.json
```

### 8.6A Internal processing — the control top-up (both routes, both kinds)

Before the plan is created, a scenario with fewer than `TSG_CONTROL_MAP_MIN_COUNT` (default 5) live
mapped controls is mapped against the Control Library. This runs on **every first plan request** —
`POST /v1/remediation-plans` with either flag, and the path route
`POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan`, which is the same call.

1. Headers authenticate; the session must belong to `X-Entity-Id` (checked first — nothing else
   runs for a caller without access).
2. **Skipped** (no matching work at all) when: the switch is off, the scenario already has enough
   controls, it carries controls **the person chose** (a hand-written scenario with any map row —
   read from the stored scenario, so the `is_manual` flag cannot change this), this is a
   **regenerate** of a scenario that already has live controls, it is not accepted, or a plan
   already exists on a first generation. The route then answers exactly as before.
3. **A scenario whose scored mapping has not finished is mapped here, not skipped.** An AI scenario
   with `ControlsMappedAt` empty is mapped on the spot and stamped in the same transaction as its
   rows — but only when rows were actually written, so a failed match (dead reranker, nothing above
   the floor) leaves it empty for the retry sweep. The old behaviour was to skip it entirely; the
   behaviour before that stamped it unconditionally and retired it from the scored pass for good. If
   the scored pass settles the scenario first, this write rolls back rather than doubling the rows.
4. **Fill size.** A scenario with **no** map rows at all is sized the way the scored pass sizes one:
   at least `TSG_CONTROL_MAP_MIN_COUNT` (5), every control above the cutoff, never past
   `TSG_CONTROL_MAP_MAX_COUNT` (25 — a safety cap, never a target). A scenario that already has rows
   is only topped up to the minimum. A hand-written scenario saved without `mapped_controls` takes
   the first branch: 5 to 25 controls, scored, exactly as a generated scenario gets.
5. Candidates: active Control Library controls for the asset's categories, widened to the whole
   library if that leaves too few. Controls already mapped are never picked again.
6. **One search query**, built in this order: threat category, threat type, threat name, threat
   actors, scenario title, scenario statement, risk statement, asset name and technology, then the
   systems the scenario involves. Threat identity leads deliberately, and the asset context trails
   where a length clip costs least. It is then ranked by the same two rounds scenario generation
   uses: a shortlist of `TSG_CONTROL_MAP_SHORTLIST_K` (60 here), then the accurate scorer.
7. The best-ranked controls fill the gap, **but nothing below the backfill floor is ever added** —
   `TSG_CONTROL_MAP_BACKFILL_RATIO` × the cutoff this pass resolved, which is `0.42 × 50 = 21.0`
   here. If only 3 controls clear that floor, the scenario ends with 3. There is no filler: an
   arbitrary control reads like a real one on a remediation plan, and earlier builds added matches
   scoring 13.55, 10.21 and 9.53 against a cutoff of 50. If **nothing** clears the floor, nothing is
   written at all — including no audit row, so there is no row to read the floor out of; in that case
   read it from the mapping pass's own `controls_mapped` entry.
8. One transaction writes the new map rows and re-numbers `MapRank` across the scenario's **whole**
   list using the one ordering rule from §7.3 — IT/OT compatibility, then score. An existing row
   with no score (a legacy row, or a control the person chose) stays behind every
   scored row and keeps its place among the other unscored ones. It also writes a
   `controls_mapped` audit row with `"source": "remediation_top_up"`, the ids and scores of the
   controls it added, `stamped` and `scenario_source`, the cutoff in force with its origin
   (`effective_min_score`, `effective_min_score_origin`), the floor that cutoff resolved to
   (`effective_backfill_min_score`), and `below_min_score` — how many of those added controls scored
   below that cutoff.
9. **`ControlsMappedAt` is claimed only when rows were written**, in that same transaction and only
   while it is still empty (audit `stamped: true`). Nothing is written when the scenario was already
   stamped, and nothing is stamped when the match produced no rows — the retry sweep keeps the
   scenario. Stamping it unconditionally was the old defect: it retired a scenario from the scored
   mapping pass for the convenience of one plan.
10. The request body is recorded verbatim under `detail.request` on the `treatment_plan_requested`
    audit event, with secrets redacted; the `treatment.requested` log line carries the same body with
    `risk_owner` masked, and headers are never logged.
11. The plan is then created exactly as the path-based create would, from the now-complete map.

> **If the matching service is down** the plan still starts (`202`) with the controls it has, and
> `warnings` says which of the three cases it was — §9.2 lists all three, and they are **not**
> interchangeable. With at least one control: `only N of the minimum M library-mapped controls —
> top-up could not reach the floor`, where M is `TSG_CONTROL_MAP_MIN_COUNT` (5 here). With none, and
> the map readable: `no library-mapped controls for this scenario (Step-4 map is empty)`. With none
> because the map could not be **read** at all: `library control lookup failed — plan generated
> without mapped controls`, which is a database fault and not a library gap. The path-based create
> tops up on the same terms — it is the same call — while a **regenerate** tops up only a scenario
> with no live controls at all, so a first attempt that matched nothing can be repaired by
> regenerating without touching scenarios that already have controls.

### 8.6 Internal processing (`is_manual=true`)

1. Headers authenticate; `entity_id` must match `X-Entity-Id`.
2. `Idempotency-Key` is reserved. A repeat of the same key and asset replays the original.
3. The asset's ownership and details are read.
4. The category, controls and library combination are resolved (fast 422 on a bad value).
5. The scenario text is validated and moderated (advisory only — never blocks the save).
6. **One transaction** writes: session, stage rows, library proposals, threat, scoped threat,
   scenario, control map, audit, acceptance. Any failure rolls back **everything**.
7. **If you sent no `mapped_controls`**, the plan launch then maps the scenario itself — 5 to 25
   scored library controls, the same matching an AI scenario gets, with a `controls_mapped` audit row
   marked `"source": "remediation_top_up"` (8.6A).
8. The plan is queued to Celery.
9. `202` is returned with the three ids.

> **Guarantees worth testing.** The controls you send are stamped as already mapped, so no mapping
> pass and no top-up can ever change, replace or add to them — a two-control list stays exactly two.
> Send none and TSG maps the scenario for you instead; what it never does is rewrite your scenario
> text or overrule a control you picked. The AI refuses to regenerate a hand-written scenario. The
> save is all-or-nothing.

### 8.7 Database

No hand-written SQL; access is through SQLAlchemy.

| Table | Operation | Purpose |
|---|---|---|
| `Scenario_Session` | INSERT | New session, `Mode='MANUAL'`, holds the idempotency key |
| `Subsystem_Stage_State` | INSERT | Stage rows, pre-settled |
| `Threat_Type`, `Threat_Catalogue` | SELECT, sometimes INSERT | Match, or propose a pending entry |
| `Identified_Threat` | INSERT | The threat, AI flags false |
| `Scoped_Threat` | INSERT | `SelectionKind='manual_entry'` |
| `Threat_Scenario` | INSERT | `ScenarioSource='manual'`, `ControlsMappedAt` stamped |
| `Threat_Scenario_Control_Map` | INSERT | One row per control you sent, in your order, `Score` NULL. Skipped when you sent none — the top-up below then fills it |
| `Scenario_Audit` | INSERT | `session_started`, `library_promoted`, acceptance records, `treatment_plan_requested` (whose `DetailJSON.request` is your request body, secrets redacted) |
| `Risk_Treatment_Plan` | INSERT | The plan row, status RUNNING |

The top-up's writes (8.6A) are extra for **either** kind, and only when it runs:

| Table | Operation | Purpose |
|---|---|---|
| `Threat_Scenario_Control_Map` | INSERT, UPDATE | The mapped controls, `Score` = the scorer's 0-100 value — including on a hand-written scenario saved without controls. `MapRank` re-numbered across the whole list by the composite rule (IT/OT, then score), and only the existing rows the merge actually moved are updated |
| `Scenario_Audit` | INSERT | `controls_mapped`, `DetailJSON.source = "remediation_top_up"`, with `stamped` and `scenario_source` |
| `Threat_Scenario` | UPDATE | **Only** `ControlsMappedAt`, only when it was still empty and only when rows were really written (8.6A step 9). A manual save has already stamped it; a failed match leaves an AI scenario empty for the sweep |

**Verify in the database**

```sql
SELECT Mode, SessionStatus, CurrentStage, StageStatus
FROM   Scenario_Session WHERE SessionID = '<session_id>';

SELECT ScenarioSource, Accepted, ControlsMappedAt
FROM   Threat_Scenario  WHERE ScenarioID = '<scenario_id>';

SELECT ControlLibraryID, MapRank, Score
FROM   Threat_Scenario_Control_Map
WHERE  ScenarioID = '<scenario_id>' ORDER BY MapRank;

-- either kind: did the top-up run, and what did it add?
SELECT CreatedAt, DetailJSON
FROM   Scenario_Audit
WHERE  ScenarioID = '<scenario_id>' AND EventType = 'controls_mapped'
  AND  DetailJSON LIKE '%remediation_top_up%';
```

### 8.8 Response

```json
{ "plan_id": "a34c3c26-...", "session_id": "65d8c0ff-...", "scenario_id": "e19af86c-...",
  "status": "RUNNING", "is_manual": true, "replayed": false,
  "library": {
    "threat":      { "name": "Ransomware on OT support systems", "status": "existing" },
    "threat_type": { "name": "Malware/Ransomware", "status": "existing" },
    "message": null } }
```

| Parameter | Type | Always present | Description |
|---|---|---|---|
| `plan_id` | string | Yes | The plan row |
| `session_id` | string | Yes | **TSG created it** when manual — keep it |
| `scenario_id` | string | Yes | **TSG created it** when manual — keep it |
| `status` | string | Yes | `RUNNING`, or the existing plan's status on a replay |
| `is_manual` | boolean | Yes | Read from the **stored** scenario, not your request flag |
| `replayed` | boolean | Yes | `true` when this key had already saved |
| `library` | object or null | Manual only | What happened to the threat library |

**The `library` block**

| `status` | Meaning | What to do |
|---|---|---|
| `existing` | Already in the library, linked | Nothing |
| `inserted` | Proposed as pending | Wait for a curator (steps 16-17) |
| `rejected_by_curator` | A curator declined this exact wording | **Choose a different name.** Resending will not re-propose it |
| `not_proposed` | Nothing created, and nothing should have been | Nothing |

`message` carries one plain sentence when action is needed, and is `null` otherwise.

**Important output for the next API:**

```
session_id  -> steps 11, 12, 13, 14, 15
scenario_id -> steps 11, 12, 13, 14, 18
plan_id     -> step 13 (evidence query) and step 14 (review body)
```

### 8.9 Errors

| Status | Error | Cause | Tester action |
|---|---|---|---|
| 404 | — | Risk module disabled | Set `TSG_RISK_MODULE_ENABLED=true` |
| 422 | `validation_error` | Missing `Idempotency-Key` with `is_manual=true` | Add the header |
| 422 | `validation_error` | Mixing `manual_scenario` with `session_id`/`scenario_id` | Send one kind only |
| 422 | `validation_error` | Unknown category, unknown or retired control code, blank name | Message names the field |
| 422 | `validation_error` | Threat filed under a different type in the library | Message names the library's type |
| 403 | `forbidden` | Asset not owned by the entity, or `entity_id` does not match `X-Entity-Id` | Check the ids |
| 409 | `idempotency_key_conflict` | Same key, different asset — or a key an AI run already used | Use a new key |
| 409 | `treatment_conflict` | A plan already exists (`plan_already_exists`) | Read the existing plan |
| 503 | — | Broker unreachable | Check `/ready`; the error carries your ids |
| 200 | — | Replay of the same key | Not an error — `replayed: true` |

### 8.10 Test cases

| ID | Scenario | Input | Expected | Pass condition |
|---|---|---|---|---|
| R-1 | Happy path, manual | 8.4B | 202 | Three ids returned, `is_manual: true` |
| R-2 | Happy path, AI | 8.4A | 202 | `is_manual: false` |
| R-3 | Missing key | Manual, no `Idempotency-Key` | 422 | Names the header |
| R-4 | Replay | Same key and body | 200 | Same ids, `replayed: true`, no new rows |
| R-5 | Key reuse, other asset | Same key, `asset_id` 100 | 409 | `idempotency_key_conflict` |
| R-6 | Cross-kind key | Key already used by `POST /v1/sessions` | 409 | Nothing saved |
| R-7 | Mixed mode | `is_manual:true` **and** `session_id` | 422 | Refused |
| R-8 | Unknown control | `["CII-CID-000"]` | 422 | Names the code |
| R-9 | Retired control | An inactive code | 422 | Names the code |
| R-10 | Blank threat type | `"   "` | 422 | Refused |
| R-11 | Wrong type for threat | Known threat, wrong type | 422 | Names the library's type |
| R-12 | Curator-rejected wording | A declined name | 202 | Saved, `library.threat.status = rejected_by_curator`, not re-proposed |
| R-13 | New type and threat | Unseen names | 202 | Both `inserted`, appear in the pending queue |
| R-14 | Asset not owned | Another entity's asset | 403 | Nothing saved |
| R-15 | Duplicate control codes | Same code twice | 422 | Names the duplicate |
| R-16 | Save fails midway | Force an error | Nothing saved | No orphan session or scenario |
| R-17 | Top-up, AI scenario short of controls | 8.4A on an accepted AI scenario with 2 controls | 202 | 5 map rows, all distinct; `library_mapped_count` 5 on evidence; one `remediation_top_up` audit row |
| R-18 | Top-up, nothing relevant enough | AI scenario whose threat matches no control well | 202 | The scenario stays **short of 5** and no control scoring below the floor **F** is added (§7.3: `TSG_CONTROL_MAP_BACKFILL_RATIO` × the cutoff, 21.0 here — take F from the mapping pass's `effective_backfill_min_score`, not from this sentence). Because nothing was added, there is **no `remediation_top_up` audit row at all** — its absence is the result. The plan's `warnings` name the shortfall (8.6A) |
| R-18b | Top-up reaches the floor from below the cutoff | AI scenario with 2 controls, where 3 more score between **F** and **C** (21.0 and 50 here) | 202 | 5 map rows. The `remediation_top_up` audit row's `below_min_score` is **3** — that field counts how many of the *added* controls scored under the cutoff, not how many were rejected under the floor. The same row's `effective_min_score` / `effective_backfill_min_score` are the C and F this run really used |
| R-19 | No top-up, already enough | AI scenario with 5+ controls | 202 | Map unchanged, no `remediation_top_up` audit row |
| R-20a | No top-up, hand-written **with** controls | 8.4A with a **manual** scenario's ids, that scenario carrying the person's own controls (plan not yet created) | 202 | Map unchanged — exactly the codes the person sent, in their order, `score` still `null`, and **no** `remediation_top_up` audit row. Two controls stay two |
| R-20b | Hand-written **without** controls is mapped | 8.4B with `mapped_controls` omitted (or `null` / `""` / `[]`) | 202 | 5 to 25 map rows with a non-null `Score`, one `remediation_top_up` audit row, `library_mapped_count` ≥ 5 on evidence, and no `Step-4 map is empty` warning. With the reranker down instead: 202, 0 rows, and that warning |
| R-20c | Path route tops up too | Accepted **AI** scenario with 2 live controls, first plan via `POST /v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` | 202 | 5 map rows and one `remediation_top_up` audit row — the same as R-17 on `/v1/remediation-plans`. Then regenerate: map unchanged, no new audit row. Regenerate a scenario with **0** rows: it is filled |
| R-21 | Switch off | `TSG_REMEDIATION_CONTROL_TOP_UP_ENABLED=false`, AI scenario with 2 controls | 202 | Map unchanged; plan `warnings` do **not** mention the floor |
| R-22 | Matching service down | Stop the reranker/embedding service, AI scenario with 2 controls | 202 | Map unchanged; plan `warnings` say `top-up could not reach the floor` |
| R-22b | Control-map read fails | Make the Step-4 map unreadable at plan time (e.g. `Threat_Scenario_Control_Map` absent or permission revoked), then `POST /v1/remediation-plans` | 202 | The plan is written with no library controls and `warnings` carry **`library control lookup failed — plan generated without mapped controls`** — *not* the Step-4-map-is-empty warning, which is emitted only when the read succeeded. The pass to check: the two strings are never both present, and an empty `library_mapped` with this warning must be treated as a retry, never as a library gap |
| R-23 | Refused request spends nothing | Repeat R-17's request | 409 `plan_already_exists` | No new map or audit rows |
| R-24 | Mitigation dates optional | 8.4A / 8.4B without both dates, or both `null` / `""` | 202 | Actions have `start_date`/`end_date` `null`, `timeline` in days, `mitigation_end_date_planned` `null`, warning `no mitigation window supplied` |
| R-25 | Mitigation dates typed | One date only, `"2026-13-40"`, or `123` | 422 | Names the field |
| R-26 | Schedule with dates | 8.4A with both dates | 202, then COMPLETE | Every action dated from `mitigation_start_date`; each `end_date` = `start_date` + `duration_days` − 1; an action with `depends_on` starts the day after its latest prerequisite ends; `mitigation_timeline_days` = critical path; no window warning if it fits |
| R-27 | Same JSON shape | Compare the plans from R-24 and R-26 | — | Identical keys on the plan and on every action; only values differ (`null` vs dates) |
| R-28 | Window too short | 8.4A with a 2-day window (`2026-10-01` → `2026-10-02`) | 202, then COMPLETE | `warnings` has `the plan finishes …, N days after the mitigation window closes (2026-10-02)`; the plan is not shortened to fit |
| R-29 | Sequence and controls | Any COMPLETE plan from R-24/R-26 | — | Ids `A1..An` in order; every `depends_on` names earlier ids; every recommended `control_code` appears in some action's `implements_controls`; no schedule warnings from the 9.2 table other than the window ones |
| R-30 | Old plan served | `GET` a plan generated before this release | 200 | New keys present as `null` / `[]`; old `timeline` text unchanged |
| R-31 | Final validation | Any COMPLETE plan that implements a control | — | The last action validates the change (implementation, effectiveness, evidence) and depends on the actions it validates |
| R-32 | More than the minimum is kept | A scenario where 8 controls score 50 or above (§7.3, scenario A) | — | `/results` returns **all 8**, not 5. Every `score` is 50 or above; the audit says 8 cleared the cutoff and 8 were mapped |
| R-33 | Minimum is a target, filled from above the floor | A scenario where only 2 score at or above **C** but 6 more score above **F** (50 and 21.0 here — §7.3) | — | **5 controls**: the 2 that cleared, then the 3 best of the 6, in that order. No `score` below F. The pass's audit entry records 2 cleared, 5 mapped, 3 backfilled — as totals for the pass, so run this on a session with one scenario if you want the numbers to be that scenario's. Take C and F from `effective_min_score` / `effective_backfill_min_score` in that same entry |
| R-34 | Short rather than padded | A scenario where nothing scores above **F** (§7.3, scenario C) | — | The list stays short — 0 controls with `controls_mapped: true`, or only the few that cleared. **No control below F appears** (21.0 here; a control at 23 is legitimately added, so do not fail it against the deprecated 25.0). Compare against the old behaviour: nothing like 13.55, 10.21 or 9.53 may be present |
| R-35 | Ceiling, not a target | A broad scenario where more than 25 controls clear the cutoff | — | At most **25 controls**; the audit records how many the ceiling dropped. No scenario is ever padded up to 25 |
| R-36 | Ranks are contiguous, scores need not be | Any scenario from R-32 or R-33 | — | `map_rank` reads `1, 2, 3 …` in the order returned. The scores may **not** descend, and that is correct: a control compatible with the scenario's IT/OT nature outranks an incompatible one whatever either scored, and backfilled controls sit at the end. Use §7.3's SQL to confirm each step down the list is explained by IT/OT first, then score. What *is* a defect: a topped-up control simply appended after better, compatible ones |
| R-37 | New per-control fields | Any scenario with controls, then its plan's `GET .../treatment-plan/evidence` | — | On `/results`: every control carries `itot`, `control_description` and `mapping_relevance` equal to `score`. In the frozen snapshot: `itot`, `control_description` and `mapping_relevance` are there, but `map_rank` and `score` are **not** — the list order is the rank, and `standards` is plain names rather than name-plus-key pairs (§9.3). A `null` `control_description` means the library row has none |
| R-38 | IT/OT decides the order | An OT scenario (OT asset and supporting systems) | — | Where two controls match comparably, the `OT` one ranks above the `IT` one — and so does an `OT` control that scored *worse*. `IT` controls may still appear lower down; that is correct, the library has no "applies to both" label. The pass's audit entry records the per-scenario labels used, where they came from, and how many controls were demoted |
| R-39 | Unresolved technology context does not narrow the pool | A session whose asset or supporting systems include a category with no matching control label | — | Controls of **both** labels are still considered and mapped, and the audit entry says the pool filter was **not** applied (no pool labels). An empty or halved control list here is the defect this guards against |
| R-39b | Resolved context does narrow the pool | A session whose categories all resolve (e.g. OT only) | — | The audit entry says the filter **was** applied and names the labels. Controls outside them are absent from every scenario in that session — not demoted, absent. This is the one place IT/OT removes a control from the running |
| R-40 | Domain only breaks ties | Any scenario with controls | — | No control with a `score` below 50 is present because its `domain` matched. Domain is the last sort key: it can separate controls that IT/OT and score cannot, and can never admit one that failed the cutoff |
| R-41 | Shortlist is the real ceiling | Set `TSG_CONTROL_MAP_SHORTLIST_K` to **25**, restart, regenerate the same scenario, then restore it to 60 | — | The 25-shortlist run maps fewer controls, and controls the 60-shortlist run mapped are simply absent — never scored, so never eligible. This is what a thin control list used to look like. **Do not use 20:** the shortlist must be at least `TSG_CONTROL_MAP_MAX_COUNT` (25 here) or the application refuses to start, because a shortlist narrower than the ceiling makes the ceiling unreachable and caps every scenario at the shortlist width without saying so. If you want 20, lower `TSG_CONTROL_MAP_MAX_COUNT` to 20 in the same change |
| R-42 | Unmapped scenario is mapped and stamped at plan launch | `POST /v1/remediation-plans` (`is_manual=false`) for an accepted scenario whose mapping has not finished (`controls_mapped: false`) | 202 | The scenario is mapped **here**: 5 to 25 scored rows, one `remediation_top_up` audit row with `"stamped": true`, `ControlsMappedAt` now set, `progress.controls` COMPLETE, and the scenario no longer listed as sweep-eligible. **The stamp follows the rows, never the attempt:** with the reranker stopped, or with nothing above the floor, the plan still returns 202 with the controls that exist, no audit row is written and `ControlsMappedAt` stays empty so the sweep (or `POST /v1/tsg/control-map/sweep`) still picks the scenario up. If the scored pass settles it first, the top-up writes nothing rather than doubling the rows |

---

## 9. STEP 11-13 — Getting the plan

### 9.1 Step 11 — `GET .../treatment-plan/status`

Path: `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status`

Poll every 10 seconds. A live run took about **3.5 minutes**.

| `progress.overall` | Meaning |
|---|---|
| `generating` | The AI is writing |
| `awaiting_review` | Done — a human must decide |
| `error` | Read `error_message` and `reason` |

> This lean poll returns lifecycle and review state only — no scenario or plan content. That is by
> design, so polling stays cheap.

### 9.2 Step 12 — `GET .../treatment-plan`

The full plan.

| Field | Type | Meaning |
|---|---|---|
| `status` | string | `RUNNING`, `COMPLETE` or `ERROR` |
| `scenario_source` | string | `manual` or `generated` |
| `library` | object or null | The block from 8.8 |
| `plan.controls_to_be_implemented.controls[]` | array | **The recommended controls** |
| `treatment_strategy` | string | For example `Mitigate` |
| `plan.remediation_action_plan[]` | array | Actions in execution order, each with `depends_on`, `duration_days`, `start_date`, `end_date`, `timeline`, `implements_controls` |
| `plan.mitigation_timeline`, `mitigation_timeline_days`, `mitigation_end_date_planned` | string, integer, date or null | The whole schedule — see below |
| `warnings` | array | Advisory notes. **Three of them are about controls and they are not interchangeable** — see the table below |

**The three control warnings — read them apart.** All three come from
`read_library_controls_for_snapshot` (`app/pipeline/treatment_input.py`), and each answers a different
question. Grading a degraded run as a clean one is exactly what telling them apart prevents:

| Warning | What actually happened | Verdict |
|---|---|---|
| `library control lookup failed — plan generated without mapped controls` | The read of the Step-4 map **raised**. A fact about the **database**, not about the scenario — the plan was written with no library controls because none could be read | **Retry the plan.** Never read the empty `library_mapped` list here as a library gap. This warning and the next one are mutually exclusive: the empty-map warning is only emitted when the read did *not* fail |
| `no library-mapped controls for this scenario (Step-4 map is empty)` | The read **succeeded** and the map really is empty: nothing cleared the floor, whoever wrote the scenario. A hand-written scenario saved without `mapped_controls` is mapped like a generated one, so this is a statement about the match, not about who typed the scenario | Believe it. Run the sweep or re-check the cutoff (§7.3) |
| `only N of the minimum M library-mapped controls — top-up could not reach the floor` | At least one control, but fewer than `TSG_CONTROL_MAP_MIN_COUNT` (5 here), and the top-up could not close the gap from above the floor | Often correct — a scenario may legitimately have 3 relevant controls |

A **regenerated** plan can also carry one warning per control the previous version had and this one
does not: `control <code> (<name>) was in the previous version but <why> — omitted from this version`,
with `<why>` one of *has been retired from the control library*, *is no longer in the control library*,
*is no longer mapped to this scenario*, or *is no longer available* when the reason could not be read.

**What the plan was written against.** The plan reasons over the scenario's mapped controls, frozen
into a snapshot at the moment generation started (read it in full at step 13). Each of those
controls carries `itot`, `control_description` and `mapping_relevance`, so the AI can read **what a
control actually does** when judging whether the risk is already covered, instead of inferring it
from the control's name. The snapshot is a **narrower set of fields** than `/results` — the exact
list is in §9.3. What to check:

| Check | Expected |
|---|---|
| Number of controls in the snapshot | The same count you saw on `/results` for that scenario (§7.3) — 8 stays 8, and a scenario left short by the backfill floor stays short. A control retired from the library after the plan was written drops out of both |
| `control_description` on each | Library text, capped in length here (`/results` serves it uncapped). `null` means the library row itself has no description — that is the state that made the AI guess |
| A control the plan calls already effective | Its reasoning should match what `control_description` says the control does, not merely its name |
| `warnings` | Only names a control **shortfall** when one really exists — a scenario that legitimately has 3 relevant controls is not a failure. But check which warning it is first: `library control lookup failed …` is not a shortfall at all, it is a failed read, and a plan carrying it must be retried rather than graded |

**A scenario whose mapping had not finished** when the plan was requested is planned with whatever
controls existed at that moment, and is left for the retry sweep. Its list fills in afterwards, so
`/results` can show more controls than the plan's snapshot. Regenerate the plan if you want it
written against the complete list.

**How the schedule is built.** The AI never writes a date. For each action it gives only
`duration_days` (days of work, sized by complexity) and `depends_on` (earlier actions it waits
for). TSG then works out the rest. The JSON has **the same keys whether or not mitigation dates
were sent** — only the values differ:

| Field | Dates not sent | Dates sent (`2026-10-01` → `2026-12-31`) |
|---|---|---|
| action `depends_on`, `duration_days` | `["A1"]`, `21` | `["A1"]`, `21` |
| action `start_date` / `end_date` | `null` / `null` | `2026-10-15` / `2026-11-04` |
| action `timeline` | `21 days, after A1 completes` | `2026-10-15 → 2026-11-04 (21 days, after A1 completes)` |
| `mitigation_timeline` | `40 days in total (critical path A1 → A3 → A4)` | `2026-10-01 → 2026-11-09 (40 days, critical path A1 → A3 → A4)` |
| `mitigation_timeline_days` | `40` | `40` |
| `mitigation_end_date_planned` | `null` | `2026-11-09` |
| `warnings` | `no mitigation window supplied — the 40-day schedule is not bounded by a register deadline` | none, or `the plan finishes …, N days after the mitigation window closes (…)` |

Actions are listed in execution order (A1 starts first). The total is the **critical path** — the
longest chain of actions that wait on each other; work running in parallel is not added. Each
action also lists `implements_controls`, the control codes it delivers.

**Dates count both ends.** A 14-day action starting `2026-10-01` ends `2026-10-14`; an action waiting
on it starts `2026-10-15`. The window is counted the same way: `2026-10-01` → `2026-12-31` is 92
days, and a same-day window holds exactly one day of work.

**Plans generated before this change** come back with the same keys: the new fields are `null`
(`duration_days`, `start_date`, `end_date`, `mitigation_timeline_days`,
`mitigation_end_date_planned`) or `[]` (`depends_on`, `implements_controls`), and the old `timeline`
text is served as stored. Nothing in the database is rewritten.

**Schedule checks.** TSG repairs what it can and adds a line to `warnings`; the plan is never
blocked. With a real model most of these only appear if the AI slips — they are pinned by the
automated tests (`tests/test_treatment_timeline_dates.py`), so a tester mainly needs to recognise
them:

| When | Warning (example) | What TSG does |
|---|---|---|
| Ids are not `A1..An` in order | `action ids are not A1..A3 in order: [...]` | Schedules as listed |
| An action waits on a later, unknown or its own id | `A2.depends_on 'A9' is not an earlier action — ignored` | Drops that link — no loop is possible |
| `depends_on` is missing | `A2.depends_on is missing — scheduled with no prerequisites` | Starts it immediately |
| The `dependencies` text names an action the ids don't include | `A2.dependencies mentions A1 but depends_on does not include it` | Schedules from the ids |
| The text says `None` but the ids name prerequisites | `A2.dependencies says None but it waits for A1` | Schedules from the ids |
| Duration not a whole number of days ≥ 1, or above 3650 | `A2.duration_days 'ten' is not a whole number of days of at least 1 — scheduled as 1 day` | Uses 1 day, or caps at 3650 |
| An action is listed after work that starts later | `A4 is listed after work that starts later (day 5) although it can start on day 0 — the sequence is out of order` | Schedules correctly anyway |
| A Critical/High action waits on a less urgent one | `A1 (Low) is a prerequisite of A2 (Critical) but is less urgent than the work it blocks` | Keeps the dependency |
| `implements_controls` is missing | `A2.implements_controls is missing — treated as delivering no control` | Treats it as `[]` |
| An action names a control not in the plan | `A1.implements_controls names 'BOGUS', which is not a control of this plan` | Keeps it |
| A recommended control has no action | `recommended control C2 is not implemented by any action` | — |
| `action_plan` states a total that differs from the computed one | `action_plan states 45 days but the computed critical path is 40 days` | Serves the computed total |
| Dates sent, plan ends after the window | `the plan finishes 2027-01-13, 13 days after the mitigation window closes (2026-12-31)` | — |
| No dates sent | `no mitigation window supplied — the 40-day schedule is not bounded by a register deadline` | — |

The rule that the plan **ends with a validation action** whenever a control is implemented or
changed is enforced by the prompt only; TSG does not check it — review it by eye (R-31).

**Breaking change for clients.** An action's `timeline` and the plan's `mitigation_timeline` used to
be ISO dates; they are now readable text. A UI or export that parsed them as dates must read
`start_date`, `end_date` and `mitigation_end_date_planned` instead.

**The check that matters for a hand-written scenario:** every `control_code` here must be one you
sent. A live run returned 9 of the 10 sent and nothing else — the AI may recommend fewer, never
others.

### 9.3 Step 13 — `GET .../treatment-plan/evidence?plan_id=...`

Proof of exactly what the AI was given. `input_snapshot.existing_controls.library_mapped` lists the
scenario's controls in mapped-rank order, and `library_mapped_count` is the count. Reading this is
how you settle whether a thin plan was a thin mapping or a thin AI answer.

Each entry carries **these fields and no others** — it is what the AI was handed, not the API's own
view of a control:

| Snapshot field | Compared with `/results` |
|---|---|
| `control_library_id` | Same number, published on `/results` as `control_id` |
| `control_code`, `control_name` | Same |
| `itot`, `domain` | Same |
| `control_description` | Same text, capped in length here |
| `mapping_relevance` | Same value; `null` only where a **person** chose the control (TSG-mapped rows are scored on a hand-written scenario too) |
| `covered_by_register` | Not on `/results` — set by TSG when one of the request's `existing_controls` entries **named this very library row** (`control_id`, `control_code` or exact `control_name`). The plan may never recommend such a control, and one the model recommends anyway is dropped with a warning. `existing_controls.register_matched_count` counts the matches; free-text register entries have no id and are judged by the AI by meaning instead |
| `standards` | Plain standard **names** only — `/results` returns `standard_id` + `standard_name` pairs |

There is no `map_rank` and no `score` in the snapshot: the order of the list is the rank, and
`mapping_relevance` is the score under its documented name. A test that asserts the snapshot has
"the same fields as `/results`" will fail, and should.

---

## 10. STEP 14-15 — Finishing

### 10.1 Step 14 — `POST .../treatment-plan/review`

```json
{ "decision": "approved", "plan_id": "a34c3c26-..." }
```

| Parameter | Type | Required | Allowed | Description |
|---|---|---|---|---|
| `decision` | string | Yes | `approved`, `declined` | The verdict |
| `plan_id` | string | Yes | — | Which version you are judging |

`plan_id` is required on purpose: a regenerate creates a new version, and a verdict must name the
one the reviewer actually read.

### 10.2 Step 15 — `GET /v1/entities/{entity_id}/treatment-plans`

The GRC register: every scenario's current plan for one entity.

| Field | Meaning |
|---|---|
| `scenario_source` | `manual` or `generated` — who wrote the scenario |
| `library` | The outcome block (null for AI scenarios) |
| `review_status` | Approved, declined or pending |

Add `?include_plan=true` for the full detail. Both forms report the same provenance.

### 10.3 Step 18 — Cleanup after a test

```bash
POST /v1/sessions/{sid}/scenarios/{scid}/unaccept      # body {}
POST /v1/sessions/{sid}/scenarios/reject               # {"scenario_ids":["<scid>"]}
```

The scenario then leaves the board and the register. Rows remain for audit — there is no delete.

---

## 11. Data handoff between APIs

| From API | Output | Example | Used by | As |
|---|---|---|---|---|
| `POST /v1/tsg/api-clients` | `secret` | `a6748c88...` | every business route | `X-API-Key` header |
| `POST /v1/tsg/api-clients` | `client_id` | `...` | revoke | path parameter |
| Platform database | `entity_id`, `asset_id`, `supporting_system_id[]` | `78`, `99`, `[306,307,308]` | `POST /v1/sessions`, `manual_scenario` | body |
| `POST /v1/sessions` | `session_id` | `bc345a7d-...` | board, results, accept, plan | path parameter |
| `GET .../results` | `scenario_id` | `bcbf72ed-...` | accept, plan | body / path |
| `POST /v1/remediation-plans` | `session_id` + `scenario_id` | created by TSG when manual | status, plan, evidence, review | path |
| `POST /v1/remediation-plans` | `plan_id` | `a34c3c26-...` | evidence (`?plan_id=`), review (body) | query / body |
| `GET .../library/pending` | `catalogue_id` | `652` | approve / reject | body array |
| Any admin job | `job_id` | `...` | its status and events routes | path parameter |

---

## 12. Database state through the flow

| Step | API | Table | Operation | Data |
|---:|---|---|---|---|
| 0 | SQL scripts | Threat + Control library | INSERT | Master data |
| 3 | Create client | `API_Client` | INSERT | Key hash |
| 5 | Create session | `Scenario_Session` | INSERT | `Mode='AUTO'` |
| 5 | Pipeline | `Subsystem_Stage_State` | INSERT/UPDATE | Stage progress |
| 6 | Pipeline | `Identified_Threat`, `Scoped_Threat` | INSERT | Threats found and scored |
| 6 | Pipeline | `Threat_Scenario` | INSERT | `ScenarioSource='generated'` |
| 6 | Pipeline | `Threat_Scenario_Control_Map` | INSERT | AI-matched controls |
| 8 | Accept | `Threat_Scenario` | UPDATE | `Accepted=1` |
| 8 | Accept | `Scenario_Audit` | INSERT | Decision trail |
| 9M | Remediation (manual) | 9 tables in ONE transaction | INSERT | See 8.7 |
| 9 / 9M | Remediation (either kind), top-up | `Threat_Scenario_Control_Map`, `Scenario_Audit`, `Threat_Scenario` | INSERT/UPDATE | Only when the scenario had fewer than 5 live controls and none of them were the person's own, and only when at least one candidate cleared the floor. `Threat_Scenario` is touched only to claim `ControlsMappedAt`, and only when it was still empty — see 8.6A |
| 9 / 9M | Remediation | `Risk_Treatment_Plan` | INSERT | Status RUNNING |
| 11 | Worker | `Risk_Treatment_Plan` | UPDATE | Plan JSON, status COMPLETE |
| 14 | Review | `Risk_Treatment_Plan` | UPDATE | Review status, reviewer, time |
| 17 | Approve / reject | `Threat_Catalogue`, `Threat_Type` | UPDATE | Activate, or soft-delete |
| 18 | Unaccept / reject | `Threat_Scenario` | UPDATE | `Accepted=0`, rejected |

---

## 13. Configuration dependency map

```
SQL scripts (tables + threat/control libraries)
        |
        +---------------> Platform tables (asset/entity)   <- platform team, NOT an API
        |                          |
Admin key in .env                  |
        |                          |
POST /v1/tsg/api-clients ----------+
        |  (API key)               |
        v                          v
Embeddings update            POST /v1/sessions        POST /v1/remediation-plans (manual)
Grounding threshold                |                            |
        |                          v                            |
        +------ affects match quality of --> scenarios ---------+
                                                |
                                     Risk module enabled?
                                                |
                                         remediation plan
```

| Configuration | Comes from | Needed by | One-time or repeated |
|---|---|---|---|
| Tables + libraries | SQL scripts | Everything | One-time per environment |
| Asset / entity rows | Platform team | Sessions, manual saves | Per asset |
| `TSG_ADMIN_API_KEY` | `.env` | All 31 admin routes | One-time |
| API key | `POST /v1/tsg/api-clients` | All 28 business routes | One-time per consumer |
| Embeddings | Admin route | Match quality | After any bulk SQL load |
| Grounding threshold | Admin route or env | Match quality | Per model pair |
| `TSG_RISK_MODULE_ENABLED` | `.env` | The 12 plan routes | One-time |
| `TSG_CONTROL_MAP_SHORTLIST_K`, `TSG_CONTROL_MAP_MIN_SCORE` | `.env` | How many controls each scenario gets, and how relevant they are | One-time; 60 and 50 here. The env cutoff is the **bootstrap** only — a stored measurement for the models in use out-votes it, and none of the three sources needs a restart. §7.3 |
| `TSG_CONTROL_MAP_MIN_COUNT`, `TSG_CONTROL_MAP_MAX_COUNT`, `TSG_CONTROL_MAP_BACKFILL_RATIO` | `.env` | The minimum to aim for, the runaway ceiling, and the floor under a backfill or a top-up — the last one as a **fraction of the cutoff in force** (0.42 × 50 = 21.0 here) | One-time; defaults 5 / 25 / 0.42. **Checked at boot:** shortlist ≥ ceiling, and minimum ≤ ceiling. **Not checked at boot:** the floor — the ratio's `0 < r < 1` bounds make it structurally below any cutoff instead, and a deprecated `TSG_CONTROL_MAP_BACKFILL_MIN_SCORE` at or above the cutoff is ignored at run time with a `controls.backfill_floor_override_ignored` log line, not refused at startup |
| `TSG_REMEDIATION_CONTROL_TOP_UP_ENABLED` | `.env` | Control top-up on every first plan request — both plan routes, both kinds of scenario (§8.6A) | One-time; default on |
| Risk register values | The caller | Every plan request | **Per transaction** |

The last row is the line people cross: risk ratings, owner and dates are **per request**, not
configuration.

---

## 14. Quick guide for non-technical users

### Step 1 — Check the system is up
Open `http://localhost:8000/health` in a browser. You should see a success response.

### Step 2 — Get your key
Ask an administrator to create an API key for you. **Copy it immediately** — it is shown once.

### Step 3 — Get your asset numbers
Ask the platform team for your **entity id**, **asset id** and **supporting system ids**. These do
not come from this system.

### Step 4 — Decide which kind of test
- The computer writes the scenario: go to Step 5.
- You write the scenario yourself: skip to Step 8.

### Step 5 — Start a run
Call `POST /v1/sessions` with your three numbers. **Copy the `session_id`.**

### Step 6 — Wait
Call `GET /v1/sessions/{session_id}` every few seconds until it says `awaiting_review`
(about 8 minutes).

### Step 7 — Look at the results and choose
Call `GET /v1/sessions/{session_id}/results`, pick a `scenario_id`, then call
`POST /v1/sessions/{session_id}/accept` with that id. Now skip to Step 9.

### Step 8 — Send your own scenario
Call `POST /v1/remediation-plans` with `is_manual` set to `true`, your written scenario, and — if you
have one — your list of control codes. The list is optional: leave it out and TSG finds the library
controls for you, the same way it does for a scenario it wrote itself. Send one and those are the only
controls the plan may recommend. Add an `Idempotency-Key` header — any unique text, such as
`my-test-1`.
**Copy the `session_id`, `scenario_id` and `plan_id`.**

### Step 9 — Wait for the plan
Call `.../treatment-plan/status` until it says `awaiting_review` (about 3 minutes).

### Step 10 — Read the plan
Call `.../treatment-plan`. Check the recommended controls are ones you sent.

### Step 11 — Approve it
Call `.../treatment-plan/review` with `{"decision":"approved","plan_id":"<your plan id>"}`.

### Step 12 — See it on the register
Call `GET /v1/entities/78/treatment-plans`. Your plan is listed.

### If something says 403
Your asset does not belong to your entity. Check with the platform team.

### If something says 422
The message names the field that is wrong. Fix that one field.

### If your threat says "rejected_by_curator"
A reviewer previously declined that exact wording. Your scenario is still saved — just pick a
different threat name if you want it linked to the library.

---

## 15. Clean environment test

Starting from a newly deployed, empty environment:

| # | Action | API? |
|---:|---|---|
| 1 | Create the database; set `READ_COMMITTED_SNAPSHOT ON` | No — DBA |
| 2 | Run the 7 SQL scripts in order (3.2) | No — SQL |
| 3 | Confirm the platform's asset tables have rows | No — platform team |
| 4 | Set `.env`: admin key, `TSG_RISK_MODULE_ENABLED=true`, model endpoints | No — config |
| 5 | Start Redis, Mongo, API, **both** Celery workers, beat | No — `start.ps1` |
| 6 | `GET /health`, `GET /ready` | Yes |
| 7 | `POST /v1/tsg/api-clients`, save the secret | Yes |
| 8 | *(optional)* Threat Intel block: library import, techniques rebuild, feeds refresh (§0.3 block 2) | Yes |
| 9 | `POST /v1/tsg/threat-library/embeddings/update` (§0.3 block 3) | Yes |
| 10 | `GET /v1/tsg/grounding/threshold` → `POST /v1/tsg/grounding/calibrate` (§0.3 block 4 — **after** 9) | Yes |
| 11 | Run the end-to-end scenario (16) | Yes |

Steps 1-5 are **performed outside the API layer** and cannot be done with any endpoint.

---

## 16. Complete end-to-end test scenario

One dataset, start to finish. Values below were observed on a live run.

```
STEP A   GET /health                                     -> 200
STEP B   GET /ready                                      -> 200, all checks ok
STEP C   POST /v1/tsg/api-clients                        -> secret = a6748c88...
STEP D   POST /v1/remediation-plans  (is_manual=true)    -> 202
         session_id  = 65d8c0ff-d8c5-89a0-9359-01a0cdcc2cf4
         scenario_id = e19af86c-5469-84e2-b7be-01a0cdcc2d76
         plan_id     = a34c3c26-6661-8e4f-9d3c-01a0cdcc2e2e
         library     = threat: existing, threat_type: existing
STEP E   GET /v1/sessions/{session_id}                   -> mode MANUAL, overall complete
STEP F   GET /v1/sessions/{session_id}/results           -> scenario_source manual,
                                                            score null, 10 controls in order
STEP G   POST /v1/remediation-plans (same key and body)  -> 200, replayed true, same ids
STEP H   POST /v1/remediation-plans (same key, asset 100)-> 409 idempotency_key_conflict
STEP I   POST /v1/sessions           (same key)          -> 409 idempotency_key_conflict
STEP J   POST .../regenerate/scenarios                   -> 409 reason manual_session
STEP K   POST .../scenarios/next-set                     -> 409 reason manual_session
STEP L   GET  .../treatment-plan/status  (poll ~3.5 min) -> awaiting_review
STEP M   GET  .../treatment-plan                         -> 9 of the 10 sent codes, none else
STEP N   GET  .../treatment-plan/evidence?plan_id=...    -> all 10 codes, in order
STEP O   GET  /v1/entities/78/treatment-plans            -> scenario_source manual
STEP P   POST .../unaccept  then  POST .../scenarios/reject -> 200, 200
```

**Add this for the library path:**

```
STEP Q   POST /v1/remediation-plans with a NEW threat type and threat
             -> library.threat.status = inserted, message "awaiting a curator's review"
STEP R   GET  /v1/tsg/threat-intel/library/pending
             -> the row, source 'manual', created_by = your user id.  Copy catalogue_id
STEP S   POST /v1/tsg/threat-intel/library/threats/reject  {"catalogue_ids":[<id>]}
             -> rejected, type_removed true
STEP T   POST /v1/remediation-plans with the SAME wording again
             -> 202, saved, threat_catalogue_id null,
                library.threat.status = rejected_by_curator, NOT re-proposed
```

Step T is the most valuable test in this document: it proves a curator's decision holds, while the
person's own words are never thrown away.

---

## 17. Final testing checklist

- [ ] Database created and `READ_COMMITTED_SNAPSHOT` is ON
- [ ] All 7 SQL scripts run, `6. TSG_Verify.sql` passes
- [ ] Platform asset/entity tables populated
- [ ] `.env` set: admin key, risk module enabled, model endpoints
- [ ] Redis, Mongo, API, both Celery workers, beat running
- [ ] `GET /health` returns 200
- [ ] `GET /ready` shows every check `ok`, including `workers_celery`
- [ ] API key minted and stored safely
- [ ] Embeddings updated after the SQL load
- [ ] Grounding threshold checked
- [ ] AI path: session, poll, results, accept
- [ ] Manual path: one call returns three ids
- [ ] Idempotency: replay 200, wrong asset 409, cross-kind 409
- [ ] AI refusals: regenerate and next-set both 409 `manual_session`
- [ ] Plan completes and cites only the codes you sent
- [ ] Evidence shows the same codes, in order
- [ ] Review recorded with `plan_id`
- [ ] Register shows the correct `scenario_source`
- [ ] Library outcomes tested: existing, inserted, rejected_by_curator
- [ ] Database checked with the queries in 8.7
- [ ] Error cases from 8.9 tested
- [ ] Test data cleaned up (unaccept + reject)

---

## 18. Known limitations

| Limitation | Detail |
|---|---|
| No asset API | Assets and entities come from platform tables only (3.3) |
| No master-data CRUD API | Threat categories/types/threats arrive via seed SQL, library import, or promote plus approve |
| No delete | Scenarios and plans are unaccepted/rejected, never deleted — audit is permanent |
| Secret shown once | A lost API key cannot be recovered; create a new client |
| One session per asset | A second concurrent run is a 409 |
| Manual scenarios are never regenerated by AI | By design — the person's words are theirs |
| No Postman collection in the repository | Use the cURL examples here, or generate a client from `/openapi.json` |

---

*Written against the implementation in this repository. Where the code and this document disagree,
the code is right — please report it.*
