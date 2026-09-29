# TSG API Reference — all 66 routes

**What this is.** Every HTTP route the application exposes, grouped by purpose, with its auth,
prerequisites and where it sits in the lifecycle.

**Companion document.** [`End_to_End_API_Testing_Guide.md`](End_to_End_API_Testing_Guide.md)
walks the main path in depth. This file is the complete list.

**How the count is guaranteed.** Every route must appear in one of the two registries in
`app/api/route_audit.py`, or `create_app()` refuses to start. That is where this list comes from:
**28 entity-scoped + 38 exempt = 66**. If a route exists and is missing here, this document is
wrong — the application cannot boot with an unregistered route.

---

## 0. Test order — the step numbers shown in Swagger

Run the blocks top to bottom: **0 → 1 → 2 → 3 → 4 → 6 → 7 → 8**. Setup blocks 1-4 must be done
before 6-8: on an unprepared platform the scenario and remediation calls still succeed, but return
weak or empty results. The reasons for each block, and the steps outside the API (database, seed
data, workers), are in the testing guide, [§0 "Before you test"](End_to_End_API_Testing_Guide.md).

Swagger (`/docs`) lists the groups in this order and starts every title with the same step number.
**As needed**, **Curation** and **Recovery** are not part of first-time setup. Two steps share a
number where either may be used (6.2 live stream or polling; 8.1 path-based or `/v1/remediation-plans`).

**This table is hand-maintained, and only part of it is pinned.**
`tests/test_api_testing_docs_are_complete.py` asserts that every route in the registry appears
somewhere in this document and that the route count below matches the registry — it does not read a
single route's Swagger `summary`, so a step number or a title here can drift from `/docs` with the
suite green. The step numbers themselves live only as literals in each route's `summary=`
(`app/api/health.py`, `admin.py`, `sessions.py`, `threat_intel.py`, `treatment.py`), ordered for
display by `_paths_in_test_order` in `app/main.py`. **Where this table and `/docs` disagree, `/docs`
is right** — and the disagreement is a defect in this file, so please report it.

| Step | What it does | Method | Path |
|---|---|---|---|
| | **Health** — Block 0 — first | | |
| 0.1 | Liveness check | GET | `/health` |
| 0.2 | Readiness check | GET | `/ready` |
| | **API Clients Admin** — Setup block 1 — the key everything needs | | |
| 1.1 | Create an API key | POST | `/v1/tsg/api-clients` |
| 1.2 | List API keys | GET | `/v1/tsg/api-clients` |
| As needed | Revoke an API key | POST | `/v1/tsg/api-clients/{client_id}/revoke` |
| | **Threat Intel Admin** — Setup block 2 — content first (threats, techniques, intel) | | |
| 2.1 | Import an open-source threat library (optional) | POST | `/v1/tsg/threat-intel/library/import/{source}` |
| 2.2 | Check a library import | GET | `/v1/tsg/threat-intel/library/import/status/{job_id}` |
| 2.2b | Stream a library import | GET | `/v1/tsg/threat-intel/library/import/events/{job_id}` |
| 2.3 | Rebuild the ATT&CK/CAPEC technique corpus | POST | `/v1/tsg/threat-intel/techniques/rebuild` |
| 2.3b | Stream a technique rebuild | GET | `/v1/tsg/threat-intel/techniques/events/{job_id}` |
| 2.4 | Check the technique corpus | GET | `/v1/tsg/threat-intel/techniques` |
| 2.5 | Refresh every enabled feed | POST | `/v1/tsg/threat-intel/feeds/refresh` |
| 2.5b | Stream a feed refresh | GET | `/v1/tsg/threat-intel/feeds/events/{job_id}` |
| 2.6 | Check threat-intel feed health | GET | `/v1/tsg/threat-intel/feeds` |
| 2.7 | Browse cached intel items | GET | `/v1/tsg/threat-intel/items` |
| As needed | Refresh one feed | POST | `/v1/tsg/threat-intel/feeds/{feed}/refresh` |
| Curation 1 | List threats awaiting curator approval | GET | `/v1/tsg/threat-intel/library/pending` |
| Curation 2 | Approve promoted threats (then run 3.1) | POST | `/v1/tsg/threat-intel/library/threats/approve` |
| Curation 2 | Discard promoted threats | POST | `/v1/tsg/threat-intel/library/threats/reject` |
| | **Embeddings Admin** — Setup block 3 — fingerprint the final library | | |
| 3.1 | Fill in any missing vectors | POST | `/v1/tsg/threat-library/embeddings/update` |
| 3.2 | Check an embedding job | GET | `/v1/tsg/threat-library/embeddings/status/{job_id}` |
| 3.2b | Stream an embedding job | GET | `/v1/tsg/threat-library/embeddings/events/{job_id}` |
| As needed | Embed specific library names | POST | `/v1/tsg/threat-library/embeddings/create` |
| As needed | Rebuild vectors from scratch | POST | `/v1/tsg/threat-library/embeddings/recreate` |
| As needed | Remove vectors permanently | POST | `/v1/tsg/threat-library/embeddings/delete` |
| | **Grounding Admin** — Setup block 4 — LAST: needs the final library + fingerprints | | |
| 4.1 | Get the current matching threshold (repeat as 4.4) | GET | `/v1/tsg/grounding/threshold` |
| 4.2 | Measure a new matching threshold | POST | `/v1/tsg/grounding/calibrate` |
| 4.3 | Check a calibration sweep | GET | `/v1/tsg/grounding/calibrate/status/{job_id}` |
| 4.3b | Stream a calibration sweep | GET | `/v1/tsg/grounding/calibrate/events/{job_id}` |
| 4.5 | List calibration history | GET | `/v1/tsg/grounding/calibrations` |
| | **Threat Scenario Generation** — Block 6 — run, review, accept | | |
| 6.1 | Start a threat-generation run | POST | `/v1/sessions` |
| 6.2 (or poll) | Check a session's progress | GET | `/v1/sessions/{session_id}` |
| 6.2 | Stream live session progress | GET | `/v1/sessions/{session_id}/events` |
| 6.3 | Read the generated scenarios | GET | `/v1/sessions/{session_id}/results` |
| 6.4 (optional) | Decline scenarios | POST | `/v1/sessions/{session_id}/scenarios/reject` |
| 6.4 (optional) | Rewrite specific scenarios | POST | `/v1/sessions/{session_id}/regenerate/scenarios` |
| 6.4 (optional) | Generate more scenarios | POST | `/v1/sessions/{session_id}/scenarios/next-set` |
| 6.5 | Accept scenarios | POST | `/v1/sessions/{session_id}/accept` |
| 6.6 | List a session's accepted scenarios | GET | `/v1/sessions/{session_id}/accepted-scenarios` |
| 6.7 (optional) | Add a scenario's threat to the library | POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library` |
| As needed | Cancel a session | POST | `/v1/sessions/{session_id}/cancel` |
| As needed | Read a session's history | GET | `/v1/sessions/{session_id}/audit` |
| As needed | Take back an acceptance | POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/unaccept` |
| | **Scenarios** — Block 7 — read-only views | | |
| 7.1 | Fetch one scenario | GET | `/v1/sessions/{session_id}/scenarios/{scenario_id}` |
| 7.2 | List scenarios by user | GET | `/v1/users/{user_id}/scenarios` |
| 7.3 | List scenarios by entity | GET | `/v1/entities/{entity_id}/scenarios` |
| | **Remediation Plans** — Block 8 — needs accepted scenarios | | |
| 8.1 | Request a remediation plan | POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` |
| 8.3 | Read a remediation plan | GET | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan` |
| 8.1 (alternative) | Request a remediation plan for any scenario | POST | `/v1/remediation-plans` |
| 8.2 | Check a remediation plan's status | GET | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/status` |
| 8.4 | Get a plan version's evidence bundle | GET | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/evidence` |
| 8.5 | Approve or decline a remediation plan | POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/review` |
| 8.6 (optional) | Regenerate a remediation plan | POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/regenerate` |
| 8.7 | List a session's remediation plans | GET | `/v1/sessions/{session_id}/treatment-plans` |
| 8.7 | List an entity's remediation plans | GET | `/v1/entities/{entity_id}/treatment-plans` |
| 8.8 | Read one scenario's plan history | GET | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/audit` |
| 8.8 | Read an entity's plan activity | GET | `/v1/entities/{entity_id}/treatment-plans/audit` |
| As needed | Cancel a running plan generation | POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/treatment-plan/cancel` |
| | **Control Mapping Admin** — steps 4.6-4.7 belong with block 4; the sweep is Recovery only | | |
| 4.6 | Measure the control-relevance cutoff | POST | `/v1/tsg/control-map/calibrate` |
| 4.7 | Check a control-relevance measurement | GET | `/v1/tsg/control-map/calibrate/status/{job_id}` |
| Recovery | Run the control-mapping retry sweep now | POST | `/v1/tsg/control-map/sweep` |

---

## 1. Authentication at a glance

| Group | Headers | Count |
|---|---|---|
| **Business** (entity-scoped) | `X-API-Key`, `X-User-Id`, `X-Entity-Id`, `X-Tenant-Id` | 28 |
| **Admin** (`admin.py`, `threat_intel.py`) | `X-Admin-Key`, `X-API-Key`, `X-User-Id` (tenant optional) | 28 |
| **API clients** | `X-Admin-Key` (+ `X-User-Id` on create and revoke) | 3 |
| **Public** | none | 3 |

Notes:
- A blank `TSG_ADMIN_API_KEY` makes **every** admin route return 401. That is deliberate — an
  unconfigured admin key must never mean "open to everyone".
- The api-client routes take no `X-API-Key` on purpose: minting a key must not require one.
- `X-API-Key` is the credential; `X-User-Id` and `X-Entity-Id` are trusted input from the calling
  service. Keys are therefore server-side only.

## 2. Feature flags that change what exists

| Setting | Default | Effect when off |
|---|---|---|
| `TSG_RISK_MODULE_ENABLED` | `false` | The **12 remediation-plan routes** are not mounted — 404 by absence |
| `TSG_REMEDIATION_CONTROL_TOP_UP_ENABLED` | `true` | Either plan route plans the scenario with whatever controls it has — no top-up to `TSG_CONTROL_MAP_MIN_COUNT` (default 5). The older name `TSG_REMEDIATION_CONTROL_MIN_COUNT` is **RETIRED**: it supplies nothing, and leaving it in the environment now **refuses the boot** naming `TSG_CONTROL_MAP_MIN_COUNT` as its replacement. See section 7 |
| `TSG_CONTROL_MAP_SWEEP_ENABLED` | `true` | Only the **scheduled** retry sweep stops. `POST /v1/tsg/control-map/sweep` still works — see section 9 |
| `APP_ENV` | `prod` | `/dev/sse-test` mounts only in `local` or `dev` |
| `TSG_ADMIN_API_KEY` | `""` | Routes exist but all **31 admin routes** return 401 |
| `verify_membership` | `false` | When on, adds a `(user, entity)` check — a mismatch becomes 403 |

**Settings that change how many controls a scenario gets.** These do not add or remove routes.
They change what comes back in every scenario's `controls` list and therefore what every
remediation plan is written against. Section 9 explains the rules they drive.

| Setting | Value in this deployment | What it decides |
|---|---|---|
| `TSG_CONTROL_MAP_SHORTLIST_K` | 60 | How many of the 1288 active controls are scored at all. Anything outside the shortlist can never be mapped |
| `TSG_CONTROL_MAP_MIN_SCORE` | 50, set in `.env` | The relevance cutoff, 0-100 — but only the **bootstrap** one. A stored control-map measurement for the models in use out-votes it; this line decides only until one exists. Section 9 has the precedence |
| `TSG_CONTROL_MAP_MIN_COUNT` | 5 (the default) | A **minimum target**, never a cap |
| `TSG_CONTROL_MAP_MAX_COUNT` | 25 (the default) | A runaway guard, never a target |
| `TSG_CONTROL_MAP_BACKFILL_RATIO` | 0.42 (the default) | The backfill/top-up floor, as a **fraction of whichever cutoff is in force** — not an absolute. At this deployment's cutoff of 50 the floor resolves to **21.0** (0.42 × 50). Move the cutoff and the floor moves with it |
| `TSG_CONTROL_MAP_BACKFILL_MIN_SCORE` | unset (commented out in `.env` and `.env.uat`) | **Deprecated absolute override** of the ratio. Honoured only when the name is actually present in the environment *and* the number lands strictly below the cutoff in force; otherwise it is ignored and the log records `controls.backfill_floor_override_ignored`. Its field default (25.0) is the floor of no deployment |

**Do not compute the floor by hand — read it back.** Every `controls_mapped` audit row publishes
`effective_min_score`, `effective_min_score_origin` and `effective_backfill_min_score` (the resolved
absolute), which is the only place the number that was actually applied can be confirmed.

**What is refused at boot** is `Settings._validate_control_map_counts` in `app/core/config.py` — the
count relationships only, because those are the ones config.py can see:

| Rule | Why |
|---|---|
| The shortlist must be **at least** the ceiling (`TSG_CONTROL_MAP_SHORTLIST_K` ≥ `TSG_CONTROL_MAP_MAX_COUNT`; 60 ≥ 25 here) | A scenario can only keep controls that were scored. A shortlist narrower than the ceiling makes the ceiling unreachable and caps every scenario at the shortlist width instead |
| The minimum must be **at or below** the ceiling (`TSG_CONTROL_MAP_MIN_COUNT` ≤ `TSG_CONTROL_MAP_MAX_COUNT`; 5 ≤ 25 here) | A minimum above the ceiling is a target that can never be met. `TSG_CONTROL_MAP_TOP_K` used to make this easy to hit by accident, because it aliased the **ceiling**; it is now **RETIRED** and aliases nothing, so an old `TSG_CONTROL_MAP_TOP_K=5` left in place **refuses the boot** naming `TSG_CONTROL_MAP_MAX_COUNT` instead of silently pinning the ceiling back to 5. Delete the line and set the ceiling you actually want (`RETIRED_ENV_NAMES` in `app/core/config.py`) |

**There is no boot check on the floor, deliberately, and none is coming.** The old
`control_map_backfill_min_score >= control_map_min_score` validator was deleted rather than left
reading like a guarantee: the cutoff resolves at run time from one of three sources (section 9), two
of which `config.py` cannot see, so a boot comparison covered one case in three while looking like
it covered all of them. The guarantee is structural instead, in two places that do cover every
source: `TSG_CONTROL_MAP_BACKFILL_RATIO` is bounded `0 < r < 1`, so a fraction of any positive cutoff
is strictly below that cutoff and the backfill band can never be empty; and
`control_mapping._backfill_floor` resolves the floor against the cutoff really in force and refuses a
deprecated absolute that would empty the band. **A bad floor therefore fails in the log, not at
boot** — grep for `controls.backfill_floor_override_ignored`.

## 3. Legend

| Phase | Meaning |
|---|---|
| **Setup** | Run once per environment |
| **Config** | Changes how the system behaves |
| **Business** | Creates or changes real data |
| **Processing** | Polls or drives work in progress |
| **Result** | Read-only |
| **Finalisation** | Closes a workflow |
| **Curation** | Library review |

"Guide" points at the section of the end-to-end guide covering that route.

---

## 4. Public routes (3)

| Method | Path | Phase | Purpose | Prerequisite | Guide |
|---|---|---|---|---|---|
| GET | `/health` | Readiness | Is the API process alive? | App running | 4 |
| GET | `/ready` | Readiness | DB, Redis, Mongo (workers reported, not enforced; **no data checked**) | Infrastructure | 4 |
| GET | `/dev/sse-test` | Dev only | Browser harness for the SSE stream | `APP_ENV` is local or dev | — |

---

## 5. API client administration (3)

Auth: `X-Admin-Key`. Create and revoke also need `X-User-Id`.

| Method | Path | Phase | Purpose | Key output | Guide |
|---|---|---|---|---|---|
| POST | `/v1/tsg/api-clients` | Setup | Mint an API key | `secret` (**shown once**), `client_id` | 5 |
| GET | `/v1/tsg/api-clients` | Result | List clients (never secrets) | — | — |
| POST | `/v1/tsg/api-clients/{client_id}/revoke` | Finalisation | Disable a key | — | — |

There is no un-revoke and no update. To rotate: create a new client, then revoke the old one.

---

## 6. Threat scenario generation — the AI path (16)

Auth: business headers. All are entity-scoped; the entity in the path or body must match
`X-Entity-Id`.

| Method | Path | Phase | Purpose | Prerequisite | Guide |
|---|---|---|---|---|---|
| POST | `/v1/sessions` | Business | Start an AI run for one asset | Asset rows, API key | 7.1 |
| GET | `/v1/sessions/{session_id}` | Processing | Status board — poll until review | A session | 7.2 |
| GET | `/v1/sessions/{session_id}/events` | Processing | Live SSE stream instead of polling | A session | 7.2 |
| GET | `/v1/sessions/{session_id}/results` | Result | The generated scenarios | Run reached review | 7.3 |
| POST | `/v1/sessions/{session_id}/accept` | Business | Keep chosen scenarios | Results read | 7.4 |
| POST | `/v1/sessions/{session_id}/scenarios/reject` | Business | Discard scenarios | Results read | 10.3 |
| POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/unaccept` | Business | Undo an acceptance | Accepted scenario | 10.3 |
| POST | `/v1/sessions/{session_id}/regenerate/scenarios` | Processing | Rewrite chosen scenarios | Session at review | — |
| POST | `/v1/sessions/{session_id}/scenarios/next-set` | Processing | Ask for more scenarios | Session at review | — |
| POST | `/v1/sessions/{session_id}/cancel` | Finalisation | Stop a running session | A running session | — |
| POST | `/v1/sessions/{session_id}/scenarios/{scenario_id}/promote-to-library` | Curation | Propose this threat to the library | Accepted scenario | 8.8 |
| GET | `/v1/sessions/{session_id}/accepted-scenarios` | Result | Only the accepted ones | Accept done | — |
| GET | `/v1/sessions/{session_id}/scenarios/{scenario_id}` | Result | One scenario | A scenario | — |
| GET | `/v1/sessions/{session_id}/audit` | Result | Step-by-step trail of the session | A session | — |
| GET | `/v1/users/{user_id}/scenarios` | Result | A user's scenarios across sessions | — | 3.3 |
| GET | `/v1/entities/{entity_id}/scenarios` | Result | An entity's scenarios across sessions | — | — |

**Regenerate and next-set refuse a hand-written session** with 409 and
`details.reason = "manual_session"`. The AI never rewrites a person's scenario.

---

## 7. Remediation plans (12)

Auth: business headers. **All 12 require `TSG_RISK_MODULE_ENABLED=true`, or they return 404.**

| Method | Path | Phase | Purpose | Prerequisite | Guide |
|---|---|---|---|---|---|
| POST | `/v1/remediation-plans` | Business | **One door for both kinds of scenario** | See guide 8.3 | 8 |
| POST | `/v1/sessions/{sid}/scenarios/{scid}/treatment-plan` | Business | The older path-based create | Accepted scenario | 8 |
| POST | `.../treatment-plan/regenerate` | Processing | Make a new plan version | A plan exists | — |
| GET | `.../treatment-plan/status` | Processing | Cheap poll: lifecycle and review only | A plan | 9.1 |
| GET | `.../treatment-plan` | Result | The full plan | A plan | 9.2 |
| GET | `.../treatment-plan/evidence` | Result | Exactly what the AI was given | A plan | 9.3 |
| GET | `.../treatment-plan/audit` | Result | That plan's history | A plan | — |
| POST | `.../treatment-plan/cancel` | Finalisation | Stop a running generation | Plan generating | — |
| POST | `.../treatment-plan/review` | Finalisation | Approve or decline | Plan COMPLETE | 10.1 |
| GET | `/v1/sessions/{session_id}/treatment-plans` | Result | Plan board for one session | A session | — |
| GET | `/v1/entities/{entity_id}/treatment-plans` | Result | **The GRC register** | — | 10.2 |
| GET | `/v1/entities/{entity_id}/treatment-plans/audit` | Result | Entity-wide plan activity | — | — |

`...` means `/v1/sessions/{session_id}/scenarios/{scenario_id}`.

`POST /v1/remediation-plans` with `is_manual=false` is the same operation as the path-based create —
the same code runs, the control top-up below included. With `is_manual=true` it also saves and
accepts the scenario first.

**Control top-up (every first plan request, both routes, both kinds of scenario).** Before the plan
is created, a scenario with fewer than `TSG_CONTROL_MAP_MIN_COUNT` (default 5) live mapped controls
is mapped against the Control Library:

| Rule | Behaviour |
|---|---|
| Who | Every scenario the plan is being written for, whoever wrote it — with ONE exception: a hand-written scenario that carries controls **the person chose** is never re-mapped, replaced or added to, however few it has (provenance is read from the scenario row, not from the `is_manual` flag). A hand-written scenario saved **without** `mapped_controls` is mapped exactly as a generated one is |
| Mapping need not be finished first | An AI scenario whose Step-4 mapping has not settled (`ControlsMappedAt` empty) is mapped **on the spot** here and stamped in the same transaction — but only when rows were really written, so a failed match still leaves it empty for the retry sweep. It used to be skipped here altogether; and before that, stamping it unconditionally retired it from the scored pass for good |
| How many | A scenario with **no** map rows at all is sized the way the scored pass sizes one: at least `TSG_CONTROL_MAP_MIN_COUNT` (5), every control above the cutoff, never past `TSG_CONTROL_MAP_MAX_COUNT` (25, a safety cap and never a target). A scenario that already has rows is only topped up to the minimum — a plan request is not the place to grow a list that was sized once already |
| When skipped | Switch off (`TSG_REMEDIATION_CONTROL_TOP_UP_ENABLED=false`), scenario already at the minimum, a hand-written scenario with the person's own controls, a regenerate of a scenario that already has live controls, or a request the route will refuse anyway (not accepted, plan already exists on a first generation, missing, not your entity) — no matching work is spent |
| What is added | Distinct, active Control Library controls not already mapped. Ranked by the same two-round search and scorer scenario generation uses, from one query built in this order: threat category, threat type, threat name, threat actors, scenario title, scenario statement, risk statement, asset name and technology, then the systems the scenario involves. Threat identity leads deliberately — the asset context trails, where a length clip costs least |
| Nothing relevant enough | Nothing below the **backfill floor** is ever added — `TSG_CONTROL_MAP_BACKFILL_RATIO` × the cutoff in force, which is 21.0 in this deployment (0.42 × 50). If only 3 controls above that floor exist, the scenario ends with 3 — there is no arbitrary filler. If **nothing** clears the floor, nothing is added and **no audit row is written at all**: an absent `remediation_top_up` row is the record that the top-up ran and found nothing |
| Where it shows | New rows appear in the scenario's `controls` (`/results`, the plan's `existing_controls.library_mapped` on `/evidence`). The scenario's whole list is then re-ordered by the one ordering rule in section 9 — so a topped-up control sits where that rule puts it, not appended at the end. One `controls_mapped` audit row with `"source": "remediation_top_up"` lists the ids and scores of what was added |
| Matching service down | **The plan still starts** (`202`) with the controls already mapped, and the plan's `warnings` say which of three things happened — see "Three different control warnings" below. They are not interchangeable |
| Path-based create, regenerate | The path route `POST .../treatment-plan` tops up too — it is the same call. **Regenerate** tops up only a scenario with **no live controls at all**, so a first attempt that matched nothing can be repaired by regenerating while a scenario that already has controls is never changed by writing its plan again |
| What is recorded | The request body is kept verbatim under `detail.request` on the plan's `treatment_plan_requested` audit event (secrets redacted; `risk_owner` is masked in the log line only, never on the row). A top-up that wrote rows adds a `controls_mapped` row with `"source": "remediation_top_up"`, plus `stamped` and `scenario_source` |

**Three different control warnings — do not read them as one.** Every plan's `warnings` can carry
one of these, and they answer different questions
(`app/pipeline/treatment_input.py::read_library_controls_for_snapshot`):

| Warning | What it means | What to do |
|---|---|---|
| `library control lookup failed — plan generated without mapped controls` | The read of the Step-4 map **raised**. This is a fact about the database, not about the scenario: the plan was written with no library controls because none could be read | **Retry.** Never read the empty `library_mapped` list as a library gap. A degraded run graded as a clean one is exactly what this warning exists to prevent |
| `no library-mapped controls for this scenario (Step-4 map is empty)` | The read **succeeded** and the map really is empty — nothing cleared the floor, whoever wrote the scenario | Believe it. A hand-written scenario saved without `mapped_controls` is mapped like a generated one, so this says the match itself found nothing above the floor: run the sweep or measure the cutoff (section 9) |
| `only N of the minimum M library-mapped controls — top-up could not reach the floor` | The scenario has at least one control but fewer than `TSG_CONTROL_MAP_MIN_COUNT` (5 here), and the top-up could not close the gap above the backfill floor | Often correct — a scenario may legitimately have 3 relevant controls |

The first two are mutually exclusive by construction: the empty-map warning is emitted only when the
read did **not** fail. A regenerated plan can also carry one warning per control the previous version
carried and this one does not — `control <code> (<name>) was in the previous version but <why> —
omitted from this version`, where `<why>` is one of *has been retired from the control library*, *is
no longer in the control library*, *is no longer mapped to this scenario*, or *is no longer
available* when the reason could not be read.

**Plan schedule (every plan, both kinds).** The AI never writes a date. For each action it gives only
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

**Dates count both ends.** A 14-day action starting `2026-10-01` ends `2026-10-14`, and an action
waiting on it starts `2026-10-15`. The window is counted the same way: `2026-10-01` → `2026-12-31`
is 92 days, and a same-day window holds exactly one day of work.

**Plans generated before this change** are served with the same keys: the new fields come back as
`null` (`duration_days`, `start_date`, `end_date`, `mitigation_timeline_days`,
`mitigation_end_date_planned`) or `[]` (`depends_on`, `implements_controls`). Stored rows are not
changed.

**Schedule checks.** TSG repairs what it can and adds a warning to the plan's `warnings` — it never
blocks the plan:

| When | Warning (example) | What TSG does |
|---|---|---|
| Ids are not `A1..An` in order | `action ids are not A1..A3 in order: [...]` | Schedules as listed |
| An action waits on a later, unknown or its own id | `A2.depends_on 'A9' is not an earlier action — ignored` | Drops that link (so no loop is possible) |
| `depends_on` is missing | `A2.depends_on is missing — scheduled with no prerequisites` | Treats it as starting immediately |
| The `dependencies` text names an action the ids don't include | `A2.dependencies mentions A1 but depends_on does not include it` | Schedules from the ids |
| The text says `None` but the ids name prerequisites | `A2.dependencies says None but it waits for A1` | Schedules from the ids |
| A duration is not a whole number of days ≥ 1, or above 3650 | `A2.duration_days 'ten' is not a whole number of days of at least 1 — scheduled as 1 day` | Uses 1 day, or caps at 3650 |
| An action is listed after work that starts later | `A4 is listed after work that starts later (day 5) although it can start on day 0 — the sequence is out of order` | Schedules correctly anyway |
| A Critical/High action waits on a less urgent one | `A1 (Low) is a prerequisite of A2 (Critical) but is less urgent than the work it blocks` | Keeps the dependency |
| `implements_controls` is missing | `A2.implements_controls is missing — treated as delivering no control` | Treats it as `[]` |
| An action names a control not in the plan | `A1.implements_controls names 'BOGUS', which is not a control of this plan` | Keeps it |
| A recommended control has no action | `recommended control C2 is not implemented by any action` | — |
| `action_plan` states a total that differs from the computed one | `action_plan states 45 days but the computed critical path is 40 days` | The computed total is served |
| Dates sent and the plan ends after the window | `the plan finishes 2027-01-13, 13 days after the mitigation window closes (2026-12-31)` | — |
| No dates sent | `no mitigation window supplied — the 40-day schedule is not bounded by a register deadline` | — |

The rule that the plan **ends with a validation action** whenever a control is implemented or
changed is enforced by the prompt only; TSG does not check it.

**The controls the plan was written against** are frozen into the plan's snapshot, so
`GET .../treatment-plan/evidence` shows them exactly as the AI saw them, in mapped-rank order. The
snapshot is a **narrower set of fields** than a mapped control on `/results` — it is what the AI was
given, not the API's own view:

| Snapshot field | Notes |
|---|---|
| `control_library_id` | The same number `/results` publishes as `control_id`, under the name the library uses |
| `control_code`, `control_name` | As on `/results` |
| `itot`, `domain` | As on `/results` |
| `control_description` | The library text, capped in length here (`/results` serves it uncapped). The AI reads this to judge whether the risk is already covered, rather than guessing from a control's name |
| `mapping_relevance` | The match confidence 0-100, or `null` — `null` only for a control the person chose |
| `covered_by_register` | Set by TSG, not by the AI: `true` when one of the request's `existing_controls` entries **named this very library row** (by `control_id`, `control_code` or exact `control_name`). The plan may never recommend such a control, and one that slips through is dropped with a warning. `existing_controls.register_matched_count` is how many matched. Free-text register entries carry no id and are judged by the AI by meaning instead |
| `standards` | Plain standard **names** only — not the `standard_id` + `standard_name` pairs `/results` returns |

There is deliberately **no `map_rank` and no `score`** in the snapshot: the order of the list is the
rank, and `mapping_relevance` is the score under its documented name.

Test it: take an accepted scenario with fewer than 5 controls, ask for its first plan on either
route (`POST /v1/remediation-plans` with `is_manual=false`, or the path-based create), then read
`GET .../treatment-plan/evidence` —
`existing_controls.library_mapped_count` is 5, or lower with the plan's warnings naming the
shortfall when too few controls clear the backfill floor.

---

## 8. Threat intel and library administration (14)

Auth: admin headers.

### Feeds

| Method | Path | Phase | Purpose | Output |
|---|---|---|---|---|
| GET | `/v1/tsg/threat-intel/feeds` | Result | Configured feeds and their state | — |
| GET | `/v1/tsg/threat-intel/items` | Result | Items pulled from feeds | — |
| POST | `/v1/tsg/threat-intel/feeds/refresh` | Config | Refresh every feed | `jobs` map of `job_id` |
| POST | `/v1/tsg/threat-intel/feeds/{feed}/refresh` | Config | Refresh one feed | `job_id` |
| GET | `/v1/tsg/threat-intel/feeds/events/{job_id}` | Processing | Live progress (SSE) | — |

### Library import

| Method | Path | Phase | Purpose | Output |
|---|---|---|---|---|
| POST | `/v1/tsg/threat-intel/library/import/{source}` | Config | Bulk-import library data | `job_id` |
| GET | `/v1/tsg/threat-intel/library/import/status/{job_id}` | Processing | Import progress | — |
| GET | `/v1/tsg/threat-intel/library/import/events/{job_id}` | Processing | Live progress (SSE) | — |

`{source}` must be one of `pytm`, `emb3d`, `atlas`, `misp_actors` — anything else is a 422
`admin_validation_error` (section 13), and so is `max_actors` on any source but `misp_actors`. Use
`dry_run` first. A second import while one runs is a 409.

### Curation — the queue a manual scenario feeds

| Method | Path | Phase | Purpose | Guide |
|---|---|---|---|---|
| GET | `/v1/tsg/threat-intel/library/pending` | Curation | Names awaiting review, with `source` and `created_by` | 16 |
| POST | `/v1/tsg/threat-intel/library/threats/approve` | Curation | Make names official (max 100 ids) | 16 |
| POST | `/v1/tsg/threat-intel/library/threats/reject` | Curation | Refuse names permanently | 16 |

There is deliberately **no "approve everything"**: one such call would make every AI-invented
threat official and defeat the review the pending state exists to force.

Rejecting the last pending threat of a pending type removes that type too — the response says
`type_removed: true`. A rejected name is never proposed again; a later scenario using that wording
is still saved, but is not linked to the library (see the `library` block, guide 8.8).

### Techniques

| Method | Path | Phase | Purpose | Output |
|---|---|---|---|---|
| POST | `/v1/tsg/threat-intel/techniques/rebuild` | Config | Rebuild the ATT&CK / CAPEC corpus | `job_id` |
| GET | `/v1/tsg/threat-intel/techniques` | Result | The corpus (`total: 0` means scenarios run without it) | — |
| GET | `/v1/tsg/threat-intel/techniques/events/{job_id}` | Processing | Live progress (SSE) | — |

---

## 9. Embeddings, grounding and control mapping (14)

Auth: admin headers.

### Embeddings — the vector cache

| Method | Path | Phase | Purpose |
|---|---|---|---|
| POST | `/v1/tsg/threat-library/embeddings/create` | Config | Embed the exact names you list (`group` and `names` both required) |
| POST | `/v1/tsg/threat-library/embeddings/update` | Config | Fill in anything missing. **The safe default** |
| POST | `/v1/tsg/threat-library/embeddings/recreate` | Config | Delete then re-embed |
| POST | `/v1/tsg/threat-library/embeddings/delete` | Config | Delete without rebuilding |
| GET | `/v1/tsg/threat-library/embeddings/status/{job_id}` | Processing | Job outcome |
| GET | `/v1/tsg/threat-library/embeddings/events/{job_id}` | Processing | Live progress (SSE) |

> **Danger — and it is not the same danger on both routes.**
>
> `recreate` with no `group` really does target **every group**: the whole cross-tenant vector cache
> is deleted and re-embedded. It is slow, it costs real AI calls, and nothing refuses it — but it
> self-heals, because it rebuilds what it removed. Always name a `group`.
>
> `delete` does not rebuild, so it has no self-heal — which is why a bare `{}` is **refused**, not
> obeyed: `422 admin_validation_error`, "delete requires group and/or names — refusing to wipe the
> entire cache with an empty request" (`app/api/admin.py`). `names` without a `group` is refused on
> both routes ("names requires a specific group"). In practice `delete` requires a `group`.

### Grounding — the match threshold

| Method | Path | Phase | Purpose | Output |
|---|---|---|---|---|
| GET | `/v1/tsg/grounding/threshold` | Result | Current value and where it came from | `origin` |
| POST | `/v1/tsg/grounding/calibrate` | Config | Measure a new threshold | `job_id`, `run_id` |
| GET | `/v1/tsg/grounding/calibrate/status/{job_id}` | Processing | Sweep progress | — |
| GET | `/v1/tsg/grounding/calibrate/events/{job_id}` | Processing | Live progress (SSE) | — |
| GET | `/v1/tsg/grounding/calibrations` | Result | History of past sweeps | — |

> **Cost.** Calibration is the only way to start a sweep — nothing queues one automatically. A
> forced sweep is roughly 10-15 minutes of billed LLM calls and overwrites the live threshold with
> no undo. Without `force`, a pair already calibrated finishes immediately and makes no AI calls.

### Control mapping

| Method | Path | Phase | Purpose | Output |
|---|---|---|---|---|
| POST | `/v1/tsg/control-map/calibrate` | Config | Measure the control-relevance cutoff for the models running now | `job_id`, `run_id` |
| GET | `/v1/tsg/control-map/calibrate/status/{job_id}` | Processing | That measurement's progress and result | `cutoff`, `cutoff_in_force`, `cutoff_origin`, `stricter_alternative`, `scenarios` |
| POST | `/v1/tsg/control-map/sweep` | Config | Run the control-mapping retry sweep now | `job_id`, `queue` |

> **Measure the cutoff, do not borrow it.** Control matching queries the library with a scenario
> *paragraph*; the grounding threshold was measured on a short *label*. The two score on different
> scales, so without its own measurement the cutoff is a guess — and a cutoff set too high leaves
> nothing clearing it, so the backfill fills each scenario from *below* the cutoff instead (down to
> `TSG_CONTROL_MAP_BACKFILL_RATIO` × the cutoff). The scenario then reads as a thin library rather
> than a wrong cutoff, and where not even that floor is reached the `controls` list is empty, which
> this document describes as a healthy library gap. Either way the cost lands on a reviewer as the
> library's fault. Run the measurement after seeding or curating the control library, after swapping
> either model, and whenever scenarios come back with no controls and you do not believe it.
>
> Bounds and cost: it reranks real scenarios against the whole active library and takes minutes;
> `limit` (default 50, 5-500) bounds how many scenarios are measured. A second call while one runs
> is a `409` — the same guard the grounding sweep uses, keyed on the model pair, so the two cannot
> run at once. If retrieval comes back empty the run reports that and stores **nothing** rather
> than storing a zero, so `SUCCESS` with a null `cutoff` is a real answer. `stricter_alternative`
> is recorded for you to consider and is never applied. The result is stored against the **model
> pair**, not the environment, so one measurement covers every deployment on the same two models;
> the status route reads that permanent record rather than a job result, so unlike the other
> job-status routes it never expires.
>
> **Where the cutoff comes from — three sources, in this order.**
> `control_mapping._min_score` resolves it per pass, and each branch records its own origin in the
> `controls_mapped` audit row (`effective_min_score`, `effective_min_score_origin`). **The order was
> INVERTED on 2026-09-25** by the repo owner's decision — the database has the final say, the env
> file is what runs until the database has an answer — because the env value is a guess written
> before anyone measured the deployment, while the measurement is the answer got by scoring real
> scenarios against the real library. Do not re-order this table back:
>
> | # | Source | Audit `origin` |
> |---|---|---|
> | 1 | The stored measurement: the newest successful `Grounding_Calibration_Run.ControlMapTh` **for this exact embedding + reranker pair**. This is what step 4.6 writes, and it is the only number ever measured for the question this stage asks — so it out-votes the env file. A cutoff measured under a different model pair is invisible here, and a stored `0.0` is a real measurement, not absence | `calibrated_for_control_mapping` |
> | 2 | `TSG_CONTROL_MAP_MIN_SCORE`, but **only when that name is actually present in the environment**. It is, at 50, in this deployment. This is the BOOTSTRAP: it is the branch in force here only because no control-map measurement has been stored for the models in use yet, and it stops deciding the moment one is | `env_pinned` |
> | 3 | The threat-grounding threshold, borrowed and relabelled. Same number as `GET /v1/tsg/grounding/threshold`, wrong scale for this question — it was measured label-against-label, and control mapping asks paragraph-against-control-text | `borrowed_from_threat_grounding_uncalibrated` |
>
> **So "picks it up with no restart" is now unconditional for the matching model pair.** A
> successful step 4.6 IS the cutoff on the next mapping pass — `_min_score` runs once per pass, not
> once at boot, and nothing is memoised, so there is no restart, no redeploy and no configuration
> edit in the loop. This deployment's live `TSG_CONTROL_MAP_MIN_SCORE=50` does not delay it and does
> not need commenting out. Two things still prevent pickup: a run that **stored nothing** (`SUCCESS`
> with a null `cutoff` — retrieval faulted, `ControlMapTh` stays NULL and the previous cutoff
> stands), and a **change to either model**, because branch 1 is keyed on the pair and a measurement
> taken under other models is invisible — which is also why a UAT measurement governs production
> only while both model names match.
>
> **To overrule a measurement you need another measurement.** Editing `TSG_CONTROL_MAP_MIN_SCORE`
> will not do it: supersede the winning run with a newer one for the same pair, or clear
> `ControlMapTh` on the row that is winning and let branch 2 answer again. If an edit to the env
> file appears to have had no effect, `effective_min_score_origin` on the next `controls_mapped`
> audit row says which branch answered instead.

**Two rounds.** The Control Library holds 1288 active controls. For each scenario a fast search
shortlists `TSG_CONTROL_MAP_SHORTLIST_K` controls, then an accurate scorer scores only those,
0-100. A control that is not shortlisted is never scored and can never be mapped, so the shortlist
size is the hard ceiling on what a scenario can ever see. `.env` and `.env.uat` previously set it
to 20 of 1288 — about 1.6% of the library — which was the largest single cause of thin mappings.
It is now 60, the shipped default.

**How many controls a scenario keeps**, in the order the rules apply:

| Step | Rule |
|---|---|
| 1 | Every control scoring at or above **the cutoff in force** — 50 here, `env_pinned`, because no measurement has been stored for these models yet; the three sources are above, in order — is kept. **All of them:** a scenario with 8 controls above the cutoff keeps 8 |
| 2 | Fewer than `TSG_CONTROL_MAP_MIN_COUNT` (default 5) cleared? A **backfill** tops the list up with the next-best already-scored controls — but never one below the **backfill floor**, `TSG_CONTROL_MAP_BACKFILL_RATIO` × that cutoff (0.42 × 50 = **21.0** here). If only 4 controls above that floor exist, 4 are returned. Backfilled controls always sit after every control that cleared the cutoff |
| 3 | `TSG_CONTROL_MAP_MAX_COUNT` (default 25) stops the list there. It is a runaway guard so one scenario cannot attach a large slice of the library; nothing is ever padded up to it |

A scenario used to be truncated to 5 even when more controls cleared the cutoff, and the loss was
recorded nowhere. The remediation-time top-up used to have no floor at all: against a cutoff of 50
it once added controls scoring 13.55, 10.21 and 9.53.

**Two mechanisms, two names.** *Backfill* is the rule in step 2, applied while a scenario is being
mapped. *Top-up* is the separate pass on `POST /v1/remediation-plans` described in section 7. Both
stop at the same floor — both call `control_mapping._backfill_floor`, so both resolve it against the
cutoff their own pass is using — and both can leave a scenario short, but only the top-up leaves an
audit row saying `"source": "remediation_top_up"`, which is how you tell them apart after the fact.

**One ordering rule.** A scenario's controls are sorted by three keys, in this order:

| Key | Effect |
|---|---|
| 1. IT/OT compatibility | A control whose label is outside the scenario's own IT/OT context sorts **behind every compatible one**, whatever either scored. An incompatible control is not a worse answer to the question — it answers a different one. An unlabelled control is never demoted |
| 2. Score | Higher first |
| 3. Preferred domain | Breaks a tie between controls the first two keys cannot separate |

`map_rank` reflects that composite order, 1 = best. **So the scores you get back do not have to
descend:** a compatible control scoring 55 legitimately outranks an incompatible one scoring 90, and
backfilled controls (below the cutoff) sit at the end of the list whatever their label.

Domain sits last on purpose. All 1288 controls carry a domain, there are 97 distinct values, and the
vocabulary is un-normalised free text this repo reports as-is and never joins on — the weakest signal
in the whole funnel, so it may break a tie and nothing more. It can never make an otherwise-
unqualified control qualify, because it is never added to a score.

**IT/OT narrows the candidate pool too — this part is a filter.** Before anything is scored, the
pool is cut in the database to the labels the session's asset and supporting-system categories
resolve to:

| Situation | What happens to the pool |
|---|---|
| Every one of the session's categories resolves to a label the active library carries | The pool is narrowed to those labels. A control outside them is never scored and can never be mapped |
| **Any** category cannot be resolved | No filter is applied at all — the whole library is in the pool. Narrowing on half an asset's nature is the defect this fail-open exists to prevent |
| A control the library left unlabelled | Always in the pool, filter or not. Unclassified is not the same as inapplicable |

That filter is **session-wide and all-or-nothing**. The per-**scenario** labels — the asset plus the
supporting systems that scenario names — are what drive the ordering above, and there nothing is
excluded: a mismatched control is only pushed down. The audit row records both facts separately, so
you can always tell which happened.

**What each mapped control publishes**, on `/results` and on `/accepted-scenarios` (the plan's
frozen snapshot on `/evidence` carries the narrower set listed in section 7):

| Field | Meaning |
|---|---|
| `control_id`, `control_code`, `control_name` | Which library control matched |
| `itot` | **New.** The library's own `IT` or `OT` label, reported verbatim — 731 controls are labelled `IT` and 557 `OT`, which accounts for all 1288. `null` only for a row the library left unlabelled |
| `domain` | The control's domain, as recorded in the library |
| `control_description` | **New.** What the control actually does, in the library's own words. The name says which control matched; this says what implementing it means. `null` for a library row with no description |
| `map_rank` | 1 = best, rising by one in the order returned. It reflects the **composite** order above — IT/OT first, then score, then domain — so it is not a re-statement of the score |
| `score` | Match confidence 0-100, **or `null`** — `null` only for the controls a **person chose** (their own ordering, never scored) and for rows mapped before scoring existed. Controls **TSG** mapped always carry the scorer's number, on a hand-written scenario as much as a generated one |
| `mapping_relevance` | **New.** Always the same value as `score`, `null` included. Both are published: `score` is kept for clients that shipped against it. This is deliberate duplication, not an oversight |
| `standards` | The standards this control refers to, each with its key |

**The audit row for a mapping pass** is the durable record of the decision. It carries: how many
controls cleared the cutoff, how many were mapped, how many were backfilled, how many the ceiling
dropped, how many were demoted for IT/OT, how many hit a concurrent-writer clash, the per-scenario
IT/OT labels used and where they came from, whether the pool filter was applied and with which
labels, the domain affinity, and the two numbers no reader can reconstruct from the settings alone:
`effective_min_score` with `effective_min_score_origin` (the cutoff actually applied and which of the
three sources produced it) and `effective_backfill_min_score` (the floor that cutoff resolved to).
"The library had five good controls" and "the library had forty and the old cap kept five" are
therefore now told apart.

It is **one row per mapping pass, not per scenario** — every number in it is a total across the
scenarios that pass handled, and the row carries no scenario id. For a single scenario's count, read
its `controls` list on `/results`. The only per-scenario `controls_mapped` row is the top-up's, which
does carry a scenario id and is marked `"source": "remediation_top_up"`.

Control mapping has **four** paths that stop without finishing a scenario — the control library had
no candidates, another worker held the lease, a rerank never answered, or the pass hit an unexpected
error and was rolled back so scenario generation could still finish. A scheduled sweep retries them,
and that schedule can be switched off with `TSG_CONTROL_MAP_SWEEP_ENABLED`.

**This route runs whether that setting is on or off** — only the scheduled tick is gated. It is the
manual drain for a queue that would otherwise have no way out. Repeating it is safe: the sweep
takes a lock and is bounded per pass. `202` means queued, not swept; watch the scenarios'
`controls` lists for the effect. It runs on the default queue, so the main worker executes it, not
the admin worker.

---

## 10. Diagnostics — why a run failed (4)

| Method | Path | Phase | Purpose | Output |
|---|---|---|---|---|
| GET | `/v1/tsg/diagnostics` | Support | Why did session X fail — the real exception behind `stage processing failed` | `rows[]`, `truncated` |
| GET | `/v1/tsg/diagnostics/logs` | Support | Captured log lines, for the period the `logs` category was on | `rows[]`, `truncated` |
| GET | `/v1/tsg/diagnostics/config` | Support | What this process is capturing right now, and whether rows are being dropped | `effective`, `override`, `env`, `dropped_rows` |
| PATCH | `/v1/tsg/diagnostics/config` | Config | Change what is captured, with no restart | the config, as above |

> **The three reads take no key; the PATCH does.** Answering "why did this run fail" must not
> require an admin key or database access — needing them is what put diagnosis behind the
> engineering team, and a container log that dies with the container is not an answer. What keeps
> open reads safe is the *shape* of the response: tracebacks, captured log bodies and the context
> blob are withheld unless `TSG_DIAGNOSTIC_PUBLIC_DETAIL` is on, and it defaults off. What stays
> public is what support actually asks for — which session, when, the exception class and message,
> and `client_message`, the exact sanitised text the customer saw, which is what turns "it said
> stage processing failed" into one lookup.
>
> **PATCH keeps the admin key** because it switches on durable capture of prompt text and asset
> context. Reading a failure is a support action; changing what the system records is not. It
> answers `503` if Redis is unreachable, having changed nothing — an override that silently did
> nothing would be worse than one that failed. Full guide:
> [`DIAGNOSTICS_CONFIGURATION.md`](../DIAGNOSTICS_CONFIGURATION.md).

---

## 11. Routes by lifecycle phase

| Phase | Routes |
|---|---|
| Readiness | `/health`, `/ready` |
| Setup | api-clients create / list / revoke |
| Config | embeddings (4), grounding calibrate, control-map calibrate, control-map sweep, feeds refresh (2), library import, techniques rebuild |
| Business | create session, accept, reject, unaccept, promote-to-library, **remediation-plans**, treatment-plan create |
| Processing | session board, session events, regenerate, next-set, plan status, plan regenerate, all job status and event routes |
| Result | results, accepted-scenarios, scenario, session audit, user and entity scenario lists, plan, evidence, plan audit, plan board, entity register, entity plan audit, threshold, calibrations, feeds, items, techniques, pending library, api-client list |
| Finalisation | session cancel, plan cancel, plan review, api-client revoke |
| Curation | promote-to-library, pending library, approve, reject |

---

## 12. Routes that are safe to call repeatedly

| Safe to repeat | Care needed |
|---|---|
| All GET routes | `embeddings/recreate` and `/delete` — scope them to a `group` |
| `/health`, `/ready` | `grounding/calibrate` with `force: true` — billed and irreversible |
| `embeddings/update` | `library/threats/reject` — a rejection is permanent |
| `control-map/sweep` | `POST /v1/sessions` — one active session per asset |
| Replay of `POST /v1/remediation-plans` with the same `Idempotency-Key` | Same key with a different asset is a 409 |
| `control-map/calibrate/status/{job_id}` | `control-map/calibrate` — minutes of reranking, and it overwrites the stored cutoff |

---

## 13. Standard error envelope

Every error uses one shape:

```json
{ "error_code": "validation_error",
  "message": "request validation failed",
  "details": { "errors": [ { "loc": ["body","threat_type"], "msg": "Field required" } ] } }
```

| Status | `error_code` | Usual cause |
|---|---|---|
| 401 | `unauthorized` | Missing or wrong key, or a blank admin key in config |
| 403 | `forbidden` | The entity does not own that asset or session |
| 404 | `not_found` | Unknown id — or the risk module is disabled |
| 409 | `idempotency_key_conflict` | Key reused for a different asset or a different kind of request |
| 409 | `active_session_exists` | One run per asset |
| 409 | `accept_conflict` / `regenerate_conflict` / `treatment_conflict` | The session or plan is not in a state that allows it |
| 422 | `validation_error` | Request-shape validation. The message names the field |
| 422 | `admin_validation_error` | An **admin route's** arguments were structurally valid but refused: an unknown import `{source}`, `max_actors` on a source other than `misp_actors`, an unknown technique source, `embeddings/delete` with neither `group` nor `names`, `names` without a `group`, `embeddings/create` without both. A client that branches only on `validation_error` will miss every one of these |
| 503 | — | Database, broker or LLM unavailable |

When a manual scenario was saved but its plan was then refused, the error `details` carry the
`session_id` and `scenario_id` — so a client can still find what was committed for it.

---

## 14. Documentation map

| Need | Read |
|---|---|
| Run an end-to-end test | [`End_to_End_API_Testing_Guide.md`](End_to_End_API_Testing_Guide.md) |
| Find a route | This file |
| Live schema, always current | `GET /openapi.json`, or `/docs` in a browser |
| SSE contract | `docs/SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md` |
| Per-route examples and DB checks | `docs/tsg_full_api_guidebook.html` (covers 50 of 66 routes) |
| Local setup | `readme_to_run.txt`, `SETUP_AND_RUN_GUIDE.md` |
| UAT and production | `readme_to_run_uat_prod.txt`, `deploy/DEPLOYMENT_HANDBOOK.md` |
| Docker demo | `DEMO_DOCKER_GUIDE.md` |
| Database install | `scripts/eyshield_handoff/readme.txt` |

**Twelve routes the HTML guidebook does not cover**, so use this file and the testing guide for them:

1. `POST /v1/remediation-plans` — the entire manual path
2. `POST /v1/tsg/control-map/sweep`
3. `POST /v1/tsg/control-map/calibrate`
4. `GET /v1/tsg/control-map/calibrate/status/{job_id}`
5. `POST /v1/tsg/threat-intel/library/import/{source}`
6. `GET /v1/tsg/threat-intel/library/import/status/{job_id}`
7. `GET /v1/tsg/threat-intel/library/import/events/{job_id}`
8. `POST /v1/tsg/threat-intel/library/threats/reject`
9. `POST /v1/tsg/threat-intel/techniques/rebuild`
10. `GET /v1/tsg/threat-intel/techniques`
11. `GET /v1/tsg/threat-intel/techniques/events/{job_id}`
12. `GET /dev/sse-test`

**No Postman collection exists in this repository.** Generate a client from `/openapi.json`, or use
the cURL examples in the testing guide.

---

*The route list is verifiable: compare it against `_ENTITY_SCOPED_ROUTES` and `_EXEMPT_ROUTES` in
`app/api/route_audit.py`. The application will not start if a route is missing from both.*
