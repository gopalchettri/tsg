# TSG — Gap Analysis vs SDD v1.4

**Gap register with proposed solutions, file/line evidence, and rationale**

| Attribute | Value |
|---|---|
| Document type | Gap Analysis / Remediation Register |
| Subject system | Threat Scenario Generator (TSG) |
| Baseline compared against | `TSG_Production_Ready_SDD_v1.4_Final_Normative_Implementation_Baseline.docx` |
| Codebase audited | `tsg/app` (61 Python files) |
| Date | 2026-08-22 |
| Status | For review |

---

## 1. Purpose and scope

**Why this document exists.** The SDD declares itself the single source of truth for TSG
implementation, with §33Q as the authoritative contract and §33R.9 as the production evidence
gate. The codebase implements a partly different architecture. This register identifies every
divergence, states why it matters in production, and proposes the smallest change that closes it.

**Decision already taken: the codebase stays. No rebuild.** Every proposed solution in this
document is an incremental change to the existing system. Where the SDD and the code disagree
but the code solves the same problem soundly by a different mechanism, the correct action is to
amend the SDD — those items are marked `doc`.

**How this was produced.** A structured audit: six parallel end-to-end flow traces (threat
scenario generation, remediation, library governance, execution/SSE, security, data/config),
each followed by an independent adversarial verification pass instructed to refute findings by
default, then a synthesis. 421 code and document reads.

Of 61 findings, **38 were severity-corrected downward during verification** and 23 were
confirmed as originally stated; one additional gap was discovered by a verifier while
cross-checking a claimed strength.

> **Repository note.** `tsg/` is its **own git repository** — the parent repo gitignores it at
> `.gitignore:31`. Any `git` command intended to reason about application history must be run as
> `git -C tsg ...`; run from the parent it silently reports on a tree that does not contain the
> application. One finding in the original audit (B11) was wrong for exactly this reason and has
> been corrected. This document is itself untracked by the parent repo for the same reason.

### Result

| Severity | Count | Meaning |
|---|---|---|
| Critical | 0 | — |
| **High** | **1** | Exploitable now, or silent data loss now |
| Medium | 16 | A realistic production incident |
| Low | 36 | Hygiene or a missing guardrail |
| Doc-only | 8 | Nothing breaks; the fix is amending the SDD |

---

## 2. Overall assessment

The codebase is production-grade. In several respects it is **stronger than the SDD requires**:

| Area | SDD requirement | What the code does | Assessment |
|---|---|---|---|
| Concurrency | `rowversion` optimistic concurrency (§33Q.11) | Conditional-UPDATE CAS with a **fencing token** — `dal.py:540-576`, `:733-755`, `:2134-2158` | **Stronger.** A zombie worker holding a stale claim cannot write at all |
| DB integrity | Uniqueness constraints declared (§33Q.11) | `invariants.py:155-195`, `:222-236`, `:334-352` — refuses to boot unless the live DB enforces the contract: each index by name, table, ordered columns, uniqueness and enabled-state, plus a live data scan | **Stronger.** Verified, not declared |
| Route authorization | Prose scope table (§24.2) | `route_audit.py:196-236` — every route must be registered entity-scoped or exempt, auth dependency verified by identity across the whole nested dependency tree; otherwise `create_app()` crashes | **Stronger.** A route shipped without auth is a boot failure, not a silent IDOR |
| Object-level access | Enforce server-side (§33A.12) | All 24 handlers in `sessions.py`/`treatment.py` reach an object-level check; the SSE stream re-validates membership **per tick** (`sessions.py:897-913`) | **Met.** No IDOR exists |

Section 8 lists the SDD requirements already satisfied by a different, sound mechanism. Those
should **not** be "fixed".

### The three priorities

1. **The integration credential carries no tenant or entity scope** (gap E1) — `X-Entity-Id` is
   the entire authorization boundary, and the check that would validate it is off by default.
2. **A treatment plan can stay RUNNING indefinitely** (gap B1) — the only unbounded state in
   the system.
3. **`POST /cancel` stops nothing** (gaps A1/D2) — a cancelled session keeps buying LLM calls.

### Reading the tables

- **Why / Benefit** — the concrete production consequence today, and what closing the gap buys.
- **Sev** — `high` / `med` / `low` / `doc` (doc = amend the SDD, not the code).
- **Eff** — `h` = hours, `d` = days, `w` = weeks.
- All file references are relative to `tsg/` unless otherwise stated.

---

## 3. Threat scenario generation flow

### 3.1 Flow as implemented

```
POST /v1/sessions                          api/sessions.py:206-266
  ├─ header auth + require_entity          api/deps.py:86-121
  ├─ asset ownership from ctm_scan_entity_bu   db/dal.py:217-232
  ├─ context sealed once -> AssetContextJSON   pipeline/context.py:443-454
  │                                            api/sessions.py:180-202  (never UPDATEd)
  ├─ tuning frozen -> TuningJSON            core/tuning.py:105-146
  └─ stage rows + _LOCK seeded              pipeline/tasks.py:353-359
        │
        v
Celery worker takes the lock                db/dal.py:608-636   <- only SessionStatus check
        │
        ├─ STAGE 1  find_threats            pipeline/tasks.py:536-665
        │     ├─ LLM call + Prompt_Log (written even on parse failure)  tasks.py:291-336
        │     ├─ grounding, self-calibrating threshold  pipeline/grounding.py:768-866, :597-640
        │     └─ identity + semantic dedup   tasks.py:129-241, :610-615
        │
        ├─ scoping / scoring                 pipeline/scoping.py -> Scoped_Threat
        │
        ├─ STAGE 2  write_scenarios          pipeline/tasks.py:1232-1348
        │     ├─ per-threat generation + one structural repair retry   tasks.py:778-894
        │     ├─ failure card keeps a real row (Status=error)          tasks.py:1202-1212
        │     └─ control mapping             pipeline/control_mapping.py
        │
        └─ REVIEW barrier                    tasks.py:1524-1542
              │
              ├─ POST /accept                pipeline/accept.py:502-526
              │     └─ library promotion phase 2 -> Threat_Candidate_Review
              └─ regenerate / next-set       pipeline/cascade.py
```

### 3.2 Gaps

| # | Gap | File : Line | Why / Benefit | Proposed solution | Sev | Eff |
|---|---|---|---|---|---|---|
| A1 | `POST /cancel` never stops an in-flight generation | `db/dal.py:709-730`, `pipeline/tasks.py:1266-1309`, `api/sessions.py:864-885` | Cancelling a 40-threat run at 30s returns 200 and the UI tears down, but the worker runs for minutes more — one **billed** LLM call per remaining threat — writing `Identified_Threat` / `Scoped_Threat` / `Threat_Scenario` rows into a session the system already reports as cancelled. The route docstring claims workers "observe the status change on their own next CAS"; they do not. **Benefit:** cancel becomes real, stopping runaway spend | Add an `EXISTS(SessionStatus == active)` subquery to `renew_lease`'s WHERE, copying the block `acquire_lock` already uses at `dal.py:615-620`. Treat the existing `False` return as the stop signal — `tasks.py:1300-1304` already breaks on it; extend the same break to the targeted branch and to `find_threats`' per-proposal renewal at `tasks.py:593-595`. Correct the docstring at `sessions.py:866-867`. **No new column, no CANCELLING state** — lease renewal is already the safe point the SDD asks for | med | h |
| A2 | LLM output is never schema-validated; every validation error is downgraded to a warning | `pipeline/validation.py:31-51`, `:59-62`; `pipeline/tasks.py:828-886`, `:937-939` | `parse_json` checks only the top-level JSON type. `_result` downgrades any error list to `warning` and the enum has no `error` member. The structural repair retry fires only for `missing` errors; if it fails to reduce the count, the **original** is persisted with `Status=complete`. A scenario citing a CVE that was never in the injected intel block — a check `validation.py:118-132` actually performs — is stored complete, listed in `/results`, accepted by accept-all, exported to Excel and used to seed a risk treatment plan. **Benefit:** hallucinated content cannot reach a signed deliverable | Do not build a schema engine. Split the existing error list into **hard** and advisory classes inside `validate_scenario` (hard = a required narrative field still missing after repair, or an invented advisory identifier). Record the class in the existing `ValidationJSON` envelope. Add one `AcceptSubsetReason` member so `dal.unacceptable_subset_reasons` refuses hard-invalid rows on accept-**all**, while an explicit subset naming the id still passes — the reviewer looked at it. ~20 lines across `validation.py`, `enums.py`, `dal.py`; no schema change | med | d |
| A3 | No durable link from a scenario to the `Prompt_Log` row that produced it | `db/models.py:519-539`, `pipeline/tasks.py:291-296` | The `CorrelationID` column exists but the generation stages pass `None`. When a reviewer escalates one specific card as wrong or hallucinated, you cannot retrieve *that card's* prompt and raw response. **Benefit:** per-scenario forensics | Thread the identifier already at the call site: `write_scenarios`' loop holds `scoped_id` (`tasks.py:1266`), which is persisted on `Threat_Scenario.ScopedThreatID` and is unique per output including siblings. Pass it as `correlation_id` | low | h |
| A4 | Provider fallback delegated to the proxy — no allowlist, no detection, no persisted reason | `pipeline/llm.py:317-320`, `pipeline/celery_app.py:177-178` | If the proxy is reconfigured, or a model entry's own fallback fires during an incident, every scenario for that period is written by a model never approved for this workload — with nothing recorded. **Benefit:** model provenance you can defend | In `LiteLLMClient.chat`, at the point where `Provenance` is already built: warn when the served model name does not prefix-match the requested one, and persist both values plus a flag | low | h |
| A5 | No AMBIGUOUS band in grounding — a near-tied match collapses two distinct threats | `core/enums.py:56-61`, `pipeline/grounding.py:389-432` | `GroundingStatus` has two bands split by one threshold. Two genuinely different proposals (e.g. "Unauthorised modification of control logic" and "…of configuration") can both rerank marginally onto the same catalogue entry; one is then silently dropped as a duplicate. **Benefit:** no silent loss of a real threat | `find_closest_match` already has the sorted list — also return the top-two delta. In `find_threat_in_library`, when both candidates clear the threshold and the delta is under a configured epsilon, route to review instead of auto-matching | low | d |
| A6 | No `max_tokens` on any chat call | `pipeline/llm.py:326-374` | Output length is bounded only by the 90-second request timeout. A model entering a repetition loop — a known failure mode with `reasoning_effort` set and a long structured-output prompt — generates until timeout, consuming the full budget for nothing. **Benefit:** bounded cost per call | One `llm_max_output_tokens` Settings field (pydantic `ge`/`le`, `None` default meaning provider default), folded into the `common` dict in `_chat_kwargs`. `drop_params=True` is already on, so a provider that rejects it degrades safely | low | h |
| A7 | `PROMPT_VERSION` is a frozen constant `"1.0"` | `pipeline/prompts.py:25-27`, `pipeline/tasks.py:311` | Every row is stamped `"1.0"` while the templates have demonstrably been edited. Reproducibility itself is **not** lost — `Prompt_Log` stores the exact wire messages and raw response — but you cannot answer "did the prompt change between these two generations?" without diffing stored text. **Benefit:** cheap attribution | `PROMPT_VERSION = "1.0+" + sha256(template source).hexdigest()[:8]`, computed at import. `Prompt_Log.PromptVersion` is `nvarchar(20)` so it fits with **no schema change**, and every stored row becomes groupable by actual prompt content | doc | h |
| A8 | Regeneration can only target the current version — lineage is a linear chain, not a tree | `pipeline/cascade.py:311-331`, `pipeline/tasks.py:1270-1273` | §33Q.4 depicts V2 and V3 both parenting from V1; `get_threat_id_to_redo` requires `Superseded == 0`, so only the head is a legal target. **Branching would change nothing observable:** regeneration never uses the target version's own text — `sibling_texts` explicitly excludes it and the prompt is built from threat, sealed context, intel and entry points only — so a V2-rooted and a V4-rooted regeneration construct an identical prompt. Accepting a preferred older version already works. Only the lineage *shape* is non-conformant | Amend §33Q.4 to a linear chain, **or** (if a tree is genuinely wanted) drop the `Superseded == 0` predicate in `get_threat_id_to_redo` and keep only session/subsystem scoping | doc | d |
| A9 | Transitions are enforced but not declared; the CAS block is duplicated byte-identically | `api/sessions.py:758-769`, `:821-830`; `pipeline/accept.py:502-536` | There is no `ALLOWED_TRANSITIONS` table and no `STATE_TRANSITION_ERROR` code. Enforcement is real but distributed. **No illegal transition is currently reachable** — this is maintainability only. The risk is prospective: the already-reserved per-scenario `scenario_unaccepted` operation has no single gate to route through | Extract the duplicated CAS block from `_do_regenerate` and `_do_next_set` into one helper in `accept.py` beside `review_gate_reason` — e.g. `begin_review_action(sess, session_id)` — and have both call sites use it. Pure de-duplication. Then either publish the matrix in the SDD or strike the requirement | doc | h |

---

## 4. Remediation / risk treatment plan flow

> **This capability has no coverage in the SDD.** `docs/RISK_TREATMENT_PLAN_SDD.md` is cited by
> section number from **15 code and SQL sites** — `api/treatment.py:1, 105`; `api/schemas.py:1982`;
> `core/enums.py:401, 417`; `core/config.py:220`; `db/dal.py:2048`; `db/invariants.py:47`;
> `db/models.py:260`; `pipeline/treatment.py:1, 57`; `pipeline/celery_app.py:224`;
> `scripts/TSG_Core.sql:417` plus two handoff copies — and by decision id from more
> (`enums.py:455` "SDD D10"). **The file exists in git history and is recoverable** — `tsg/` is
> its own git repository (the parent repo gitignores it at `.gitignore:31`), and
> `docs/RISK_TREATMENT_PLAN_SDD.md` is a committed 71 KB document with 10+ commits of history,
> currently deleted from the working tree along with 16 other docs.
> See gap **B11** — the fix is one `git checkout`, not a writing project.

### 4.1 Flow as implemented

```
POST /v1/sessions/{id}/scenarios/{scenario_id}/treatment-plan   api/treatment.py:122-140
  ├─ gate checks (TreatmentGateReason)      core/enums.py:399-414
  │    scenario_not_accepted | generation_in_progress | plan_already_exists | ...
  ├─ Risk_Treatment_Plan row (RUNNING)      db/models.py:258-307
  │    + InputSnapshotJSON (sealed input)   pipeline/treatment.py:163-193
  └─ Celery enqueue                         pipeline/celery_app.py:221-231
        │
        v
run_treatment_generation                    pipeline/treatment.py
  ├─ prompts.treatment_prompt               pipeline/prompts.py:648-660
  ├─ LLM call, touch_plan progress clock    pipeline/treatment.py:526-529
  ├─ _validate_plan  (advisory clamps only) pipeline/treatment.py:313-358
  ├─ control resolution against library      pipeline/treatment.py:384-393
  └─ COMPLETE | ERROR + TreatmentOutcomeReason
        │
        ├─ review (approved | rejected)     api/treatment.py:568-579
        ├─ regenerate -> supersede + new row / approve-swap restores a version
        ├─ cancel                            api/treatment.py:538-556
        ├─ SSE treatment_plan_result         (advisory hint only)
        └─ Excel export                      REMOVED (was api/treatment_plan_excel.py)
```

### 4.2 Gaps

> **2026-08-28 note:** the library returned to `Threat_Catalogue` + its two junction maps (the crm_threat_risk_register interlude was reverted before shipping). Still RETIRED and not returning: `Threat_Candidate_Review`/auto-promotion (replaced by the explicit `promote-to-library` API), the bulk importer (`threat_library_import.py`), sector scoping, and `Config_Threat_Rule`. Rows citing those remain historical; rows citing the catalogue itself may be live findings again, though their line numbers predate the current code.

| # | Gap | File : Line | Why / Benefit | Proposed solution | Sev | Eff |
|---|---|---|---|---|---|---|
| B1 | Unbounded autoretry — a plan can stay RUNNING indefinitely | `pipeline/celery_app.py:221-231` (contrast the explicit note at `:253-258`), `pipeline/treatment.py:526-529` | `max_retries=None` with `autoretry_for=(LLMSlotUnavailable,)`. Unlike the pipeline tasks, `Risk_Treatment_Plan` has **no attempt counter** — the module comment states "PlanID itself is the fence" — and each retry calls `touch_plan`, resetting the progress clock the `timed_out` projection reads. During an LLM provider incident every plan requested that day sits RUNNING forever; operators cannot distinguish wedged from generating; the plan blocks the ScenarioID's active slot so a user cannot create a replacement without cancelling by hand. **Benefit: removes the only unbounded state in the system** | Give the task a bounded ceiling exactly as the admin embedding task already does: replace `max_retries=None` with a config'd `treatment_max_llm_retries`, mirroring `admin_embedding_max_retries` at `celery_app.py:253-258`. Celery then re-raises and the **existing** terminal handler parks the row `ERROR` / `generation_failed`. Optionally add a wall-clock guard on `now() - row['CreatedAt']` inside `run_treatment_generation` | med | h |
| B2 | No authorization scope on review/approve; the recorded approver is an unverified header | `api/deps.py:86-121`, `api/treatment.py:568-579`, `:633-637` | There is no scope concept in `deps.py`. Every treatment route — read, generate, regenerate, cancel, approve, register, audit feed, evidence bundle — is guarded by the same two checks. Nothing distinguishes "may read a plan" from "may spend LLM budget" from "may record the organisation's risk decision". One over-shared key lets any caller inside an entity approve every outstanding plan, stamped with **any user id they choose** — for example a real CISO's, read off a previous API response. **Approval is the artefact presented to a regulator.** **Benefit:** the signature means something | Do **not** build the 13-scope model. Three changes: (1) promote the `verify_membership` posture check from a warning at `config.py:725-733` to a hard boot failure for staging/prod, matching how the API-key gate already works in `invariants.py` — this alone makes `X-User-Id` DB-verified rather than self-asserted; (2) persist `principal.client_id` alongside `ReviewedBy` (one column, value already in hand) so the audit shows which integration asserted the identity; (3) one optional per-client capability column on `API_Client` | med | d |
| B3 | The SSE stream closes for completed sessions — the advertised plan hand-off never works | `api/sessions.py:897-913`, `sse/bus.py:198-206` | `_stream_still_open` closes the stream when the session is not `active`, but treatment plans run on **completed** sessions. A UI following the documented contract opens the events stream after POSTing a plan, receives a heartbeat or two, then the connection drops with no error. **Benefit:** the published contract actually functions | One class of change in `_stream_still_open`: keep the stream open for a `completed` session when the caller is watching treatment plans — return `False` only when the row is missing or the membership re-check fails | low | h |
| B4 | A worker that dies mid-regenerate hides the last good plan | `pipeline/reaper.py:54-121`, `api/treatment.py:209-216` | An operator regenerates a plan for a Critical risk at 17:00 and the worker pod is rescheduled mid-call. Next morning the compliance register shows ERROR / no-plan for a risk that **still has an approved COMPLETE plan in history**. **Benefit:** the register stops misreporting | Do not add a reaper for this. In `_present_status` / `_plan_status_from_row`, when the active row projects to `timed_out`/ERROR and the scenario has a superseded COMPLETE version, surface that version's content | low | d |
| B5 | `PlanJSON` carries no output schema version | `pipeline/treatment.py:543-544`, `api/treatment.py:366-387` | Read paths must duck-type across three historical document shapes. A pre-v0.5 plan retrieved for an audit renders `controls_to_be_implemented.controls: []` — reading as "no controls recommended" when the controls **are** present. **Benefit:** historical plans render correctly forever | Stamp `"schema_version": "TSG_TREATMENT_PLAN_V1"` into `parsed` inside `_inject_reserved` — already the one place server-owned keys are written, and `_RESERVED_PLAN_KEYS` already carries a drift-pin assert. Branch the read path on it | low | h |
| B6 | Plan values are only "advisory clamped" — out-of-vocabulary values are persisted | `pipeline/treatment.py:313-358`, `api/treatment.py:390-398` | Model drift or a jailbroken response yields controls carrying `priority: "Urgent"` and `control_type: "quantum"` — values outside the wire vocabulary the OpenAPI schema publishes. **Benefit:** the reviewer signing off can see what is out of contract | Do not build a schema layer. Delete one `exclude=True` at `api/schemas.py:2179-2185` so plan `warnings` are visible on `TreatmentPlanStatus` — the data is already computed | low | h |
| B7 | Concurrent reviews — the losing verdict is silently discarded | `db/dal.py:2213-2223`, `api/treatment.py:570-579` | Two members of a risk committee open the same plan from a shared queue. One rejects with a comment explaining why; the other approves seconds later. Both UIs show success and the rejection vanishes. **Benefit:** no lost governance decisions | Add one optional body field to `TreatmentReviewBody` — `if_review_status: TreatmentReviewStatus \| None` (or a plain `if_unreviewed: bool`) — and append it as a predicate in `review_plan`'s WHERE. A miss returns the existing 409 | low | h |
| B8 | The evidence bundle lacks model parameters, requested-vs-served model, and fallback reason | `pipeline/treatment.py:533-534` | An auditor asks why two plans generated a week apart from an identical snapshot recommend different controls. TSG can show both prompts and both responses byte-for-byte, but not the parameters each was asked under. **Benefit:** complete reproducibility | Stop discarding the provenance: change `parsed, _prov` to `parsed, prov` and merge `_summarize_ai_call(prov)` — already written and already used by the scenario path — into the `validation_json` dict the worker builds | low | h |
| B9 | No per-tenant or per-client rate limit on the LLM-spending endpoints | `pipeline/llm.py:135-142`, `api/treatment.py:122-168` | One misbehaving or compromised integration key can loop `/regenerate` across an entity's accepted scenarios and consume the shared global LLM slot pool. **Benefit:** blast-radius containment | Do not build a rate-limiter framework. Add a Redis `INCR` + `EXPIRE` counter keyed on `(client_id, tenant_id, 'treatment_generate')` against a configured hourly cap on the two POST routes, raising the existing 429 | low | h |
| B10 | `TenantID` is written on every plan row but never used as a predicate | `api/treatment.py:218-221`, `db/dal.py:2252-2275` | No exploit today — entity id is the real isolation boundary and the header-forgery vector is closed by it. The exposure is latent: if two tenants ever share an entity id, the entity-wide readers would cross the boundary. **Benefit:** defence in depth | Add `p.TenantID == principal.tenant_id` as an additional predicate on `entity_plan_rows` and `entity_treatment_audit_rows` — the column is already populated on every row | low | h |
| B11 | The whole capability is governed by a document that has never existed | `api/treatment.py:1`, `:105`; `api/schemas.py:1982`; +12 more sites | Nothing breaks at runtime, but it is the reason several findings above are hard to adjudicate: a maintainer reading `enums.py:455` ("SDD D10") has no D10 to consult. **The document is not missing — it is deleted from the working tree.** `git -C tsg log` shows 10+ commits on a 71 KB file, and **16 other docs are deleted alongside it**, including `TSG_API_AUTHENTICATION_GUIDE.md` (cited at `api/deps.py:4`), `THREAT_SCENARIO_FLOW_FUNCTIONAL.md`, `REAPER_AND_PROMOTION_GUIDE.md` and `SSE_SESSION_PROGRESS_CONTRACT_GUIDE.md`. **Benefit:** every dangling documentation reference in the codebase resolves again, for the cost of one command | **Restore, do not rewrite.** Run `git -C tsg checkout -- docs/` to bring back all 17 deleted documents, then establish whether the deletion was deliberate. If it was, the code citations must be corrected in the same change — do not leave 15 dangling references pointing at files nobody intends to restore. Add one row to the SDD's §33R.1 canonical concept registry pointing at the restored file, which the registry explicitly provides for. **Do not strip the references from the code** — they are correct the moment the files are back | doc | **min** |

---

## 5. Master library and candidate governance

> **2026-08-28 note:** the library returned to `Threat_Catalogue` + its two junction maps (the crm_threat_risk_register interlude was reverted before shipping). Still RETIRED and not returning: `Threat_Candidate_Review`/auto-promotion (replaced by the explicit `promote-to-library` API), the bulk importer (`threat_library_import.py`), sector scoping, and `Config_Threat_Rule`. Rows citing those remain historical; rows citing the catalogue itself may be live findings again, though their line numbers predate the current code.

| # | Gap | File : Line | Why / Benefit | Proposed solution | Sev | Eff |
|---|---|---|---|---|---|---|
| C1 | The AMBIGUOUS review card shows no near-match evidence, and there is no MERGE action | `pipeline/accept.py:856-863`, `:1056-1058`, `:1102-1111`; `api/admin.py:267-279` | `accept.py` **computes exactly the evidence the reviewer needs** — the best-matching catalogue id and its cosine — then discards it into a `Scenario_Audit` DetailJSON blob. The card stores neither. A reworded duplicate scoring 0.94 (between the bands) reaches the queue; the admin, with no near-match shown and no merge button, approves it, minting a second entry for the same real threat. **That state then breaks the matcher:** `grounding._auto_calibrate` refuses to calibrate at all once any catalogue pair scores ≥ `near_duplicate_score`. **Benefit:** stops a self-reinforcing library corruption | Three additions, no new subsystem. (1) Add `MatchedCatalogueID` and `MatchCosine` to `Threat_Candidate_Review`, populated from the `_CandidateFate` already in hand at `accept.py:1102-1111`. (2) Surface them on `PendingCandidate` alongside the matched entry's stored name. (3) Add `POST /candidates/{candidate_id}/merge` reusing `resolve_candidate`'s existing CAS — close the card as accepted with `catalogue_id` set to the merge target, mint nothing. This is the same write shape `auto_reject` already performs | med | d |
| C2 | External source ingestion writes **directly into the master tables** | `pipeline/threat_library_import.py:681-689`, `:752`; `db/models.py:339`, `356`, `373` | `import_records` upserts every adapted external record through the same DAL primitives the admin-approval path uses; `misp_actors` writes straight into `Threat_Actor`. The only thing distinguishing an imported row from a curator-approved one is a `Source` string tag, and **no read site filters on it**. Importing CISA KEV mints roughly one master row per exploited CVE; CAPEC/ATT&CK mint hundreds more — all as authoritative organizational records. Grounding can then mark an AI proposal "verified" against a CVE record and render that identifier as the organization's own reference. **Benefit:** restores the SDD's knowledge-layer boundary (§33Q.7) | Do not move the data. Add `IsExternalReference` (default 0) to `Threat_Type` / `Threat_Catalogue` / `Threat_Actor`, set it in `import_records` and `upsert_threat_actor` when a source tag is present, and apply the predicate at the **authority sites only**: exclude external rows from auto_reject eligibility (`accept.py:661-667`) and from the calibration sample (`grounding.py:685-686`). Retrieval matching keeps working — SDD §10 block 170 explicitly permits external patterns as generation context | med | d |
| C3 | `Threat_Type` resolution is exact-name only — no semantic band | `pipeline/accept.py:635-638`, `:475-476`; `db/dal.py:1706-1741` | The banded triage that produces the four SDD outcomes runs only over `Threat_Catalogue` names. `Threat_Type` never passes through it — `upsert_threat_type` is a pure exact-string insert-or-find on the natural key. So `"Credential Stuffing Attacks"` gets minted beside an existing `"Credential Stuffing Attack"`. Because `get_possible_names` scopes the catalogue search to exactly **one** matched type, every entry curated under the original becomes **invisible** to any future proposal that matches the twin — those come back unverified, feed promotion again, and mint further near-duplicates. **Benefit:** breaks the duplication spiral at its source | Reuse machinery that already exists. Before minting a novel type in `_find_or_create_type_and_catalogue` and in `resolve_candidate`, run the same cosine band over active `Threat_Type` names that `_triage_generic_name` runs over catalogue names — the `'threat_type'` embedding group is already cached by `embeddings.get_vectors` (`embeddings.py:65-69`). `auto_reject` → reuse the matched id; `review` → demote to a card; `auto_approve` → mint | med | d |
| C4 | Imported records carry no source object id, version or checksum | `pipeline/threat_library_import.py:681-689`, `:336-342`, `:470-475` | Imports are idempotent by **name only**. The external id (T1078, CAPEC-66, CVE-…) is concatenated *into* the display name rather than stored as a field, so it cannot be queried or joined. When MITRE renames a technique between releases, the next import inserts a **new** row while the old stays `IsActive=1` forever — no DEPRECATED path exists. Every rename therefore adds a near-duplicate pair, which is precisely the condition that permanently disables grounding's auto-calibration. **Benefit:** renames update in place | Add `SourceObjectID`, `SourceVersion`, `SourceChecksum` to `Threat_Catalogue` (and `Threat_Type`); have each adapter emit the external id it already extracts as a **field** rather than only concatenating it into the name; key `import_records`' upsert on `(Source, SourceObjectID)` with an UPDATE when the version differs. Add a Redis `SETNX` source-level lock around `run_import`, and a max-bytes read to `load()` mirroring `_MAX_FETCH_BYTES` | med | w |
| C5 | Candidate governance API: one admin key for read + approve + reject, no tenant scoping | `api/admin.py:260-264`, `api/deps.py:154-167` | Least privilege is absent — anyone who can view the curator queue can also mint master-library rows. **Benefit:** separation of read and write authority | Add an optional `tenant_id` parameter to `dal.list_pending_candidates` / `get_candidate` and pass `principal.tenant_id` from `api/admin.py` when the header is present | low | d |
| C6 | An AI-invented `control_code` is persisted and exported verbatim | `pipeline/treatment.py:384-393` | `control_code` is only overwritten on a library hit; on a miss the raw model echo is kept. A treatment plan exported to Excel and circulated to a risk committee or auditor contains a row reading `control_code: ISO-27001-A.9.4.2` that the model invented. **Benefit:** no fabricated framework references in a signed deliverable | **One line** in the branch that already detects it: at `treatment.py:392`, when `hit is None`, set `ctl['control_code']` to `None` before appending to unresolved. `control_library_id` is already `None` there, so the pair becomes consistently "unresolved" | low | h |
| C7 | `Threat_Candidate_Review` has no uniqueness constraint | `pipeline/accept.py:1089-1093`, `:996` | Dedup is preload-then-insert in Python (the code notes "the table has no unique index"). Beyond duplicate queue noise, the window **defeats the rejection blacklist** that governance depends on: two concurrent accepts proposing the same novel threat both preload, both miss, both insert | Add a persisted `IdentityKey` column (CandidateKind + the folded generic-or-name string `accept.py:1094` already computes, plus TenantID) and a filtered unique index over `Status='pending'`; register it in `invariants.REQUIRED_INDEXES` | low | d |
| C8 | `Threat_Actor` uniqueness is on the raw name | `db/invariants.py:40`, `db/dal.py:1772-1798` | Normalized identity is enforced only in Python. Two admins approving actor cards for `'APT-41'` and `'APT 41'` at the same moment both read before either commits, both miss, and both insert | Add a persisted `NormalizedName` column written from `grounding.norm_actor_name` at the single choke point `dal.upsert_threat_actor`; replace `UX_ThreatActor_NaturalKey` with a unique index on it; register the new index; resolve the IntegrityError winner by the normalized value | low | d |
| C9 | Admin approval mints with `sector_id=None` while accept mints sector-scoped | `pipeline/accept.py:470-479`, `:581-590` | A curator-approved card for a name that already exists as a sector-scoped entry under the same type inserts a second, **global** row rather than reusing the existing one | The card already carries `SessionID`. In `resolve_candidate`, look up that session's `SectorIDsJSON` and reuse `_pick_sector_for_promotion`, falling back to `None` only when genuinely unavailable | low | h |
| C10 | `promotion_auto_approve_enabled=True` makes scenario accept a direct master-write path | `core/config.py:441-443`, `pipeline/accept.py:931` | Nothing breaks while the switch is off, which is the shipped default — under it, five separate demotion rules route every novel candidate to the curator and `allow_mint=False` mints nothing. The exposure is that **a single environment-variable change** silently converts accept into a master-write path | Amend the SDD to record the switch as a sanctioned operating mode, **and** add a boot invariant in `db/invariants.py` refusing to start with it `True` when `app_env` is staging/prod (same shape as `_assert_api_client_configured`). Also write `auto_mode` into the durable `promotion_triage` DetailJSON at `accept.py:1144-1148` — it is currently only in a log line | doc | h |

---

## 6. Execution state, async processing and SSE

| # | Gap | File : Line | Why / Benefit | Proposed solution | Sev | Eff |
|---|---|---|---|---|---|---|
| D1 | `reconcile` fires once per connection and is never re-emitted | `api/sessions.py:1013` vs `:1033`; `:897-913`; `pipeline/tasks.py:1524-1540`; `sse/bus.py:110`, `:138` | There is no outbox and no replay — accepted by design — but the compensating DB reconcile is emitted **exactly once**, before the Redis SUBSCRIBE. The per-tick handler re-queries the board yet uses it only to decide close-or-continue, keyed on `SessionStatus`. `_send_to_review` deliberately leaves `SessionStatus == active` and changes only `CurrentStage`/`StageStatus`. Concrete interleaving: a user opens the stream at t=0; at t=40s an unrelated publish hits a stale pooled Redis connection and opens the process-global breaker for 30s; at t=55s `_send_to_review` commits durably and its publish is **silently swallowed**. From t=55s the session is AWAITING_DECISION and the UI never learns. **Benefit:** no wedged UI | Re-emit reconcile on change, reusing the query the tick already makes. In `_stream_still_open`, return the board row it **already loaded** instead of a bare bool; in the SUBSCRIBE_TICK branch, compare a cheap `(CurrentStage, StageStatus, UpdatedAt)` fingerprint against the last emitted and yield a fresh `reconcile` when it differs. **Zero extra DB round trips**, ~15 lines, one file, no schema change, no outbox table. The pattern already ships at `api/admin_sse.py:96-102` | med | h |
| D2 | Cancel is not observed mid-task *(same root cause as A1)* | `db/dal.py:613-620`, `pipeline/tasks.py:587-618`, `:1266-1309` | `SessionStatus == active` is consulted in exactly one place on the work path — `acquire_lock`, at task start. After the lock is taken neither hot loop consults session status. Generations **commit** into a session already reported cancelled | See A1 — one EXISTS predicate on `renew_lease`, converting cancel into a lease revocation with no new state, no new column and no new call site | med | h |
| D3 | `prometheus-client` is a declared dependency with **zero imports** | `pyproject.toml:22`, `requirements.txt`, `app/main.py:194-207` | A repo-wide grep matches only the two dependency files — no import, no Counter, no ASGI mount, no scrape endpoint. Logs are the only telemetry. No alerting is possible on the signals that predict this system's failure modes: SSE breaker openings (currently a WARN line and nothing else), reaped-session rate, stage attempt-exhaustion, LLM slot exhaustion, Celery queue depth, and open SSE stream count against the 180-stream cap. A saturated slot pool or a Redis silently dropping publishes is invisible. **Benefit:** the failures this system actually has become alertable | Do not instrument everything. Mount `prometheus_client.make_asgi_app()` at `/metrics` in `main.py` — one line, dependency already installed — and add exactly **four** counters at points that already log: `sse/bus.py:139` (breaker open), `pipeline/reaper.py:120` (cancelled), `db/dal.py:560` (poison ceiling), `pipeline/llm.py:167` (`LLMSlotUnavailable`). Use multiprocess mode under gunicorn | med | d |
| D4 | Correlation id is not propagated into Celery tasks | `core/middleware.py:54-55`, `pipeline/celery_app.py:177-229` | An operator investigating a slow session in Loki finds the API line with `request_id=X`, then has to pivot manually via `session_id` to find the worker lines. **Benefit:** one-hop log joins | Two signal handlers in `celery_app.py`, **no signature changes**: a `before_task_publish` handler copying `request_id` from contextvars into the message headers, and a `task_prerun` handler binding it back | low | h |
| D5 | `/ready` is not capability-aware | `api/health.py:129-132` | Redis is only the Celery broker and the SSE fan-out. During a 5-minute managed-Redis failover every API replica reports not-ready and the platform pulls them all from the Service — including read-only routes that need nothing but MSSQL. **Note:** this is a design preference, not a spec gap; a "ready" pod during a broker outage would accept work it cannot service | Keep one endpoint, change one predicate: only `database` fails readiness; demote redis/mongo to the advisory treatment `workers` already gets — they stay in the `checks` payload for monitoring | low | h |
| D6 | Partial outcome is untyped | `pipeline/tasks.py:1330-1331`, `api/sessions.py:97-111` | A partially-completed run is distinguishable only by parsing a free-text `ErrorMessage` assembled from AI-derived text. **Benefit:** clients can branch on a boolean | Two lines, no schema change. In `build_board`, derive `progress.partial` and expose it as a typed boolean alongside the existing prose | low | h |
| D7 | `treatment_plan_result` is absent from reconcile | `api/sessions.py:140-163`, `:979-985` | This is the **one** event class where DB-reconcile cannot compensate, because the board carries no plan state. A user clicks Generate, the worker takes 10-60s, the publish is swallowed by an open breaker (or the worker dies, which never publishes at all), and reconcile has nothing to say | Add the active plan's `(PlanID, Status, UpdatedAt)` to `build_board`'s payload — one indexed query, gated on `risk_module_enabled` — so the existing reconcile, and the reconcile-on-change fix in D1, both cover it. **Free once D1 lands** | low | h |
| D8 | Maintenance tasks share the work queue | `pipeline/celery_app.py:42-99`, `pipeline/llm.py:158-169` | The failure correlates with exactly the condition that needs the reaper: under an LLM-provider slowdown, sessions pile up, all greenlets sit in `_llm_slot`'s poll loop, and the reaper queues behind them. **Benefit:** recovery machinery stays responsive precisely when it is needed | Config only, no logic change. Add `task_routes` sending `tsg.reap`, `tsg.retry_promotions`, `tsg.self_check` and `tsg.intel_refresh*` to a `maintenance` queue, and run one extra small `-Q maintenance -c 2` worker | low | h |
| D9 | The embeddings job outcome exists only in Redis | `pipeline/celery_app.py:250-316`, `api/admin_jobs.py:49-56` | A Redis restart or eviction during or after a long re-embed erases the job's existence: the status route 404s, the SSE stream 404s, and there is no authoritative record it ever ran | Reuse the pattern already in this file: give the embeddings task the same `record_started`/`record_finished` treatment `import_threat_library_task` has, writing to a small run-history table | low | d |
| D10 | The treatment plan has no reaper | `pipeline/treatment.py:483`, `api/treatment.py:419` | A row whose worker died stays RUNNING in MSSQL forever; the API corrects it only at read time. It bites operators and any consumer reading the table directly — a monitoring query, an export, or a report | Add a plan sweep to the **existing** reaper pass — the beat task and transaction already exist. One CAS UPDATE: `Risk_Treatment_Plan SET Status=ERROR, ErrorReason=timed_out WHERE Status='RUNNING' AND UpdatedAt < _stale_cutoff()`. ~10 lines, no new schedule. Keep the read-time projection | low | h |
| D11 | SSE events carry no `event_id`, `sequence`, progress percentages or `message_code` | `pipeline/tasks.py:344-350`, `sse/bus.py:1-7` | Documentation-only **once D1 lands**. An unconditional full snapshot before any live event is exactly the outcome §33Q.9's RESYNC_REQUIRED path degrades to, applied always; sequence numbers buy nothing when the client re-derives full state rather than folding deltas | Amend the SDD to record DB-reconcile-on-connect-and-on-change as the accepted mechanism. **One requirement survives and should stay:** §33J block 661 / §33Q.9 block 819 mandate a backend-computed `overall_progress_percent` and forbid the UI inferring it. `build_board` supplies none — add it to the reconcile payload (derivable from selected `Scoped_Threat` rows vs non-superseded outputs) without touching the event envelope | doc | h |

---

## 7. Security, tenancy and egress

| # | Gap | File : Line | Why / Benefit | Proposed solution | Sev | Eff |
|---|---|---|---|---|---|---|
| **E1** | **The integration credential carries no tenant or entity scope** | `db/models.py:599-615`, `api/deps.py:53-65`, `:68-83`, `:104-106`, `:120-121` | `API_Client` has `ClientID`, `KeyHash`, `Name`, `Module`, `Active` and audit columns — **nothing binding a key to a tenant, an entity, or a set of allowed operations**. `verify_api_key` returns only a ClientID, which is bound to the log context and never consulted again for any authorization decision. `_authenticate` takes `X-User-Id` and `X-Tenant-Id` verbatim; `get_principal` takes `X-Entity-Id` verbatim. A holder of **any** active `Module='tsg'` key can read and mutate **every** entity's data by changing one header: `GET /v1/entities/{entity_id}/scenarios` returns another organization's full threat-scenario set, and `.../treatment-plans` returns their unremediated Critical risks. **Benefit:** the credential becomes the authorization boundary instead of the caller's own claim | Add nullable `TenantID` and `EntityScopeJSON` columns to `API_Client`, and have `verify_api_key` return the row rather than just the ClientID. In `_authenticate`, when the row carries a scope, require the requested tenant/entity to be inside it and raise `AuthError`/`EntityForbidden` otherwise; **a NULL scope keeps today's behaviour**, so existing keys are not broken on deploy. **No route-handler changes at all** — they already call `require_entity`/`get_authorized_session` against `Principal.entities`, so narrowing what lands in that set is sufficient. Then backfill real keys and make NULL a boot failure in staging/prod using the `invariants.py:132-149` pattern | **high** | d |
| E2 | `verify_membership` is off by default and production only **warns** | `core/config.py:490-491`, `:725-735`; `api/deps.py:108-116`; cf. `db/invariants.py:133-149` | This is the compensating control for E1, **and it is off**. When enabled the check is correct and complete — it validates the (user, entity) pair against `user_scope_assignment` and fails closed on any lookup exception. But `assert_security_posture` only emits a WARNING for staging/prod with the flag off; boot proceeds. Compare `invariants.py:133-149`, which **does** hard-fail boot when no active API client row exists. An operator rotating an env file and dropping the flag gets one warning line among normal boot logs | Two lines. Turn the staging/prod branch into a `raise`, matching `invariants.py:146`, after confirming `user_scope_assignment` is populated for production entities — the check already fails closed on lookup errors, so a partially-populated table denies rather than allows. Keep a documented, time-boxed `TSG_ALLOW_UNVERIFIED_MEMBERSHIP` escape hatch for the cutover window. **Do this with E1, not before** | med | h |
| E3 | Forty-four administrative routes sit behind one shared static secret | `api/deps.py:154-167`, `core/config.py:484-486`, `api/api_clients.py:34-55`, `api/route_audit.py:65-140` | `require_admin` is implemented carefully — constant-time on bytes, no default value, denies when unset, opaque message — so this is a weak-**authentication** finding, not a missing-authorization one, and the acting user *is* recorded. But that identity is `X-User-Id`, taken on trust from the same header set the admin key unlocks. One leaked key — from a CI variable, a shared password-manager entry, a curl in a runbook — mints a fresh tsg API key which (per E1) reads every entity, and **that key survives rotating the admin secret**. The same holder can soft-delete master rows and approve candidates while attributing each action to any colleague's name | Reuse the table that already exists rather than building a role model. Provision admin identities as `API_Client` rows with `Module='tsg-admin'`, and reimplement `require_admin` as a second `verify_api_key(module='tsg-admin')` call that returns the ClientID and asserts a non-blank `X-User-Id`. That yields per-admin revocation (the existing revoke route), attribution bound to a credential, and rotation without a fleet-wide secret change — using the existing table, hashing, endpoint and `route_audit` exemptions. Keep the env key as break-glass | med | d |
| E4 | `X-Tenant-Id` is stamped on every tenant-owned row, never verified, never filters a query | `api/sessions.py:220`, `db/dal.py:349-357` | **Not** a cross-tenant read — entity is the real boundary, so no data leaks on this axis alone. It is an audit-integrity and compliance-reporting failure: a caller can stamp an arbitrary tenant string onto durable rows, so stored tenancy data is not trustworthy for reporting or evidence | Once `API_Client` carries `TenantID` (E1), change `_authenticate` to return the row's tenant and ignore the header entirely — the header stays bound to the log context as a client-reported field. One line | low | h |
| E5 | Outbound feed fetches follow redirects to any host and forward the OTX key across the hop | `intel/fetchers.py:131-132`, `intel/otx.py:76-79` | A hijacked or compromised upstream — or DNS/BGP interference against `raw.githubusercontent.com`, `otx.alienvault.com` or `cisa.gov` — answers 302 to `http://169.254.169.254/latest/...` and the fetcher follows, **with the API key still attached**. **Benefit:** closes the SSRF and credential-forwarding surface in one place | One shared opener in `fetchers.py`: subclass `HTTPRedirectHandler.redirect_request` to (a) reject any non-https target, (b) reject a host outside a small allowlist derived from the `URLS` dict and the `intel_*` settings, (c) reject loopback/private/link-local/cloud-metadata addresses, and (d) drop all headers but User-Agent on a cross-host hop. Use `opener.open` at `fetchers.py:132` | low | h |
| E6 | Threat-library downloads read an unbounded response body into worker memory | `pipeline/threat_library_import.py:537`, `:544`; `intel/fetchers.py:119` | `enterprise-attack.json` is already tens of megabytes and grows every release; `yaml.safe_load` of a large ATLAS dataset multiplies that several times in Python objects | Delete the two raw `urlopen` calls and route both through `fetchers._get`, raising `_MAX_FETCH_BYTES` or giving it an optional per-call cap. **This removes code rather than adding it**, and inherits E5's redirect hardening | low | h |
| E7 | No data-classification or egress decision before content leaves for the LLM | `pipeline/context.py:443-454`, `pipeline/prompts.py:177-186` | An operator flips `LLM_PROVIDER` from `azure_openai` to `openai` — a single env var, no code review, no gate — and every subsequent asset description leaves for a non-approved provider, with the record not naming which provider received it | Two small changes, **not** the SDD's classification engine. (1) Add an IPv4/IPv6-literal pattern to `_SECRET_PATTERNS` in `core/security.py` — one entry in an existing list, every call site inherits it. (2) Add a `model_validator` gating provider changes (`config.py` already has two) | low | h |
| E8 | The LiteLLM credential and endpoint have working **insecure defaults** | `core/config.py:177-178`, `pipeline/llm.py:286-291` | A typo'd or dropped env var does not fail — it silently reconfigures the AI path to talk cleartext to a default-credentialled endpoint. If nothing is listening, the failure is loud; if something is, it is not | Default `litellm_api_key` to `''` and add a `model_validator` that raises when `llm_provider == 'litellm_proxy'` and the key is blank. Optionally reject a non-https `litellm_base_url` outside development | low | h |
| E9 | `get_authorized_session`'s docstring claims a 404-before-403 property the code does not have | `api/sessions.py:166-177`, `api/errors.py:49-51` | Low practical exploitability: session ids are COMB v8 UUIDs seeded from `os.urandom`, so they cannot be enumerated | Correct the docstring to describe what the code actually does — smaller and better than changing the behaviour, which would cost callers a clear 403 diagnostic | low | h |
| E10 | *(found during verification)* ATLAS is **not** the only remote-steered fetch | `intel/fetchers.py:174-194`, `pipeline/threat_library_import.py:478-491` | A claimed strength asserted that "the one place remote content steers an outgoing fetch (the MITRE ATLAS manifest) validates the path against a fixed regex". Verification found a second remote-steered fetch without that guard | Add the missing path regex at `fetchers.py:194`, mirroring `_ATLAS_V6_PATH_RE` | low | d |
| E11 | No named authorization scopes; idempotency is not keyed by tenant or client | `api/route_audit.py:32-140`, `db/dal.py:256-280` | Documentation-only. Nothing is exploitable through this gap. Every authorization decision the thirteen SDD scopes would encode is **already** made by entity membership plus the administrative key, and `route_audit.py` enforces the classification mechanically at boot across 25 entity-scoped and 56 admin routes. Building a scope engine now would add a second, weaker surface alongside the one that already works | Amend the SDD, not the code. Replace §33A.13's scope list with a description of the implemented two-level model and name `route_audit.py` as the enforcement artefact. Restate the idempotency rule as `entity_id + idempotency_key`, which is what the unique indexes actually guarantee | doc | h |

---

## 8. What the code already gets right

These are SDD requirements met by a **different, sound mechanism**. Do not "fix" them.

| SDD requirement | How the code meets it | Evidence |
|---|---|---|
| Scenario versioning with parent lineage (§13.2, §33B.2, §33Q.4) | Exists under different names. `IdentityHash` is the root id — a sha256 over `SessionID\|SubsystemID\|threat dedup key`, derived from the **threat**, so it survives regeneration unchanged. `ReplacesScenarioID` is the parent pointer, stamped from what the supersede actually retired. `Superseded=1` is SUPERSEDED; prior versions are never deleted | `db/models.py:203-213`, `db/dal.py:985-990`, `pipeline/tasks.py:1123-1129`, `api/sessions.py:294-343` |
| Accept targets a concrete version (§33Q.4 block 788) | Fully met. `Accepted` is deliberately decoupled from `Superseded`, so an **older** version can be accepted; `UX_Scenario_ActiveAccepted` enforces one accepted version per identity, with a pre-flight guard rejecting a subset naming two versions of one scenario before any write | `db/dal.py:1281-1312`, `pipeline/accept.py:176-206`, `tests/test_accept_any_version.py:132-170` |
| Config pinned per execution (§19.4, §33R.7) | **Stronger than a version pointer:** the resolved calibration is validated through the full `Settings` model and frozen as JSON on the session. Every worker stage reads the frozen snapshot, never live config. An invalid override 422s session creation | `core/tuning.py:105-146`, `:174-188`; `api/sessions.py:243`; `pipeline/tasks.py:550`, `:790`, `:1164` |
| Sealed context snapshot (§33A.5) | No CREATED/SEALED column, but immutability is enforced by construction — one writer, all other references are reads. For treatment, `InputSnapshotJSON` carries the sealed input, pinned byte-for-byte by test | `api/sessions.py:197-198`; `pipeline/cascade.py:337-339`; `pipeline/treatment.py:163-193`; `tests/test_treatment_plan_versions.py:152-190` |
| Optimistic concurrency (§33Q.11 block 830) | No `rowversion`, but conditional-UPDATE CAS with `rowcount==1` **plus a fencing token** — strictly stronger, since a zombie holding a stale claim cannot write at all | `db/dal.py:540-576`, `:733-755`, `:689-707`, `:850-866`, `:2053-2223` |
| DB integrity contract (§33Q.11) | **Verified, not declared.** Refuses to boot unless the live database enforces it: each index by name AND table AND ordered columns AND uniqueness AND enabled-state; filtered-index predicates checked against enum literals; NOT NULL on isolation keys; every ORM-mapped column asserted present; RCSI on; plus a live **data** scan | `db/invariants.py:155-195`, `:198-219`, `:222-236`, `:239-264`, `:267-299`, `:334-352` |
| Route authorization (§24.2, §16.2 control 1) | Boot-time route audit forces every live route into an entity-scoped or exempt registry, verifies the required dependency **by identity across the whole nested dependency tree**, asserts the registries are disjoint at import, and crashes `create_app()` otherwise | `api/route_audit.py:143-156`, `:159-168`, `:196-236` |
| No IDOR | All 24 handlers reach an object-level check; the five without an inline call delegate to one. The SSE stream re-validates membership **per tick** | `api/sessions.py:487`→`:367`, `:792`→`:743`, `:861`→`:806`, `:1013`→`:893`; `api/treatment.py:136`→`:181`; `api/sessions.py:897-913` |
| Prompt injection defence (§15, §16.2, §33O) | System instructions are fixed literals with an explicit DATA BOUNDARY; context rides as JSON in the user message; intel is a fenced block with every value defanged of the fence literals and only external_id/title/url emitted. For treatment, untrusted text stays inside a JSON object so **JSON escaping makes fence-forging impossible**. `chat()` carries a last-line assertion that no database primary key leaves the process | `pipeline/prompts.py:256-268`, `:171-174`, `:353-384`, `:648-660`; `pipeline/treatment.py:693-707`; `pipeline/llm.py:190-231` |
| AI output never becomes master by default (§9.3, §33A.4, §33Q.7) | With the shipped default, accepting a scenario mints **nothing**: novel types are not minted, novel names are demoted to review, actor links may only seed a type minted in the same accept. Five demotion rules push doubtful cases to the curator; `close_candidate_review` is a single-winner CAS with rejected identities forming a cross-session blacklist | `core/config.py:443`; `pipeline/accept.py:628-634`, `:874-881`, `:865-902`, `:1041-1055`; `db/dal.py:1900-1924`; `pipeline/accept_actors.py:194-212` |
| Actor merging | **Stricter than the SDD.** The code refuses a semantic merge band for actors, with the rationale written out: a 0.95 ratio would let "Authorized third-party user" absorb "**Un**authorized third-party user" | `pipeline/accept_actors.py:254-311`, esp. `:265-271` |
| Controls are library-backed (§33F) | LLM free text is used only as a retrieval *query*; candidates come only from `Control_Library`; the API **replaces** `scenario.controls` with grounded rows while exposing AI text separately as `suggested_controls` — an explicit library-gap signal | `pipeline/grounding.py:211-232`; `pipeline/control_mapping.py:220-229`; `api/sessions.py:603-647` |
| Partial completion at item level (§33A.8) | Each failed scenario persists its own row with a typed client-safe message; successes commit independently; failure cards are excluded from accept and from the "already served" set; each can be regenerated individually; the all-failed case re-raises so the stage goes ERROR | `pipeline/tasks.py:1202-1212`, `:1286-1297`, `:1311-1312` |
| Commit-then-publish (§32 block 424, §33Q.10 block 828) | Enforced at every session-scoped publish site with the ordering rationale in the code. The system can lose an event but **can never emit a phantom** describing rolled-back state | `pipeline/tasks.py:650`→`663`, `1491`→`1494`, `1538`→`1539`; `pipeline/cascade.py:187`→`191`; `pipeline/reaper.py:94`→`98` |
| Durable mirrors for advisory outcomes (§33A.7 block 490) | `next_set_result` and `regen_result` each write an audit row **first** and are re-served on the board — an outbox by a different mechanism. Terminal transitions never depend on the publish | `pipeline/cascade.py:163-187`; `api/sessions.py:155-161`, `:897-913` |
| Reproducibility manifest (§33A.6) | Rather than hashes, TSG stores the **artefacts**: the complete redacted input snapshot, plus the complete prompt messages, raw response, Model, ModelVersion and PromptVersion, served byte-for-byte by a dedicated evidence endpoint that works for versions replaced long ago. `Prompt_Log` is written **even on parse failure** via a rollback-and-insert | `api/treatment.py:772-798`; `db/dal.py:2365-2420`; `pipeline/tasks.py:316-318`, `:325-336` |
| Poison isolation and per-operation timeouts (§22) | `AttemptCount < stage_max_attempts` makes an exhausted stage permanently unclaimable with its ERROR surfacing on the board; a 3300/3600 backstop pinned to `visibility_timeout` | `db/dal.py:560`; `core/config.py:423`; `pipeline/celery_app.py:88-89`, `:377-378` |
| Excel formula-injection escaping | **A control the SDD never asks for** — leading formula-trigger characters were escaped, treating LLM prose as a real trust boundary for the spreadsheet consumer. No longer applicable: the treatment-plan Excel export was removed | REMOVED (was `api/treatment_plan_excel.py:55-67`, `:152`) |
| No secrets in configuration data (§19.2, §33Q.15) | API client secrets are never stored — only a SHA-256 of the 32-byte value, with several Active rows permitted for make-before-break rotation. The seeding instruction hashes in Python, explicitly not in SQL. `Config_Tuning` has no column that could hold one | `db/models.py:599-615`; `db/invariants.py:146-152` |
| Expand/contract migrations (§30) | Met without a framework: additive guarded DDL, converge-to-target re-runnable scripts, read-only preflight/verify gates, and an ORM that types new columns `\| None` with comments explaining the intermediate state. `metadata.create_all()` is forbidden; platform-owned tables are mapped read-only | `scripts/TSG_Core.sql:71-93`, `:106-116`, `:140-142`; `db/models.py:74`, `129`, `182`, `212`; `db/engine.py:4-5` |
| Structured logging and correlation (§27) | structlog emits JSON in API and worker with stdlib records bridged in; `X-Request-Id` is accepted or generated, bound into contextvars, echoed on the response and unconditionally cleared on unwind; Flower task events are set **in code**, so Flower works on every launch path | `core/logging.py:20-47`; `core/middleware.py:57-93`; `pipeline/celery_app.py:69-70` |
| Capability-aware AI readiness (§33A.18) | `/ready` deliberately probes no LLM and treats worker absence as advisory, with the reasoning in the code — a LiteLLM outage cannot take API pods out of rotation | `api/health.py:90-105` |

---

## 9. Data model, configuration and concurrency

| # | Gap | File : Line | Why / Benefit | Proposed solution | Sev | Eff |
|---|---|---|---|---|---|---|
| F1 | `Config_Threat_Rule` is read **live** at every scoring pass while tuning is read from the frozen snapshot | `pipeline/tasks.py:1164` vs `:1170`; `db/dal.py:1069-1087`; `pipeline/scoping.py:107-152` | `_prepare_scenario_batch` is the single scoring site and runs on the initial pipeline run, on every regeneration hop and on every next-set hop. **Two lines apart** it reads tuning from the frozen session snapshot and `Config_Threat_Rule` live from the database. Those rows carry a weight summed additively into the score, and `tech_gate` rules can flip `Selected` to False outright. A curator edits a rule while a session is parked at REVIEW; the user clicks regenerate → **that scenario is scored under the new rulebook while its siblings in the same report were scored under the old one** — different base score, or gated out entirely. **Benefit:** one report, one rulebook | Reuse the mechanism that already exists. At session creation (beside the tuning resolve at `api/sessions.py:243`) also read the active rule set and store a stable hash — ordered `(ThreatRuleID, RuleType, ThreatTypeID, RuleKey, RuleValue, Metadata)` tuples through sha256 — into `TuningJSON` under `_rules_hash`. In `_prepare_scenario_batch`, recompute and log a warning plus stamp the mismatch into `FactorsJSON` when it differs. Makes the drift **loud and auditable with no schema change** | med | h |
| F2 | `tsg-beat` draws its environment from a **different Secret** than the API and worker | `deploy/deploy.yaml:209-211` vs `:63-67`, `:143-147`; `pipeline/celery_app.py:90-98` | `tsg-api` and `celery-worker` both use `configMapRef: tsg-api-config` + `secretRef: tsg-api-secrets`; `tsg-beat` uses `secretRef: tsg-uat-env`, a different object entirely — the file's own header comment admits it. This matters because `celery_app.py` evaluates settings at **module import** and builds `beat_schedule` from them. An operator sets `TSG_INTEL_ENABLED=true` in the shared ConfigMap and rolls API and worker: the API reports intel enabled and the worker is ready to execute the task, but beat's stale Secret still says false, so the schedule is built without the entry and the task **never fires**. Live threat intel silently goes stale forever — every pod healthy, the feature flag reading true. **Benefit:** the scheduler and the executors agree | One-line manifest change: replace `envFrom: - secretRef: tsg-uat-env` with the `configMapRef: tsg-api-config` + `secretRef: tsg-api-secrets` pair the other two Deployments use, then delete `tsg-uat-env`. As a recurrence guard, have the existing `tsg.self_check` task log the beat-relevant settings it sees | med | h |
| F3 | No retention policy or purge job anywhere — `Prompt_Log` grows without bound | `pipeline/celery_app.py:90-98`; `db/models.py:518-539`; `scripts/TSG_Core.sql:333`, `:611-612` | `beat_schedule` has four entries and none deletes anything; there is no retention setting; no deployment script contains a DELETE. Two compounding failures. **Operationally**, `Prompt_Log` is the fastest-growing table in the schema — one row per LLM call, each holding two copies of a multi-kilobyte prompt plus the response — and there is **no `CreatedAt` index**, so the first purge would be a full-table scan against a live database. **Contractually**, a customer exercising a data-deletion or retention right has no mechanism to satisfy it. **Benefit:** bounded growth and a deletion story | One beat task and one setting. Add `prompt_log_retention_days` (0 = keep forever, the safe default) to Settings, and a `tsg.purge` task running a chunked `DELETE TOP (5000) ... WHERE CreatedAt < DATEADD(day, -N, SYSUTCDATETIME())` in a loop until rowcount is 0, so it never takes a long lock. Add `CREATE INDEX IX_PromptLog_CreatedAt` to `TSG_Core.sql` in the **same change**. Extend to `Identified_Duplicate_Threat` with its own horizon. **Deliberately do not auto-purge `Scenario_Audit`** — it is the append-only governance ledger | med | d |
| F4 | `Config_Tuning` has no version, approval state, audit event or application write path | `db/models.py:464-482`, `db/dal.py:237-254` | A direct `UPDATE Config_Tuning SET TuningValue='0.9' WHERE TuningKey='scoping_score_threshold'` at 02:00 silently changes every session created afterwards, with no attribution and no record | Two additive columns and one route, no new subsystem. Add a `Version` column bumped on every edit; include the resolved `(key, version)` pairs in the `TuningJSON` snapshot so a session records exactly which policy it ran under | low | d |
| F5 | Curated master-library rows have **no** optimistic concurrency | `db/dal.py:1957-1967`, `db/models.py:308-461` | Two curators open the same `Threat_Catalogue` row in the admin UI. One rewrites the Description; the other, seconds later, corrects the SectorID from a stale copy of the form — a silent lost update | **No schema change needed** — use the `UpdatedAt` column that already exists as the version token. Have the GET routes return it as an ETag, and add `model.UpdatedAt == expected` to `update_library_row` and `soft_delete_library_row` when `If-Match` is supplied; 409 on rowcount 0. Non-breaking. The same shape gives `if_review_status` on `review_plan` (gap B7) | low | d |
| F6 | `TenantID` is caller-supplied, written NOT NULL onto every row, and never used as a filter *(same as E4)* | `db/models.py:58`, `api/deps.py:68-83`, `:127-151` | Isolation itself is **not** broken — `EntityID` enforces it soundly, so this is not a data-leak finding. The failure is downstream reporting and evidence | See E1 / E4 | low | h |
| F7 | `PROMPT_VERSION` is a frozen constant *(same as A7)* | `pipeline/prompts.py:25-27` | See A7 | See A7 | low | h |
| F8 | `Threat_Candidate_Review` has no uniqueness index *(same as C7)* | `db/invariants.py:27-70`, `db/dal.py:1806-1825` | Bounded and already reasoned about in the code: two sessions accepting simultaneously queue two identical cards; approving the first resolves both to the same master row | Defer until admins actually report the noise. See C7 for the fix shape | low | h |
| F9 | No backup/RPO/RTO/restore-test documentation, and no record of which script level a database is at | `db/invariants.py:118-130` | The migration half is documentation-only — the boot-time invariants already fail closed against a stale schema, which is a **stronger** guarantee than a version table, so no incident is enabled. **The DR half is a real business gap:** a repo-wide search finds no RPO, RTO, backup cadence, restore-test schedule or named recovery owner anywhere | An SDD/runbook amendment, not a code change. Add a DR section to `tsg/scripts/readme.txt` — already the DBA-facing runbook — stating the agreed RPO, RTO, backup schedule, restore-test cadence and named owner for MSSQL and Mongo, plus the standing note that Redis is rebuildable coordination state. Optionally add a two-column `TSG_Schema_Level(ScriptName, AppliedAt)` table each script inserts into. **Do NOT introduce alembic on this branch** — it would be retrofitted over a database-first schema TSG does not exclusively own, duplicating what `invariants.py` already guarantees. (Note: some feature branches carry a `migrations/versions/` tree; reconcile that choice deliberately rather than by merge.) | doc | h |

---

## 10. Execution order

### Wave 1 — do now
**~200 lines across 12 files. No schema change. No API contract change. 2-3 days for one developer.**

| Order | Gap | Change |
|---|---|---|
| **0** | **B11** | **`git -C tsg checkout -- docs/`** — restores 17 deleted documents including the 71 KB `RISK_TREATMENT_PLAN_SDD.md` that 15 code sites cite. Minutes, and it resolves every dangling reference in the codebase |
| 1 | B1 | Bound the treatment retry — `celery_app.py:221-223` |
| 2 | A1 / D2 | Make cancel actually cancel — `dal.py:709-730` + two break sites |
| 3 | F2 | Fix the beat pod's config source — `deploy.yaml:209-211` |
| 4 | D1 + D7 | Reconcile on change, and add plan state to the board — `sessions.py` |
| 5 | E5 + E6 + E10 | Harden the outbound fetch path — `intel/fetchers.py` (net code removal) |
| 6 | D3 | Mount `/metrics` + four counters |
| 7 | F1 | Detect the rules drift via `_rules_hash` |
| 8 | C6, B6, B8, E7, E9, A6, A3 | Cheap correctness batch — one PR, six files |
| 9 | D10 | Reaper sweep for treatment plans |
| 10 | D6 | Typed partial outcome |

### Wave 2 — next
**~600 lines plus six additive `ALTER TABLE ADD` migrations. 2-3 weeks.**

E1 → E2 → E3 → A2 → F3 → C1 → C3 → C2 → C8 → D4 + D8 → F5 + B7

> E1 is Wave 2 rather than Wave 1 **only** because it needs a backfill and a coordinated
> rollout on the calling side. It ships dark — NULL scope preserves current behaviour — so the
> code change can land well before activation.

### Wave 3 — deferred, each with a written trigger

| Gap | Trigger that promotes it |
|---|---|
| C4 — source object identity for imports | Orphan near-duplicates observed after two upstream releases, **or** an auditor asks which MITRE version a library row came from |
| B9 — per-tenant rate limiting | A second integration key exists (E1 makes this safe to issue) |
| F4 — `Config_Tuning` versioning | A second person gains production DB write access, or a compliance review asks who changed a threshold |
| C7 / F8 — candidate uniqueness index | Admins report duplicate cards, or an approve-after-reject contradiction is observed |
| E7 (full) — DB-driven AI egress policy | A regulator or customer contract requires a documented classification decision per outbound payload, or a second AI provider is introduced |
| E11 — named authorization scopes | A genuinely read-only consumer needs provisioning |
| D5 — `/ready` capability split | A Redis or Mongo failover actually causes a read outage that matters |
| F9 — DR runbook | Production go-live sign-off |

### SDD amendments

A7, A8, A9, B11, C10, D11, E11, F9 — plus the **12 internal contradictions** in the SDD itself
(§33Q declares that it supersedes earlier sections, but the superseded text was left in place;
notably `SCENARIO_REGENERATION` has no OPERATION value despite the endpoint existing, and the
STAGE enum is absent from the catalogue §33Q.18 gates on). Track these together with B11 as one
reconciliation pass.

---

## 11. Verification

```bash
cd tsg && python -m pytest tests/ -x
```

- `tests/test_accept_any_version.py` and `tests/test_treatment_plan_versions.py` pin the
  behaviours most at risk from Wave 1.
- **A1 / D2** — start a session, `POST /cancel` mid-generation, and confirm the worker stops
  within one lease renewal instead of running to completion.
- **B1** — force `LLMSlotUnavailable` and confirm the row reaches `ERROR` / `generation_failed`
  rather than staying RUNNING.
- **D1** — open the SSE stream, force a publish failure, and confirm the client still observes
  the review transition via a re-emitted `reconcile`.
- **F2** — manifest only; verify `tsg-beat` and `tsg-api` resolve identical settings via
  `tsg.self_check`.
- **Any Wave 2 schema change must register its index in `invariants.REQUIRED_INDEXES`** or the
  application will refuse to boot. That is the guardrail — use it rather than working around it.
