# TSG Library-First Threat Identification — Development Tracker

Replaces the LLM validator (`_validate_candidates`) with a library-first, rerank-gated
retrieval funnel. The LLM becomes a bounded gap-filler, never a catalogue validator.

**Status legend**: `[ ]` pending · `[x]` done · `[~]` in progress. Update this file as
each item lands; add notes inline.

---

## Why (measured problem)

One production run (session `eede3dee`, asset PGS, 2026-08-31): `_validate_candidates`
sent all 1,642 active `Threat_Catalogue` rows through 42 sequential billed LLM batches —
**2,521s (~42 min), 93% of the total 45-min run** — and only 6 of the 1,642 verdicts were
used (the library alone filled all six STRIDE slots; generation was skipped). Cost scales
linearly with catalogue size: at 10,000 rows this becomes ~250 batches per run.

## Target behavior

> Hybrid-search the threat library first. If the library contains enough high-quality,
> relevant, unique threats satisfying the requested count and coverage requirements, do
> not call the LLM for threat identification at all. If insufficient, invoke the LLM only
> to generate the specific missing quantity/coverage. Count is always matched — weaker
> (below-threshold) candidates may backfill, explicitly flagged. Applies identically to
> the initial run and to "generate next set".

## Target flow

```
ASSET CONTEXT → context normalization (existing)
  → hybrid retrieval: metadata/BM25/dense (existing) + reranker (NEW)
  → Top-K pool (NEW, TSG_THREAT_RETRIEVAL_TOP_K)
  → hard relevance gate (NEW, TSG_THREAT_RELEVANCE_THRESHOLD; below-threshold kept as backfill pool)
  → dedup (existing: identity + retrieved-vs-prior semantic)
  → STRIDE selection pass 1 (existing stride.allocate/assign)
  → coverage evaluation: quantity gap + coverage gap
      ├─ SUFFICIENT → zero LLM calls
      └─ GAP → one bounded LLM call (gap + buffer, capped)
           → structural validation → grounding (library match adopts canonical id
             / no match = custom) → cross-dedup
  → final STRIDE selection over merged pool (NEW second pass)
  → count backfill to requested (flagged) → COMPLETE | PARTIAL
  → persist → scenarios → controls (unchanged)
```

---

## Phase 1 — Retrieval gate (`threat_retrieval.py`, `grounding.py`)

- [x] 1.1 Widen `grounding.ground_control_queries` with optional `shortlist_k: int | None`
      (fallback to `control_map_shortlist_k`; zero change for control mapping).
      File: `app/pipeline/grounding.py`. Done when: control-mapping tests untouched/green.
- [x] 1.2 New `threat_retrieval.score_relevance(llm, candidates, subsystems, asset_context, s)`
      → `{catalogue_id: max reranker score across queries}` via `build_queries` + one
      query-embed + `ground_control_queries(shortlist_k=threat_retrieval_top_k)`.
      Done when: returns 0-100 scores; RRF score never compared to threshold.
- [x] 1.3 Hard gate + backfill pool in `find_threats`: ≥ threshold passes first-class;
      below-threshold retained sorted as backfill. Done when: gate audit shows kept/dropped.
- [x] 1.4 Failure states: remove catch-all (tasks.py:804-810) — infra failures propagate to
      Celery stage retry; empty result = legitimate fallback; reranker failure → ungated
      Top-K + `ranking_degraded=True`. Done when: test G-11 passes.

## Phase 2 — `find_threats` restructure (`app/pipeline/tasks.py`)

- [x] 2.1 `RELEVANCE GATE` trace step replaces `LLM VALIDATOR` block (811-817).
- [x] 2.2 Order: gate → identity dedup → retrieved-vs-prior semantic scan → `deduped_relevant`.
- [x] 2.3 Pass-1 STRIDE selection on gated pool (existing allocate/assign).
- [x] 2.4 Coverage evaluation: explicit `quantity_gap` + `coverage_quota`, both audited.
- [x] 2.5 Gap path: `gap_ask = min(_gap_ask(gap), threat_llm_max_generation)`; delete early
      break (line 1001) and GAP-B `rejected_catalogue_ids` (825-826, 1031-1038); extend
      `_usable_proposal` with STRIDE-enum check; provider failure → keep library results →
      backfill → PARTIAL only if still short; `LLMSlotUnavailable` still propagates.
- [x] 2.6 Final STRIDE selection over merged pool (library first); build retrieved records
      post-merge with assigned category.
- [x] 2.7 Count backfill to requested: (a) unpicked above-threshold, (b) surplus generated,
      (c) below-threshold pool by score — each flagged `backfill: true` + score.
- [x] 2.8 Audit block replaces `validator`: status/requested/delivered/backfilled/gaps/
      missing_stride/per_category/threshold/gate tallies/llm tallies/ranking_degraded.
- [x] 2.9 Next-set parity: additive inputs (`held`, `prior_threats`, `existing_identities`,
      `exclude`) preserved; `run_next_set` inherits automatically. Test G-17.
- [x] 2.10 Downstream (Phase-2b fan-out, scenarios, controls) untouched.

## Phase 3 — Deletions & config

- [x] 3.1 Delete `_validate_candidates` (tasks.py) + `prompts.threat_validation_prompt`.
- [x] 3.2 Delete `validator_batch_size` (config.py) + `TSG_VALIDATOR_BATCH_SIZE` in
      `.env.example`, `.env.uat`, `.env.prod.example`, local `.env` note.
- [x] 3.3 Add `threat_retrieval_top_k` (int, 100), `threat_relevance_threshold`
      (float, 50.0), `threat_llm_max_generation` (int, 15) to config §10 + env templates.
- [x] 3.4 Keep `DuplicateReason.validator_rejected` (historical rows readable).
- [x] 3.5 `python -m app.core.env_selfcheck` passes.

## Phase 4 — Provenance & observability

- [x] 4.1 `retrieval_score` (RRF) + `relevance_score` (reranker) carried on candidates into
      per-threat `grounding_summary` entries.
- [x] 4.2 Trace steps provide latencies (retrieval / rerank gate / generation / grounding).

## Phase 5 — Tests

- [x] 5.1 Delete `tests/test_validator_reversal.py`.
- [x] 5.2 Rewrite `tests/test_library_first_identification.py` (no validator branch;
      `FakeLLM.rerank` load-bearing; new audit shape).
- [x] 5.3 New `tests/test_relevance_gate.py` covering the G-matrix:
      G-1 library-sufficient → zero chat calls · G-2 exact quantity gap in prompt ·
      G-3 coverage gap triggers LLM with missing categories · G-4 duplicates don't count ·
      G-5 generated dup grounds to canonical id · G-6 novel custom accepted ·
      G-7 malformed LLM output rejected safely · G-8 short generation → backfill, flagged ·
      G-9 429 bounded retry · G-10 empty retrieval → fallback · G-11 infra failure
      propagates · G-12 task retry idempotent · G-13 terminal assign corrects imbalance ·
      G-14 deterministic for fixed input · G-15 no shared-session concurrency ·
      G-16 injection fences intact · G-17 next-set parity · G-18 backfill order + exact count.

## Phase 6 — Measurement & rollout

- [x] 6.1 New `scripts/measure_threat_relevance_scores.py` (clone of
      `measure_control_map_scores.py`): kept/dropped reranker-score distributions.
- [ ] 6.2 Run on UAT; pin `TSG_THREAT_RELEVANCE_THRESHOLD` per environment from data.
- [ ] 6.3 Replay traced session (PGS): `RELEVANCE GATE` replaces `LLM VALIDATOR`; ~45 min →
      low minutes; same 6 verified threats; audit `status: COMPLETE`.
- [ ] 6.4 Resilience check: LLM proxy down → library threats persist, `status: PARTIAL`
      only when backfill can't reach count.

## Hardening pass (post-implementation audit, 2026-09-01) — DONE

Adversarial review of the new funnel found and fixed 9 root-cause issues (574 tests green):

- [x] H1 Terminal relabel now updates `ThreatCategoryID` alongside `ThreatCategory`
      (promote reads the ID — prevented the "everything is DoS" bug re-entering).
- [x] H2 Backfill pool passes the semantic-duplicate scan (vs prior + kept threats)
      before admission; blocked count recorded (`backfill_semantic_blocked`).
- [x] H3 Backfill is coverage-aware: unfilled STRIDE cells served via `stride.assign`
      first (no positional `categories[0]` labelling), then score-order padding.
- [x] H4 Provenance split: `selection_source` stays the retrieval leg ("hybrid");
      `gate_outcome` (passed/below_threshold/ungated) is its own fact; audit lists
      `backfilled_threats` with scores.
- [x] H5 `LLMSlotUnavailable` re-raised (never degraded) in retrieval embed,
      `_semantic_duplicates`, and `prime_query_embeddings`.
- [x] H6 ONE query-embed round per run: `find_threats` embeds the funnel queries once and
      hands vectors to retrieval AND the gate (optional params, back-compatible).
- [x] H7 Corpus tokenized once per run for BM25 (`hybrid_match(docs_tokens=...)`),
      not once per query.
- [x] H8 `_MATRIX` cache holds up to 4 text-list shapes per (model, group, kind) —
      the gate's Top-K subset and regrounding's full corpus no longer evict each other
      every run.
- [x] H9 Identity claims released when a threat is dropped by a semantic scan — no more
      false PARTIAL from claimed-but-never-inserted identities. (`admitted_cids` deleted
      as redundant with the identity check.)

## Structure pass (audit round 3, 2026-09-01) — DONE

`find_threats` had become a 630-line god function inside a 2,337-line tasks.py. Fixed at
the cause by extraction + decomposition (574 tests green; zero behavior change):

- [x] S1 New `app/pipeline/pipeline_common.py` (231 lines): shared stage primitives moved
      verbatim (`_ask_ai`, SSE/progress helpers, text/identity utils, `_dedup_key`).
- [x] S2 New `app/pipeline/threat_identification.py` (1,131 lines): all of Stage 1,
      decomposed into single-responsibility stage functions (gate, pass-1 selection,
      prior-paraphrase drop, coverage eval, gap generation, proposal consumption,
      generated dedup, terminal selection, backfill, fan-out, audit) + an
      `_IdentificationRound` data record for round state. `find_threats` is now a
      117-line orchestrator.
- [x] S3 tasks.py: 2,337 → 1,399 lines; re-exports every externally referenced name, so
      dal/promote/cascade/tests keep importing via `app.pipeline.tasks` unchanged.
      Layering is acyclic: pipeline_common ← threat_identification ← tasks.
- [x] S4 Guard scripts verified: the `_ask_ai` correlation guard targets scenario-path
      functions (still in tasks.py); the app-tree AST guards scan recursively and cover
      the new modules automatically. One test updated to patch the moved module
      (`threat_identification._ask_ai`) instead of tasks' re-export — an import-path
      change only.
- Out of scope, flagged: pre-existing large files (schemas.py 2,717 / dal.py 2,437 /
  sessions.py 1,413 / grounding.py 1,123) predate this work and were left untouched
  deliberately (Rule 21: no unnecessary rewrites of working components).

## Naming pass (audit round 4, 2026-09-01) — DONE

- [x] N1 Renamed 14 vague internal names in `threat_identification.py` to precise ones
      (e.g. `_pass1_selection` → `_select_library_candidates`, `_generate_gap` →
      `_generate_gap_proposals`, `_consume_proposals` → `_ground_and_admit_proposals`,
      `_Round` → `_IdentificationRound`, `cat_id` → `resolve_category_id`). All private
      to that module — zero external churn. Pre-existing re-exported names kept (they are
      import contracts for dal/promote/cascade/tests).
- [x] N2 Every function in the new modules (and `threat_retrieval`'s retrieval/gate pair)
      now opens its docstring with one short plain-English sentence saying what it does;
      detailed rationale kept below. 574 tests + pipeline guards green after both passes.

## Residue sweep (audit round 5, 2026-09-01) — DONE

Fresh audit over the post-restructure state found no logic/IO/structure defects (rounds
1-4's fixes all held); it caught extraction residue, fixed at the cause (574 tests green):

- [x] R1 Stale comments describing the DELETED LLM validator as live, corrected in
      `threat_retrieval.py` (module docstring), `core/enums.py` (`validator_rejected` is
      now explicitly HISTORICAL-ONLY), `db/models.py` (Description-drop note).
- [x] R2 Eight dead imports removed from the slimmed tasks.py (`math`, `re`, `overload`,
      `DuplicateReason`, `GroundingStatus`, `stride`, `grounding`, `threat_retrieval`) —
      verified unreferenced by AST scan + repo-wide external-reference grep. The
      re-export block is intentionally kept (it IS the external contract).
- [x] R3 Two test monkeypatches retargeted from tasks' removed module alias to
      `threat_identification.threat_retrieval` (the namespace the code reads).
- [x] R4 Cosmetic: `_ask_ai`'s docstring moved flush under its signature.

## Boundary-resilience pass (audit round 6, 2026-09-01) — DONE

Adversarial audit of the INTEGRATION boundaries around the funnel (internals were clean).
Found and fixed at the cause (577 tests green, +3 new):

- [x] B1 [HIGH] A transient DB error (deadlock/connection reset) during retrieval was
      swallowed by the Celery task layer's `except Exception` and CANCELLED the whole
      session (Celery's autoretry never saw it). Fix: named contract
      `pipeline_common.TRANSIENT_INFRA_ERRORS` (= `OperationalError` only — broader
      DBAPIError would retry genuine SQL bugs), re-raised past the failure handler and
      added to `autoretry_for` on tsg.run_pipeline / tsg.next_set / tsg.regenerate.
      Transient blip → clean stage retry (CAS-idempotent) → session completes.
- [x] B2 [MED] The next-set top-up swallowed the same errors and stamped the stage
      COMPLETE — a failed retrieval looked healthy. Fix: transient re-raise at both the
      inner top-up (skips the COMPLETE stamp) and the outer round handler.
- [x] B3 Enum-classified, detailed error logging (user requirement): new
      `InfraErrorKind` enum + shared `log_transient_infra_retry` helper — one structured
      WARNING (`pipeline.transient_infra_error_retrying`) with site, session, subsystem,
      enum kind, exception class, truncated detail, action taken, and full traceback.
- [x] B4 Confirmed CLEAN by the same audit: cascade arithmetic under PARTIAL/backfill/
      trim, grounding_summary API readers, stage-CAS re-claim on retry, and no caller
      relying on removed exception flows.
- [x] B5 Three regression tests: session NOT cancelled + log fields asserted; next-set
      propagation; autoretry_for config pin on all three tasks.

## Cleanup-path resilience pass (audit round 7, 2026-09-01) — DONE

Round 7 audited round 6's own changes and found the transient re-raise was defeated by
its own cleanup path:

- [x] C1 [HIGH] `_process_all_supporting_systems` re-raised the transient without
      `sess.rollback()` — the `finally`'s release_lock then ran SQL on a failed
      transaction and raised PendingRollbackError, REPLACING the OperationalError
      mid-flight; PendingRollbackError is not in autoretry_for, so the task failed
      permanently (the exact symptom B1 was meant to prevent). Fix: rollback in the
      transient clause before the raise (mirrors `_record_failure`'s own first line).
- [x] C2 [MED] `_subsystem_lock`'s guarded release prevented masking in cascade but
      failed silently on a dirty session — the lock row stayed RUNNING into the Celery
      retry, and this hit regenerate too (no transient clause of its own). Fix at the
      cause: rollback-on-exception inside `_subsystem_lock` itself, covering next-set,
      regenerate, control-map sweep, and any future user in one place.
- [x] C3 [TEST-FIDELITY] Both round-6 transient tests passed VACUOUSLY: the fakes
      raised without deactivating the session (a real deadlock does), and the next-set
      test never even reached the fake — `next_unserved_unique_threats` raised its own
      accidental OperationalError because Threat_Scenario and Scoped_Threat were missing
      from the test schema subset. Fixes: failed-flush poison in both fakes (genuine
      PendingRollbackError state), both tables added to `_engine()`, and a lock-released
      assertion after next-set propagation. Each test was proven to FAIL with its
      rollback removed before the fix was restored (no more vacuous green).

## Regeneration transient-contract pass (audit round 8, 2026-09-01) — DONE

Round 8 swept every remaining `_record_failure` / `except Exception` site for the
transient contract rounds 6–7 established, and found regeneration was left out:

- [x] D1 [HIGH] `run_regeneration`'s in-lock `except Exception` routed transients into
      `_record_failure` → session cancelled; the `autoretry_for` on `tsg.regenerate`
      (added in B-round "for consistency") was dead code for exactly the errors it
      names. Fix: transient re-raise clause (site `regenerate.subsystem`), dirty
      session handled by `_subsystem_lock`'s C2 rollback.
- [x] D2 [HIGH, same class] The pre-lock handler (target reads before any stage claim)
      had the same swallow. Fix: transient re-raise clause (site `regenerate.pre_lock`)
      with its own rollback (no lock manager on that path).
- [x] D3 Judged CORRECT and left alone: `_subsystem_lock`'s guarded release, the
      best-effort regen result publish (work already committed; clients poll), the
      variant top-up fallback (deliberate user-retryable click outcome), the
      control-map sweep's per-session isolation (next tick retries naturally), and the
      two already-fixed sites.

Two regression tests (in-lock: session active + lock released; pre-lock: session
active), each proven RED against the old swallow behavior before the fix was restored.

## Treatment-plan (remediation-plan) audit — DONE

A separate cross-check of the risk-treatment/remediation-plan feature
(`app/pipeline/treatment.py`, `app/api/treatment.py`) — its own self-contained module,
outside the stage machinery the rest of this tracker covers. Verdict: exceptionally
well-engineered (PII redaction, server-owned reserved-key stamping, case-folded
control-code resolution, structural-vs-advisory validation split); `_launch_generation`'s
133 lines judged justified sequential/transactional complexity, not a god function — left
untouched.

- [x] E1 [HIGH] `run_treatment_generation` / `generate_treatment_plan_task` never got the
      `TRANSIENT_INFRA_ERRORS` retry contract rounds 6-8 added to run_pipeline/regenerate/
      next_set — a transient DB blip during plan generation was misclassified as a
      permanent "generation_failed" and the plan parked ERROR with no Celery retry. Fix:
      same contract, same helpers (`TRANSIENT_INFRA_ERRORS`, `log_transient_infra_retry`),
      applied to `treatment.py` and `celery_app.py`'s `generate_treatment_plan_task`
      (autoretry_for + a tuple-catch on the manual exhaustion branch).
- [x] E2 [MED, found while fixing E1] The exhaustion branch wrote
      `TreatmentOutcomeReason.timed_out` on slot/infra exhaustion — but `timed_out` is
      documented (`app/core/enums.py:532-537`) as a READ-TIME-ONLY projection
      (`api.treatment._present_status`) with "no writer for it." Fix: both exhaustion
      causes now write `generation_failed` ("retryable as-is" — the accurate, already
      writable value), with cause-specific client messages.
- [x] E3 [MED, found via the self-check] `_plan_result_event`'s SSE payload published
      `ScenarioID` instead of the schema's `scenario_id` — the field the
      `TreatmentPlanResultEvent` docstring explicitly tells clients to "MATCH ON," since
      it's stable across regenerations unlike `plan_id`. Any real client following that
      documented advice silently failed to match. Fix: corrected the key. Zero tests
      pinned the old key (no coverage existed), so no test needed updating.
- [x] E4 [LOW] `treatment.py`'s own `__main__` self-check (pure-logic, no DB/LLM) had been
      broken for a while — E3's bug plus two stale assertions that predated later rule
      changes (`_validate_plan`'s "empty action plan warns even when covered" rule, and
      `_clip`'s appended `" [truncated]"` marker). All three fixed; `treatment self-check
      ok` now genuinely passes.

Tests: 3 new (one parametrized ×2) in `test_treatment_plan_versions.py`, each proven RED
against the pre-fix code before being restored to green. Full suite: 583 passed.

## Phase 7 — Retrieval cache (follow-on commit)

- [ ] 7.1 `app/pipeline/retrieval_cache.py` on the embeddings.py Mongo template.
      Key = sha256(canonical asset_context + subsystems) + library_version
      (`MAX(ThreatCatalogueID), COUNT(*)` — catalogue is append-only) + model ids +
      top_k + threshold. Value = gated scored candidate list. Fail-open on Mongo breaker.
