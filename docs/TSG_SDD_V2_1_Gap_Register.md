# TSG — logical and fundamental gaps in SDD v2.1

**Companion to `Threat_Scenario_Generator_SDD_V2.docx` v2.1**

| Attribute | Value |
|---|---|
| Document type | Gap register (document completeness, not factual accuracy) |
| Subject | The SDD itself, as an artefact to be reviewed and signed off |
| Method | Four independent lenses over the document and the code, each followed by a refute-by-default verification pass |
| Result | 53 candidate gaps raised, **12 refuted**, **41 confirmed**, deduplicated below to 32 distinct items |
| Date | 2026-09-20 |
| Status | **Closed in SDD v3.0 (21 September 2026)** — kept as the record of what was fixed and why |

> **All 32 items are closed.** They were addressed in the clean rewrite,
> `Threat_Scenario_Generator_SDD_V3.docx` v3.0, and in the new
> `Remediation_Plan_SDD_V1.docx` v1.0, which now owns the treatment-plan items (17, and the plan
> halves of 5 and 11). A reviewer checked each item against the finished drafts before the
> documents were built. The `[v2.1]` markers below refer to the superseded v2.1 tracked-change
> draft and are kept for history.

---

## Verdict

**No — the document is not free of logical and fundamental gaps.** Its *factual* claims now match
the code (that was the v2.1 synchronisation). What remains is a different class of problem: places
where the document does not hang together as a design, promises something it never delivers, or
omits content a reviewer signing the approval table would need.

Four items are severe enough that a reviewer could approve this document believing something
untrue about the system. They are listed first.

Several gaps were **created or exposed by the v2.1 correction itself**, and are marked `[v2.1]`.
That is a direct consequence of the agreed v2.1 scope — "repair false counts, add one-line
mentions, no new full sections" — which made the counts true without supplying the prose behind
them. Closing them means writing new content.

---

## The four that matter most

### 1. Section 6 announces seven administrative operations and describes four `[v2.1]`

*Found independently by all four lenses.*

Section 6's opening now says "the seven administrative operations", and Fig 7 carries a row for
each. But the "How it works" bullets cover only embedding cache, calibration, threat intel and API
clients. **Threat-library import, curator approval of promoted library rows, and the ATT&CK/CAPEC
technique reference have no steps anywhere in the document.**

This is not cosmetic, because two other sections terminate their flow at the missing one:

- §2 Key rules: "until a curator approves it through the library approval queue in section 6"
- §3 promote bullet: "reaches the shared library only once a curator approves it"

Both forward-references dangle. The document's own stated purpose is that each module section gives
"the exact steps the system runs, in order"; for three of seven operations it does not. The
technique reference is the sharpest case — it is a live input to every scenario prompt, and an
operator has a route prefix and nothing else.

**Fix:** three new bullet sets in §6 — inputs, steps, idempotency, failure behaviour, and how an
operator confirms success. For the approval queue specifically: who works it, approve/reject
outcomes, and what happens to a promoted row nobody ever reviews.

### 2. The entity-isolation argument does not close

§5 states: "The API key is hashed and looked up against active `API_Client` rows for this module;
the user, entity and tenant headers are then **trusted as request input**." §1 states that the
requested entity must be "the caller's entity".

Nothing in the document binds an API key to a set of entities. As written, the entity check is a
caller-asserted value checked against a caller-asserted value. The tables that could close it —
`user`, `user_scope_assignment` — appear once, in the Data stores row, with no prose. In the code
`verify_membership` defaults to `False` and is documented as the accepted model, not an unfinished
one (`app/core/config.py:626-629`).

That may well be the right design given an upstream identity service. **The gap is that the
document never says so.** It never names the upstream service that authenticates end users and
populates `X-User-Id`/`X-Entity-Id`, never states that entity isolation therefore rests on that
caller being trusted, and never states the blast radius of a leaked API key — which, on the
document's own description, is any entity's CII threat data via an attacker-chosen header.

Related: the document names **reviewer**, **curator**, **administrator** and **operator** as if
they were roles. Only two credentials exist, and one shared admin key gates curation, calibration
and key minting alike. There is no separation of duties, and the acting identity on every audit
row is an unverified header.

**Fix:** a short trust-boundary and role subsection in §5, mapping the four named roles onto the
two credentials that exist, and stating plainly what TSG verifies and what it delegates.

### 3. `grounding_summary: COMPLETE` is a count verdict, not a quality verdict

The audit row is named `grounding_summary` and §2 says it "records COMPLETE or PARTIAL". The
document never defines what those mean. In the code:

```
final_status = "COMPLETE" if delivered >= max_threats else "PARTIAL"
```
`app/pipeline/threat_identification.py:1221`

It measures **requested versus delivered count only**. Nothing about grounding.

This matters most at cold start. §2's whole premise is library-first, but with a thin or unseeded
`Threat_Catalogue` the gap equals the full requested count, every threat is AI-generated, and most
will be unverified — while the audit row still reports `COMPLETE`. A reviewer reading Fig 1's
"every threat grounded" alongside a COMPLETE status would reasonably conclude the output was
library-grounded when none of it was.

**Fix:** define COMPLETE and PARTIAL explicitly in §2 as the count verdict they are, add a Key
rule describing the thin-library behaviour, and soften Fig 1's "every threat grounded" to match
§2's own unverified path.

### 4. The assessment's completeness verdict is absent

§2 writes "one copy of each threat per supporting system (coverage grid)" and its audit bullet
mentions gate statistics — but the document never defines the coverage grid as the
(supporting system × STRIDE category) matrix the session is supposed to answer, never states the
rule that attributes a threat to a system, and never gives a session-level verdict for whether the
assessment is actually complete.

Compounding it: coverage reporting is **off by default** (`coverage_reporting_enabled`), so in the
default posture the grid is never computed, audited or published at all — and a session reaches
REVIEW with status `completed` regardless.

**Fix:** a §2 subsection defining the grid, the attribution rule and the session-level coverage
verdict, stating explicitly that a session can complete at REVIEW while the assessment is
incomplete.

---

## Flow and state gaps

| # | Gap | Fix |
|---|---|---|
| 5 | Fig 4 shows seven reviewer actions; the prose explains five. **unaccept** and reviewer **cancel** appear once each, in a figure line, and nowhere else `[v2.1]` | Add §3 bullets for both: preconditions, audit row, and the effect of unaccepting a scenario that already has a treatment plan |
| 6 | **Cancel is offered as a review action but the session is already `completed` at REVIEW** | State that cancel applies only to an active session, and that a cancel during generation does not interrupt in-flight stages — they stop at their next claim check |
| 7 | "either can be recorded later, in any order" is misleading: **a rejection is final**; unaccept reverses an acceptance only | State that a rejection is terminal and a regenerated version is the only route back |
| 8 | **Total generation failure has no described outcome** — what a wedged session looks like and what an operator does | State the terminal path: stage stays ERROR, session finalised to cancelled, asset released, new session the only remedy |
| 9 | The **stage attempt cap** has no exhaustion behaviour or operator recourse | State the resulting state, how a wedged session is recognised, and the documented reset path |
| 10 | **`content_blocked` is a terminal, non-retryable outcome** the document never describes, and it contradicts §3/§5's claim that moderation is advisory and never blocks | Add the provider guardrail refusal as a distinct AI-call outcome; qualify the "advisory" statements |
| 11 | **Acceptance displacement** — accepting a different version of an already-accepted scenario — is undescribed, as is what it does to an existing remediation plan | Describe the two linked audit rows from one request; state that a plan is bound to the scenario version it was generated from |
| 12 | Three of the four ways a threat can be dropped are **permanent**, and neither the kinds nor their finality are stated | Name the rejection kinds, say which are re-servable, and define `exhausted` as "no re-servable threats remain" |
| 13 | **Next-set re-reserves an asset that the review barrier released** — no stated failure path when a newer session already holds it | Add the status and reason code returned, and qualify §1's "releases the asset for a new session" |
| 14 | States are introduced piecemeal across six sections and **never enumerated** | Add a state table — stage, session status, session stage, scenario decision, plan — with legal transitions |

## Undefined vocabulary

| # | Term | Status |
|---|---|---|
| 15 | **`epoch`** — used 7 times; the central fencing concept of the whole concurrency model | Never defined |
| 16 | **`asset unit`** — used twice; it is the row carrying the canonical `Identified_Threat` | Never defined, and used interchangeably with "subsystem" and "supporting system" where the concurrency model depends on the distinction |
| 17 | **`invalid_plan`, `content_blocked`** | Listed as error reasons, never defined |
| 18 | **`next_set_outcome`: complete / partial_retryable / exhausted** | Listed, never defined |
| 19 | **`curator` vs `administrator`** `[v2.1]` | Two words for one actor; neither defined, and no curator role exists in the code |

## Missing fundamental content

| # | Gap |
|---|---|
| 20 | **No retention, purge or classification policy.** `Prompt_Log` holds exact prompts and raw replies, `Scenario_Audit` is append-only, versions are never deleted — presented as a feature, with no retention period, no access rule, and nothing about entity offboarding |
| 21 | **The AI provider is never treated as a trust boundary.** Which gateway production uses, whether prompts carrying a named CII asset's criticality, RTO/RPO, hosting and vendor profile leave the organisation's network or jurisdiction, and whether the provider retains or trains on them |
| 22 | **No non-functional requirements at all** — no throughput, latency, concurrency, volume, or expected duration from the 202 to REVIEW, so a consumer cannot set a timeout |
| 23 | **No deployment topology, environment definition, release/rollback or migration strategy.** `local`/`dev`/`staging`/`prod` drive documented behaviour in §5 but are never introduced; nothing says migrations must precede a new build, or whether the four processes may run at mixed versions |
| 24 | **No scope, assumptions, constraints or dependencies section.** The upstream identity service, the AI provider, five intel feeds, ATT&CK/CAPEC, local model files and the platform's `ctm_scan`/`onboarding` tables are all load-bearing dependencies never named as such — nor is what TSG is *not* |
| 25 | **Degraded-mode posture is partial.** Redis and the AI provider are covered; **SQL Server and MongoDB failure are never addressed** — notably whether identification re-embeds, proceeds without intel, or fails the stage when Mongo is down |
| 26 | **No backup/DR, RTO or RPO for TSG itself** — the acronym table defines RTO/RPO, and the document uses them only as attributes of the *assets it reads* |
| 27 | **Bootstrap paradox.** Start-up refuses to serve without at least one active API client (staging/prod), and the only documented way to create one is to POST to the running API. The out-of-band seed step appears nowhere. The admin key is likewise never documented as a configuration item |
| 28 | **Behaviour is repeatedly deferred to configuration that is never enumerated.** No appendix lists the settings the prose defers to, their defaults, or safe ranges |

## Defaults that disable documented protections

| # | Gap |
|---|---|
| 29 | The **shared AI-call limiter** is presented as always-on; it takes no slot until an operator sets a non-zero ceiling. §1 already uses the right wording for the session ceilings — this needs the same |
| 30 | The §3 Key rule certifies an **empty control list** as a genuine library gap. It reads the same way when the Control Library is unseeded or the minimum score is set too high |
| 31 | **Only one of three decision thresholds has documented provenance.** Grounding is calibrated; the relevance gate and the control-mapping minimum score are separate configured values that must each be measured for their own query shape, and the grounding calibration does not transfer to them |
| 32 | **Which processes run the start-up guards is now ambiguous** `[v2.1]`. Fig 6 says "START-UP (API and worker)" while the Overview now says four processes. The guards fire in the API and **both** workers (`worker_init`/`worker_process_init`, `app/pipeline/celery_app.py:209-211`) and **not** in beat |

---

## What was refuted

Twelve candidate gaps did not survive verification — most because the document does cover them
somewhere the first reviewer had not looked (the acronym table, a Key rules list, or the Data
stores and Appendix A tables), and the rest because they belong in an operations runbook, a test
plan or an infrastructure design rather than in a solution design document. They are not listed
here; the point is that the 32 above are what remained after trying to dismiss them.

## Suggested sequencing

1. **Cheap and mechanical** — items 15–19 and 32: define five terms, align one vocabulary, fix one
   figure line. No design decisions needed.
2. **Needs writing, no decisions** — items 1, 5–14: the missing §6 operations and the flow/state
   prose. The behaviour is already settled in code; it just is not written down.
3. **Needs an author decision** — items 2, 20, 21, 22, 23, 24, 26: the trust boundary, retention,
   AI egress, NFRs and scope statements are assertions about intent that only the design owner can
   make.
4. **Needs measurement** — items 3, 4, 30, 31: the completeness verdict and the two unmeasured
   thresholds.
