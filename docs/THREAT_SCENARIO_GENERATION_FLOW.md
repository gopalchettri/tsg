# Threat Scenario Generation — Flow and Known Gaps

> **Vintage:** this document reflects the codebase after the PROFILE-stage removal and the
> UI-supplied-context validation feature (July 2026, branch `tsg-without-profile-decomposition`).
> It was produced from a complete line-by-line read of the codebase. If the pipeline changes,
> update this document alongside the code.

---

## Part 1 — How threat scenario generation works, step by step

### Phase 1: Starting a session (the API request)

**Step 1 — Login check.** Every request must prove who's calling — either a real JWT token, or
dev-mode headers on a local machine. *Business rule: nobody anonymous touches anything.*
(`app/api/deps.py`, `app/core/security.py`)

**Step 2 — Entity authorization check.** The system verifies the caller's JWT `entities[]` claim
includes the entity id the request claims to act as. *Business rule: a caller can only act as an
entity their token actually authorizes.* (`app/api/deps.py::Principal.require_entity`) — **note
(2026-07-12):** this used to be paired with a second, DB-level check that a specific `asset_id`
truly belongs to that entity (`check_asset_belongs_to_entity`); that check was deliberately removed
(the platform column it depended on is always NULL in real data) — see `TSG_Gap_Analysis.md` §13.15.
Entity authorization today is JWT-claim-only.

**Step 3 — Input validation against the database.** Every field the UI sent (asset description,
critical service, sector/sub-sector, data handled, and each supporting system's details) is
compared against the platform's real records in a fixed number of batched queries. Any mismatch
rejects the whole request with a `422` listing every wrong field at once. *Business rule: the AI
only ever works from verified data, never from whatever the UI claims.*
(`app/pipeline/context.py::validate_ui_supplied_context`)

**Step 4 — One-at-a-time and capacity rules.** Only one active session per asset (a second attempt
gets `409` with the existing session id), a system-wide cap on concurrent sessions (`503` +
Retry-After beyond it), and safe retries via the `Idempotency-Key` header (the same request retried
doesn't create duplicates; the same key with a different payload is a loud conflict). *Business
rules: no double work, no overload, no duplicates.* (`app/db/dal.py`, unique index `UX_Session_ActiveAsset`)

**Step 5 — Session saved, background job queued.** The session row and a progress-tracking row per
supporting system per stage are committed first; only then is the Celery worker told to start. The
caller immediately gets back a session id (`202`).

### Phase 2: The AI pipeline (background, per supporting system)

**Step 6 — Lock the supporting system.** The worker takes an exclusive lock per supporting system,
with a 5-minute lease. *Business rules: only one worker touches a system at a time; if a worker
dies, the lease expires and the cleanup job reclaims it; a stage that fails 5 times is declared
poisoned and stops retrying forever.* (`app/db/dal.py::acquire_lock` / `claim_stage`)

**Step 7 — AI proposes threats.** The AI is shown: the asset context (description, critical
service, sector, sub-sector, data handled), the supporting system's details (name, asset type,
accessibility channel, managed-by, hosting environment, data residency, past incidents), and the
six STRIDE category names. Everything sent passes an allowlist (only approved fields) and a
secret/PII redaction pass. The AI returns a list of proposed threats. *Business rules: the AI sees
only approved, scrubbed data; its output is treated as suggestions, never as final; every AI call
is logged word-for-word (`Prompt_Log`) for audit.* (`app/pipeline/prompts.py::threats_prompt`,
`app/core/security.py`)

**Step 8 — Each proposal is checked against the threat library ("grounding").** Category by exact
(case-insensitive) name match; threat type and name by meaning-similarity — a local embedding model
plus a reranker, with two score bands: rerank ≥ 75 = solid match ("grounded"), 60–74 = near match
("confirm"), below = not in the library ("flagged"). Threat actors are kept only if they appear in
the library's approved actor list for that threat type — invented actors are dropped. The library
search respects sector visibility: only globally-visible entries or entries for this asset's
sector/parent-sector are considered. Embeddings are computed once and cached (in-process + MongoDB).
*Business rule: the same real-world threat, worded differently, always maps back to the same
official library entry.* (`app/pipeline/grounding.py`, `app/pipeline/embeddings.py`)

**Step 9 — Score and filter ("scoping").** Each threat gets a deterministic score (base 50, +20
grounded, +10 confirm, +0 flagged), then admin-configured rules from `Config_Threat_Rule` run —
`tech_gate` rules hard-exclude a threat, `relevance_*` rules adjust its score. Survivors are
ranked; the ranking and every fired rule are persisted (`Scoped_Threat.FactorsJSON`) for audit.
*Business rule as designed: non-applicable threats are excluded here, deterministically, before any
scenario is written. In practice at the time of writing: the rules table was empty, so nothing was
ever excluded — see gap 2.* (`app/pipeline/scoping.py`)

**Step 10 — AI writes one scenario per surviving threat.** Using the library's official threat
name (falling back to the AI's own wording only for flagged threats), the AI writes the scenario:
title, statement, business impact, operational impact, assumptions, risk statement, excluded
details. A deterministic checker verifies the required fields are present and that the statement
actually mentions the threat — problems are flagged for the reviewer (`ValidationJSON`), never
silently fixed and never blocking. Old versions are marked superseded, never deleted. *Business
rules: official terminology wins; validation flags but doesn't block; full history is preserved.*
(`app/pipeline/tasks.py::_generate_one_scenario`, `app/pipeline/validation.py`)

**Step 11 — Wait for a human.** Each supporting system lands in `AWAITING_DECISION`. When no
system is still running and at least one is ready, the session moves to `REVIEW`. If some systems
failed but others succeeded, the good ones still reach review (partial success is preserved); only
if everything failed is the session cancelled. *Business rule: exactly one human decision point,
at the end.* (`app/pipeline/tasks.py::decide_session_outcome`)

### Phase 3: After generation

**Step 12 — Human reviews and accepts.** Accept (all scenarios, or a chosen subset) marks them
accepted and completes the session. Before completing, the system re-checks every library entry
used is still active. Then any accepted "flagged" threats — ones not in the library — are
automatically promoted into the shared threat library, including their validated actors, race-safely
(natural-key unique indexes; two concurrent accepts can't create duplicates). *Business rules: the
library grows only through human-accepted content; accept and regenerate are mutually exclusive.*
(`app/pipeline/accept.py`)

**Step 13 — Regenerate (optional).** From review, specific scenarios can be regenerated by ID.
Only the targeted ones are redone (siblings untouched), under a new generation epoch so Celery
redeliveries and races are safe, and the session returns to review. (`app/pipeline/cascade.py`)

**Step 14 — Cleanup crew (the reaper).** A scheduled job runs periodically: it finds sessions
whose worker died (expired leases), marks stuck work as failed, releases locks, and drives each
abandoned session to the same review-or-cancel decision the pipeline itself uses. Sessions waiting
at REVIEW are never touched — a human taking their time is not "abandoned."
(`app/pipeline/reaper.py`)

**Step 15 — Downstream consumption.** Other systems fetch results from
`GET /v1/assets/{asset_id}/accepted-scenarios`, which returns only *accepted*, *non-superseded*
scenarios from the *latest completed* session — one clean version of the truth per asset.

---

## Part 2 — Known gaps at the time of writing

### A. Gaps against the "Threat Scenario Generation Logic" spec

1. **Risk statement formula not implemented (spec Step 3).** The AI was asked for a
   `risk_statement` with zero instructions, didn't receive the critical service when writing
   scenarios, and nothing checked the field existed. *(Addressed by the risk-statement-formula
   change accompanying this document.)*
2. **Threat exclusion never actually happened (spec Step 2).** The filtering machinery exists and
   is well-built, but `Config_Threat_Rule` had zero rows, and the rule engine could only see 3
   fields — not the 6 newer context fields (asset type, accessibility channel, hosting, data
   residency, managed-by, past incidents). *(Addressed by the rule-engine extension + seeded
   OT/IT asset-type rules accompanying this document.)*
3. **The AI never consults the library before proposing (spec Step 2).** It proposes freely and is
   checked afterward — the "library as reference structure" idea is not implemented.
   *(Explicitly deferred.)*
4. **No "user confirms threats" pause (spec Step 2).** Scenarios are generated immediately after
   threat identification; the only human gate is after scenarios already exist.
   *(Explicitly deferred.)*

### B. Data / content gaps (not code)

5. **`Threat_Category` table is empty** and no threat type is linked to a category — category-level
   matching in grounding always matches nothing and silently widens the search to all types.
   Works, but weaker than designed.
6. **The threat library is 100% internal-OT** (all 71 threat types) — no internet-facing, cloud,
   API, or data-residency threats exist, so most of the newer context fields have nothing they
   could ever filter until the library grows.

### C. Design / housekeeping gaps

7. **The curator review gate (R11) is half-built.** Promoted threats get a
   `Threat_Candidate_Review` record, but only ever with status `accepted` — the pending/rejected
   curator workflow defined in the enums has no code behind it. The library effectively grows with
   reviewer-accept as the only control.
8. **Newly promoted threats get no filter rules.** When an accepted flagged threat enters the
   library, nothing assigns it exclusion rules — it applies to every asset type until a curator
   adds a rule. Applicability should be stated at threat intake going forward.
9. **`Threat_Scenario_Output.AcceptedSubsetJSON` is a dead column** — defined, always written as
   NULL, never read. Subset accept works via the `Accepted` flag on specific rows plus the audit
   trail.
10. **`past_incidents` can structurally never drive a filter rule** — the rule matcher does exact
    text comparison, and a free-text narrative will never exactly equal a rule value.
11. **Stale comments** in a few places still describe the old 3-stage pipeline (the removed
    profile stage); cosmetic only.
