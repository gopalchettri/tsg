# TSG — What Happens When You Click Each Button

Three buttons, three workflows. Pick the one you are about to press.

Every step states **why it exists**, **how the answer is actually reached** — the real rule or
calculation, not "the system checks it" — **what the AI does** (often nothing), and **what it passes to
the next step**.

**Colour key** — 🟠 amber: a person acts · 🔵 blue: automatic, no AI · 🟣 purple: **the AI is used here**

| Button | AI requests involved |
|---|---|
| **Generate scenarios** | 3 kinds: find threats (1) · write scenario (1 per scenario) · match controls |
| **Regenerate** | 2 kinds: write scenario (1 per pick) · match controls. **No threat-finding.** |
| **Next set** | up to 4 kinds: *maybe* find threats (1) · write scenario · *maybe* variants · match controls |

---

## Workflow 1 — "Generate scenarios"

```mermaid
flowchart TD
    A1["<b>1 · YOU START AN ASSESSMENT</b>
    WHY: one asset per assessment, so every result is attributable to
    something specific.
    HOW: the request carries ID NUMBERS ONLY — asset, organisation,
    sector, and 1 to 50 system IDs. Repeated IDs are rejected outright.
    No typed descriptions exist in the request, so no text can be
    pushed toward the AI from outside.
    AI: none.
    → PASSES ON: a set of ID numbers, still unverified"]

    A1 --> A2["<b>2 · CHECKS BEFORE ANY WORK BEGINS</b>
    WHY: you may only assess your own organisation's assets, and only
    with systems that genuinely belong to them.
    HOW — fixed rules, in this order:
    1 Your login must list this organisation. A missing or empty list
    DENIES. It never falls back to allowing everything.
    2 The asset's owner is read from the ownership table. No owner
    record means denied, never assumed.
    3 Every system ID must come back from a lookup that joins it to
    THIS asset. Any ID that does not → the WHOLE request is refused,
    naming the offending IDs.
    4 One active assessment per asset, enforced by a database rule.
    AI: none.
    → PASSES ON: a confirmed asset and a verified system list"]

    A2 --> A3["<b>3 · THE REAL FACTS ARE GATHERED AND FROZEN</b>
    WHY: the assessment must rest on your records, not on anything a
    screen supplied.
    HOW: reads the asset row, the services it supports, its sector and
    parent sector, and about thirty recorded details per system. Stored
    codes become readable words by lookup, matched IGNORING
    capitalisation on both sides; an unmatched code is printed as-is
    rather than dropped; malformed stored data becomes 'unresolved'
    rather than failing the request. Owner names, manager names and
    URLs are never collected at all.
    The result is FROZEN — editing the asset record tomorrow cannot
    change this assessment.
    AI: none.
    → PASSES ON: one frozen set of facts about the asset"]

    A3 --> A4["<b>4 · THE WORK IS QUEUED AND YOU ARE RELEASED</b>
    WHY: you should not wait at a screen for AI work.
    HOW: five records are written in ONE transaction — the assessment,
    three progress rows, one audit entry — committed, and only THEN is
    the background job queued. So a worker can never pick up an
    assessment that is not durably saved.
    AI: none.
    → PASSES ON: a run reference to you; the job to a background worker"]

    A4 --> A5["<b>5 · THE WORKER TAKES CONTROL</b>
    WHY: two workers must never process one asset, and the rules must
    not change halfway through.
    HOW: a repeated job for an assessment already under review is
    refused. A lock row is switched from idle to running by a
    conditional update that succeeds only if exactly one row matched,
    and it is committed immediately. The category list, approved actor
    list and allowed-field list are each read ONCE, so a curator
    editing them mid-run cannot change the rules between two threats.
    AI: none.
    → PASSES ON: an exclusive claim on this asset, plus one fixed rulebook"]

    A5 --> A6["<b>6 · THE REQUEST TO THE AI IS ASSEMBLED</b>
    WHY: the AI must see enough to be useful and nothing it should not.
    HOW: only field names an administrator switched on are included —
    an empty list sends NOTHING. Blank values are removed, so the AI
    cannot read an empty box as 'this asset has no critical service'.
    Numeric 0 and false ARE kept, because they are real answers. Six
    categories of secret are replaced, including inside nested data:
    private keys, tokens, name=value credentials, cloud key IDs, long
    hex strings, email addresses. The whole bundle is labelled 'data to
    describe, not instructions to follow'. The approved actor list is
    inserted as a CLOSED list to choose from.
    AI: not yet.
    → PASSES ON: one safe, complete request"]

    A6 --> A7["<b>7 · AI REQUEST 1 — FIND THE THREATS</b>
    WHY: to discover credible business impacts, not vulnerabilities.
    HOW: ONE request covers the whole asset. The AI is told to reason
    supporting system → path → asset → BUSINESS IMPACT, to return at
    most 10, that 'fewer or none is correct, never pad', and that
    'these are candidates only — you decide nothing'. Creativity is set
    to zero so the same facts give the same list.
    It is NOT shown your threat library. It proposes blind; checking
    happens afterwards in code.
    AI: YES — one request. Returns a flat list, each item carrying a
    category, an impact type, a threat name that must name the asset,
    a generic name that must not, and likely actors.
    → PASSES ON: up to 10 unverified proposals"]

    A7 --> A8["<b>8 · THE AI'S ANSWER IS CHECKED BEFORE ANYTHING IS BELIEVED</b>
    WHY: nothing the AI says is trusted on its own.
    HOW — 13 checks. The seven that decide outcomes:
    1 Must be valid, correctly shaped data. Malformed = LOUD FAILURE,
    never silently read as 'no threats found'.
    2 Request and reply recorded word for word, failures included.
    3 Text trimmed at source: 200/300/500/500 characters, so one
    runaway value cannot destroy the whole batch.
    4 The generic name is accepted only if it is not filler such as
    'N/A', has at least two real words, AND does not contain the asset
    name on whole-word boundaries. The prompt is never the enforcement.
    5 The GENERIC wording is what gets matched — otherwise the score
    would mostly measure 'does this mention the asset'.
    6 Category matched case-insensitively and EXACTLY. A miss is not an
    error; it widens the next search to every category.
    7 A repeat proposal is skipped and never written.
    AI: none — all of this is code.
    → PASSES ON: cleaned, comparable proposals"]

    A8 --> A9["<b>9 · EACH PROPOSAL IS COMPARED TO YOUR LIBRARY</b>
    WHY: the same real threat worded two ways must land on one library
    entry, and your official wording must win.
    HOW — three checks in a fixed order:
    IMPACT TYPE: candidates limited to entries active and visible to
    this sector. Wording compared by meaning; anything under 0.60
    similarity discarded; the 10 CLOSEST get a careful second scoring
    out of 100; highest wins; 75 or above counts as a match.
    HALT RULE: if the type does not match, the name and actor checks
    DO NOT RUN AT ALL. Actors are kept exactly as proposed and flagged
    unchecked. There is no best-guess path.
    THREAT NAME: same method, but candidates restricted to names filed
    under the type that just matched.
    WITHHOLDING RULE: if the name does not match, NO library reference
    and NO library wording are recorded — even though a closest
    candidate existed. Having a candidate is not evidence.
    ACTORS: kept only if character-for-character one of the actors
    approved for that matched type.
    VERDICT: the WEAKER of the type and name results.
    AI: none — comparison and scoring are code.
    → PASSES ON: each threat marked matched or new, with its confidence"]

    A9 --> A10["<b>10 · THREATS SAVED, WITH BOTH WORDINGS</b>
    WHY: nothing the AI said should be lost, and nothing should be
    silently overwritten.
    HOW: one record per threat holding the AI's category, type, name
    and generic name, PLUS your library's type and name where matched,
    the library references where matched, the verdict, the confidence,
    and the actors with a flag saying whether they were checked.
    Accepting stops at 10 records however many were proposed.
    If the list came back EMPTY: the database is re-read and the stage
    must be confirmed finished. If it cannot be confirmed, scenario
    writing is SKIPPED, rather than landing a finished-but-empty result
    in your review queue.
    AI: none.
    → PASSES ON: up to 10 saved threats"]

    A10 --> A11["<b>11 · THREATS SCORED AND RANKED</b>
    WHY: to decide which are worth writing up, defensibly.
    HOW — plain arithmetic, no AI:
    START AT 50. ADD 20 if it matched your library, or 15 if it is new.
    ADD OR SUBTRACT each curator rule that applies — 10 each unless the
    rule states its own weight. KEEP IT IF THE TOTAL IS 55 OR MORE.
    Gate rules: a gate passes if ANY one system matches its field and
    value. If none does, the threat is excluded and the reason names
    the gate. An unknown rule, or a field blank on every system, has NO
    effect and is logged — it never silently excludes.
    Duplicates: a threat with the same identity as a higher-ranked one
    is set aside, and the demotion DOES NOT consume a place — the next
    genuinely different threat takes it.
    Sorted highest first, ties broken by record order, so the sequence
    never changes between runs.
    AI: none. Same asset and same records always give the same ranking.
    → PASSES ON: a ranked list of threats that qualify"]

    A11 --> A12["<b>12 · AI REQUEST 2 — WRITE EACH SCENARIO</b>
    WHY: a threat is not usable until someone can read what it means.
    HOW: taken in rank order, ONE request per scenario, one at a time.
    Before each one, advisories are looked up — search words taken ONLY
    from recorded technology fields plus asset type, minimum four
    letters, never from the threat wording; capped at 5; only the
    reference number, title and link are sent. If unavailable, the
    scenario is written identically.
    The AI is given YOUR library's wording where the threat matched,
    and its own wording where it did not.
    AI: YES — one request per scenario. Returns a title, how the threat
    reaches and damages the asset, what it means for the business, up
    to 5 suggested controls, the assumptions it had to make, and which
    route it came in by.
    → PASSES ON: one written scenario, unchecked"]

    A12 --> A13["<b>13 · EACH SCENARIO IS CHECKED — WARNINGS ONLY</b>
    WHY: a reviewer should be told about a weak scenario, but a machine
    must not delete a reviewer's work item.
    HOW: required fields must be non-blank. 'Does the text mention X'
    is measured as at least ONE THIRD of X's significant words
    appearing — words of 3+ letters, ignoring common words — AND every
    number in X must appear exactly, so 'Gateway 4' never satisfies
    'Gateway 7'. Look-alike detection compares two scenario texts
    character by character; 85% or more overlap attaches a warning,
    checked against other scenarios of the same threat and of other
    threats.
    EVERY finding is a warning. Nothing is blocked or deleted.
    The route named is matched back, ignoring capitalisation, to a real
    system ID; an unrecognised name records NO route rather than
    guessing.
    AI: none — these are text rules, not a second AI opinion.
    → PASSES ON: a scenario plus any warnings, saved immediately"]

    A13 --> A14["<b>14 · HOW MANY SCENARIOS ONE THREAT EARNS</b>
    WHY: depth should follow real exposure, not a fixed quota.
    HOW: with the FIRST scenario the AI also names which other systems
    could credibly carry the same threat. That list is then FROZEN. The
    threat stays eligible while an uncovered route remains, and stops at
    the number of routes plus 2. The plus 2 exists only because nothing
    forces the AI to write about the route it was asked for.
    So a 2-system asset finishes a threat in 2 scenarios and an
    8-system one in 8.
    AI: none — this is a counting rule over the frozen list.
    → PASSES ON: either another scenario request, or done"]

    A14 --> A15["<b>15 · AI REQUEST 3 — MATCH THE CONTROLS</b>
    WHY: a scenario without remedies is only half an answer.
    HOW: each AI control suggestion becomes search text. A scenario
    with no usable suggestions falls back to its own title and
    statement. The library is narrowed to IT-only or OT-only ONLY when
    every signal agrees — a mixed asset searches everything, because
    dropping the right control would be worse than searching wider.
    Each suggestion's best match is scored out of 100; below the cutoff
    it is DROPPED, never force-fitted. Duplicates collapse keeping the
    best score. Top 5 kept, numbered 1 to 5.
    It runs as a self-contained step whose own writes can be undone
    alone, so a failure here can never discard your scenarios. A stamp
    records that it ran, so 'nothing matched' is distinguishable from
    'has not run yet'.
    AI: YES — the AI's own suggestions are reused as the search text.
    → PASSES ON: up to 5 approved controls per scenario, plus the
    suggestions that matched nothing, shown to you as library gaps"]

    A15 --> A16["<b>16 · IT STOPS AND WAITS FOR YOU</b>
    WHY: exactly one human decision point, and it comes after the work
    is finished, so you review completed material.
    HOW: the stage is set to 'awaiting decision' — deliberately NOT
    'complete', because this state IS the review barrier. If some
    scenarios failed, the rest still arrive with the shortfall
    attached; only a total failure cancels. An assessment waiting for a
    person is never timed out or cleaned up.
    AI: none.
    → PASSES ON: everything, to you"]

    classDef you fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef sys fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef ai fill:#f3ebfa,stroke:#7d51a8,color:#33174d
    class A1 you
    class A16 you
    class A2,A3,A4,A5,A6,A8,A9,A10,A11,A13,A14 sys
    class A7,A12,A15 ai
```

---

## Workflow 2 — "Regenerate"

Rewrites only what you pick. **No threat-finding happens at all** — it reuses threats already found.

```mermaid
flowchart TD
    B1["<b>1 · YOU PICK THE SCENARIOS TO REWRITE</b>
    WHY: you target SCENARIOS, never threats. One threat can own
    several scenarios, so 'redo this threat' has no single answer.
    HOW: between 1 and 50 scenario references, plus an optional note.
    AI: none.
    → PASSES ON: a list of scenario references"]

    B1 --> B2["<b>2 · IS THE ASSESSMENT STILL OPEN TO CHANGES?</b>
    WHY: you cannot rewrite something already accepted, or something
    still being generated.
    HOW: one shared rule used by accept, regenerate and next-set alike,
    so the three can never drift apart. It checks the assessment's
    status FIRST — already completed, or cancelled — then whether
    generation is currently running. The lock row must not be running.
    A fresh version number is reserved for this click, so a repeated
    background message cannot apply the same rewrite twice.
    AI: none.
    → PASSES ON: permission to proceed, and a version number"]

    B2 --> B3["<b>3 · YOUR PICKS ARE RESOLVED</b>
    WHY: a valid request must never be refused on a technicality.
    HOW: submitted references are converted to canonical form BEFORE
    being compared with what was found — otherwise a differently
    formatted but perfectly valid reference would be reported as
    missing. Anything genuinely not found, or no longer active,
    REFUSES the request and names it. Nothing is changed.
    AI: none.
    → PASSES ON: confirmed target scenarios, and the threats behind them"]

    B3 --> B4["<b>4 · CURRENT SETTINGS ARE RE-READ</b>
    WHY: a rewrite must reflect today's policy, not the policy in force
    when the assessment first ran.
    HOW: the allowed-field list is read fresh. A field a curator has
    since switched off STAYS OFF in the rewrite.
    This is deliberately the OPPOSITE of a first run, which freezes its
    settings at the start. It is also why a rewritten scenario can
    legitimately differ from the original for reasons that have nothing
    to do with the AI.
    AI: none.
    → PASSES ON: today's field policy"]

    B4 --> B5["<b>5 · TARGETS ARE RE-SCORED</b>
    WHY: a rule may have changed since the assessment ran.
    HOW: the same arithmetic as a first run — 50, plus 20 or 15, plus
    curator rule weights, keep at 55 or more. A target whose threat no
    longer passes is SKIPPED, and its existing scenario is LEFT IN
    PLACE. Deleting a scenario with nothing to replace it would be
    losing your data. The assessment is returned to review first, so it
    stays usable, and the skipped item is reported to you by name.
    AI: none.
    → PASSES ON: the targets that still qualify"]

    B5 --> B6["<b>6 · AI REQUEST — REWRITE EACH ONE</b>
    WHY: the rewrite must be meaningfully different, not a reshuffle.
    HOW: one request per surviving target. The scenario's existing
    siblings are quoted into the request so the AI is told what to
    differ from. Note the asymmetry: the request shows the AI up to 3
    siblings, but the look-alike detector afterwards compares against
    ALL of them — otherwise a threat with 20 siblings would only ever
    be checked against 3.
    AI: YES — one request per scenario you picked.
    → PASSES ON: rewritten scenarios, unchecked"]

    B6 --> B7["<b>7 · THE SAME CHECKS AS A FIRST RUN</b>
    WHY: a rewrite is held to the same standard.
    HOW: required fields non-blank; one third of significant words must
    appear and every number must match exactly; look-alike detection at
    85% character overlap. All findings are WARNINGS. Nothing is
    blocked or deleted.
    AI: none.
    → PASSES ON: rewritten scenarios plus any warnings"]

    B7 --> B8["<b>8 · WRITTEN IN ONE STEP, NOT ONE AT A TIME</b>
    WHY: you must never see a moment where neither the old nor the new
    version exists.
    HOW: all rewrites are held, then the old ones are marked replaced
    and the new ones inserted TOGETHER. Collisions inside the batch are
    folded to one, and a database rule prevents a double click
    inserting twice.
    Note this differs from a first run, which saves each scenario as it
    is written. Here the batch is atomic on purpose.
    AI: none.
    → PASSES ON: the new scenarios, committed"]

    B8 --> B9["<b>9 · CONTROLS RE-MATCHED, HISTORY LINKED</b>
    WHY: new scenario text deserves freshly matched controls, and the
    previous version must remain readable.
    HOW: controls matched exactly as in a first run — scored out of
    100, weak matches dropped rather than force-fitted, top 5 kept.
    Old and new are linked as a pair, so the full history is auditable.
    The durable record is the version number stored on the results; the
    on-screen notification is only a hint.
    AI: YES for control matching — the AI's suggestions become the
    search text.
    → PASSES ON: back to you for review"]

    classDef you fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef sys fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef ai fill:#f3ebfa,stroke:#7d51a8,color:#33174d
    class B1 you
    class B2,B3,B4,B5,B7,B8 sys
    class B6,B9 ai
```

---

## Workflow 3 — "Next set"

Adds up to five more. **Nothing existing is ever replaced.**

```mermaid
flowchart TD
    C1["<b>1 · YOU CLICK GET MORE</b>
    WHY: to widen coverage without disturbing what you already have.
    HOW: no input needed. The batch size is 5. The same open-to-changes
    rule as accept and regenerate applies. TWO version numbers are
    reserved — one for threat-finding, one for scenario-writing — so a
    repeated background message re-runs at the same numbers instead of
    firing a second AI request.
    AI: none.
    → PASSES ON: permission, and a target of 5"]

    C1 --> C2["<b>2 · CONCURRENT CLICKS ARE SERIALISED</b>
    WHY: an impatient double click must not produce ten scenarios.
    HOW: a per-asset mutex. If another click is already running, this
    one is ignored rather than queued.
    AI: none.
    → PASSES ON: an exclusive claim"]

    C2 --> C3["<b>3 · SOURCE 1 — THREATS ALREADY FOUND BUT NOT WRITTEN UP</b>
    WHY: the cheapest scenarios are the ones needing no new thinking.
    HOW: threats already scored and selected, with no active scenario,
    taken in rank order. Two candidates sharing one identity collapse
    to the better-ranked, so a single click can never propose an
    internal duplicate.
    AI: NONE AT ALL for this source. This is why the first click after
    a run is usually the cheapest.
    → PASSES ON: a pool of ready threats, possibly fewer than 5"]

    C3 --> C4{"Pool fills the batch of 5?"}

    C4 -->|"YES"| C6
    C4 -->|"NO"| C5

    C5["<b>4 · SOURCE 2 — AI REQUEST, ONE EXTRA THREAT SEARCH</b>
    WHY: only pay for new thinking when the ready pool runs dry.
    HOW: ONE request, told which threats are already covered — a list
    of up to 50, newest first — so it looks for genuinely different
    impacts. Nothing prior is replaced, so threats ACCUMULATE. Any
    re-proposal matching an existing threat is silently dropped, so the
    covered list is steering, not enforcement.
    IF THIS REQUEST FAILS: the click still serves whatever was already
    in the pool. The failure is logged and rolled back. This matters —
    handling it any other way would leave the assessment stuck, the
    cleanup job would then cancel it, and every scenario you had
    already accumulated would be destroyed.
    AI: YES — one request, and only in this branch.
    → PASSES ON: a refilled pool"]

    C5 --> C6["<b>5 · AI REQUEST — WRITE THE SCENARIOS</b>
    WHY: to turn the pool into readable results.
    HOW: one request per scenario, exactly as in a first run, including
    the advisory lookup and your library's wording where the threat
    matched. Accumulation works because this mode only replaces a
    scenario whose identity already matches — and a brand new identity
    has no match, so nothing is displaced.
    AI: YES — one request per scenario.
    → PASSES ON: new scenarios, added alongside the existing ones"]

    C6 --> C7{"Still short of 5?"}

    C7 -->|"YES"| C8
    C7 -->|"NO"| C9

    C8["<b>6 · SOURCE 3 — AI REQUEST, VARIANTS</b>
    WHY: a threat already written about may still have an unexamined
    route in.
    HOW: a threat qualifies only if it has at least one finished
    scenario, its frozen route list is not empty, an uncovered route
    remains, and its scenario count is below the number of routes plus
    2. A lost race against a concurrent click is skipped, not errored.
    AI: YES — one request per variant.
    → PASSES ON: extra scenarios through fresh routes"]

    C8 --> C9["<b>7 · CONTROLS MATCHED</b>
    WHY: every new scenario needs its remedies.
    HOW: identical to a first run — suggestions become search text,
    scored out of 100, weak matches dropped rather than force-fitted,
    top 5 kept and ranked, isolated so a failure cannot kill the batch.
    AI: YES — suggestions reused as search text.
    → PASSES ON: scenarios with controls attached"]

    C9 --> C10["<b>8 · THE OUTCOME IS REPORTED IN ONE OF THREE WORDS</b>
    WHY: 'short because something failed' and 'short because nothing is
    left' need OPPOSITE responses from you, so one number would not do.
    HOW — by comparing scenarios produced against threats handed over:
    COMPLETE — all 5 delivered.
    PARTIAL, RETRYABLE — fewer scenarios came back than threats handed
    over, or the variant top-up failed. Those targets remain selected,
    so clicking again IS the retry.
    EXHAUSTED — the pool was empty and every threat has been written
    about through every route it credibly has. A finished answer, not a
    fault.
    The durable record is written BEFORE the on-screen notification, so
    the two can never disagree.
    AI: none.
    → PASSES ON: back to you for review"]

    classDef you fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef sys fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef ai fill:#f3ebfa,stroke:#7d51a8,color:#33174d
    class C1 you
    class C2,C3,C10 sys
    class C5,C6,C8,C9 ai
```

---

## The three buttons side by side

| | Generate scenarios | Regenerate | Next set |
|---|---|---|---|
| **Finds new threats?** | Yes, always — one AI request | **No, never** | Only if the ready pool cannot fill the batch |
| **AI requests** | 1 threat search + 1 per scenario + controls | 1 per pick + controls | 0–1 threat search + 1 per scenario + variants + controls |
| **What is replaced** | The previous run's threats | **Only the scenarios you picked** | **Nothing** |
| **When work is saved** | Each scenario as it is written | All held, then written in one step | Each as written |
| **Which settings apply** | Frozen at the start | **Today's settings, re-read** | Frozen at the start |
| **How many you get** | One per credible route per qualifying threat | Exactly the ones you picked | Up to 5 |
| **Outcome reported as** | Ready for review, with any shortfall noted | Which old scenario each new one replaced | Complete / Partial-retryable / Exhausted |
| **If it partly fails** | The rest still reach you; only total failure cancels | Failed picks keep their existing scenario | Serves whatever was already in the pool |

---

## The five rules that hold across all three

1. **The AI is never shown your threat library before proposing.** It proposes blind; every comparison
   happens afterwards in code. This is deliberate — otherwise your library's current contents would
   cap what could ever be discovered.
2. **The AI is told outright that it decides nothing.** Prioritisation is arithmetic: 50, plus 20 or
   15, plus curator rule weights, pass at 55. Same inputs, same ranking, every time.
3. **A malformed AI reply fails loudly.** It is never quietly treated as "no threats found".
4. **Automated checks warn; they never delete.** A machine may flag a weak scenario for a reviewer. It
   may not discard a reviewer's work item.
5. **Nothing enters your shared library without a person accepting it first**, and a new threat actor
   is never created automatically — only linked to one you already approved.

---

*Every rule, formula and number here was taken from the source code on branch
`tsg-without-profile-decomposition`. If the pipeline changes, update this file with it.*
