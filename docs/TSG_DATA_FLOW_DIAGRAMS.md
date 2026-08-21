# TSG — End-to-End Data Flow

**For senior management.** Two diagrams. Diagram 1 covers how an asset becomes a checked list of
threats. Diagram 2 covers how those threats become accepted scenarios with controls.

**To edit:** these are Mermaid diagrams — plain text. Change a label by changing the words inside the
quotes. They render automatically in GitHub, VS Code (Markdown preview), Confluence and Teams.

**Legend**

| Shape | Meaning |
|---|---|
| Rounded box | A person acts |
| Rectangle | The system does work |
| Diamond | A decision point |
| Cylinder | Stored data |
| Dotted line | Data being read or written |
| Amber box | Something worth knowing — a rule or a limit |

---

## Diagram 1 — From an asset to a checked list of threats

```mermaid
flowchart TD
    REQ(["Requester picks ONE asset<br/>and its supporting systems"])

    REQ -->|"Sends ID numbers only.<br/>No descriptions, no free text.<br/>1 asset, 1 to 50 supporting systems"| V

    V{"Validate,<br/>cheapest check first"}
    V -->|"any check fails"| STOP["Request refused.<br/>Nothing is created"]
    V -->|"all pass"| GATHER

    PLAT[("Platform records:<br/>assets, supporting systems,<br/>sectors, code lookups")]
    PLAT -.->|"Ownership and linkage are<br/>PROVED here, never trusted<br/>from the request"| V

    GATHER["Gather the real facts and freeze them.<br/>Codes turned into readable names.<br/>Owner and manager names left out"]
    PLAT -.-> GATHER
    GATHER --> SNAP[("Frozen snapshot<br/>for this assessment")]

    SNAP --> PREP["Prepare what the AI may see.<br/>Only approved fields.<br/>Secrets and personal data stripped"]
    CFG[("Curator settings:<br/>allowed fields, categories,<br/>approved actor list")]
    CFG -.->|"Actor list is sent as<br/>preferred spellings to use"| PREP

    PREP --> AI["ONE AI request for the whole asset"]
    AI --> OUT["Up to 10 candidate threats.<br/>Each one carries: category, threat type,<br/>threat name, generic name, actors"]

    OUT --> CMP["Compare every candidate<br/>against the approved library"]
    LIB[("Approved threat library:<br/>categories, types,<br/>threat names, actors")]
    LIB -.-> CMP

    CMP --> T{"Threat type<br/>recognised?"}
    T -->|"NO - comparison stops here"| NEW["Marked NEW to the library.<br/>Actors kept but unvalidated.<br/>No library wording claimed"]
    T -->|"YES"| N{"Threat name<br/>recognised?"}
    N -->|"NO"| PART["Library wording for the type.<br/>Name stays as the AI wrote it"]
    N -->|"YES"| FULL["Library wording used<br/>for both type and name"]

    PART --> ACT
    FULL --> ACT
    ACT["Actors cut down to those approved<br/>for that type. Invented ones dropped"]

    NEW --> SAVE
    ACT --> SAVE
    SAVE["Save one record per threat.<br/>The AI wording and the library wording<br/>are kept SIDE BY SIDE, with the verdict"]
    SAVE --> REG[("Threat register<br/>for this assessment")]

    NOTE1["No STRIDE guarantee.<br/>One pass, and the AI labels each threat<br/>itself. Nothing requires any category<br/>to appear - a run can return ten of one<br/>kind and none of the other five"]
    NOTE2["Counts: up to 10 threats, so up to<br/>10 types and 10 names.<br/>Actors vary per threat"]

    AI -.- NOTE1
    OUT -.- NOTE2

    classDef store fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef note fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef halt fill:#fbe4e4,stroke:#b03a2e,color:#4d1712
    class PLAT,SNAP,CFG,LIB,REG store
    class NOTE1,NOTE2 note
    class STOP,NEW halt
```

### Why each comparison works the way it does

| Step | Rationale in one line |
|---|---|
| Category matched exactly | It only narrows the search, so a near-match would buy nothing. |
| Threat type matched by meaning | The same threat worded two ways must land on one library entry. |
| **Stop if the type fails** | The type is the key that unlocks both the names worth comparing against and the approved actor list. Without it, the system refuses to guess. |
| Name searched inside that type only | Stops an unrelated type's wording winning on similar text alone. |
| The **generic** wording is compared | The library is written generically. Comparing asset-named text would mostly measure "does this mention the asset". |
| Actors matched exactly | A curator owns this vocabulary, so the only fair question is "is this exactly one of ours". |
| Overall verdict = the weaker of the two | Confidence is only as good as the weakest check that ran. |
| Nothing claimed on a failed name | The system always has a "closest" candidate, even a poor one. Having a candidate is not evidence of a match. |

> **"NEW to the library" does not mean rejected.** It means nobody has catalogued this threat yet. It
> still gets a full scenario and still reaches a reviewer. These are how the library grows.

---

## Diagram 2 — From threats to accepted scenarios

```mermaid
flowchart TD
    REG[("Threat register<br/>from Diagram 1")]

    REG --> SCORE["Score and rank every threat.<br/>50 to start, plus 20 if it matched the<br/>library or 15 if it is new,<br/>plus or minus curator rule weights"]
    RULES[("Curator rules")]
    RULES -.->|"Every rule that fired<br/>is recorded per threat"| SCORE

    SCORE --> GATE{"Excluded by<br/>a curator rule?"}
    GATE -->|"YES"| DROP["No scenario.<br/>The reason is always recorded"]
    GATE -->|"NO"| PASS{"Scored 55<br/>or above?"}
    PASS -->|"NO"| DROP
    PASS -->|"YES"| DUP{"Same library entry as a<br/>higher-ranked threat?"}
    DUP -->|"YES"| DEMOTE["Set aside, kept for audit.<br/>Its place is FREED for the<br/>next distinct threat"]
    DUP -->|"NO"| SEL["Selected for a scenario"]

    SEL --> WRITE["Write the scenarios, highest score first.<br/>One AI request per scenario, one at a time.<br/>Each is saved before the next begins"]
    INTEL[("Recent published<br/>advisories")]
    INTEL -.->|"Up to 5, as references only.<br/>If unavailable, nothing changes"| WRITE

    WRITE --> ROUTE["The AI names the ONE route the threat<br/>travels in by, and the other credible routes.<br/>That list is then FROZEN"]
    ROUTE --> COV{"Any credible route<br/>not yet written about?"}
    COV -->|"YES - one scenario per route"| WRITE
    COV -->|"NO - this threat is done"| CHK

    CHK["Automatic checks: required fields present,<br/>does it name the threat, the asset and the<br/>critical service, is it too close to another.<br/>Problems are FLAGGED, never blocked or deleted"]

    CHK --> CTRL["Identify controls. The AI suggestions<br/>become search terms against the approved<br/>control library. Weak matches are DROPPED,<br/>not forced. Top 5 kept and ranked"]
    CLIB[("Approved control<br/>library")]
    CLIB -.->|"Suggestions that match nothing<br/>are shown to you as library gaps"| CTRL

    CTRL --> REVIEW(["Waiting for a person.<br/>A partial batch still arrives here"])
    REVIEW --> DEC{"Your decision"}

    DEC -->|"Regenerate, 1 to 50 of them"| WRITE
    DEC -->|"Get more, 5 at a time"| WRITE
    DEC -->|"Cancel"| CAN["Run ends"]
    DEC -->|"Accept: all, none, or chosen ones"| ACC

    ACC["Accepted scenarios become the result"]
    ACC --> DOWN[("Read by<br/>other systems")]
    ACC --> LEARN["The library learns. Threat type may be<br/>added. A threat name only if clearly new,<br/>otherwise a CURATOR decides.<br/>Actors are linked, NEVER created"]
    LEARN --> LIB2[("Approved threat<br/>library")]

    NOTE3["No cap on how many threats get a<br/>scenario. Every distinct threat that<br/>passes 55 gets one. Volume therefore<br/>varies with the asset"]
    NOTE4["Depth is EARNED, not set.<br/>A 2-system asset finishes a threat in<br/>2 scenarios, an 8-system one in 8"]

    PASS -.- NOTE3
    COV -.- NOTE4

    classDef store fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef note fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef halt fill:#fbe4e4,stroke:#b03a2e,color:#4d1712
    class REG,RULES,INTEL,CLIB,DOWN,LIB2 store
    class NOTE3,NOTE4 note
    class DROP,CAN halt
```

### How duplicates are handled

Three different outcomes, depending on what is duplicated.

| What is duplicated | Outcome | Why |
|---|---|---|
| The **same threat** proposed twice in one run | **Blocked.** Never recorded. | It is the same finding; a second copy adds nothing. |
| A **route** already written about for that threat | **Blocked.** No further scenario. | The work is already done; this is what makes a run finish. |
| Two threats matching the **same library entry** | **Set aside**, kept for audit, and **its place is freed**. | They are one threat. Freeing the place means you still get a full set of distinct findings. |
| A **scenario** that reads like another one | **Flagged only. The scenario is kept.** | A machine may warn a reviewer. It may not delete a reviewer's work item. |

### What "get more" tells you

| Answer | Meaning | What to do |
|---|---|---|
| **Complete** | Full batch delivered. | Carry on. |
| **Partial, retryable** | Short because something **failed**. | Click again. That is the retry. |
| **Exhausted** | Short because **nothing further exists** — every threat has been written about through every credible route. | Nothing to fix. This is a finished answer. |

---

## Diagram 3 — "Get more" (the next-set flow)

Adds scenarios. Nothing existing is ever replaced.

```mermaid
flowchart TD
    U(["You click Get more"])

    U --> OPEN{"Is the run still<br/>open for changes?"}
    OPEN -->|"already accepted, cancelled,<br/>or still generating"| REFUSE["Refused, with the reason.<br/>Nothing changes"]
    OPEN -->|"yes"| ONE{"Is another click already<br/>running for this asset?"}
    ONE -->|"yes"| IGNORE["Ignored, so two clicks can<br/>never double-generate"]
    ONE -->|"no"| S1

    S1["SOURCE 1 - threats already scored<br/>but never written up.<br/>NO AI request needed"]
    POOL[("Threat register")]
    POOL -.-> S1

    S1 --> Q1{"Enough to fill<br/>the batch of 5?"}
    Q1 -->|"YES"| WRITE
    Q1 -->|"NO"| S2

    S2["SOURCE 2 - ONE more AI request.<br/>It is told which threats are already<br/>covered, so it looks for genuinely<br/>different business impacts"]
    S2 --> WRITE

    WRITE["Write the scenarios.<br/>NOTHING existing is replaced.<br/>The new ones are ADDED"]

    WRITE --> Q3{"Still short<br/>of 5?"}
    Q3 -->|"YES"| S3["SOURCE 3 - extra scenarios for threats<br/>that already have one, through a route<br/>not yet written about"]
    Q3 -->|"NO"| OUTC
    S3 --> OUTC

    OUTC{"Report the<br/>outcome"}
    OUTC -->|"got the full batch"| C1["COMPLETE"]
    OUTC -->|"fewer came back than<br/>threats handed over"| C2["PARTIAL, RETRYABLE.<br/>Click again - that IS the retry"]
    OUTC -->|"nothing further exists"| C3["EXHAUSTED.<br/>A finished answer, not a fault"]

    NOTE5["If the extra AI request fails, the click<br/>still serves whatever was already in the<br/>pool. A bad round can never wedge or<br/>destroy the scenarios you already have"]
    S2 -.- NOTE5

    classDef store fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef note fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef halt fill:#fbe4e4,stroke:#b03a2e,color:#4d1712
    class POOL store
    class NOTE5 note
    class REFUSE,IGNORE halt
```

| Design point | Rationale in one line |
|---|---|
| Cheapest source first | Threats already scored need no AI request at all, so paying for one before that pool is empty would be waste. |
| Only **one** extra AI request per click | Bounds the cost of a click to something predictable. |
| Nothing is replaced | "Get more" means more. Superseding prior work would make the button destructive. |
| Three outcome words, not a count | "Short because something failed" and "short because nothing is left" need opposite responses from you. |
| An extra-request failure is survivable | The click falls back to serving the existing pool rather than failing the whole run. |

---

## Diagram 4 — "Regenerate" (rewriting chosen scenarios)

Replaces only what you pick. Everything else is untouched.

```mermaid
flowchart TD
    U(["You pick the exact scenarios<br/>to rewrite, 1 to 50 of them"])

    U --> OPEN{"Is the run still<br/>open for changes?"}
    OPEN -->|"no"| REF1["Refused, with the reason"]
    OPEN -->|"yes"| FOUND{"Do all the picked scenarios<br/>still exist and are they active?"}
    FOUND -->|"no"| REF2["Refused, naming exactly which<br/>ones. Nothing is changed"]
    FOUND -->|"yes"| QUAL{"Does each one's threat still<br/>pass the current rules?"}

    QUAL -->|"NO - a rule changed since the run"| KEEP["That one is SKIPPED and its existing<br/>scenario is LEFT IN PLACE.<br/>Deleting it with no replacement<br/>would be losing your data"]
    QUAL -->|"YES"| CFG

    CFG["Re-read the CURRENT approved field list.<br/>A field a curator has since switched off<br/>stays off in the rewrite"]
    CFGSTORE[("Curator settings")]
    CFGSTORE -.-> CFG

    CFG --> W["Rewrite ONLY those scenarios.<br/>Siblings of the same threat, and every<br/>other scenario, are untouched"]

    W --> BUF["Held together, then written in ONE step:<br/>old marked as replaced, new inserted"]
    BUF --> HIST["Old and new are linked as a pair,<br/>so the full history stays auditable"]
    HIST --> STORE[("Scenario history")]

    HIST --> CTRL["Controls re-matched<br/>for the new scenarios"]
    CTRL --> BACK(["Back to you for review"])

    NOTE6["You pick SCENARIOS, never threats.<br/>One threat can own several scenarios,<br/>so redo this threat would be ambiguous"]
    NOTE7["Each rewrite carries its own version<br/>number, so a repeated background<br/>message cannot apply it twice"]

    U -.- NOTE6
    BUF -.- NOTE7

    classDef store fill:#e6eef8,stroke:#3f6699,color:#12233d
    classDef note fill:#fff3df,stroke:#bf8524,color:#4d3204
    classDef halt fill:#fbe4e4,stroke:#b03a2e,color:#4d1712
    class CFGSTORE,STORE store
    class NOTE6,NOTE7 note
    class REF1,REF2 halt
```

| Design point | Rationale in one line |
|---|---|
| You target scenarios, not threats | A threat can own several scenarios, so "redo this threat" has no single answer. |
| A no-longer-qualifying target is left alone | Destroying a scenario with nothing to put in its place would be data loss, so the old one stays. |
| Current field settings are used, not the original ones | If a curator has since switched a field off, a rewrite must respect that — this is deliberately the opposite of a first run, which freezes its settings. |
| Old and new written in one step | You never see a gap where neither version exists. |
| History kept, not overwritten | The previous version stays readable, so a reviewer can see what changed and why. |

---

## The five things worth remembering

1. **Only ID numbers are accepted.** The system looks up every fact itself, so no description can be
   pushed in from outside.
2. **One unlinked supporting system refuses the whole request** rather than quietly assessing a
   partial picture.
3. **The AI never sees the library before proposing.** It proposes freely and everything is checked
   afterwards, so the library's current contents cannot cap what gets discovered.
4. **Automatic checks warn; they never discard.** Every borderline case goes to a person.
5. **Nothing enters the shared library without a human acceptance first**, and new threat actors are
   never created automatically.

---

*Every figure and rule here was taken from the source code on branch
`tsg-without-profile-decomposition`, not from earlier documentation. If the pipeline changes, update
this file with it.*
