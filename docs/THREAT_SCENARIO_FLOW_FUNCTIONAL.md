# TSG — What You Get, and How It Gets Made

**For business and functional teams.** This shows you the actual output first, then walks through how
it was produced, using one example the whole way through.

> All example content below is **illustrative** — realistic in shape and wording, but invented for
> this document. It is not output from your system.

---

## 1. Start here: this is what lands on your desk

One scenario looks like this. A run produces several.

---

### 🗂 Scenario 3 of 7 — *Citizen Personal Information*

| | |
|---|---|
| **Threat** | Sensitive data exposure *(your library's official wording)* |
| **Reaches the asset through** | Corporate Identity Provider |
| **Likely actor** | Nation-state / APT |
| **Status** | Matched your library ✓ |

**Title**
> Unauthorized disclosure of Citizen Personal Information

**How it happens**
> An attacker who gains administrative control of the Corporate Identity Provider can issue valid
> credentials for privileged roles, allowing unauthorized disclosure of Citizen Personal Information
> without triggering failed-login alerts. Because the Customer Records Database trusts that identity
> provider, the access appears legitimate and records can be read at scale.

**What it means for the business**
> Unauthorized disclosure of Citizen Personal Information would compromise the confidentiality of the
> records supporting Citizen Identity Verification, undermining the service's ability to confirm
> identities reliably and creating regulatory notification obligations.

**Suggested controls** *(matched to your approved control library)*

| # | Control | Why it helps |
|---|---|---|
| 1 | Multi-factor authentication for privileged accounts | Stops a stolen administrative password alone from granting access |
| 2 | Privileged access recertification | Removes standing administrative rights that are no longer needed |
| 3 | Database activity monitoring | Detects bulk record reads that look legitimate but are abnormal |

**Suggested, but not in your control library** — ⚠️ *Identity provider anomaly detection*
→ *This is a gap in your control library, not an error.*

**Assumptions the system had to make**
> The available information does not state whether administrative access to the Corporate Identity
> Provider requires multi-factor authentication.

**Deliberately left out** · Specific techniques for compromising administrative sessions.

**Also reachable through** · Public API Gateway *(so this threat may earn a second scenario)*

---

**Three things to notice about that card, because they drive how you use the tool:**

1. **"Assumptions"** is your data-quality report. It names exactly what your asset records failed to
   say. If a scenario feels generic, read this first — it usually explains why.
2. **"Suggested, but not in your control library"** is free gap analysis. It appears nowhere else.
3. **"Also reachable through"** tells you more scenarios for this threat are still available.

---

## 2. The example used throughout this document

| | |
|---|---|
| **Asset being protected** | Citizen Personal Information |
| **Critical service it supports** | Citizen Identity Verification |
| **Supporting systems in scope** | Customer Records Database · Corporate Identity Provider · Public API Gateway |

**The one rule that shapes everything:** only the **asset** is being assessed. The three supporting
systems are *routes a threat travels* to reach it. You will never get a scenario titled "threat to the
Customer Records Database".

---

## 3. The journey, step by step

### Step 1 — You start the run · ⏱ seconds

**You provide:** the asset, its sector, and which supporting systems are in scope.

**You get back immediately:** a run reference. The work then continues without you — you can close
the screen.

**What can stop you here**

| Message | What it means |
|---|---|
| "Asset already has an active run" | Someone is already assessing it. Only one run per asset at a time. |
| "Not permitted for this organisation" | Your access does not cover this organisation. Being signed in is not enough. |
| "Try again shortly" | The platform is at capacity. Nothing was created; just retry. |

> The system then reads the asset's real records itself. It does **not** use whatever the screen
> passed in. If you list a supporting system that isn't actually linked to the asset, the run is
> refused rather than quietly assessing the wrong thing.

---

### Step 2 — The system finds candidate threats · ⏱ under a minute

One request to the AI covers the whole asset. It comes back with **up to 10** candidates, then each is
checked against your approved threat library.

**What our example produced**

| # | Candidate threat | In your library? |
|---|---|---|
| 1 | Unauthorized disclosure of Citizen Personal Information | ✓ Matched |
| 2 | Loss of availability of Citizen Personal Information | ✓ Matched |
| 3 | Unauthorized modification of Citizen Personal Information | ✓ Matched |
| 4 | Loss of accountability for changes to Citizen Personal Information | ✦ New to your library |
| 5 | Exposure of Citizen Personal Information records | ✓ Matched |
| 6 | Physical tampering with Citizen Personal Information storage | ✓ Matched |

> **✦ "New to your library" is not a problem, and it is not a rejection.** It means nobody has
> catalogued this threat yet. It gets a full scenario and full review exactly like the others. These
> are often the most valuable findings in a run — and they are how your library grows.

---

### Step 3 — The system decides which are worth writing up · ⏱ instant

Not AI judgement — a fixed calculation. **Same asset, same records, same result, every time.** You can
defend the outcome in an audit.

**Every threat starts at 50 points**, then:

| Add | When |
|---|---|
| **+20** | It matched your library |
| **+15** | It is new to your library |
| **± more** | If an administrator has written a rule about it |

**Pass mark: 55.** So a matched threat sits at 70 and a new one at 65 — **both comfortably pass.**

> **What this means in practice:** whether a threat is in your library never decides if it gets a
> scenario. Only a rule an administrator wrote can exclude one.

**How our six candidates resolved**

| # | Candidate | Score | Scenario? | Reason you'll see |
|---|---|---|---|---|
| 1 | Unauthorized disclosure… | 70 | ✅ Yes | Matched library |
| 2 | Loss of availability… | 70 | ✅ Yes | Matched library |
| 3 | Unauthorized modification… | 70 | ✅ Yes | Matched library |
| 4 | Loss of accountability… | 65 | ✅ Yes | New to library |
| 5 | Exposure of… records | 70 | ❌ No | **Same threat as #1**, worded differently. Its place went to the next distinct threat. |
| 6 | Physical tampering… | — | ❌ No | **Excluded by rule** — no on-premises site is in scope for this asset |

**Every exclusion names its reason.** You are never left guessing why something is missing.

> **Duplicates do not cost you a finding.** When #5 was set aside as a reworded #1, it *freed its
> place*. You get distinct findings, not a list padded with rewordings.

---

### Step 4 — The system writes the scenarios · ⏱ the longest step

One AI request per scenario. Each one is written, checked, and **saved immediately** — so if something
fails halfway, everything already produced is safe.

**Recent security advisories are looked up first** and quoted as references where relevant. If that
feature is off or finds nothing, the scenario is written exactly the same way. It never blocks
anything.

**How many scenarios will you get?** This is the question most people get wrong, so:

> **It is not a fixed number.** Each threat earns **one scenario per route it could credibly travel**
> to reach your asset.
>
> Our example asset has 3 supporting systems. If threat #1 could credibly arrive through 2 of them, it
> earns **2 scenarios** — one per route. A threat that could only arrive one way earns **1**.
>
> **So an asset with 8 supporting systems produces far more than one with 2.** Depth follows real
> exposure, not a setting. Expect variable volume between runs, and do not treat a large result as a
> fault.

**Every scenario is automatically checked** — required fields present, does it actually describe the
threat it claims to, does it name the asset and its critical service.

> ### ⚠️ These checks warn you. They never delete anything.
>
> A flagged scenario still reaches you, with its flag visible. A machine may warn a person; it may not
> silently discard a person's work item. **If you see a flag, read the scenario and judge it
> yourself** — the flag is frequently just the AI paraphrasing rather than an actual error.

**If one scenario fails**, you get a placeholder marked as an error, and you can retry just that one.
The rest of your batch is untouched.

---

### Step 5 — Controls are attached · ⏱ seconds

The AI's suggestions are matched to your **approved control library**. Up to 5 per scenario.

**A suggestion that matches nothing approved is dropped, not forced into the nearest slot.** You see
both lists — matched, and unmatched. The unmatched list is your control-library gap report.

---

### Step 6 — Your turn: review · ⏱ as long as you need

**The run stops and waits. This is the only time it waits for a person, and it comes at the end.**
There is no earlier "approve the threats" step.

**A run waiting for you is never cleaned up or timed out.** Taking two days is fine.

> ### ⚠️ One display quirk to know about
>
> While a first run is in progress, the main stage label may keep reading *"threat identification"*
> even while scenarios are already being written. **Watch the progress indicators, not that label.**
> The run is not stuck.

---

### Step 7 — Your turn: decide

Four choices. **Use this table to pick.**

| If you're thinking… | Do this | What happens |
|---|---|---|
| "This scenario is vague / wrong / poorly written" | **Regenerate** it | Only the ones you pick are rewritten. Everything else untouched. Up to 50 at a time. |
| "This is good, but I want fuller coverage" | **Generate next set** | Adds up to **5 more**. Nothing existing is replaced. |
| "This one says *error*" | **Regenerate** just it | The failure was isolated to that scenario. |
| "These are right — I'm done" | **Accept** | You must say **all**, **none**, or **specific ones**. No default. |
| "Wrong asset / started by mistake" | **Cancel** | Ends the run. |

**Regenerate targets scenarios, not threats** — because one threat can own several scenarios, so
"redo this threat" would be ambiguous.

**When you click "generate next set", you get one of three answers.** They mean different things:

| Answer | Meaning | Your move |
|---|---|---|
| **Complete** | Full batch delivered. | Carry on. |
| **Partial — retryable** | Short because some generations *failed*. | **Click again.** That is the retry. |
| **Exhausted** | Short because **nothing further exists**. | ✅ Nothing to fix. Every threat has now been covered through every route it could arrive by. This is a finished answer, not a shortfall. |

**On accepting**, the system re-checks that every library entry your threats rely on is still active —
someone may have retired one since the run began. If any item you selected cannot be accepted,
**nothing is accepted**, and you are told which and why in plain language.

Accept and regenerate cannot run at the same time.

---

### Step 8 — What accepting changes

**Your accepted scenarios become the official result** and are what other systems read.

**Your threat library learns — but only through you.** A threat is considered for the library only if
it was genuinely new *and* you accepted its scenario. Even then:

| | What happens automatically |
|---|---|
| **Threat type** | May be added |
| **Threat name** | Added only if clearly new. Very close to something existing → linked to that instead. Anything in between → **a curator's queue for a person to word properly.** |
| **Threat actor** | **Never created.** Only linked, if it already exists. |

**Nothing in your library is ever rewritten or retired automatically.**

Optionally, an accepted scenario can then be sent for a **Risk Treatment Plan** — a comparison of the
controls this scenario needs against the controls you already have.

---

## 4. When the results don't look right

Check this before raising a defect. Usually the system ran correctly and something upstream is empty.

| What you're seeing | Why | What to do |
|---|---|---|
| **Everything says "new to library"** | Your threat library isn't loaded | Scenarios are still valid — they just use the AI's wording instead of yours. Ask for the library to be loaded. |
| **Scenarios are vague and generic** | Your asset records are thin, or too few fields are permitted | **Read the "assumptions" on any scenario** — it names exactly what was missing. Fill those fields in and re-run. |
| **No controls on any scenario** | Control library isn't loaded | Nothing else is affected. |
| **No actors named anywhere** | Approved actor list is empty | No actor can be validated until it's populated. |
| **Fewer scenarios than expected** | A rule is excluding threats | Check the exclusion reason on each threat — it names the rule. |
| **Far more scenarios than expected** | The asset has many supporting systems | Expected behaviour — one scenario per credible route. Not a fault. |
| **No advisories referenced** | Intelligence feed is off or empty | Harmless. Never blocks a scenario. |
| **A scenario marked "error"** | That one generation failed | Regenerate just it. |
| **A scenario has a warning flag** | An automatic check wasn't satisfied | **Read it and judge.** Often just paraphrasing. Never auto-deleted. |

---

## 5. Eight things that surprise people

1. **You review once, at the end.** No step asks you to approve the threats first.
2. **"New to library" means new, not rejected.** Full scenario, full review.
3. **One run = one asset.** Supporting systems are routes, never subjects.
4. **The AI never reads your library before proposing.** It proposes freely, then everything is
   checked. This is deliberate — otherwise your library's current contents would cap what can be
   discovered.
5. **Results are repeatable.** Same asset, same records, same threats. Not a lottery.
6. **Scenario count varies by design** — one per credible route into the asset.
7. **Automatic checks only ever warn.** Nothing is discarded on a machine's judgement.
8. **Every AI request and reply is recorded word for word**, including failures. Any scenario traces
   back to exactly what was asked and answered.

---

## 6. Quick reference

| | |
|---|---|
| Threats found per round | up to **10** |
| Pass mark for a scenario | **55** — matched threats score 70, new ones 65 |
| Scenarios written | **one per credible route**, per qualifying threat |
| "Next set" adds | **5** per click, accumulating |
| Controls per scenario | up to **5** approved |
| Advisories per scenario | up to **5**, reference only |
| Accept / regenerate per request | **1–50** items |
| Runs at once, platform-wide | **100** |
| Runs at once, per asset | **1** |

---

*Verified against the code on branch `tsg-without-profile-decomposition`. Example content is
illustrative. If the pipeline changes, update this document with it.*
