# Diagnostics — what gets recorded, and how to switch it

When a run fails, the customer sees `stage processing failed`. That text is deliberately vague and
must stay that way — it is shown to tenants and must never carry internal detail.

The real cause used to exist only in the server's screen output, which disappears when a container
restarts and needs server access to read at all. One real incident (session `6174F288`, a reranker
timeout) took a pasted screen log to diagnose. This page is how that is answered now.

---

## 0. First-time setup — do these in order

Five steps. Steps 1 and 2 are required; nothing works without them.

### Step 1 — Create the two tables

**Do this before deploying the code.** The application reads its schema at boot, so it will not
start against a database that lacks these tables.

```bash
sqlcmd -S <host> -d <database> -i "scripts/tsg_script/TSG_Deploy_All.sql"
```

Safe to re-run: every statement checks whether the object already exists first. It creates
`Diagnostic_Event`, `Application_Log` and four indexes, and changes nothing else.

**Check it worked.** The last section of that script prints a verdict, which must say:

```
Tables: 24   Columns: 319   Indexes: 36
```

If any number is lower, stop — the script did not finish, and the application will refuse to boot
rather than run against a half-built schema.

### Step 2 — Set the two settings that matter

In the environment file for that deployment:

```bash
TSG_DIAGNOSTIC_DB_CATEGORIES=exceptions,retries,degraded,slow
TSG_DIAGNOSTIC_PUBLIC_DETAIL=true
```

The first decides **what is recorded**. Note what is NOT in that list: `logs`, the ordinary line
stream. It is left out on purpose — see section 6 — and switched on for an investigation rather
than left running. The second decides **how much a lookup shows**; without it you get the summary
but not the error trace, which is usually not enough to act on.

**Do not rely on the built-in defaults for the first one.** If the line is absent the code falls
back to `all`, which INCLUDES `logs` — so an environment deployed from a secret store that never
sets it will quietly start writing every log line to the database, which is the one outcome
section 6 exists to prevent. The shipped `.env` files set it explicitly for exactly this reason;
set it explicitly wherever those files are not the source.

The second one defaults to off, which gives you capture without detail — a lookup that answers
"something failed" but not what, which reads as "the feature does not work".

**Read section 6 before setting these on a system holding real customer data.** `all` plus
`true` means anyone with the web address can read saved log lines, and those can contain contract
details, landlord and tenant information and Emirates ID numbers.

### Step 3 — Restart

Both the API and the workers. Settings are read at startup, so a worker that was not restarted
carries on with the old configuration and records nothing — and because the others are working,
that is easy to miss.

### Step 4 — Confirm it is on

```bash
curl "https://<host>/v1/tsg/diagnostics/config"
```

Look for:

| Field | Should say | If it does not |
|---|---|---|
| `effective` | `all` | The setting did not reach this process — check the file and restart |
| `redis_reachable` | `true` | Runtime switching is unavailable; everything else still works |
| `dropped_rows` | `0` | Records are being discarded — the database cannot keep up |

This reports **the process that answered**, not the whole system. Ask twice; if the API and a
worker disagree, one of them was not restarted.

### Step 5 — Prove it records a real failure

Do not wait for a real incident to find out it is not working.

1. Start any run and let it fail, or pick the id of a run that already failed.
2. Look it up:

```bash
curl "https://<host>/v1/tsg/diagnostics?session_id=<the-run-id>"
```

3. You should get a row naming the actual error — for example `"exception_class": "Timeout"` —
   next to `"client_message": "stage processing failed"`, which is the vague text the customer saw.

**That pairing is the whole point.** If you see it, the setup is complete. An empty result means
capture is off, the wrong process was restarted, or the failure happened before the change.

---

## 1. What gets recorded

Five kinds, each independently switchable.

| Kind | What it captures | Volume |
|---|---|---|
| `exceptions` | A failure: the error class, message and full trace | One per failure |
| `retries` | Something that went wrong and recovered by itself | Spikes during an outage |
| `degraded` | The run finished, but produced less than it was asked for | Low |
| `slow` | A step that took longer than the configured threshold | Depends on the threshold |
| `logs` | **Every ordinary log line** as well, not just problems | Hundreds per run |

**Leave `retries` on.** Once a hiccup recovers automatically it leaves no other trace, so this is
the only way to notice a service degrading *before* it starts failing runs outright. That matters
more than it sounds: retries make outages survivable, and therefore invisible.

**`logs` is different from the other four**, and is treated differently everywhere below. See §6.

### The one that catches an outage before it becomes one

`retries` records each recovered hiccup. On its own that is a trail, not a warning — nobody reads
a warning stream closely enough to notice a rate change. So the retries are also **counted across
the whole deployment**, and when the count crosses a threshold inside one window, a single
`infra.degraded` event is written:

```bash
TSG_INFRA_DEGRADED_THRESHOLD=20        # retries in one window before it is called degrading; 0 = off
TSG_INFRA_DEGRADED_WINDOW_SECONDS=300  # the window, in seconds
```

**Why this exists.** Retrying a slow AI service is the right behaviour, but it means an outage no
longer announces itself. It used to: runs failed and people complained. Now the same outage is
absorbed quietly until the retries run out — and only then do runs start failing. This is what
turns that silence back into one signal.

**One alarm per window for the entire system**, not one per retry and not one per worker. Find it
with:

```bash
curl "https://<host>/v1/tsg/diagnostics?kind=degraded_outcome"
```

---

## 2. Where it goes

| Destination | What it needs | Notes |
|---|---|---|
| **The database** | Nothing — built in | Two tables: `Diagnostic_Event` (the four small kinds) and `Application_Log` (the `logs` stream) |
| **Standard output** | Nothing — always on | Structured JSON. **Cannot be switched off**; it is the fallback when everything else fails |
| **Grafana** | Point it at the database | **No code, no setting.** Grafana reads SQL Server natively |
| **Loki / Fluent Bit / Vector** | Collect container output | **No code, no setting.** It is already JSON and always on |
| **Prometheus / OpenTelemetry / Sentry** | One module each, not yet written | The seam is built; the modules are not — see §7 |

The cheapest win here needs nothing from this page: your logs are already structured JSON on
stdout, so any container log shipper collects them as they are.

---

## 3. Turning it on and off

Three blocks, copy-paste.

**Record everything, for one investigation (UAT):**

```bash
TSG_DIAGNOSTIC_DB_CATEGORIES=all
TSG_DIAGNOSTIC_PUBLIC_DETAIL=true
```

`all` includes `logs`, which writes every line to the database. Prefer switching it on at runtime
with a time limit (section 4) rather than setting it here, where nothing turns it off again.

**Problems only (production):**

```bash
TSG_DIAGNOSTIC_DB_CATEGORIES=exceptions,retries,degraded,slow
TSG_DIAGNOSTIC_PUBLIC_DETAIL=false
```

**Nothing:**

```bash
TSG_DIAGNOSTIC_DB_CATEGORIES=none
```

`none` stops database capture without touching anything else. Standard output keeps working.

---

## 4. Changing it without a restart

An environment change needs a redeploy, which destroys the state you were trying to reproduce.
The runtime switch does not.

```bash
curl -X PATCH https://<host>/v1/tsg/diagnostics/config -H "X-Admin-Key: $ADMIN_KEY" -H "Content-Type: application/json" -d '{"categories":"all","ttl_seconds":1800}'
```

**The UAT workflow:** switch on → reproduce → read → let it expire.

`ttl_seconds` makes the switch turn itself off. **Always use it with `logs`.** The realistic
mistake is not a bad decision but a forgotten one — switched on to reproduce something, still on a
month later, in every backup taken since.

Three things worth knowing before you use it:

- **`null` and `"none"` are different.** `null` *clears* the override and falls back to the
  deployed setting. `"none"` pins capture off regardless of what was deployed.
- **The change takes about 10 seconds to reach every process.** TSG runs one API process and
  several workers, each holding its own short-lived copy. `GET /config` reports the process that
  answered, so a worker that has not caught up yet is visible rather than guessed at.
- **It needs Redis.** With Redis unreachable the endpoint answers **503** and changes nothing —
  deliberately loud, because an override that silently did nothing is worse than one that failed.
  Change the environment setting and restart instead.

---

## 5. Where to look afterwards

**Why did this run fail:**

```bash
curl "https://<host>/v1/tsg/diagnostics?session_id=6174F288-222C-890E-98C1-01A0EC098CBD"
```

**No key required.** These reads are open so support can answer a question without an admin key or
database access — needing them is what put diagnosis behind the engineering team in the first
place. *Writing* (§4) still needs the admin key, because that switch starts recording prompt text.

The field that matters is `client_message`: it holds the exact text the customer saw, so a report
of *"it said stage processing failed"* becomes one lookup instead of a conversation.

| Route | Answers |
|---|---|
| `GET /v1/tsg/diagnostics` | Why did session X fail |
| `GET /v1/tsg/diagnostics/logs` | The captured log lines (only while `logs` is on) |
| `GET /v1/tsg/diagnostics/config` | What is being captured now, and are rows being dropped |

Straight from the database, if you have access:

```sql
SELECT TOP 20 CreatedAt, Kind, ExceptionClass, ExceptionMessage, ClientMessage FROM dbo.Diagnostic_Event WHERE SessionID = '6174F288-222C-890E-98C1-01A0EC098CBD' ORDER BY CreatedAt DESC;
```

**Two things this cannot tell you.** Only *handled* failures are recorded — a worker killed by the
OOM killer, or a container terminated mid-stage, writes nothing and leaves only standard output.
And if `dropped_rows` in `GET /config` is above zero, capture is currently lossy: the queue filled
because the database or the writer could not keep up. Application behaviour is unaffected; the
record is incomplete.

---

## 6. The `logs` decision, retention, and size

**Volume.** One run emits hundreds of lines at INFO and above; a busy day is six figures of rows.
Enable `logs` in UAT first and measure a day before considering it anywhere busier.

**Personal data — the part that needs a decision, not a default.** Log lines in this system carry
whatever the code was working on, which includes tenancy contracts, landlord and tenant data,
Emirates ID and prompt text. Switching `logs` on creates a **durable store of personal data that
did not exist before**, and it then enters your backups.

So:

- The production environment template leaves `logs` out on purpose. UAT ships with it on.
- `TSG_DIAGNOSTIC_PUBLIC_DETAIL` defaults to **off**, which withholds traces and log bodies from
  the open read endpoints. Turn it on where the data is test data. Turning it on where real
  customer data lives publishes that data to anyone with the address.
- Retention is enforced, not aspirational — the scheduled reaper deletes past the horizon:

```bash
TSG_DIAGNOSTIC_RETENTION_DAYS=90
TSG_APPLICATION_LOG_RETENTION_DAYS=0
TSG_PROMPT_LOG_RETENTION_DAYS=0
```

**`0` means never delete.** It is a value rather than missing code on purpose: with the cleanup
branch removed, turning retention back on would be a code change, a review and a release — while
the thing prompting it is a disk filling up tonight. As a value it is one setting and a restart.

Failures are kept 90 days. The log stream and the AI receipts are kept indefinitely, which is a
decision with a cost: at around 2,000 runs a day the log table adds roughly 100 GB a year, and it
grows in every backup too. The way out is not to delete rows faster but to stop writing them —
leave `logs` out of the categories above, and use a log collector for the stream instead.

```bash
TSG_DIAGNOSTIC_QUEUE_MAX=10000
```

Writing happens on a background thread, in batches, so it never slows the system down. That is the
limit on how many records may wait. Past it, new records are thrown away and a warning is logged,
rather than the queue growing until the service runs out of memory. Losing some records is a bad
day; losing the service is an outage.

---

## 7. Adding another tool

| Tool | What it costs you |
|---|---|
| **Grafana** | Nothing. Add the database as a datasource and build panels |
| **Loki / Fluent Bit / Vector** | Nothing. Collect container stdout — already JSON, always on |
| **Prometheus** | One module plus a `/metrics` route. It must **not** label by session or request id — unbounded label cardinality is the standard way to take a Prometheus server down |
| **OpenTelemetry** | One module. The future-proof choice: one integration reaches Datadog, Honeycomb, Tempo and Jaeger by configuration |
| **Sentry** | One module. Subsumes `exceptions` with grouping; complements the table rather than replacing it |

The first two are worth doing first, and neither needs anything from this page.

**What "one module" actually means.** Every recorded event is handed to a registry of
destinations as one normalised value, so a new destination reads that value and never touches the
pipeline. It needs a name, a check for whether its prerequisites are met, a per-category filter,
and a non-blocking `emit`. Nothing else in the system changes.

**A destination is ON as soon as it is available** — there is no second switch to remember. That is
deliberate: an opt-in list is how someone installs a tool, configures it, sees no data, and spends
an afternoon hunting for the setting they were also supposed to change. Configuring the tool *is*
the opt-in.

To switch one back off without removing it:

```bash
TSG_DIAGNOSTIC_BACKENDS_DISABLED=prometheus
```

That is the strongest switch there is — a name listed there cannot be re-enabled from the admin
endpoint, only by editing the environment, which is what makes it usable mid-incident.
`GET /v1/tsg/diagnostics/config` lists every destination including the disabled and unavailable
ones, with a `failures` count, so a destination that is silently absent is visible rather than
guessed at.

---

## 8. Two failures you will actually hit

**"I changed it and nothing happened."** The change is cached for about 10 seconds per process.
Wait, then re-read `GET /v1/tsg/diagnostics/config` — it reports the live value for the process
that answered, so a worker that has not picked it up is visible rather than assumed.

**"Redis is down and I need to change it."** Runtime overrides need Redis. Without it the
environment setting applies, and changing it needs a restart. The endpoint says so with a 503
rather than appearing to succeed.
