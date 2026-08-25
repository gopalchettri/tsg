# TSG Deployment Handbook

**A complete step-by-step guide. If you can follow a recipe, you can follow this.**

This handbook takes you from the source code on a computer to a fully running TSG system on
OpenShift. Every command is written out completely. Under each command you will find:
- **What it does** — in plain words
- **What you should see** — so you know it worked
- **If it fails** — what to check

> **Rule number one: do the steps IN ORDER.** The order is not decoration — several steps
> exist to protect the steps after them. Skipping ahead is how deployments break.

---

## 1. What you are deploying (the big picture)

TSG is one application deployed as several cooperating pieces across three OpenShift
"namespaces" (a namespace is like a separate room in the same building):

```
 ai-threatgen (the main room)        ai-remediation (extra muscle)     ai-common (the cameras)
 ┌─────────────────────────────┐     ┌───────────────────────────┐     ┌─────────────────────┐
 │ tsg-api  x2   answers HTTP  │     │ celery-worker x2          │     │ celery-exporter     │
 │ celery-worker x2  does the  │     │   more workers, nothing   │     │   feeds numbers to  │
 │                AI pipeline  │     │   else — no api, no beat  │     │   Prometheus/Grafana│
 │ tsg-beat x1   the scheduler │     │                           │     │   (already there)   │
 └──────────────┬──────────────┘     └─────────────┬─────────────┘     └──────────┬──────────┘
                └──────────────┬───────────────────┘                              │ (watches)
                               ▼                                                  │
              ONE shared job queue in Redis (outside the cluster) ◄───────────────┘
              + SQL Server + MongoDB (also outside the cluster)
```

Why this shape, in one line each:
- **Two copies** of the API and workers = if one crashes, the other keeps working.
- **Exactly ONE beat** = it schedules background jobs; two beats would run every job twice.
- **Workers in a second namespace** = they watch the *same* queue, so they just add power.
  4 workers × 10 jobs each = **40 AI sessions running at the same time from day one**.
- **Monitoring** = two graphs that tell you when to add or remove workers.

---

## 2. What you need before you start

### Tools (install once)

| Tool | What it is | Check it works with |
|---|---|---|
| **Docker** (or Podman) | Builds and ships the application "image" (a sealed box with the app + everything it needs) | `docker --version` |
| **oc** | The OpenShift command line — how you talk to the cluster | `oc version` |
| **Python 3.12** | Runs the helper scripts in this repo | `py -3.12 --version` |
| **Git** | Gets the source code | `git --version` |

### Access you must have

- A login for the OpenShift cluster (username/password or token)
- A login for the internal image registry (Quay)
- Network access to the registry host — you may need to be on the company network or a
  "jump server" (a company computer that can reach internal systems)

### Values to collect — fill in this table first

You will paste these into commands wherever you see `ALL-CAPS-PLACEHOLDERS`:

| Placeholder | What it is | Where to get it |
|---|---|---|
| `CLUSTER-URL` | The OpenShift API address | Your platform team, or the cluster web console → top-right → "Copy login command" |
| `API-KEY` | A TSG API_Client key | The TSG team / the API_Client table |
| `USER-ID`, `ENTITY-ID`, `TENANT-ID` | Test identity for the smoke test | The TSG team |
| `ASSET-ID` | A real asset that belongs to `ENTITY-ID` | The EYShield database |

These are **fixed** for this deployment (do not change them):

| Name | Value |
|---|---|
| Registry | `quay-quay-registry.apps.dda-desc-az1-01.desccii.local` |
| Image name | `dda-desc/tsg-api` |
| Version to deploy | `579eb8c` (a git commit id — it names exactly which code you are shipping) |

---

## 3. Part A — Get the code and build the image (your computer)

### Step A1 — Get the exact code version

```bash
git clone https://github.com/gopalchettri/tsg.git
```
```bash
cd tsg && git checkout tsg-without-profile-decomposition && git pull
```

**What it does:** downloads the code and switches to the deployment branch.

Now confirm two things — the version and that nothing extra is mixed in:

```bash
git rev-parse --short HEAD
```
**You should see:** `579eb8c`. If not, run `git checkout 579eb8c`.

```bash
git status --porcelain
```
**You should see:** *nothing at all* (empty output). If files are listed, the code has local
edits — the image you build would not match the version number it claims. Run `git stash` to
put the edits aside.

### Step A2 — Build the image

```bash
docker build -t quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:579eb8c .
```

**What it does:** builds the sealed application box and names it with the exact code version.
The build installs Python packages from `requirements.lock` — a list of exact versions, so
building today and building next month produce the same thing. Takes a few minutes.

**You should see:** it ends with something like `naming to ...tsg-api:579eb8c`.

**If it fails** at `COPY requirements.lock`: you are on an old code version — go back to A1.

### Step A3 — Quick health check of the image

```bash
docker run --rm quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:579eb8c python -c "import pyodbc, app.main; print('image OK')"
```

**What it does:** starts the box for one second and asks it to load two critical things —
the database driver (`pyodbc`) and the application itself.

**You should see:** `image OK`.

---

## 4. Part B — Push the image to the registry

> **Important idea:** we push the image under its *version name* (`:579eb8c`) now, but we do
> **NOT** yet give it the name `:latest`. The running cluster automatically pulls whatever is
> called `:latest` whenever a pod restarts — and the new code refuses to start on the old
> cluster settings. So the safe order is: **push version → fix settings → then rename to
> latest.** This handbook follows that order.

### Step B1 — Log in to the registry

```bash
docker login quay-quay-registry.apps.dda-desc-az1-01.desccii.local
```

**What it does:** asks for your registry username/password and remembers them.

**If it fails** with a certificate error: the internal registry uses a company certificate.
With Podman add `--tls-verify=false` to the login and push commands. With Docker Desktop, add
the registry under Settings → Docker Engine → `insecure-registries`, then restart Docker.

### Step B2 — Push the versioned image

```bash
docker push quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:579eb8c
```

**What it does:** uploads the box. Nothing running in the cluster refers to this name, so
this cannot disturb anything.

**If your computer cannot reach the registry:** build on your computer, then move the image
as a file through the jump server (do **not** use a PowerShell pipe — it corrupts the file):

```bash
docker save -o tsg-579eb8c.tar quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:579eb8c
```
Copy `tsg-579eb8c.tar` to the jump server (e.g. with `scp`), then there:
```bash
docker load -i tsg-579eb8c.tar
```
and continue from B1 on the jump server.

### Step B3 — Mirror the monitoring image

The cluster cannot download from the public internet, so the small monitoring program must
also be copied into the internal registry. Use a **numbered** version (ask which is current —
`0.11.3` is an example), never the moving name `latest`:

```bash
docker pull danihodovic/celery-exporter:0.11.3
```
```bash
docker tag danihodovic/celery-exporter:0.11.3 quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/celery-exporter:0.11.3
```
```bash
docker push quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/celery-exporter:0.11.3
```

Then open `deploy/monitoring.yaml` in a text editor, find the line containing `MIRROR-ME`,
and replace that whole image reference with the one you just pushed.

---

## 5. Part C — Prepare and SAFETY-CHECK the configuration

The application's settings (database addresses, passwords, tuning) live in one tested file:
`.env.uat`. The cluster cannot read that file directly — it reads a "Secret" (OpenShift's
locked settings box). A script converts the file into the Secret so the two can never drift
apart. **Never edit the Secret by hand — edit `.env.uat` and re-run the script.**

### Step C1 — Log in to the cluster

```bash
oc login CLUSTER-URL
```

**What it does:** connects your `oc` commands to the cluster. It will ask for your login.

### Step C2 — Generate the settings for BOTH namespaces

```bash
py -3.12 scripts/gen_secret_from_env.py .env.uat deploy/secrets.yaml
```
```bash
py -3.12 scripts/gen_secret_from_env.py .env.uat deploy/secrets.ai-remediation.yaml --namespace ai-remediation
```

**You should see:** each prints `... 131 keys from .env.uat ...` (the exact number may vary
slightly). Both files now contain identical settings — one per namespace.

### Step C3 — Take safety copies of what is running now (your "undo" button)

```bash
oc -n ai-threatgen get secret tsg-api-secrets -o yaml > tsg-api-secrets.live.yaml
```
```bash
oc -n ai-threatgen get cm tsg-api-config -o yaml > tsg-api-config.live.yaml
```
```bash
oc -n ai-threatgen get pods -o jsonpath='{..imageID}' > running-images-before.txt
```

**What they do:** save the current live settings and a note of exactly which image is running.
If anything goes wrong later, these files are how you go back. **Keep them; do not commit
them to git** (they contain passwords).

### Step C4 — THE SAFETY GATE (do not skip)

```bash
py -3.12 scripts/resolve_cluster_env.py tsg-api-config.live.yaml
```

**What it does:** pretends to be a cluster pod. It merges the live ConfigMap (from C3) with
your new Secret exactly the way real pods will, and boots the application's settings code on
your machine. If any combination would crash a pod, you find out **here**, in seconds — not
in the cluster, in flames.

**You should see:** a table of settings ending with **`GATE OK`**.

**If it says GATE FAILED:** it prints the exact setting name causing the problem (usually an
old value pinned inside the ConfigMap). Remove that line from the ConfigMap
(`oc -n ai-threatgen edit cm tsg-api-config`), re-download it (C3), and run the gate again.
**Do not continue until you see GATE OK.**

### Step C5 — Three quick questions to answer once

**1. Does every workload read the settings we are about to fix?**

```bash
oc -n ai-threatgen get deploy -o jsonpath="{range .items[*]}{.metadata.name}{': '}{..envFrom}{'\n'}{end}"
```

**You should see:** every line mentions `tsg-api-config` and `tsg-api-secrets`. If any line
mentions a different Secret (for example `tsg-uat-env`), tell the platform team it must be
rewired to the standard pair **before** Part D — otherwise that pod can crash later.

**2. Is the currently running (old) image safe to receive the new settings?**

```bash
oc -n ai-threatgen exec deploy/tsg-api -- python -c "from app.core.config import Settings; print([f for f in Settings.model_fields if 'jwt' in f])"
```

**You should see:** `[]` (an empty list) → safe, continue.
**If it prints JWT field names:** the running image is very old and would refuse the new
settings. Ask the TSG team before continuing (the fix is a small temporary addition to the
Secret).

**3. What label does Prometheus require?**

```bash
oc -n ai-common get prometheus -o yaml | grep -A3 serviceMonitorSelector
```

**Write down the label it shows** (often something like `release: <name>`). Open
`deploy/monitoring.yaml`, find the `TODO(step-0)` comment in the ServiceMonitor section, and
add that label there. Without it, monitoring silently shows nothing.

---

## 6. Part D — Deploy the main application (ai-threatgen)

### Step D1 — Stop any TSG running on the jump server

If the jump server runs TSG's worker or beat (from earlier testing), **stop them now**
(close their windows / run the repo's `stop.ps1`). They share the same job queue as the
cluster — and two schedulers means every background job runs twice.

### Step D2 — Load the new settings into the cluster

```bash
oc replace -f deploy/secrets.yaml
```

**What it does:** swaps the cluster's settings box for the new one, exactly. The pods that
are *currently running* keep their old settings in memory (pods only read settings at start),
so nothing changes yet — this just makes the cluster **safe** for the new image.

### Step D3 — NOW give the image the name "latest"

```bash
docker tag quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:579eb8c quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:latest
```
```bash
docker push quay-quay-registry.apps.dda-desc-az1-01.desccii.local/dda-desc/tsg-api:latest
```

**What it does:** from this moment, any pod that starts will get the new code — and thanks to
D2, the new code will find settings it accepts.

### Step D4 — Roll out, ONE deployment at a time

The namespace has a CPU budget. Restarting the API and the workers at the same time briefly
needs more CPU than the budget allows and the rollout would get stuck. So we hold the workers
still, do the API, then release the workers:

```bash
oc -n ai-threatgen rollout pause deploy/celery-worker
```
```bash
oc apply -f deploy/deploy.yaml
```
```bash
oc -n ai-threatgen rollout restart deploy/tsg-api
```
```bash
oc -n ai-threatgen rollout status deploy/tsg-api --watch
```

**Wait** until it says `successfully rolled out`. Then the workers:

```bash
oc -n ai-threatgen rollout resume deploy/celery-worker
```
```bash
oc -n ai-threatgen rollout restart deploy/celery-worker
```
```bash
oc -n ai-threatgen rollout status deploy/celery-worker --watch
```

And finally the scheduler:

```bash
oc -n ai-threatgen rollout status deploy/tsg-beat
```
If that line shows no new rollout happened, give it one:
```bash
oc -n ai-threatgen rollout restart deploy/tsg-beat
```

**Why the explicit `restart` commands:** "apply" only restarts pods if the deployment
description changed. The restart makes *certain* every pod is reborn with the new image and
new settings — it is harmless if the apply already did it.

**Note:** the first worker start takes a few minutes longer than usual — it calibrates its
matching thresholds and test-fires real AI calls before accepting work. That is normal.

### Step D5 — PROVE it worked (three checks)

**Check 1 — the right image is running:**
```bash
oc -n ai-threatgen get pods -o jsonpath='{..imageID}'
```
**You should see:** image IDs *different* from the ones saved in `running-images-before.txt`.

**Check 2 — the right settings are inside the pods:**
```bash
oc -n ai-threatgen exec deploy/tsg-api -- printenv APP_ENV TSG_LLM_TIMEOUT_SECONDS TSG_DB_POOL_SIZE TSG_INFERENCE_FALLBACK_MODEL
```
**You should see, exactly:**
```
staging
180.0
15
kimi-k2.5
```

**Check 3 — the full health check, run inside a real pod:**
```bash
oc -n ai-threatgen exec deploy/celery-worker -- python scripts/uat_preflight.py
```
**You should see:** a report where every line says `PASS` (or `SKIP`), and the script exits
happily. It tests the real database, Redis, MongoDB, and makes one real call to each AI model.

### Step D6 — One real test drive (and your speed measurement)

Create a test file `smoke.json` (ask the team for a real `ASSET-ID` owned by your test entity):

```json
{ "entity_id": "ENTITY-ID", "asset_id": "ASSET-ID" }
```

Open a private tunnel to the API and time one full session:

```bash
oc -n ai-threatgen port-forward svc/tsg-api 8000:8000
```
Leave that running; in a **second** terminal:

```bash
curl -s -X POST http://127.0.0.1:8000/v1/sessions -H "X-API-Key: API-KEY" -H "X-User-Id: USER-ID" -H "X-Entity-Id: ENTITY-ID" -H "X-Tenant-Id: TENANT-ID" -H "Content-Type: application/json" -d @smoke.json
```

**You should see:** a JSON answer containing a `session_id`. Note the clock time. Check
progress until it reaches review:

```bash
curl -s http://127.0.0.1:8000/v1/sessions/PASTE-SESSION-ID-HERE -H "X-API-Key: API-KEY" -H "X-User-Id: USER-ID" -H "X-Entity-Id: ENTITY-ID" -H "X-Tenant-Id: TENANT-ID"
```

**Write down how many minutes the session took.** That number is your speed baseline — every
future "is it slower today?" question is answered against it.

---

## 7. Part E — Deploy the extra workers (ai-remediation)

A new namespace is an empty room — four things must be carried in before the workers can work.
Two of them are copies of things in ai-threatgen; the copy command below includes a small
cleaning step (servers attach bookkeeping labels to live objects that must be removed before
an object can be created elsewhere — you do not need to understand the line, just paste it).

**E1 — the registry pass** (lets the room pull images):

```bash
oc -n ai-threatgen get secret quay-pull -o json | py -3.12 -c "import json,sys; o=json.load(sys.stdin); m=o['metadata']; [m.pop(k,None) for k in ('resourceVersion','uid','creationTimestamp','managedFields')]; m.get('annotations',{}).pop('kubectl.kubernetes.io/last-applied-configuration',None); m['namespace']='ai-remediation'; print(json.dumps(o))" | oc apply -f -
```

**E2 — the shared ConfigMap** (same cleaning trick):

```bash
oc -n ai-threatgen get cm tsg-api-config -o json | py -3.12 -c "import json,sys; o=json.load(sys.stdin); m=o['metadata']; [m.pop(k,None) for k in ('resourceVersion','uid','creationTimestamp','managedFields')]; m.get('annotations',{}).pop('kubectl.kubernetes.io/last-applied-configuration',None); m['namespace']='ai-remediation'; print(json.dumps(o))" | oc apply -f -
```

**E3 — the settings Secret** (generated in Step C2):

```bash
oc apply -f deploy/secrets.ai-remediation.yaml
```

**E4 — the network permissions** (without these the workers start "healthy" but sit silent —
they would have no permission to reach the job queue):

```bash
oc apply -f deploy/networkpolicy.ai-remediation.yaml
```

**E5 — the workers themselves:**

```bash
oc apply -f deploy/deploy.ai-remediation.yaml
```

**E6 — prove the whole fleet is together.** Two different checks for two different things:

```bash
oc -n ai-threatgen exec deploy/celery-worker -- celery -A app.pipeline.celery_worker:celery_app inspect stats
```
**You should see:** **4** worker names (2 per namespace). All four now eat from one queue.

```bash
oc get pods -A -l component=beat
```
**You should see:** exactly **ONE** pod, in ai-threatgen. (The scheduler never shows up in
the first command — that is normal; this second command is how you count it.)

---

## 8. Part F — Deploy the monitoring (ai-common)

You already prepared `deploy/monitoring.yaml` in steps B3 (image) and C5 (label). The
monitoring pod also needs the registry pass in its own room:

```bash
oc -n ai-threatgen get secret quay-pull -o json | py -3.12 -c "import json,sys; o=json.load(sys.stdin); m=o['metadata']; [m.pop(k,None) for k in ('resourceVersion','uid','creationTimestamp','managedFields')]; m.get('annotations',{}).pop('kubectl.kubernetes.io/last-applied-configuration',None); m['namespace']='ai-common'; print(json.dumps(o))" | oc apply -f -
```
```bash
oc apply -f deploy/monitoring-secrets.yaml
```
```bash
oc apply -f deploy/monitoring.yaml
```

**Prove it:** open the Prometheus web page → Status → Targets. A `celery-exporter` target
must **appear** there and show UP. If it is *missing entirely*, the label from step C5 is
wrong. If it shows but is DOWN, check the pod: `oc -n ai-common get pods`.

In Grafana, make one dashboard with two graphs:

| Graph | Metric | What it tells you |
|---|---|---|
| Waiting time | `celery_task_queued_time_seconds` | How long jobs wait for a free worker |
| Working time | `celery_task_runtime_seconds` | How long jobs take once started |

---

## 9. Part G — Running it day to day (the only two dials)

| What you see in Grafana | What it means | What to do |
|---|---|---|
| Waiting time **high**, working time steady | Not enough workers | `oc -n ai-remediation scale deploy/celery-worker --replicas=3` |
| Working time **rising** toward 180s | The AI GPU is overloaded — more workers make it *worse* | `oc -n ai-remediation scale deploy/celery-worker --replicas=1` |
| Everything low and flat | All is well | Nothing 🎉 |

One more number worth a glance in the logs (Loki): count of `llm.fallback_model_used` —
each one means the backup AI model (kimi) rescued a call the main model (glm) failed. A few
is healthy resilience; a flood means the main model is struggling.

### Emergency undo (in order of severity)

| Problem | Command |
|---|---|
| New settings broke something | `oc replace --force -f tsg-api-secrets.live.yaml` then restart the deployments (D4) |
| New image broke something | Edit `deploy/deploy.yaml`: replace `:latest` in the image lines with the old image ID saved in `running-images-before.txt`, then `oc apply -f deploy/deploy.yaml` |
| Extra workers cause trouble | `oc -n ai-remediation scale deploy/celery-worker --replicas=0` |

---

## 10. Deploying the NEXT version (much shorter!)

1. Part A with the new commit id (if `pyproject.toml` changed, regenerate the lock first:
   `py -3.12 -m uv pip compile pyproject.toml --extra prod -o requirements.lock --python-platform linux --python-version 3.12` and commit it)
2. Part B step B2 (push the new version tag)
3. If `.env.uat` changed: Steps C2, C4 (the gate!), D2
4. D3 (promote to latest) and D4 (the sequential restarts — including beat this time:
   its description doesn't change, but its settings might have)
5. D5 (prove it)

---

## Troubleshooting quick table

| Symptom | Likely cause | Fix |
|---|---|---|
| Build fails at `COPY requirements.lock` | Old code version | Step A1 — checkout `579eb8c` or newer |
| `ErrImagePull` on a pod | Image name/tag mismatch, or missing registry pass in that namespace | Check the pod's image name vs what you pushed; Part E1/F for the pass |
| Pod restarts forever (`CrashLoopBackOff`) | Settings the app refuses | `oc logs <pod>` — the app prints exactly which setting; fix `.env.uat`, rerun C2 + C4 + D2, restart |
| Rollout stuck at "1 old replica" | CPU budget — both rollouts at once | You skipped the pause/resume order in D4 |
| Workers running but no session progresses | Workers can't reach the queue | Network policy missing (E4) or wrong Redis address |
| Monitoring target missing in Prometheus | ServiceMonitor label wrong | Step C5, question 3 |
| Session returns 401 | Missing one of the four `X-…` headers | All four headers are required, including `X-Tenant-Id` |
| Session returns 404 on create | Wrong URL path | It is `/v1/sessions` (not `/v1/tsg/sessions`) |

---

*This handbook encodes the verified deployment plan (3 adversarial review rounds, 46 findings
resolved). The order of Parts B→C→D is deliberate and load-bearing: version-tag first,
settings second, "latest" last — do not rearrange it.*
