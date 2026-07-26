# TSG — Production Setup, Run & End-to-End Test Guide

This guide runs the Threat Scenario Generator **the way production runs it**: in containers,
with **real JWT authentication** (no dev shortcuts), a **scheduled reaper**, and **health probes** —
then tests it end to end through the live API.

for in mssql db run - ALTER DATABASE "datbase_name" SET READ_COMMITTED_SNAPSHOT ON;

ALTER DATABASE TSG SET READ_COMMITTED_SNAPSHOT ON;

> **Two supporting files you'll use:** `Dockerfile` (builds the image) and
> `docker/compose.prod.yml` (runs the three processes). The settings template is
> `.env.prod.example`.
>
> ```powershell
> .venv\Scripts\Activate.ps1
> ```

---

## 0. How production differs from local/dev

| Area                | Dev                               | **Production (this guide)**                       |
| ------------------- | --------------------------------- | ------------------------------------------------------- |
| Login               | `AUTH_DEV_MODE` header shortcut | **Real JWT** from your SSO (dev mode OFF)         |
| Web server          | `uvicorn --reload`              | **gunicorn** with uvicorn workers, in a container |
| Processes           | started by hand                   | **api + worker + beat** containers                |
| Reaper (stuck jobs) | not scheduled                     | **runs every 60s** (Celery beat)                  |
| Secrets             | `.env` file                     | **OpenShift Secrets / Vault** (never committed)   |
| Embeddings/reranker | local in-process                  | **served on GPU via litellm/TEI** (recommended)   |
| DB reads            | default                           | **RCSI on**, connection pools sized               |
| Health              | none                              | **`/healthz`, `/readyz`** probes              |

---

## 1. Prerequisites

- **A container runtime** — Docker or Podman on a server, or **OpenShift** (the real target).
- **Your `TSG` database**, reachable, with the platform's base tables already present.
- **Redis**, reachable (use a password + TLS in production).
- **Your SSO** (e.g. Keycloak) reachable, and a way to get a token that carries the **`entities`** claim
  (the list of `group.id`s a caller may access).
- **Azure OpenAI** access (`gpt-5-mini`), **or** a litellm proxy fronting your models.
- For embeddings/reranker: **a litellm/TEI endpoint** (recommended), or the two local model folders
  (single-box option).

> **Pre-flight (optional but wise):** before deploying, run the automated tests on a dev machine —
> `python -m pytest -q` (needs no servers). Green means the logic is sound.

---

## 2. Build the container image

From the `tsg` folder:

```bash
docker build -t tsg:latest .    # DEFAULT includes local embedding/reranker models (pulls torch, large)
# Slim image for the litellm/TEI proxy path instead:
# docker build -t tsg:latest --build-arg EXTRAS=prod .
```

The image includes the ODBC Driver 17 (for SQL Server), gunicorn, and runs as a non-root user.

---

## 3. Configure (settings & secrets)

Copy the template and fill in **real** values:

```bash
cp .env.prod.example .env.uat   # Windows: Copy-Item .env.prod.example .env.uat
```

Key settings to set (see the file for the full list):

- **`TSG_DB_DSN`** — your real TSG (with `Encrypt=yes`).
- **`TSG_REDIS_URL`** — `rediss://:password@host:6379/0`.
- **Authentication (real JWT):** `TSG_JWT_ISSUER`, `TSG_JWT_AUDIENCE`, `TSG_JWT_JWKS_URL`, and
  `TSG_JWT_ENTITIES_CLAIM` (the claim that holds the caller's allowed `group.id`s — default `entities`).
  **Do not set `AUTH_DEV_MODE`** (it stays off).
- **`AZURE_OPENAI_API_KEY`** — from a Secret, not committed.
- **Embeddings/reranker:** **default `local`** (in-process, no network) — build with
  `--build-arg EXTRAS=prod,local` and mount the model dirs. Multi-node/GPU alternative: `litellm_proxy`
  + `TSG_LITELLM_BASE_URL` (TEI/vLLM, not in the compose).
- **`APP_ENV`** — `prod` by default. **Fail-closed:** in `staging`/`prod` the app **refuses to start**
  if authentication is bypassed.

> **✅ You can run `APP_ENV=prod`** — the fail-closed guard only checks that authentication isn't
> bypassed (no dev bypass needed). Note: the asset↔entity DB ownership check (`ASSET_ENTITY_BINDING`)
> was removed 2026-07-12 — it depended on a platform column that's always NULL in real data. Entity
> authorization is JWT-claim-only now (`Principal.require_entity`) — see `TSG_Gap_Analysis.md` §13.15.

> **Secrets:** in OpenShift these values become a **Secret** (keys, DSN) + **ConfigMap** (non-secret).
> Never bake secrets into the image or git. **Rotate the Azure key** that was shared earlier.

---

## 4. Prepare the database (one-time, controlled)

Run the migrations using the image (so the exact app version applies them):

```bash
# Database-first: the schema is stood up from scripts/*.sql, not a migration tool.
# Run against the target DB from any machine with sqlcmd (safe to re-run):
sqlcmd -S <server> -d <database> -i scripts/TSG_Core.sql
```

Then, once, in SQL Server: `ALTER DATABASE TSG SET READ_COMMITTED_SNAPSHOT ON;`

> If a migration says a table doesn't exist, your `TSG` is missing the platform base tables —
> those must be present first (the app reuses them, it does not create them).

---

## 5. Run the services

**Option A — Docker Compose (single host):**

```bash
docker compose -f docker/compose.prod.yml --env-file .env.uat up -d
```

This starts **api** (gunicorn + 4 uvicorn workers), **worker** (Celery, gevent, 50 slots),
**beat** (fires the reaper every 60s, and the operational self-check every 5 minutes — see §9), and **redis**.

**Option B — OpenShift (the real target, SDD §13):** create three Deployments from `tsg:latest`
(commands = the api/worker/beat commands in `compose.prod.yml`), a **Route** to the api on port 8000,
a **Secret + ConfigMap** for the env, and health probes:

- **liveness** → `GET /healthz`
- **readiness** → `GET /readyz`

Scale the **api** and **worker** Deployments to add capacity (they're stateless; §concurrency).

---

## 6. Verify it started healthy

```bash
curl http://YOUR_HOST:8000/healthz    # {"status":"ok"}
curl http://YOUR_HOST:8000/readyz     # {"status":"ready","checks":{"database":"ok","redis":"ok","mongo":"ok"}}
```

`checks.mongo` reads `"skipped"` instead of `"ok"`/`"error"` when `EMBEDDING_STORE=memory` — a valid
configuration that never touches Mongo, not a failure. Any dependency actually failing (not skipped)
returns HTTP 503 with `"status":"not_ready"`, so orchestrators pull the pod from rotation.

Check the logs (structured JSON). On boot the **api** runs the DB invariant checks (it refuses to
start if a required index/column is missing), and the **worker** warm-loads the models (if local).

---

## 7. Get a real access token

The API only accepts valid JWTs from your SSO. Get one (Keycloak client-credentials example):

```bash
TOKEN=$(curl -s -X POST "https://sso.yourcompany.com/realms/platform/protocol/openid-connect/token" \
  -d grant_type=client_credentials -d client_id=YOUR_CLIENT -d client_secret=YOUR_SECRET \
  | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```

> **Critical:** the token **must contain the `entities` claim** — the `group.id`s this caller may use.
> If your SSO doesn't add it, configure a claim/mapper for it, or set `TSG_JWT_ENTITIES_CLAIM` to the
> claim your SSO actually uses. If the org you test with isn't in the token, every call returns **403**
> (that's the real access control working).

---

## 8. Test the application end to end (real auth)

**Pick a real asset and organisation** from your DB:

```sql
SELECT TOP 5 id AS asset_id, name FROM ctm_scan_entity WHERE is_deleted = 0;
SELECT TOP 5 id AS entity, name FROM [group];
```

The organisation id you use **must be in your token's `entities` claim**.

**Step 1 — Create a session:**

```bash
curl -X POST http://YOUR_HOST:8000/v1/sessions \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{ "asset_id": 100, "entity": "5", "user_id": "svc-platform" }'
# → 202 { "session_id": "..." }   (409 if that asset already has a running session)
```

**Step 2 — Watch progress (live):**

```bash
curl -N http://YOUR_HOST:8000/v1/sessions/SESSION_ID/events -H "Authorization: Bearer $TOKEN"
```

**Step 3 — Check status** until `awaiting_review`:

```bash
curl http://YOUR_HOST:8000/v1/sessions/SESSION_ID -H "Authorization: Bearer $TOKEN"
```

**Step 4 — Read results** (profiles, grounded threats, scenarios):

```bash
curl http://YOUR_HOST:8000/v1/sessions/SESSION_ID/results -H "Authorization: Bearer $TOKEN"
```

**Step 5 — Accept** (human approval; only accepted content is saved):

```bash
curl -X POST http://YOUR_HOST:8000/v1/sessions/SESSION_ID/accept \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{}'
# → { "status": "completed" }
```

**Step 6 — Confirm:** repeat Step 3 (session is done), and a new session for the same asset is now allowed.

That is the full production flow: **authenticate → create → generate → review → accept**, with real
tokens, real database, real models.

---

## 9. Observe & operate

- **Logs:** structured JSON on stdout (pipeline start/stage/complete, lock acquire/release, reaper
  cancellations, errors). Ship to your log stack.
- **Celery monitoring:** run **Flower** against the same broker to watch queues/tasks.
- **What to watch:** stuck sessions (the reaper cancels them and frees the asset), `stage_error`
  events, grounding scores, and `409/503` rates.
- **The app watches some of this for you now:** a `tsg.self_check` Celery beat task runs every
  `TSG_SELF_CHECK_INTERVAL_SECONDS` (default 300s) and logs a `selfcheck.*` WARNING event for anything
  worth attention — `active_sessions_high` (nearing `TSG_MAX_ACTIVE_SESSIONS`), `pool_saturated`
  (database connection pool nearly fully checked-out), `tempdb_version_store_high` and
  `tempdb_long_running_txn` (the RCSI tempdb-growth risk called out in `scripts/TSG_Core.sql` —
  the version store isn't just turned on and forgotten anymore). All five thresholds
  (`TSG_TEMPDB_VERSION_STORE_WARN_MB`, `TSG_TEMPDB_LONG_TXN_WARN_SECONDS`,
  `TSG_ACTIVE_SESSIONS_WARN_RATIO`, `TSG_POOL_UTILIZATION_WARN_RATIO`, and the interval itself) are
  untuned placeholders — set them against your real workload, not the shipped defaults.
  Point your log-stack's alert rules at these event names and at `readyz.not_ready` (§6).
- *(Prometheus metrics + OpenTelemetry traces are still Milestone 4 — see §12 — but the log/`readyz`-based
  signal above already closes the "nothing watches this" gap in the meantime.)*

---

## 10. Production security checklist

- [ ] `AUTH_DEV_MODE` is **off** (default) — real JWT only.
- [ ] Secrets in OpenShift Secrets/Vault, not in the image or git; **Azure key rotated**.
- [ ] DB `Encrypt=yes`; Redis over `rediss://` with a password.
- [ ] `READ_COMMITTED_SNAPSHOT` on.
- [ ] Container runs as non-root (the image does).
- [ ] The SSO issues the **`entities`** claim correctly (this is your per-organisation access control).
- [ ] Connection pools sized: `(api replicas + workers) × (pool + overflow)` under the MSSQL limit —
  and watched at runtime too: the `pool_saturated` self-check (§9) warns before that sizing actually runs out.

---

## 11. Stop / roll back

```bash
docker compose -f docker/compose.prod.yml --env-file .env.uat down
```

OpenShift: scale the Deployments to 0, or roll back to the previous image tag.

---

## 12. Honest production-readiness status

This is **Milestone 1 (the vertical slice), production-configured**. It is safe to **deploy and test
end to end** with real auth and infra. Before it carries **real production traffic at scale**, finish
these hardening items (Milestones 2–4 in the plan):

- **Audit tamper-proofing** — the audit trail is append-only in the app but not yet a SQL Server
  **ledger/WORM** with a retention-lock purge (M10/§11).
- **Library curation** — the curator gate + candidate queue for new threats (M3).
- **Breadth & overload** — multi-subsystem fan-out, regeneration cascade, partial accept, and the
  `503` backpressure signal (M2).
- **Observability & scale proof** — Prometheus metrics, OpenTelemetry traces, Flower, and a load test
  to size GPU/worker capacity; full OpenShift manifests (M4). (A dependency-free stopgap already exists —
  see §9's `tsg.self_check` task and `/readyz`'s per-dependency status — so this isn't zero signal until
  M4 ships, just not real metrics/alerting infrastructure yet.)

---

### Cheat sheet

```bash
docker build -t tsg:latest .
cp .env.prod.example .env.uat                                   # then fill in real values
sqlcmd -S <server> -d <database> -i scripts/TSG_Core.sql          # schema, database-first
docker compose -f docker/compose.prod.yml --env-file .env.uat up -d
curl http://YOUR_HOST:8000/readyz                                # ready?
TOKEN=... (Section 7)                                            # real JWT with entities claim
# create → events → status → results → accept (Section 8)
```
