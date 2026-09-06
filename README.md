# Threat Scenario Generator (TSG)

AI pipeline that produces grounded, human-reviewed STRIDE threat scenarios for CII
assets. Built on the existing `TSG` MSSQL schema (**database-first** — reuse,
do not recreate). Design: [`../TSG_SDD.md`](../TSG_SDD.md) v1.1; build-coverage
matrix: [`../TSG_SDD_Remediation.md`](../TSG_SDD_Remediation.md).

## Status — Milestone 1 (vertical slice)
End-to-end happy path: `create → profile → identify+ground → scenario → single
review → accept`, **concurrency-correct from day one**. Run `pytest --collect-only -q`
for the current test count — the number moves often enough that hardcoding it here
just goes stale.

## Architecture
Async queue-based load-leveling: FastAPI (REST + SSE) → Redis → Celery workers →
litellm (metered) → models; MSSQL for state (DB-enforced locks), MongoDB for
embeddings (M2+). See SDD §4/§13.

## Layout
```
app/core     enums (Appendix B), config (12-factor), security (JWT + redaction)
app/db       engine, models (Core mirror of TSG), dal (isolation + CAS), invariants
app/pipeline context, llm (litellm adapter), grounding (§8.4), scoping, tasks, accept, reaper
app/api      deps (authz), sessions (routes), errors
app/sse      bus (Redis pub/sub, [R4])
scripts      TSG_Core.sql + Threat_library.sql + Control_library.sql (+ their Seed_to_*) — the schema (database-first, no migration tool)
tests        M1 acceptance subset (runs on SQLite)
```

## Run locally
```bash
python -m venv .venv && ./.venv/Scripts/pip install -e ".[dev]"
docker compose -f docker/compose.yml up -d          # mssql, redis, mongo, litellm

# database-first: the schema comes from scripts/, not from a migration tool.
# Run once against the target DB (safe to re-run — every CREATE TABLE is guarded):
sqlcmd -S <server> -d <database> -i "scripts/eyshield_handoff/1. TSG_Core.sql"
sqlcmd -S <server> -d <database> -i "scripts/eyshield_handoff/2. Threat_library.sql"
sqlcmd -S <server> -d <database> -i "scripts/eyshield_handoff/3. Seed_to_Threat_library.sql"
sqlcmd -S <server> -d <database> -i "scripts/eyshield_handoff/4. Control_library.sql"          # Step-4 control mapping
sqlcmd -S <server> -d <database> -i "scripts/eyshield_handoff/5. Seed_to_Control_library.sql"  # 30 standards, 1288 controls

uvicorn app.main:app                                 # API (runs INV checks at boot)
celery -A app.pipeline.celery_worker.celery_app worker -Q celery -P gevent -l info
# ...and a SECOND worker for the `admin` queue. Without -Q on the line above, the pipeline
# worker also drains `admin` and a 51 MB technique rebuild lands on the queue users wait on.
# -A celery_app (not celery_worker): the latter monkey-patches gevent and hangs a solo pool.
celery -A app.pipeline.celery_app.celery_app worker -Q admin -P solo -l info
celery -A app.pipeline.celery_app.celery_app beat -l info   # reaper (M2 wires the schedule)
```

## Test
```bash
./.venv/Scripts/python -m pytest -q                  # SQLite logic + acceptance subset
```
Local models: `pip install -e ".[local]"` then `python scripts/smoke_local_models.py`
verifies both model paths load and stay **concurrency-safe under gevent** (fires
concurrent grounding calls; asserts the worker hub is not frozen by torch inference).
Integration/load tests (filtered-index 409, GPU sizing) against a real MSSQL/broker
are currently run manually, not in CI — see the SDD verification plan for what that
tier is meant to cover once it's wired up.

## Config
All settings are env vars prefixed `TSG_` (see `app/core/config.py`); copy
`.env.example` to `.env`. Nothing is hardcoded — thresholds, timeouts, pool sizes and
credentials all come from the environment.

**Swap models without code changes** via `.env` (three independent switches — see
`.env.example` for a ready-to-use dev config, `.env.prod.example` for production):
- `LLM_PROVIDER` — inference/generation: `azure_openai` (default, `AZURE_OPENAI_*`) · `openai` · `litellm_proxy`.
- `EMBEDDING_PROVIDER` — `local` (default; in-process, no network; `EMBEDDING_MODEL`=disk path, e.g. `multilingual-e5-large`) · `litellm_proxy`. `SEMANTIC_MATCH_THRESHOLD` is the cosine floor; `EMBEDDING_DIMENSIONS` must match whichever model is actually configured (e.g. 1024 for local `multilingual-e5-large`, but a proxy-routed model can use a different width — a mismatch fails loud at worker boot).
- `RERANKER_PROVIDER` — `local` (default; `RERANKER_MODEL`=disk path, e.g. `bge-reranker-v2-m3`) · `litellm_proxy`.

Typical local dev: keep all three at their defaults (`azure_openai`/`local`/`local`) — no
proxy access needed. Typical production: flip `EMBEDDING_PROVIDER`/`RERANKER_PROVIDER` (and
optionally `LLM_PROVIDER`) to `litellm_proxy` and point `TSG_LITELLM_BASE_URL`/
`TSG_LITELLM_API_KEY` at the real proxy — no code change either way.

**UAT/production capacity tuning** (see the matching block in `.env.example`): set
`TSG_LLM_TIMEOUT_SECONDS=600` — the 90s default suits direct Azure, but the proxy's
self-hosted models queue under concurrent load (proxy allows 1800s; a live probe measured 36s
for one uncontended call). Leave `TSG_STAGE_LEASE_SECONDS` unset so the reaper's lease
auto-derives from the timeout (`timeout × (retries+1) × 2`); an explicitly-set lease below the
safe floor refuses to boot. A provider rate limit that outlives litellm's retries (kimi-k2.5
has a platform-wide `rpm=192` shared across all teams; glm-5 has none) is treated as
temporary capacity — the task retries with backoff instead of failing the session.

Optional safety features (off/unset by default, litellm_proxy only): `LLM_MODERATION_ENABLED`
(flags generated scenario text via the proxy's moderation endpoint — soft-flag, never blocks),
`LLM_GUARDRAILS` (proxy-side guardrail name(s) to run on every chat call).

Local models need the extra: `pip install -e ".[local]"` (sentence-transformers).
The real `AZURE_OPENAI_API_KEY` goes in `.env` only — never committed.

## Authentication — read this before issuing a key

**`X-API-Key` is the credential. Everything else is input.** TSG authenticates the *calling
service*, not the end user: `X-User-Id`, `X-Entity-Id` and `X-Tenant-Id` are request data that
the caller is trusted to populate truthfully, having already authenticated the person behind the
request. They are used for scoping and for the audit trail; they are not verified against a
membership table (`TSG_VERIFY_MEMBERSHIP` is off by design).

**A key is not scoped to a tenant.** Keys are scoped by `Module` and nothing else, so one valid
key can address every entity in every tenant simply by varying `X-Entity-Id`. That is the intended
contract for a trusted server-to-server caller — and it is why key handling *is* the security
model:

- **Server-side only.** Never ship a key to a browser, mobile app, or anything the end user can
  inspect. A key in a client is a full cross-tenant compromise.
- **One key per calling service**, so a rotation or a revocation has a known blast radius.
- **Rotate by replacing, never by recovering.** The secret is `secrets.token_hex(32)`, returned
  exactly once at creation and stored only as a SHA-256 hash — it cannot be read back. Lost or
  suspected-leaked: `POST /v1/tsg/api-clients/{client_id}/revoke`, then mint a new one.
- **`X-Admin-Key` is separate and stronger**: it gates the cross-tenant admin surface (libraries,
  embeddings, intel feeds, key issuance) on its own, deliberately without needing a client key —
  minting the first key must not require already having one.

CORS is `["*"]` by design and is safe here: `allow_credentials` is never enabled, so a browser
attaches no ambient credential and a hostile origin must already hold a key — at which point CORS
is irrelevant.
