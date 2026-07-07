# Threat Scenario Generator (TSG)

AI pipeline that produces grounded, human-reviewed STRIDE threat scenarios for CII
assets. Built on the existing `TSG` MSSQL schema (**database-first** — reuse,
do not recreate). Design: [`../TSG_SDD.md`](../TSG_SDD.md) v1.1; build-coverage
matrix: [`../TSG_SDD_Remediation.md`](../TSG_SDD_Remediation.md).

## Status — Milestone 1 (vertical slice)
End-to-end happy path: `create → profile → identify+ground → scenario → single
review → accept`, **concurrency-correct from day one**. 121 tests green.

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
migrations   Alembic: baseline-stamp then M1,M3–M8 + M2 (0010)
tests        M1 acceptance subset (runs on SQLite)
```

## Run locally
```bash
python -m venv .venv && ./.venv/Scripts/pip install -e ".[dev]"
docker compose -f docker/compose.yml up -d          # mssql, redis, mongo, litellm

# database-first: mark the existing schema as baseline, then apply the slice guards
alembic stamp 0001
alembic upgrade head                                 # M1,M3,M4,M5,M6,M7,M8,M2

uvicorn app.main:app                                 # API (runs INV checks at boot)
celery -A app.pipeline.celery_worker.celery_app worker -P gevent -l info
celery -A app.pipeline.celery_app.celery_app beat -l info   # reaper (M2 wires the schedule)
```

## Test
```bash
./.venv/Scripts/python -m pytest -q                  # SQLite logic + acceptance subset
```
Local models: `pip install -e ".[local]"` then `python scripts/smoke_local_models.py`
verifies both model paths load and stay **concurrency-safe under gevent** (fires
concurrent grounding calls; asserts the worker hub is not frozen by torch inference).
Integration/load tests (filtered-index 409, GPU sizing) run against a dev TSG
in CI — see the SDD verification plan.

## Config
All settings are env vars prefixed `TSG_` (see `app/core/config.py`); copy
`.env.example` to `.env`. Nothing is hardcoded — thresholds, timeouts, pool sizes,
JWT issuer/JWKS all come from the environment.

**Swap models without code changes** via `.env` (three independent switches):
- `LLM_PROVIDER` — inference/generation: `litellm_proxy` (default) · `azure_openai` (`AZURE_OPENAI_*`) · `openai`.
- `EMBEDDING_PROVIDER` — `litellm_proxy` (default) · `local` (in-process, no network; `EMBEDDING_MODEL`=disk path, e.g. `multilingual-e5-large`). `SEMANTIC_MATCH_THRESHOLD` is the cosine floor.
- `RERANKER_PROVIDER` — `litellm_proxy` (default) · `local` (`RERANKER_MODEL`=disk path, e.g. `bge-reranker-v2-m3`).

Local models need the extra: `pip install -e ".[local]"` (sentence-transformers).
The real `AZURE_OPENAI_API_KEY` goes in `.env` only — never committed.
