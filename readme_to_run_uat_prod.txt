# FINAL ONE -- UAT + PRODUCTION
# Companion to readme_to_run.txt (that one is DEV). UAT and PRODUCTION use the SAME steps and
# the SAME file (.env.uat); only the values inside it differ per environment.
#
# NOTE: run every command below from the "tsg" folder (the one with pyproject.toml).
cd /opt/tsg          # Windows: cd "C:\Chettri_World\IT World\Development\DESC\TSG\tsg"

# WHAT IS DIFFERENT FROM DEV -- read this first, it explains every step below:
#   dev  = Azure gpt-5-mini + LOCAL e5/bge models + 1024 dims + login bypass ON
#   uat  = glm-5 + qwen3 embed/rerank ON THE GPU CLUSTER via litellm + 4096 dims + bypass OFF
# So here: no local model files are needed at all, a REAL JWT is required (the x-dev-entities
# header does nothing), and the vector cache must be rebuilt because dev's vectors are the
# wrong size (1024) for qwen3 (4096).


# =============================================================================================
# STEP 0. MAKE SURE .env.uat IS ACTUALLY LOADED  <-- the single most important step
# =============================================================================================
# A file named ".env.uat" is NOT picked up automatically -- config.py's default is ".env".
# If it is not loaded, the app starts CLEANLY on the DEV config: wrong model, wrong vector size,
# and AUTH_DEV_MODE=true (anyone can send x-dev-entities and be authenticated). Nothing errors.
# Pick the ONE line matching how you deploy:
#
#   docker compose -> nothing to do; docker/compose.prod.yml already points env_file at ../.env.uat
#   OpenShift/K8s  -> every key in .env.uat must exist as a real env var in the ConfigMap/Secret
#                     (real env vars always win over any file)
#   direct on host -> export TSG_ENV_FILE=.env.uat        # PowerShell: $env:TSG_ENV_FILE=".env.uat"
#
# A mistyped TSG_ENV_FILE now FAILS LOUDLY instead of silently falling back to .env.

# Confirm what the app will actually read (safe, prints no secrets):
TSG_ENV_FILE=.env.uat python -c "from app.core.config import Settings; s=Settings(); print(s.llm_provider, s.inference_model, s.embedding_dimensions, s.app_env, 'dev_bypass=', s.auth_dev_mode)"
# MUST print:  litellm_proxy glm-5 4096 staging dev_bypass= False
# If it prints azure_openai / 1024 / dev_bypass= True  -> .env.uat did NOT load. STOP and fix.


# =============================================================================================
# STEP 1. PRE-FLIGHT -- run this BEFORE starting anything
# =============================================================================================
# Checks the things a passing test suite provably cannot: real SQL Server, real Redis, real
# MongoDB, and the real models through the proxy. It also prints the grounding thresholds it
# calibrates for this model pair. Read-only apart from a self-deleting Redis key.
TSG_ENV_FILE=.env.uat python scripts/uat_preflight.py

# Section A must show: litellm_proxy / glm-5 / 4096 / staging / auth_dev_mode False / admin_api_key SET
# Every other check must be PASS (the "no proxy in use" SKIP only appears in dev).
# Exit code 0 = good to proceed. Re-run with PREFLIGHT_TRACEBACKS=1 for detail on a failure.


# =============================================================================================
# STEP 2A. RUN IT -- DOCKER (recommended)
# =============================================================================================
# Build once per release. EXTRAS=prod pulls in gunicorn. Do NOT add ",local" -- the embedding and
# reranker models run on the GPU cluster here, so bundling sentence-transformers only bloats the
# image (~2GB) and slows worker boot.
docker build -t tsg:latest --build-arg EXTRAS=prod .

# Starts api (gunicorn + 4 uvicorn workers, port 8000), worker (Celery/gevent, 50 slots),
# beat (the reaper schedule) and redis.
docker compose -f docker/compose.prod.yml --env-file .env.uat up -d

# Watch the first boot -- see STEP 3 for what to look for.
docker compose -f docker/compose.prod.yml logs -f worker

# Stop:
docker compose -f docker/compose.prod.yml --env-file .env.uat down


# =============================================================================================
# STEP 2B. RUN IT -- DIRECTLY ON A HOST (no Docker)
# =============================================================================================
# Same venv rules as dev: the folder MUST be named .venv (dot-prefixed), and the Celery worker
# needs the venv ACTIVATED or a bare `celery` resolves to a global Python with no gevent.
py -3.12 -m venv .venv                  # Linux: python3.12 -m venv .venv
.venv\Scripts\Activate.ps1              # Linux/Git Bash: source .venv/bin/activate
python -m pip install --upgrade pip

# ".[prod]" = gunicorn. NOT ".[local]" -- no local models in this environment.
pip install -e ".[prod]"
pip check

export TSG_ENV_FILE=.env.uat            # PowerShell: $env:TSG_ENV_FILE=".env.uat"

# API (gunicorn, not `uvicorn --reload` -- that is a dev-only auto-restarting server):
gunicorn app.main:app -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:8000 --timeout 120

# Worker (separate terminal, venv activated):
.venv\Scripts\celery.exe -A app.pipeline.celery_worker.celery_app worker -P gevent -c 50 -l info

# Beat -- the reaper that cleans up abandoned sessions (separate terminal):
.venv\Scripts\celery.exe -A app.pipeline.celery_app.celery_app beat -l info


# =============================================================================================
# STEP 3. WHAT THE FIRST BOOT DOES (it is slower than dev -- this is expected, and deliberate)
# =============================================================================================
# Before serving anything, each worker:
#   1. verifies the proxy lists glm-5 / qwen3-embedding-8b-mig / qwen3-reranker-8b-mig
#   2. makes ONE real embedding call and refuses to start if the width is not 4096
#   3. makes ONE real chat call to glm-5 -- this is what catches the model entry's
#      "stream": true setting at DEPLOY time instead of on a user's first request
#   4. calibrates the grounding thresholds for this model pair and stores them in MongoDB
#      (one time only; every later worker reads the stored values)
#
# Log lines worth confirming:
#   grounding.thresholds_calibrated       <- good: real numbers derived for qwen3
#   grounding.thresholds_uncalibrated_fallback  <- WARNING: running on dev-tuned numbers;
#                                                  usually means the threat library is empty
# A boot failure here is the system refusing to run misconfigured -- read the message, fix, restart.


# =============================================================================================
# STEP 4. REBUILD THE VECTOR CACHE  (required once, after the dev -> qwen3 switch)
# =============================================================================================
# Dev's cached vectors are 1024-wide; qwen3 produces 4096. Old entries are useless and must be
# regenerated or threat matching silently degrades.
# X-Admin-Key = TSG_ADMIN_API_KEY from .env.uat. A real JWT is ALSO required (both gates apply).
curl -X POST https://<uat-host>/v1/tsg/threat-library/embeddings/recreate \
  -H "X-Admin-Key: <TSG_ADMIN_API_KEY>" \
  -H "Authorization: Bearer <JWT>" \
  -H "Content-Type: application/json" -d '{}'

# Returns 202 + a job_id. Poll until state=SUCCESS:
curl https://<uat-host>/v1/tsg/threat-library/embeddings/status/<job_id> \
  -H "X-Admin-Key: <TSG_ADMIN_API_KEY>" -H "Authorization: Bearer <JWT>"


# =============================================================================================
# STEP 5. VERIFY THE APPLICATION
# =============================================================================================
curl https://<uat-host>/health      # 200 {"status":"ok"} -- process is alive
curl https://<uat-host>/readyz      # 200 {"status":"ready"} -- DB + Redis + Mongo all reachable

# Then walk documents/API_Smoke_Testing_Guide.md (4-hour guide, P1 section first).
# IMPORTANT: the dev shortcut does NOT work here. auth_dev_mode is OFF, so "x-dev-entities: 5"
# is ignored -- every call needs a real JWT whose `entities` claim contains the entity id.
# Confirm your IdP (TSG_JWT_ISSUER / _AUDIENCE / _JWKS_URL in .env.uat) is reachable first.


# =============================================================================================
# PRODUCTION -- same as above, with these changes
# =============================================================================================
#   1. APP_ENV=prod in the env file (UAT uses staging). Both block the dev login bypass.
#   2. Its own TSG_DB_DSN, TSG_REDIS_URL, TSG_MONGO_DB and a freshly generated TSG_ADMIN_API_KEY:
#        python -c "import secrets; print(secrets.token_hex(32))"
#   3. Re-run STEP 1 and STEP 4 against production -- calibrated thresholds and cached vectors
#      live in ITS OWN MongoDB database and do not carry over from UAT.
#   4. Review these two before real load; they are reasoned starting points, not measured:
#        TSG_MAX_CONCURRENT_LLM_CALLS=32        (ceiling on simultaneous AI calls, all workers)
#        TSG_MAX_ACTIVE_SESSIONS_PER_ENTITY=20  (stops one tenant taking all 100 session slots)
#   5. Scaling for throughput = MORE WORKER REPLICAS, not a bigger -c value. Keep
#      (api replicas + workers) x (TSG_DB_POOL_SIZE + TSG_DB_MAX_OVERFLOW) under SQL Server's
#      connection cap.


# =============================================================================================
# TROUBLESHOOTING -- issues actually hit in this environment
# =============================================================================================
# 401 from every proxy call
#   The proxy sits behind a gateway that eats the Authorization header. .env.uat already sets
#   LITELLM_API_KEY_HEADER=x-litellm-api-key, which sends the key in BOTH headers. Confirm it is
#   present and that the value matches TSG_LITELLM_API_KEY.
#
# Proxy calls hang / never connect from a jump server
#   HTTP_PROXY/HTTPS_PROXY are set and the corporate proxy never completes the CONNECT tunnel.
#   The app self-applies a NO_PROXY bypass for the litellm host at boot. To confirm by hand:
#     export NO_PROXY="$NO_PROXY,llmapi.govai.ae"
#
# App starts but behaves like dev
#   .env.uat was not loaded. Re-run the STEP 0 confirmation command.
#
# Admin routes always 401
#   TSG_ADMIN_API_KEY empty in the loaded config -- check the X-Admin-Key header AND that a valid
#   JWT is present; BOTH gates must pass.
#
# `docker compose up` fails on a volume/bind-mount path
#   Only happens if EMBEDDING_MODEL_HOST/RERANKER_MODEL_HOST are set to paths that do not exist.
#   With the proxy providers they are unnecessary -- leave them unset (the compose file defaults
#   them, so unset is safe).
#
# Worker container restarts repeatedly, logs stop after "_init_worker"
#   First boot does real network work (model checks, one chat call, threshold calibration).
#   The healthcheck allows for it; if it still trips, the proxy is unreachable -- run STEP 1.
