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
# (gunicorn installs fine on Windows but can only RUN on Linux -- install step is the same on both.)
pip install -e ".[prod]"
pip check

export TSG_ENV_FILE=.env.uat            # PowerShell: $env:TSG_ENV_FILE=".env.uat"

# SET IT IN EVERY TERMINAL BELOW, not just this one. A new shell does NOT inherit it, and
# nothing fails loudly when it is missing: that shell silently loads .env (dev), whose broker
# is redis://127.0.0.1:6379/0. A worker started that way consumes a DIFFERENT queue from the
# one the API publishes to -- so POST /v1/sessions returns a session_id, writes its single
# Scenario_Session row, and then NOTHING EVER HAPPENS. No Subsystem_Stage_State rows, no
# threats, "running" forever. Confirm per terminal before starting the process:
python -c "from app.core.config import Settings; s=Settings(); print(s.llm_provider, (s.celery_broker_url or s.redis_url).split(chr(64))[-1])"
# MUST print:  litellm_proxy 10.228.146.4:6379/1     (azure_openai / 127.0.0.1 = wrong file)

# FOUR terminals, not three -- the fourth (Flower) is the task dashboard. Every command tees
# its output to logs\ as well as the window: a console is a volatile log sink, and a process
# that dies takes its last words with it, which is what makes "the API never came up" or
# "5555 is not working" undiagnosable afterwards. The app ALSO writes logs\trace\app-<pid>.jsonl
# on its own (LOG_FILE=true in .env.uat) -- that is the structured copy; these are the readable one.
mkdir logs                              # Linux: mkdir -p logs

# API -- pick the line for your OS. gunicorn is Linux-only (it imports fcntl, a Unix stdlib
# module, so on Windows it dies with "No module named 'fcntl'"). On Windows run uvicorn
# SINGLE-PROCESS -- uvicorn is a base dependency, nothing extra to install; see the note
# under the Windows line for why --workers must not be used there.
# Neither line uses --reload (that is the dev-only auto-restarting server).
gunicorn app.main:app -k uvicorn.workers.UvicornWorker -w 4 -b 0.0.0.0:8000 --timeout 120 2>&1 | tee -a logs/api.log   # Linux
uvicorn app.main:app --host 0.0.0.0 --port 8000 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath logs\api.log -Append   # Windows
# NO --workers ON WINDOWS. Multi-worker mode makes the PARENT bind the listening socket and
# hand it to spawned children; a child then fails in asyncio's _start_serving with
#   OSError: [WinError 10022] An invalid argument was supplied   (WSAEINVAL on sock.listen)
# and crash-loops while the others serve -- so the stack looks up and is quietly degraded.
# Seen on Python 3.14, whose asyncio socket internals differ from the 3.12 requirements.lock
# was compiled against. One process is right here anyway: the API only accepts and enqueues,
# every expensive stage runs in the Celery worker. On Linux use the gunicorn line above
# instead (gunicorn imports fcntl and cannot run on Windows at all).

# Worker (separate terminal, venv activated). `python -m celery`, NOT .venv\Scripts\celery.exe:
# the console-script shim resolves its interpreter through pyvenv.cfg, so a .venv COPIED from
# another directory silently runs a FOREIGN python -- this checkout's code on sys.path, the
# other venv's site-packages loaded. Naming the interpreter cannot resolve anywhere but here.
$env:TSG_ENV_FILE=".env.uat"     # this terminal too
python -m celery -A app.pipeline.celery_worker.celery_app worker -P gevent -c 50 -l info 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath logs\celery.log -Append

# Beat -- the reaper that cleans up abandoned sessions (separate terminal):
$env:TSG_ENV_FILE=".env.uat"     # this terminal too
python -m celery -A app.pipeline.celery_app.celery_app beat -l info 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath logs\beat.log -Append

# Flower -- the Celery task dashboard, http://127.0.0.1:5555 (fourth terminal). NOTHING ELSE IN
# THIS RUNBOOK STARTS IT: if 5555 is dead, this terminal is simply missing -- that is the whole
# bug, not a Flower fault. Three things this line gets right and are easy to get wrong:
#   -A is celery_app.celery_app, NEVER celery_worker -- the latter monkey-patches gevent at
#     import, which corrupts Flower's own tornado event loop.
#   task events are already on in code (celery_app.py: worker_send_task_events +
#     task_send_sent_event), so no -E is needed on the worker. Without them Flower shows live
#     workers and an EMPTY task list, which looks like a broken dashboard and is not one.
#   --address=127.0.0.1 is deliberate: Flower exposes task revoke/terminate to anyone who
#     reaches the port. Browse it ON this host (RDP/console), do NOT bind 0.0.0.0.
$env:TSG_ENV_FILE=".env.uat"     # this terminal too
python -m celery -A app.pipeline.celery_app.celery_app flower --address=127.0.0.1 --port=5555 --basic-auth=USER:PASS --logging=error 2>&1 | ForEach-Object { $_.ToString() } | Tee-Object -FilePath logs\flower.log -Append
#   ^ USER:PASS = the TSG_FLOWER_BASIC_AUTH value from .env.uat (not read automatically here --
#     it is infra-only config, never loaded by app/core/config.py into the process env).


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
curl https://<uat-host>/health      # 200 {"status":"ok"} -- process alive, NOTHING else checked
curl https://<uat-host>/ready       # 200 {"status":"ready"} + a per-dependency "checks" object

# /ready is THE answer to "is staging working" -- one call, four dependencies: database,
# redis, mongo AND workers (app/api/health.py). READ THE BODY, not just the status code:
# `workers` is ADVISORY and deliberately never fails the probe (evicting API pods because a
# worker is down would turn a delay into an outage), so /ready can answer 200 "ready" while
# "workers":"error" means every session you submit will queue forever and nothing will run.
Invoke-RestMethod http://127.0.0.1:8000/ready | ConvertTo-Json

# Watch it actually work. Each of the four terminals in Step 2B tees to its own file:
Get-Content logs\celery.log -Wait -Tail 50            # the pipeline, live
Get-Content logs\api.log    -Wait -Tail 50            # requests, and boot failures
Select-String -Path logs\*.log -Pattern '"level": "(error|warning)"'   # everything that went wrong
# Structured copy, one file per process (LOG_FILE=true):  logs\trace\app-<pid>.jsonl
# Task-by-task view: http://127.0.0.1:5555 (Flower, Step 2B) -- from THIS host only.

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
# Litellm calls still time out even with HTTP_PROXY/HTTPS_PROXY set (opposite case)
#   If network support says the proxy is REQUIRED to reach the litellm host (not broken), the
#   self-heal above is working against you -- it forces a direct connection every time. Set
#   TSG_LITELLM_BYPASS_PROXY=false to disable it and let HTTP_PROXY/HTTPS_PROXY actually route
#   litellm traffic through the proxy.
#
# Worker dies ~2 min after "GET /v1/models 200 OK": worker.boot_guard_failed with a ConnectTimeout
# to openaipublic.blob.core.windows.net/.../cl100k_base.tiktoken
#   `import litellm` makes tiktoken DOWNLOAD its cl100k_base encoding from the public internet on
#   first use -- blocked on this network (only the litellm host is reachable). The API is affected
#   too: it imports litellm lazily, so it boots fine and then hits the same wall on the FIRST real
#   LLM request. Fix = put the file on the box and point tiktoken at it:
#     1. on any internet machine, download
#        https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken
#     2. place it in a folder NAMED AS the sha1 of that URL (tiktoken's cache-key filename):
#          9b5ad71b2ce5302211f9c61530b329a4922fc6a4
#     3. in EVERY terminal (api + worker + beat), REAL env vars -- .env.uat cannot carry them,
#        pydantic-settings only feeds the app's own Settings:
#          export CUSTOM_TIKTOKEN_CACHE_DIR=/opt/tiktoken_cache   # <-- THE ONE THAT MATTERS
#          export TIKTOKEN_CACHE_DIR=/opt/tiktoken_cache          # for anything using tiktoken directly
#        PowerShell: $env:CUSTOM_TIKTOKEN_CACHE_DIR="C:\tiktoken_cache"; $env:TIKTOKEN_CACHE_DIR="C:\tiktoken_cache"
#        (persist on Windows with setx -- takes effect in NEW terminals only)
#
#        SETTING ONLY TIKTOKEN_CACHE_DIR DOES NOTHING AND THE TRACEBACK STAYS IDENTICAL: litellm's
#        litellm_core_utils/default_encoding.py OVERWRITES os.environ["TIKTOKEN_CACHE_DIR"] with its
#        own bundled tokenizers dir a few lines before calling tiktoken.get_encoding(). It reads
#        CUSTOM_TIKTOKEN_CACHE_DIR as the override. Verify what your version does -- it is a plain
#        file read, no import, so it cannot hang:
#          type .venv\Lib\site-packages\litellm\litellm_core_utils\default_encoding.py
#        Env-var-free alternative: copy the file into litellm's own directory, where it already looks:
#          .venv/Lib/site-packages/litellm/litellm_core_utils/tokenizers/
#     3b. quick test, 2 seconds instead of a 2-minute worker boot -- this is the exact failing line:
#          python -c "import litellm; print('litellm imported OK')"
#   Same class of import-time fetch, worth setting alongside it on no-internet hosts:
#     LITELLM_LOCAL_MODEL_COST_MAP=True   # litellm uses its bundled model-price table instead of
#                                         # fetching it from raw.githubusercontent.com
#   OpenShift/K8s: bake the file into the image (or mount it) and set both vars in the ConfigMap.
#
# Worker boots OK but logs embeddings.mongo_breaker_open / ServerSelectionTimeoutError
# "Could not reach any servers in [('<host>', 27018)] ... getaddrinfo failed"
#   getaddrinfo/WinError 11001 = DNS, NOT auth and NOT a firewall: the box cannot resolve that
#   Mongo hostname to an IP at all. Note pymongo's own hint in the message ("Replica set is
#   configured with internal hostnames or IPs?"): for a REPLICA SET, pymongo connects once using
#   TSG_MONGO_URL, then re-dials the member hostnames from the replica set config -- so pointing
#   TSG_MONGO_URL at an IP does NOT help if the RS advertises names this host cannot resolve.
#   Fix (any one):
#     - add the members to the hosts file  (Windows: C:\Windows\System32\drivers\etc\hosts,
#       Linux: /etc/hosts)  ->  <ip>  <mongo-hostname>
#     - give the host the right DNS server / search suffix so the names resolve
#     - single node and you do NOT need replica-set failover: add directConnection=true to
#       TSG_MONGO_URL, which skips RS discovery entirely
#   Boot does NOT fail (the breaker just opens for TSG_MONGO_BREAKER_COOLDOWN_SECONDS), but do
#   not ignore it -- with Mongo down: /ready returns not-ready, the L2 vector cache is bypassed so
#   every embedding is recomputed and billed, and store_thresholds() silently no-ops, so the
#   expensive boot calibration RE-RUNS ON EVERY WORKER BOOT instead of being reused. STEP 4 also
#   cannot work. Fix Mongo, then restart the worker so the calibration is actually persisted.
#
# Repeated grounding.calibration_paraphrase_failed (JSONDecodeError "Expecting value: line 1
# column 1") during boot calibration
#   The model answered (the trace line above each warning shows status ok and a non-zero
#   response_chars) but the reply did not START with '[' -- glm-5 wrapping the array in a
#   ```json fence or adding a sentence first. These calls ask for a JSON ARRAY, and provider-side
#   JSON mode is deliberately NOT applied to array calls (json_object would reject a list), so
#   nothing enforces the format server-side; the prompt is the only instruction.
#   Best-effort by design -- a failed paraphrase contributes nothing and calibration continues --
#   but a high failure rate thins the POSITIVES set, so the derived threshold is weaker. If most
#   names fail, prefer an explicit threshold in the env file, or run
#   scripts/calibrate_grounding.py with labelled data (its value wins over auto-calibration).
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

# --- 2026-08-18: admin-gated library growth [RETIRED] ---
# Historical only — auto-promotion, the admin candidates queue, and Threat_Candidate_Review
# were all removed. Library growth is now the explicit POST .../promote-to-library API only
# (anyone holding session_id+output_id; no admin gate, no auto-mode switch). Nothing below
# this line needs doing; the note is kept so old TSG_PROMOTION_AUTO_APPROVE_ENABLED references
# elsewhere aren't mistaken for a still-live setting.
