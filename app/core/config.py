"""Application configuration — 12-factor, environment-driven.

Every tunable value (timeouts, thresholds, pool sizes, the concurrency ceiling)
lives here and is read from the environment, never hard-coded elsewhere. One
cached Settings instance is shared everywhere: injected via FastAPI
`Depends(get_settings)` in the API, and imported directly by Celery workers.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TSG_", env_file=".env", extra="ignore", populate_by_name=True)

    # --- Identity / tenant (single tenant, coarse scope) ---
    # A label for which single customer/organization this app instance serves.
    # TSG only supports one tenant at a time, so this is mostly for record-keeping —
    # it gets stamped onto every row this app writes.
    tenant_id: str = "DESC"

    # Which environment this is running in. In 'staging' and 'prod', the app refuses
    # to start at all if the developer-only auth bypass is still turned on.
    app_env: Literal["local", "dev", "staging", "prod"] = Field(
        "prod", validation_alias=AliasChoices("APP_ENV", "TSG_APP_ENV"))
    # How much detail gets written to the application logs. Use DEBUG when
    # troubleshooting locally (very detailed, noisy); use INFO or WARNING in
    # production so logs stay small and readable.
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO", validation_alias=AliasChoices("LOG_LEVEL", "TSG_LOG_LEVEL"))

    # --- Database: existing MSSQL TSG (reuse, do not recreate) ---
    # Which SQL Server database to connect to and how — server address, driver,
    # and credentials/trust settings are all bundled into this one connection string.
    # Override with TSG_DB_DSN. Kept as a raw string (r"...") because a backslash
    # sequence like \S isn't valid otherwise — Python already warns about this and
    # will eventually treat it as a hard error.
    db_dsn: str = (
        r"mssql+pyodbc://@XWF8TNJR3\SQLEXPRESS/TSG?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes"  # noqa: E501
    )
    # A "connection pool" is a small set of already-open database connections the
    # app reuses, instead of opening a brand-new one for every request (which would
    # be slow). `db_pool_size` is how many stay open normally; `db_max_overflow` is
    # how many EXTRA can open temporarily under heavy load; `db_pool_timeout` is how
    # many seconds a request waits for a free connection before giving up.
    #
    # These numbers need to stay big enough to cover how many things can be working
    # at once (see `celery -P gevent -c 50` in the deploy config): a background job
    # can hold its connection open while waiting on a slow AI call, not just for a
    # quick query, so the pool has to cover the full worker count or requests start
    # timing out under normal load. If that worker count changes, these should too.
    db_pool_size: int = 50
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    # How many seconds to wait when opening a brand-new connection to the database
    # (not waiting for a free pooled one — actually establishing one) before giving
    # up. Without this, an unreachable database host can block forever instead of
    # failing with a clear error.
    db_connect_timeout_seconds: int = 5
    # How many seconds a single already-acquired connection may spend actually
    # executing a statement before the driver cancels it. This is separate from
    # db_connect_timeout_seconds (which only bounds opening a new connection) and
    # from db_pool_timeout (which only bounds waiting for a free pooled slot) --
    # without this, a query blocked on a lock held by some other session/process
    # can pin a pool connection forever. Stays well under stage_lease_seconds so a
    # wedged statement is cancelled long before its stage lease would expire.
    db_statement_timeout_seconds: int = 30

    # --- Redis: live-update pub/sub + cache. Celery broker/backend may be separate DBs. ---
    # The address of the Redis server used both for pushing live session updates to
    # the browser, and as the queue background workers pull jobs from.
    redis_url: str = Field(
        "redis://127.0.0.1:6379/0", validation_alias=AliasChoices("REDIS_URL", "TSG_REDIS_URL"))
    # Optional: use a different Redis server (or database number) just for the
    # background job queue instead of sharing the one above. Falls back to
    # redis_url if left unset.
    celery_broker_url: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_BROKER_URL", "TSG_CELERY_BROKER_URL", "TSG_REDIS_CELERY_BROKER_URL"))
    # Optional: where a finished background job's result is stored temporarily so
    # it can be checked later. Same fallback behavior as celery_broker_url above.
    celery_result_backend: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_RESULT_BACKEND", "TSG_CELERY_RESULT_BACKEND", "TSG_REDIS_CELERY_RESULT_BACKEND"))
    # How long a finished job's result is kept before it's automatically deleted,
    # so this storage doesn't grow forever.
    result_expires_seconds: int = 3600

    # --- MongoDB: master-library embeddings ---
    # The address of the MongoDB database used to cache AI-generated vectors, so the
    # exact same text is never sent to the AI model to be converted twice.
    mongo_url: str = "mongodb://localhost:27017"
    # Which database name inside that MongoDB server to use.
    mongo_db: str = "tsg_embeddings"
    # How many milliseconds to wait when first connecting to that MongoDB database
    # before giving up and treating it as unreachable.
    mongo_connect_timeout_ms: int = 3000

    # --- litellm proxy: all models reached here ---
    # "litellm" is a small routing service some deployments use so the app can talk
    # to different AI providers (Azure, OpenAI, others) through one consistent
    # interface, without needing to know each provider's specific API details.
    #
    # The web address of that AI-routing service, used when LLM_PROVIDER=litellm_proxy
    # (or for embeddings/reranking when their own provider setting is litellm_proxy).
    litellm_base_url: str = "http://localhost:4000"
    # The password/key used to authenticate with that AI-routing service.
    litellm_api_key: str = "sk-local"
    # Which AI model name to ask the routing service for (e.g. "gpt-5") — only used
    # on the litellm-proxy or plain-OpenAI paths. Azure has its own "deployment name"
    # setting instead, below.
    inference_model: str = "gpt-5"
    # The embedding model to use — a model name when going through the proxy, or a
    # local file path when EMBEDDING_PROVIDER=local.
    embedding_model: str = Field(
        "multilingual-e5-large", validation_alias=AliasChoices("EMBEDDING_MODEL", "TSG_EMBEDDING_MODEL"))
    # The reranker model to use — same rule as embedding_model above (proxy name or local path).
    reranker_model: str = Field(
        "bge-reranker-v2-m3", validation_alias=AliasChoices("RERANKER_MODEL", "TSG_RERANKER_MODEL"))
    # How many seconds to wait for the AI to reply before giving up on that one call.
    llm_timeout_seconds: float = 90.0
    # How many times to automatically retry a single AI call if it fails for a
    # temporary reason (like a brief network hiccup), before giving up entirely.
    llm_max_retries: int = 3
    # Ask the AI provider to guarantee its reply is valid JSON. Off by default: the
    # backup model this app can fall back to may not support this option, and if it
    # doesn't, every single call would fail outright. Turn on per-provider only
    # after confirming it actually works with that provider.
    llm_json_mode: bool = Field(False, validation_alias=AliasChoices("LLM_JSON_MODE", "TSG_LLM_JSON_MODE"))
    # Optional: pin how random/creative the AI's replies are (0.0 = very
    # consistent, 2.0 = very varied). Leave unset (None) to let the AI provider
    # use its own default.
    llm_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices("LLM_TEMPERATURE", "TSG_LLM_TEMPERATURE"))
    # Optional: pin how much "thinking effort" a reasoning-capable model (like
    # gpt-5) spends per reply. Leave unset (None) to let the AI provider decide.
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        None, validation_alias=AliasChoices("LLM_REASONING_EFFORT", "TSG_LLM_REASONING_EFFORT"))

    # --- LLM provider (INFERENCE only — swap via .env, no code change) ---
    # Which AI provider handles the main threat/scenario generation calls. This can
    # be changed just by editing the environment, with no code changes needed.
    # Embeddings and reranking are configured separately below, since not every
    # provider here supports those (Azure has no reranker, for example).
    llm_provider: Literal["litellm_proxy", "azure_openai", "openai"] = Field(
        "azure_openai", validation_alias=AliasChoices("LLM_PROVIDER", "TSG_LLM_PROVIDER"))
    # The secret key used to authenticate with Azure's AI service.
    azure_openai_api_key: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_API_KEY", "TSG_AZURE_OPENAI_API_KEY"))
    # The web address of your organization's specific Azure AI resource.
    azure_openai_endpoint: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_ENDPOINT", "TSG_AZURE_OPENAI_ENDPOINT"))
    # The specific named AI model setup configured inside that Azure resource —
    # Azure calls this a "deployment" rather than just naming the model directly.
    azure_openai_deployment_name: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_DEPLOYMENT_NAME", "TSG_AZURE_OPENAI_DEPLOYMENT_NAME"))
    # Which version of Azure's API format to speak. Azure periodically introduces
    # new versions; this pins a known-working one so nothing changes underneath us.
    azure_openai_api_version: str = Field(
        "2024-12-01-preview", validation_alias=AliasChoices("AZURE_OPENAI_API_VERSION", "TSG_AZURE_OPENAI_API_VERSION"))
    # Credentials for calling OpenAI directly instead of through Azure or the
    # litellm proxy — only used when LLM_PROVIDER=openai.
    openai_api_key: str = Field("", validation_alias=AliasChoices("OPENAI_API_KEY", "TSG_OPENAI_API_KEY"))
    openai_base_url: str = ""

    # --- Embedding & reranker providers (independent of LLM_PROVIDER) ---
    # 'local' loads the model straight from disk, in-process, with no network call
    # (via sentence-transformers); 'litellm_proxy' calls out to the proxy instead.
    # embedding_model/reranker_model above hold the local file path when this is 'local'.
    embedding_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("EMBEDDING_PROVIDER", "TSG_EMBEDDING_PROVIDER"))
    embedding_dimensions: int = Field(
        1024, validation_alias=AliasChoices("EMBEDDING_DIMENSIONS", "TSG_EMBEDDING_DIMENSIONS"))
    # Where generated vectors are stored for reuse: 'mongo' (default — survives
    # restarts and is shared across workers) or 'memory' (kept only in this one
    # process, lost on restart). If Mongo is unreachable, this falls back to memory.
    embedding_store: Literal["memory", "mongo"] = Field(
        "mongo", validation_alias=AliasChoices("EMBEDDING_STORE", "TSG_EMBEDDING_STORE"))
    # Some embedding models (like e5) expect their input text to be prefixed with
    # "query:" or "passage:" to work well. 'auto' turns this on automatically when
    # the model name looks like an e5 model.
    embedding_prefix_style: Literal["auto", "e5", "none"] = Field(
        "auto", validation_alias=AliasChoices("EMBEDDING_PREFIX_STYLE", "TSG_EMBEDDING_PREFIX_STYLE"))
    # How similar (0 to 1) an AI-generated threat has to be to a threat-library entry
    # before it's even considered a possible match — below this, it isn't shortlisted
    # for a closer look at all.
    semantic_match_threshold: float = Field(
        0.60, validation_alias=AliasChoices("SEMANTIC_MATCH_THRESHOLD", "TSG_SEMANTIC_MATCH_THRESHOLD"))
    reranker_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("RERANKER_PROVIDER", "TSG_RERANKER_PROVIDER"))
    # How many local AI models (embedding + reranker, combined) can be kept loaded
    # in memory at once. Only matters if the model in use changes at runtime — most
    # deployments use one of each and never need to raise this.
    local_model_cache_size: int = 4

    # --- Grounding: two-band routing on the 0-100 reranker score ---
    # "Grounding" means checking whether a threat the AI just invented actually
    # matches something real in the organization's approved threat library, instead
    # of just taking the AI's word for it.
    #
    # These two cutoffs (0-100 scale) decide how much to trust an AI-proposed
    # threat's match: below the lower number, it's flagged as unmatched; between
    # the two, it's a probable match that still gets a second look from a human;
    # at or above the higher number, it's automatically accepted as confirmed.
    grounding_confirm_threshold: float = 60.0
    grounding_grounded_threshold: float = 75.0
    # How many of the closest-matching library entries get a more careful second
    # check by the reranker model, out of everything that was even considered.
    grounding_shortlist_k: int = 10

    # --- Threat proposal volume ---
    # The most candidate threats the AI is asked to propose for one supporting system in a
    # single call, so the same context doesn't yield a wildly different-sized list from one
    # run to the next. 12 (~2 per STRIDE category) is a reasoned starting point, not derived
    # from real usage data — this deployment's threat library is empty as of writing, so
    # there's no "typical" proposal count to measure yet. Tune this once real data exists.
    max_threats_per_subsystem: int = 12

    # --- Threat-scoping selection cutoff ---
    # Once threats have been matched against the library, these two settings decide
    # which ones are actually worth writing a full, detailed scenario for — not
    # every matched threat gets one. Both default to None, meaning no cutoff is
    # applied and every threat that passes the other checks stays selected.
    #
    # A threat scoring below this number doesn't get a scenario written for it at all.
    scoping_score_threshold: float | None = None
    # Only the highest-scoring N threats get a scenario written; anything past the
    # top N is skipped.
    scoping_top_n: int | None = None

    # --- Concurrency / admission control ---
    # The most sessions the app will process at the same time. Once this many are
    # already running, a new request is turned away with a "try again shortly"
    # response instead of piling on more work than the system can handle.
    max_active_sessions: int = 100
    # How many seconds to tell a client to wait before trying again, when a new
    # session is rejected because the system is at capacity.
    capacity_retry_after_seconds: int = 10
    # How long a single step of work is allowed to run before the background
    # cleanup job (the "reaper") assumes the worker doing it has crashed and steps
    # in to fix it.
    stage_lease_seconds: int = 300
    # How often (in seconds) the reaper checks for crashed/stuck sessions and fixes
    # them so they don't stay stuck forever.
    reaper_interval_seconds: float = 60.0
    # How often (in seconds) a separate background check looks for early warning
    # signs of trouble (see the five settings right below) and logs a warning if it
    # finds any. Slower than the reaper on purpose — these are slow-moving signals,
    # not crashes that need catching within a minute.
    self_check_interval_seconds: float = 300.0
    # How much space (in MB) SQL Server's tempdb "version store" is allowed to use
    # before this app warns that it's worth a look. This store holds a copy of every
    # row a write changes, kept around until the oldest still-open read finishes —
    # under sustained write load, or a read transaction that's open for a long time,
    # it can grow large enough to fill tempdb and affect the whole SQL Server
    # instance, not just this app's database.
    tempdb_version_store_warn_mb: int = 1024
    # How many seconds a read transaction is allowed to stay open before this app
    # warns about it — a long-open read is exactly what lets the tempdb version
    # store above keep growing instead of shrinking back down.
    tempdb_long_txn_warn_seconds: int = 300
    # How close to the max_active_sessions ceiling (above) the app has to get before
    # it's worth a warning — e.g. 0.9 means "warn once 90% of the ceiling is in use,"
    # so an operator has some runway before requests actually start getting rejected.
    active_sessions_warn_ratio: float = 0.9
    # Same idea as active_sessions_warn_ratio, but for the database connection pool
    # (db_pool_size + db_max_overflow, above) instead of the session ceiling — warns
    # once the pool is close to fully checked-out, before requests actually start
    # queuing for a free connection.
    pool_utilization_warn_ratio: float = 0.9
    # A safety cap on how many times the same piece of work can be picked up again
    # (e.g. after a crash) before it's given up on for good — so one permanently
    # broken piece of work can never be retried forever. This is separate from
    # llm_max_retries above: that one bounds retries of a single AI call within one
    # attempt, while this bounds how many times the whole attempt itself gets
    # redone after crashing partway through.
    stage_max_attempts: int = 5
    # How often (in seconds) a small "still here" signal is sent to a browser
    # watching a session's live updates, so the connection doesn't get dropped for
    # looking idle.
    sse_ping_seconds: int = 15
    # After a live-update message fails to send (e.g. the live-update server is
    # briefly down), how many seconds to stop trying before attempting to send
    # updates again — so one slow/down live-update server can never repeatedly
    # stall the pipeline.
    sse_breaker_cooldown_seconds: float = 30.0
    # How many seconds a background worker waits for the live-update server to
    # respond when sending one update, before giving up. Kept short on purpose so a
    # slow live-update server never stalls the actual AI pipeline work.
    sse_publish_timeout_seconds: float = 1.0
    # How many seconds the API waits when a browser connects to watch a session's
    # live updates, before giving up on reaching the live-update server.
    sse_subscribe_connect_timeout_seconds: float = 2.0

    # --- JWT: resource server, validate only — no issuing ---
    # This app never creates its own login tokens — it only checks tokens that some
    # other login system (the organization's SSO) already issued, to confirm a
    # request is really coming from a logged-in, authorized user.
    #
    # Which login system is allowed to have issued the token — a token from anyone
    # else is rejected.
    jwt_issuer: str = ""
    # Which application the token was meant for — makes sure a token issued for a
    # different app can't be reused here.
    jwt_audience: str = ""
    # Where to fetch the public keys used to verify a token's signature is genuine
    # and hasn't been tampered with.
    jwt_jwks_url: str = ""
    # Which cryptographic signing methods are trusted when checking a token's signature.
    jwt_algorithms: tuple[str, ...] = ("RS256",)
    # The name of the field inside the login token that lists which
    # organizations/entities this user is allowed to access.
    jwt_entities_claim: str = "entities"
    # DEV ONLY — bypass JWT and read entities from the X-Dev-Entities header
    # instead. Default off; never enable in production (the app logs a loud
    # warning if it is on, and refuses to start at all in staging/prod).
    auth_dev_mode: bool = Field(False, validation_alias=AliasChoices("AUTH_DEV_MODE", "TSG_AUTH_DEV_MODE"))


@lru_cache
def get_settings() -> Settings:
    """Hands back the one shared settings object every part of the app should
    read from, instead of each part re-reading the environment separately.
    Cached, so it's only built once; used both as a FastAPI dependency and
    imported directly by Celery workers."""
    return Settings()


def assert_security_posture(settings: Settings | None = None) -> None:
    """A safety check run when the app starts up in a real (staging/production)
    environment: refuses to start at all if the developer-only auth bypass is
    still turned on. Called from both the API startup and the Celery worker
    startup, so a misconfigured production process can never come up running."""
    s = settings or get_settings()
    prod_like = s.app_env in ("staging", "prod")
    if s.auth_dev_mode and prod_like:
        raise RuntimeError(
            f"AUTH_DEV_MODE is enabled but APP_ENV={s.app_env}. The dev auth bypass is only allowed "
            "when APP_ENV is 'dev' or 'local'. Refusing to start.")
