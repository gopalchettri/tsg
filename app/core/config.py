"""Application configuration — 12-factor, environment-driven (SDD §13, §14).

Every tunable — grounding thresholds, model timeouts, DB pool sizes, the
concurrency ceiling — lives here and is read from the environment, never as an
inline constant (SDD §8.4 says the cut-offs "live in config, not constants";
§12 says the NFR targets are configurable). One cached Settings instance is
injected via FastAPI `Depends(get_settings)` and imported by Celery workers.
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
    # A label identifying which single customer/organization this whole app
    # instance serves. TSG only supports one at a time today, so this is
    # mostly for record-keeping (it gets stamped onto every row this app writes).
    tenant_id: str = "DESC"

    # Deployment environment. 'staging'/'prod' are FAIL-CLOSED: they refuse to boot with
    # authentication bypassed or the asset↔entity binding disabled (assert_security_posture).
    app_env: Literal["local", "dev", "staging", "prod"] = Field(
        "prod", validation_alias=AliasChoices("APP_ENV", "TSG_APP_ENV"))
    # How much detail gets written to the application logs. Use DEBUG when troubleshooting
    # a problem locally (very detailed, noisy); use INFO or WARNING in production so logs
    # stay small and readable.
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO", validation_alias=AliasChoices("LOG_LEVEL", "TSG_LOG_LEVEL"))

    # --- Database: existing MSSQL TSG (reuse, do not recreate) ---
    # The single line that tells the app which SQL Server database to connect
    # to, and how — server address, driver, and credentials/trust settings are
    # all bundled together into this one connection string.
    db_dsn: str = (
        "mssql+pyodbc://@XWF8TNJR3\SQLEXPRESS/TSG?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes"  # noqa: E501
    )
    # Asset↔entity ownership binding Modes:
    #   'service' (default) — asset.(asset_service_column) → onboarding_service_entity.service_id → group_id
    #   'none'              — skip (dev/local only; assert_security_posture blocks it in staging/prod)
    asset_entity_binding: Literal["service", "none"] = Field(
        "service", validation_alias=AliasChoices("ASSET_ENTITY_BINDING", "TSG_ASSET_ENTITY_BINDING"))
    asset_service_column: str = Field(  # ctm_scan_entity column → onboarding_service_entity.service_id
        "tier1_critical_service_id",
        validation_alias=AliasChoices("ASSET_SERVICE_COLUMN", "TSG_ASSET_SERVICE_COLUMN"))
    # A "connection pool" is a small set of already-open connections to the database
    # that the app reuses instead of opening a brand-new one for every single request
    # (opening a fresh connection each time would be slow). `db_pool_size` is how many
    # stay open normally; `db_max_overflow` is how many EXTRA can be opened temporarily
    # under heavy load; `db_pool_timeout` is how many seconds a request will wait for a
    # free connection before giving up.
    #
    # Pool sizing is deliberate: (api_replicas + workers) × (pool_size + max_overflow)
    # must stay under the MSSQL connection cap (SDD concurrency spine / [R14]).
    db_pool_size: int = 5
    db_max_overflow: int = 5
    db_pool_timeout: int = 30

    # --- Redis: live-update pub/sub + cache. Celery broker/backend may be separate DBs. ---
    # The address of the Redis server used both for sending live session updates
    # to the browser, and as the queue background workers pull jobs from.
    redis_url: str = Field(
        "redis://127.0.0.1:6379/0", validation_alias=AliasChoices("REDIS_URL", "TSG_REDIS_URL"))
    # Optional: use a different Redis server (or a different database number on the
    # same one) just for the background job queue, instead of sharing the one above.
    celery_broker_url: str = Field(  # falls back to redis_url if unset
        "", validation_alias=AliasChoices(
            "CELERY_BROKER_URL", "TSG_CELERY_BROKER_URL", "TSG_REDIS_CELERY_BROKER_URL"))
    # Optional: where the result of each finished background job gets stored
    # temporarily so it can be checked later. Same fallback behavior as above.
    celery_result_backend: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_RESULT_BACKEND", "TSG_CELERY_RESULT_BACKEND", "TSG_REDIS_CELERY_RESULT_BACKEND"))
    # How long a finished job's result is kept around before it's automatically
    # deleted, so this storage doesn't grow forever.
    result_expires_seconds: int = 3600  # cap result-backend growth under load

    # --- MongoDB: master-library embeddings (SDD §7.6) ---
    # The address of the MongoDB database used to cache AI-generated vectors, so
    # the exact same text is never sent to the AI model to be converted twice.
    mongo_url: str = "mongodb://localhost:27017"
    # Which database name inside that MongoDB server to use.
    mongo_db: str = "tsg"
    # How many milliseconds to wait when first connecting to the MongoDB database that
    # stores cached AI vectors, before giving up and treating it as unreachable.
    mongo_connect_timeout_ms: int = 3000

    # --- litellm proxy: all models reached here (SDD §8.1) ---
    # In plain English: "litellm" is a small routing service some deployments use
    # so the app can talk to different AI providers (Azure, OpenAI, others) through
    # one consistent interface, without the app itself needing to know the details
    # of each provider's API.
    #
    # The web address of that AI-routing service, used when LLM_PROVIDER=litellm_proxy
    # (or for embeddings/reranking when their own provider setting is litellm_proxy).
    litellm_base_url: str = "http://localhost:4000"
    # The password/key used to authenticate with that AI-routing service.
    litellm_api_key: str = "sk-local"
    # Which AI model name to ask the routing service for (e.g. "gpt-5") — only used
    # on the litellm-proxy or plain-OpenAI paths, not the Azure path (which uses its
    # own "deployment name" instead, below).
    inference_model: str = "gpt-5"
    embedding_model: str = Field(  # name (proxy) OR local path when EMBEDDING_PROVIDER=local
        "multilingual-e5-large", validation_alias=AliasChoices("EMBEDDING_MODEL", "TSG_EMBEDDING_MODEL"))
    reranker_model: str = Field(  # name (proxy) OR local path when RERANKER_PROVIDER=local
        "bge-reranker-v2-m3", validation_alias=AliasChoices("RERANKER_MODEL", "TSG_RERANKER_MODEL"))
    # How many seconds to wait for the AI to reply before giving up on that one call.
    llm_timeout_seconds: float = 90.0  # per-call timeout so a hung call fails fast
    # How many times to automatically retry a single AI call if it fails for a
    # temporary reason (like a brief network hiccup), before giving up entirely.
    llm_max_retries: int = 3           # bounded, transient-only
    # API-enforced JSON output (response_format={"type":"json_object"}). Default OFF:
    # the litellm fallback route (glm-5) may not support the param, and an unsupported
    # provider would fail EVERY call deterministically — enable per-provider after a
    # smoke test. # ponytail: single flag, not a per-provider capability matrix.
    llm_json_mode: bool = Field(False, validation_alias=AliasChoices("LLM_JSON_MODE", "TSG_LLM_JSON_MODE"))
    # Optional operator-pinned sampling temperature (0.0-2.0, litellm/OpenAI/Azure valid
    # range). Default None: no-op unless LLM_TEMPERATURE is explicitly set — lets litellm/
    # provider decide.
    llm_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices("LLM_TEMPERATURE", "TSG_LLM_TEMPERATURE"))
    # Optional operator-pinned reasoning effort for reasoning-capable models (e.g. gpt-5).
    # Default None: no-op unless LLM_REASONING_EFFORT is explicitly set — lets litellm/
    # provider decide.
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        None, validation_alias=AliasChoices("LLM_REASONING_EFFORT", "TSG_LLM_REASONING_EFFORT"))

    # --- LLM provider (INFERENCE only — swap via .env, no code change).
    # Aliases accept the exact platform env names AND the TSG_ forms. Embeddings +
    # reranker are NOT swapped here (Azure has no reranker; grounding needs it).
    llm_provider: Literal["litellm_proxy", "azure_openai", "openai"] = Field(  # default Azure; .env-configurable
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
    # Which version of Azure's API format to speak — Azure periodically introduces
    # new versions; this pins a known-working one so nothing changes underneath us.
    azure_openai_api_version: str = Field(
        "2024-12-01-preview", validation_alias=AliasChoices("AZURE_OPENAI_API_VERSION", "TSG_AZURE_OPENAI_API_VERSION"))
    # Credentials for calling OpenAI directly instead of through Azure or the
    # litellm proxy — only used when LLM_PROVIDER=openai.
    openai_api_key: str = Field("", validation_alias=AliasChoices("OPENAI_API_KEY", "TSG_OPENAI_API_KEY"))
    openai_base_url: str = ""

    # --- Embedding & reranker providers (independent of LLM_PROVIDER).
    # 'local' loads the model from disk in-process (no network) via sentence-transformers;
    # 'litellm_proxy' calls the proxy / TEI. `embedding_model`/`reranker_model` above hold
    # the local path when the provider is 'local'.
    embedding_provider: Literal["litellm_proxy", "local"] = Field(  # default local; .env-configurable
        "local", validation_alias=AliasChoices("EMBEDDING_PROVIDER", "TSG_EMBEDDING_PROVIDER"))
    embedding_dimensions: int = Field(
        1024, validation_alias=AliasChoices("EMBEDDING_DIMENSIONS", "TSG_EMBEDDING_DIMENSIONS"))
    # Where master-library vectors persist (§7.6): 'mongo' (default, survives restarts / shared
    # across workers) or 'memory' (process-local only). A Mongo outage degrades to memory.
    embedding_store: Literal["memory", "mongo"] = Field(
        "mongo", validation_alias=AliasChoices("EMBEDDING_STORE", "TSG_EMBEDDING_STORE"))
    # e5 models need query:/passage: prefixes; 'auto' = apply when the model name looks like e5.
    embedding_prefix_style: Literal["auto", "e5", "none"] = Field(
        "auto", validation_alias=AliasChoices("EMBEDDING_PREFIX_STYLE", "TSG_EMBEDDING_PREFIX_STYLE"))
    # How similar (on a 0-to-1 scale) an AI-generated threat has to be to an entry in
    # the threat library before it's even considered a possible match — below this,
    # it's not shortlisted for a closer look at all.
    semantic_match_threshold: float = Field(  # cosine floor for candidate shortlisting (§8.4)
        0.60, validation_alias=AliasChoices("SEMANTIC_MATCH_THRESHOLD", "TSG_SEMANTIC_MATCH_THRESHOLD"))
    reranker_provider: Literal["litellm_proxy", "local"] = Field(  # default local; .env-configurable
        "local", validation_alias=AliasChoices("RERANKER_PROVIDER", "TSG_RERANKER_PROVIDER"))
    # How many different local AI models (embedding + relevance-scoring models, combined)
    # can be kept loaded in memory at once. Only matters if the model in use is changed
    # at runtime; most deployments use one of each and never need to raise this.
    local_model_cache_size: int = 4

    # --- Grounding: two-band routing on the 0–100 reranker score (SDD §8.4) ---
    # In plain English: "grounding" means checking whether a threat the AI just
    # invented actually matches something real in the organization's approved
    # threat library — like double-checking a claim against a trusted source
    # instead of just taking the AI's word for it.
    #
    # These two numbers (0-100 scale) are the match-confidence cutoffs that decide
    # how much to trust an AI-proposed threat's match: below the lower number, it's
    # flagged as unmatched; between the two, it's a probable match that still gets
    # a second look from a human; above the higher number, it's automatically
    # accepted as a confirmed match.
    grounding_confirm_threshold: float = 60.0   # 60–75 → confirm
    grounding_grounded_threshold: float = 75.0  # ≥75 → grounded (auto-accept match)
    # How many of the closest-matching library entries get a more careful second
    # check (by the "reranker" model), out of everything that was even considered.
    grounding_shortlist_k: int = 10

    # --- Threat-scoping selection cutoff (SDD §5.4 step 3, [R12]) — "lives in config,
    # not constants". Both None (default) = no cutoff: every gate-passing threat stays
    # selected, exactly the pre-R12 behavior. tech_gate exclusions apply regardless.
    #
    # In plain English: once threats have been matched against the library, these two
    # settings decide which ones are actually worth writing a full, detailed scenario
    # for — not every possible threat gets one.
    # A threat scoring below this number is not written up as a scenario at all.
    # Leave unset (None) to disable this cutoff entirely.
    scoping_score_threshold: float | None = None  # Selected=0 below this Score
    # Only the highest-scoring N threats get written up as full scenarios; everything
    # past the top N is skipped. Leave unset (None) to disable this cutoff entirely.
    scoping_top_n: int | None = None              # keep only the N best-ranked selected

    # --- Concurrency / admission control ---
    # The most sessions the app will process at the same time. Once this many are
    # already running, a brand-new request is turned away (with a "try again
    # shortly" response) instead of piling on more work than the system can handle.
    max_active_sessions: int = 100        # backpressure ceiling (503, M2)
    # How many seconds to tell a client to wait before trying again, when a new session
    # is rejected because the system is at capacity (paired with max_active_sessions above).
    capacity_retry_after_seconds: int = 10
    # How long a single step of work is allowed to run before the background cleanup
    # job (the "reaper") assumes the worker doing it has crashed and steps in to fix it.
    stage_lease_seconds: int = 300        # reaper lease for RUNNING / _LOCK rows
    # How often (in seconds) the background cleanup job (the "reaper") checks for
    # crashed/stuck sessions and fixes them so they don't stay stuck forever.
    reaper_interval_seconds: float = 60.0
    # A safety cap on how many times the same piece of work can be picked up again
    # (e.g. after a crash) before it's given up on for good, so one permanently-broken
    # piece of work can never be retried forever.
    #
    # poison-terminal: a stage-claim attempt budget distinct from llm_max_retries
    # (that bounds transient LLM retries WITHIN one attempt; this bounds stage-claim
    # attempts ACROSS Celery redeliveries — a worker that crashes the whole process
    # before a caught exception can fire re-claims with a fresh lease every time, so
    # the reaper's expired-lease sweep never sees it as abandoned without this cap).
    stage_max_attempts: int = 5
    # How often (in seconds) a small "still here" signal is sent to a browser
    # watching a session's live updates, so the connection doesn't get dropped
    # for looking idle.
    sse_ping_seconds: int = 15
    # After a live-update message fails to send (e.g. the live-update server is briefly
    # down), how many seconds to stop trying before attempting to send live updates
    # again — so one slow/down live-update server can never repeatedly stall the pipeline.
    sse_breaker_cooldown_seconds: float = 30.0
    # How many seconds a background worker waits for the live-update server to respond
    # when sending one update, before giving up. Kept short on purpose so a slow
    # live-update server never stalls the actual AI pipeline work.
    sse_publish_timeout_seconds: float = 1.0
    # How many seconds the API waits when a browser connects to watch a session's live
    # updates, before giving up on reaching the live-update server.
    sse_subscribe_connect_timeout_seconds: float = 2.0

    # --- JWT: resource server, validate only — no issuing (SDD §10.1) ---
    # In plain English: this app never creates its own login tokens — it only checks
    # tokens that some other login system (the organization's SSO) already issued, to
    # confirm a request is really coming from a logged-in, authorized user.
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
    jwt_entities_claim: str = "entities"  # [R2] claim holding allowed group.id list
    # DEV ONLY — bypass JWT and read entities from the X-Dev-Entities header. Default off;
    # never enable in production (the app logs a loud warning if it is on).
    auth_dev_mode: bool = Field(False, validation_alias=AliasChoices("AUTH_DEV_MODE", "TSG_AUTH_DEV_MODE"))


@lru_cache
def get_settings() -> Settings:
    """In plain English: hands back the one shared settings object every part
    of the app should read from, instead of each part re-reading the
    environment separately.

    Cached singleton; FastAPI dependency and worker import target."""
    return Settings()


def assert_security_posture(settings: Settings | None = None) -> None:
    """In plain English: a safety check that runs when the app starts up in a
    real (staging/production) environment, refusing to start at all if
    dangerous developer-only shortcuts are still turned on.

    Fail-closed startup guard: production must not run with authentication bypassed
    or the asset↔entity ownership binding disabled. Called from the API lifespan and
    the Celery worker init so a misconfigured prod process refuses to start."""
    s = settings or get_settings()
    prod_like = s.app_env in ("staging", "prod")
    if s.auth_dev_mode and prod_like:
        raise RuntimeError(
            f"AUTH_DEV_MODE is enabled but APP_ENV={s.app_env}. The dev auth bypass is only allowed "
            "when APP_ENV is 'dev' or 'local'. Refusing to start.")
    if s.asset_entity_binding == "none" and prod_like:
        raise RuntimeError(
            f"Asset↔entity ownership binding is disabled (ASSET_ENTITY_BINDING=none) but APP_ENV={s.app_env}. "
            "Use 'service' binding, or set APP_ENV=dev for local testing only. Refusing to start.")
