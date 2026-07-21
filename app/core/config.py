"""Application configuration. Every setting is read from the environment (via a .env file),
never hard-coded elsewhere. One shared Settings object is used everywhere: injected in the API,
and imported directly by Celery workers.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TSG_", env_file=".env", extra="ignore", populate_by_name=True)

    # --- Identity ---
    # Name of the customer/organization this app instance serves. TSG only supports one at a time.
    tenant_id: str = "DESC"

    # Which environment this is running in. Blocks the dev-only login bypass from running in staging/prod.
    app_env: Literal["local", "dev", "staging", "prod"] = Field(
        "prod", validation_alias=AliasChoices("APP_ENV", "TSG_APP_ENV"))
    # How much detail goes into the logs. Use DEBUG locally; INFO or WARNING in production.
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO", validation_alias=AliasChoices("LOG_LEVEL", "TSG_LOG_LEVEL"))

    # --- Database (MSSQL) ---
    # Connection string for the SQL Server database. Override with TSG_DB_DSN.
    # This default is a placeholder, not a real database — if TSG_DB_DSN is missing from .env,
    # the app fails loudly instead of silently connecting to the wrong database.
    db_dsn: str = (
        r"mssql+pyodbc://@CONFIGURE_TSG_DB_DSN_IN_ENV\SQLEXPRESS/CONFIGURE_TSG_DB_DSN_IN_ENV?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes"  # noqa: E501
    )
    # Database connection pool: how many stay open (db_pool_size), how many extra can open under
    # heavy load (db_max_overflow), and how long a request waits for a free one (db_pool_timeout).
    db_pool_size: int = 50
    db_max_overflow: int = 10
    db_pool_timeout: int = 30
    # How long to wait when opening a brand-new database connection before giving up.
    db_connect_timeout_seconds: int = 5
    # How long a single database query may run before it's cancelled.
    db_statement_timeout_seconds: int = 30

    # --- Redis (live updates + background job queue) ---
    redis_url: str = Field(
        "redis://127.0.0.1:6379/0", validation_alias=AliasChoices("REDIS_URL", "TSG_REDIS_URL"))
    # Optional: a separate Redis for the background job queue. Falls back to redis_url if unset.
    celery_broker_url: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_BROKER_URL", "TSG_CELERY_BROKER_URL", "TSG_REDIS_CELERY_BROKER_URL"))
    # Optional: where a finished job's result is stored. Same fallback as celery_broker_url.
    celery_result_backend: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_RESULT_BACKEND", "TSG_CELERY_RESULT_BACKEND", "TSG_REDIS_CELERY_RESULT_BACKEND"))
    # How long a finished job's result is kept before it's deleted.
    result_expires_seconds: int = 3600

    # --- MongoDB (caches AI-generated vectors so the same text is never processed twice) ---
    mongo_url: str = "mongodb://localhost:27017"
    mongo_db: str = "tsg_embeddings"
    # How long to wait when first connecting to MongoDB before giving up.
    mongo_connect_timeout_ms: int = 3000

    # --- litellm proxy: lets the app talk to different AI providers through one interface ---
    # Address of the litellm proxy, used when LLM_PROVIDER=litellm_proxy.
    litellm_base_url: str = "http://localhost:4000"
    # Key used to authenticate with the litellm proxy.
    litellm_api_key: str = "sk-local"
    # Chat model to use (litellm proxy or plain OpenAI only — Azure uses a deployment name instead).
    inference_model: str = "gpt-5"
    # Embedding model — a model name (proxy) or a local file path (EMBEDDING_PROVIDER=local).
    embedding_model: str = Field(
        "multilingual-e5-large", validation_alias=AliasChoices("EMBEDDING_MODEL", "TSG_EMBEDDING_MODEL"))
    # Reranker model — same rule as embedding_model.
    reranker_model: str = Field(
        "bge-reranker-v2-m3", validation_alias=AliasChoices("RERANKER_MODEL", "TSG_RERANKER_MODEL"))
    # How long to wait for an AI reply before giving up.
    llm_timeout_seconds: float = 90.0
    # How many times to retry a failed AI call before giving up.
    llm_max_retries: int = 3
    # Ask the AI to guarantee valid JSON replies. Off by default — not every provider supports it.
    llm_json_mode: bool = Field(False, validation_alias=AliasChoices("LLM_JSON_MODE", "TSG_LLM_JSON_MODE"))
    # How random/creative the AI's replies are (0 = consistent, 2 = varied). Unset = provider's default.
    llm_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices("LLM_TEMPERATURE", "TSG_LLM_TEMPERATURE"))
    # Same idea as llm_temperature, but only for the threat-identification step. Defaults to 0
    # (consistent) so the same asset gets the same list of threats each time it's run.
    threat_identification_temperature: float | None = Field(
        0.0, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "THREAT_IDENTIFICATION_TEMPERATURE", "TSG_THREAT_IDENTIFICATION_TEMPERATURE"))
    # How much "thinking effort" the AI spends per reply. Unset = provider's own default.
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        None, validation_alias=AliasChoices("LLM_REASONING_EFFORT", "TSG_LLM_REASONING_EFFORT"))

    # --- Optional safety features (litellm proxy only, both off by default) ---
    # Check every AI-generated scenario for inappropriate content before saving it. This is a
    # soft flag for a human reviewer, never a hard block — this app's whole job is describing
    # attacks and breaches, which some moderation categories would otherwise misfire on.
    llm_moderation_enabled: bool = Field(
        False, validation_alias=AliasChoices("LLM_MODERATION_ENABLED", "TSG_LLM_MODERATION_ENABLED"))
    # Which moderation model to use. Unset = let the proxy pick its default.
    llm_moderation_model: str | None = Field(
        None, validation_alias=AliasChoices("LLM_MODERATION_MODEL", "TSG_LLM_MODERATION_MODEL"))
    # Optional proxy-side safety filters (e.g. prompt-injection detectors) run on every chat call.
    # Only works with LLM_PROVIDER=litellm_proxy.
    llm_guardrails: list[str] | None = Field(
        None, validation_alias=AliasChoices("LLM_GUARDRAILS", "TSG_LLM_GUARDRAILS"))

    # --- LLM provider (which AI service handles chat) ---
    # Switch providers just by changing this — no code change needed.
    llm_provider: Literal["litellm_proxy", "azure_openai", "openai"] = Field(
        "azure_openai", validation_alias=AliasChoices("LLM_PROVIDER", "TSG_LLM_PROVIDER"))
    # Azure OpenAI credentials — only used when llm_provider=azure_openai.
    azure_openai_api_key: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_API_KEY", "TSG_AZURE_OPENAI_API_KEY"))
    azure_openai_endpoint: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_ENDPOINT", "TSG_AZURE_OPENAI_ENDPOINT"))
    azure_openai_deployment_name: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_DEPLOYMENT_NAME", "TSG_AZURE_OPENAI_DEPLOYMENT_NAME"))
    # Which version of Azure's API to use.
    azure_openai_api_version: str = Field(
        "2024-12-01-preview", validation_alias=AliasChoices("AZURE_OPENAI_API_VERSION", "TSG_AZURE_OPENAI_API_VERSION"))
    # OpenAI credentials — only used when llm_provider=openai.
    openai_api_key: str = Field("", validation_alias=AliasChoices("OPENAI_API_KEY", "TSG_OPENAI_API_KEY"))
    openai_base_url: str = ""

    # --- Embedding & reranker providers ---
    # 'local' runs the model on this machine directly; 'litellm_proxy' calls the proxy instead.
    # Leave unset to follow llm_provider automatically (see _derive_embedding_reranker_provider below).
    embedding_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("EMBEDDING_PROVIDER", "TSG_EMBEDDING_PROVIDER"))
    embedding_dimensions: int = Field(
        1024, validation_alias=AliasChoices("EMBEDDING_DIMENSIONS", "TSG_EMBEDDING_DIMENSIONS"))
    # Where generated vectors are stored: 'mongo' (default, survives restarts) or 'memory' (this
    # process only). Falls back to memory automatically if Mongo is unreachable.
    embedding_store: Literal["memory", "mongo"] = Field(
        "mongo", validation_alias=AliasChoices("EMBEDDING_STORE", "TSG_EMBEDDING_STORE"))
    # Some embedding models expect a "query:"/"passage:" prefix on their input text. 'auto' turns
    # this on automatically for e5-family models.
    embedding_prefix_style: Literal["auto", "e5", "none"] = Field(
        "auto", validation_alias=AliasChoices("EMBEDDING_PREFIX_STYLE", "TSG_EMBEDDING_PREFIX_STYLE"))
    # How similar (0 to 1) an AI-proposed threat must be to a library entry before it's even
    # considered a possible match.
    semantic_match_threshold: float = Field(
        0.60, validation_alias=AliasChoices("SEMANTIC_MATCH_THRESHOLD", "TSG_SEMANTIC_MATCH_THRESHOLD"))
    # Same "follows llm_provider unless set" rule as embedding_provider above.
    reranker_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("RERANKER_PROVIDER", "TSG_RERANKER_PROVIDER"))
    # How many local AI models can be kept loaded in memory at once.
    local_model_cache_size: int = 4
    # How many local embedding/reranker calls can run truly at once (gevent's native thread
    # pool — see local_models.py::_offload). 10 matches gevent's own built-in default; this
    # just makes it a visible, tunable setting instead of an invisible ceiling nobody can see
    # or change. Independent of Celery's own -c/--concurrency worker setting.
    local_model_threadpool_size: int = 10

    # --- Grounding: how much to trust an AI-proposed threat's match to the library (0-100 scale) ---
    # Below grounding_confirm_threshold: unmatched. Between the two: a probable match that still
    # needs a human look. At or above grounding_grounded_threshold: accepted automatically.
    grounding_confirm_threshold: float = 60.0
    grounding_grounded_threshold: float = 75.0
    # How many of the closest-matching library entries get a closer, second-pass check.
    grounding_shortlist_k: int = 10

    # --- Threat proposal volume ---
    # Most candidate threats the AI can propose for one supporting system in a single call.
    max_threats_per_subsystem: int = 15

    # --- Threat-scoping selection cutoff ---
    # A threat scoring below this doesn't get a full scenario written for it.
    scoping_score_threshold: float | None = Field(55.0, ge=0.0, le=100.0)
    # Only the highest-scoring N unique threats get a scenario written. None = no limit.
    # 5 scenarios from 15 candidates = 3x headroom, so catalogue-dedup reliably still hits 5.
    scoping_top_n: int | None = Field(5, ge=1)

    # --- Concurrency / capacity limits ---
    # Most sessions the app processes at the same time. New requests are rejected past this.
    max_active_sessions: int = 100
    # Most sessions any ONE entity can have active at once. 0 (default) = no per-entity cap,
    # only the global max_active_sessions above applies. Without this, one entity creating
    # sessions in a loop can exhaust the entire global ceiling for every other entity in the
    # same tenant — this bounds that blast radius to a deliberate, reportable event instead.
    max_active_sessions_per_entity: int = 0
    # Ceiling on concurrent AI calls across all workers, shared via Redis. 0 = no limit (default).
    max_concurrent_llm_calls: int = 0
    # How long an AI call waits for a free slot before it's rejected (and retried automatically).
    llm_slot_wait_timeout_seconds: float = 30.0
    # How often an in-progress AI call renews its "still running" signal.
    llm_slot_heartbeat_seconds: float = 10.0
    # How long without a signal before a call is assumed crashed and its slot freed up.
    llm_slot_stale_after_seconds: float = 30.0
    # Warn once in-flight AI calls get this close to max_concurrent_llm_calls.
    llm_slots_warn_ratio: float = 0.8
    # Timeout for the Redis calls used just to track AI-call slots.
    llm_slot_redis_timeout_seconds: float = 3.0
    # How many seconds to tell a client to wait before retrying, when the app is at capacity.
    capacity_retry_after_seconds: int = 10
    # Secret key that unlocks the admin-only threat-library endpoints. Empty (default) = disabled.
    admin_api_key: str = Field(
        "", validation_alias=AliasChoices("ADMIN_API_KEY", "TSG_ADMIN_API_KEY"))
    # How long one step of work can run before it's assumed crashed and cleaned up automatically.
    # Calculated automatically from llm_timeout_seconds/llm_max_retries unless set explicitly
    # (see _derive_stage_lease_seconds below).
    stage_lease_seconds: int = 300
    # How often the cleanup job checks for crashed/stuck sessions.
    reaper_interval_seconds: float = 60.0
    # How long a session with NO live lease at all (never started, or its lease already
    # cleared) must sit untouched before the cleanup job treats it as abandoned. Defaults
    # to stage_lease_seconds unless set explicitly (see _derive_reaper_stale_grace_seconds
    # below) — its own setting, not just reaper.py reading stage_lease_seconds directly, so
    # the two CAN diverge later without touching the stage CAS's own timeout floor. Plain
    # `float` (not `float | None`), same as stage_lease_seconds's own `int` default just
    # below — "was it set explicitly" is answered via `model_fields_set`, not a None sentinel,
    # so the resolved value's static type never needs to carry an Optional it can't have.
    reaper_stale_grace_seconds: float = 300.0
    # How often a background check looks for early warning signs of trouble and logs them.
    self_check_interval_seconds: float = 300.0
    # Warn once SQL Server's internal "version store" grows past this size (MB).
    tempdb_version_store_warn_mb: int = 1024
    # Warn once a database read has been open this many seconds.
    tempdb_long_txn_warn_seconds: int = 300
    # Warn once active sessions get this close to max_active_sessions.
    active_sessions_warn_ratio: float = 0.9
    # Warn once the database connection pool gets this close to full.
    pool_utilization_warn_ratio: float = 0.9
    # Most times a crashed piece of work can be retried before it's given up on for good.
    stage_max_attempts: int = 5
    # How often a "still here" signal is sent to a browser watching a session live.
    sse_ping_seconds: int = 15
    # After a live-update fails to send, how long to pause before trying again.
    sse_breaker_cooldown_seconds: float = 30.0
    # How long a background worker waits for the live-update server to respond.
    sse_publish_timeout_seconds: float = 1.0
    # How long the API waits when a browser connects to watch a session live.
    sse_subscribe_connect_timeout_seconds: float = 2.0

    # --- JWT: this app only checks login tokens issued elsewhere, never issues its own ---
    # Which login system's tokens are trusted.
    jwt_issuer: str = ""
    # Which app the token must be meant for.
    jwt_audience: str = ""
    # Where to fetch the keys used to verify a token's signature.
    jwt_jwks_url: str = ""
    # Which signing methods are trusted.
    jwt_algorithms: tuple[str, ...] = ("RS256",)
    # Field in the token that lists which organizations the user can access.
    jwt_entities_claim: str = "entities"
    # DEV ONLY — skip login checks. Off by default; the app refuses to start with this on in staging/prod.
    auth_dev_mode: bool = Field(False, validation_alias=AliasChoices("AUTH_DEV_MODE", "TSG_AUTH_DEV_MODE"))

    @model_validator(mode="after")
    def _derive_embedding_reranker_provider(self) -> "Settings":
        """If LLM_PROVIDER is set to litellm_proxy and EMBEDDING_PROVIDER/RERANKER_PROVIDER are
        left unset, both follow it automatically — one setting switches the whole deployment
        between local models and the proxy. Setting either one explicitly always overrides this."""
        if self.llm_provider == "litellm_proxy":
            if "embedding_provider" not in self.model_fields_set:
                self.embedding_provider = "litellm_proxy"
            if "reranker_provider" not in self.model_fields_set:
                self.reranker_provider = "litellm_proxy"
        return self

    @model_validator(mode="after")
    def _derive_stage_lease_seconds(self) -> "Settings":
        """If not set explicitly, calculates a safe value from llm_timeout_seconds/llm_max_retries
        (with margin) instead of using a guessed number. If set explicitly below that safe floor,
        the app refuses to start — too low a value risks the cleanup job wrongly killing a slow
        but still-running AI call."""
        floor = self.llm_timeout_seconds * (self.llm_max_retries + 1)
        if "stage_lease_seconds" not in self.model_fields_set:
            self.stage_lease_seconds = int(floor * 2)
        elif self.stage_lease_seconds < floor:
            raise ValueError(
                f"stage_lease_seconds ({self.stage_lease_seconds}s) is below the safe floor "
                f"({floor:.0f}s = llm_timeout_seconds * (llm_max_retries + 1)) — a genuinely "
                "slow (not crashed) call could be wrongly reaped. Raise it above the floor.")
        return self

    @model_validator(mode="after")
    def _bind_scenario_count_to_threat_count(self) -> "Settings":
        """scoping_top_n (scenarios written) can never exceed max_threats_per_subsystem (threats
        the AI is even allowed to propose) — the pipeline can't write more UNIQUE scenarios than it
        identifies threats. Hard-fail at startup on that inversion. Also emit a startup WARNING (not
        an error) when the headroom is thin (< 1.25x candidates per target scenario): catalogue
        dedup can then under-shoot scoping_top_n when the model repeats itself, and the operator
        should widen the gap. The gap IS the headroom knob — no separate setting. (tasks.write_
        scenarios additionally clamps min(scoping_top_n, max_threats_per_subsystem) at runtime.)"""
        top_n = self.scoping_top_n
        if top_n is None:
            return self
        if top_n > self.max_threats_per_subsystem:
            raise ValueError(
                f"scoping_top_n ({top_n}) exceeds max_threats_per_subsystem "
                f"({self.max_threats_per_subsystem}) — the pipeline can never write more unique "
                "scenarios than it identifies threats. Lower scoping_top_n or raise "
                "max_threats_per_subsystem.")
        if self.max_threats_per_subsystem < top_n * 1.25:
            # Lazy import avoids a config<->logging import cycle (logging imports config); by the
            # time any Settings() is built, both modules are fully defined.
            from app.core.logging import get_logger
            get_logger(__name__).warning(
                "config.thin_dedup_headroom", scoping_top_n=top_n,
                max_threats_per_subsystem=self.max_threats_per_subsystem,
                note="fewer than 1.25x candidate threats per target scenario — catalogue dedup "
                    "may under-shoot scoping_top_n when the model repeats threats")
        return self

    @model_validator(mode="after")
    def _derive_reaper_stale_grace_seconds(self) -> "Settings":
        """If not set explicitly, follows stage_lease_seconds (already resolved by
        _derive_stage_lease_seconds above, which runs first) — the same "how long can one
        step legitimately run" window doubles as "how long can a session sit with no lease
        at all before it's abandoned," today's actual behavior. Runs after
        _derive_stage_lease_seconds so it reads that field's DERIVED value, not its
        unresolved 300-second class default, when both are left unset."""
        if "reaper_stale_grace_seconds" not in self.model_fields_set:
            self.reaper_stale_grace_seconds = self.stage_lease_seconds
        return self


@lru_cache
def get_settings() -> Settings:
    """The one shared settings object every part of the app reads from. Built once, then reused."""
    return Settings()


def assert_security_posture(settings: Settings | None = None) -> None:
    """Startup safety check: refuses to start in staging/prod if the dev-only login bypass is on."""
    s = settings or get_settings()
    prod_like = s.app_env in ("staging", "prod")
    if s.auth_dev_mode and prod_like:
        raise RuntimeError(
            f"AUTH_DEV_MODE is enabled but APP_ENV={s.app_env}. The dev auth bypass is only allowed "
            "when APP_ENV is 'dev' or 'local'. Refusing to start.")
