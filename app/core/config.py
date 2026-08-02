"""Application configuration. Every setting is read from the environment (via a .env file),
never hard-coded elsewhere. One shared Settings object is used everywhere: injected in the API,
and imported directly by Celery workers.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _env_file() -> str:
    """Which .env file to load — `TSG_ENV_FILE` if set, else the default `.env`.

    Without this, `env_file=".env"` was the ONLY file pydantic-settings ever read, so an
    environment-specific file (`.env.uat`, `.env.prod`) was inert: a UAT host with a perfectly
    correct `.env.uat` silently ran whatever was in `.env` instead — dev provider, dev model, dev
    dimensions, and AUTH_DEV_MODE on. Nothing errored; it was just the wrong environment.

    Fails LOUDLY when TSG_ENV_FILE names a file that does not exist: a typo'd path must never
    fall back to `.env`, because that fallback IS the failure mode this exists to remove.
    (Real environment variables — a K8s ConfigMap/Secret, docker compose `env_file:` — still take
    priority over any file, so this only matters where the app reads a file at all.)"""
    chosen = os.environ.get("TSG_ENV_FILE", "").strip()
    if not chosen:
        return ".env"
    if not Path(chosen).is_file():
        raise RuntimeError(
            f"TSG_ENV_FILE={chosen!r} does not exist (cwd={Path.cwd()}) — refusing to fall back "
            "to .env, which would silently start this deployment on another environment's config")
    return chosen


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TSG_", env_file=_env_file(), extra="ignore", populate_by_name=True)

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

    # --- Live threat intel (open feeds cached in Mongo 'threat_intel'; enrichment is fail-open) ---
    # Master switch for the daily intel-refresh beat task (app/intel/fetchers.py).
    intel_enabled: bool = False

    # Cache TTL: items STILL present in a feed get their timestamp refreshed on every run and
    # never expire; TTL only purges items a feed has dropped (or a whole decommissioned feed).
    intel_ttl_days: int = 30

    # How often the beat task refreshes all enabled feeds (default: daily).
    intel_refresh_interval_seconds: int = 86400

    # CISA Known Exploited Vulnerabilities — actively exploited CVEs (IT + OT), no auth.
    intel_kev_enabled: bool = True
    intel_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # CISA ICS advisories — the primary live OT intel source, no auth. Read from CISA's
    # official CSAF mirror on GitHub (cisagov/CSAF): www.cisa.gov's own RSS endpoint
    # bot-blocks non-browser TLS stacks (Akamai 403), the mirror serves identical data.
    intel_ics_advisories_enabled: bool = True
    intel_ics_advisories_url: str = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv"

    # URLhaus recent malicious URLs (IOC feed; cached but not used in prompt enrichment).
    intel_urlhaus_enabled: bool = False
    intel_urlhaus_url: str = "https://urlhaus.abuse.ch/downloads/json_recent/"

    # AlienVault OTX pulses — requires a free API key; the fetcher is skipped while the key is empty.
    intel_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "TSG_INTEL_OTX_API_KEY"))
    intel_otx_url: str = "https://otx.alienvault.com/api/v1/pulses/subscribed"

    # Generic TAXII 2.1 sources — JSON list like
    # [{"label": "org-opencti", "url": "https://cti.example.org/taxii2/root/", "collection": "<id>"}].
    # Empty = none. An org OpenCTI/MISP instance later is one entry here, no code change.
    intel_taxii_servers: str = ""

    # --- LLM provider (which AI service handles chat, and its credentials) ---
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

    # litellm proxy connection — only used when llm_provider=litellm_proxy.
    # Address of the litellm proxy, used when LLM_PROVIDER=litellm_proxy.
    litellm_base_url: str = "http://localhost:4000"

    # Key used to authenticate with the litellm proxy.
    litellm_api_key: str = "sk-local"

    # Optional ALTERNATE header to carry that key, e.g. "x-litellm-api-key".
    # Empty (default) = standard `Authorization: Bearer <key>`, which is what litellm expects.
    # Set this when the proxy sits behind a gateway that consumes/rewrites `Authorization`
    # before litellm ever sees it — the symptom is a 401 from every call even though the same
    # key works with `x-litellm-api-key` (confirmed against the UAT proxy). The key is sent in
    # BOTH headers when this is set, so it works either side of such a gateway.
    litellm_api_key_header: str = Field(
        "", validation_alias=AliasChoices("LITELLM_API_KEY_HEADER", "TSG_LITELLM_API_KEY_HEADER"))

    # --- LLM behaviour (chat model + tuning, all providers) ---
    # Chat model to use (litellm proxy or plain OpenAI only — Azure uses a deployment name instead).
    inference_model: str = "gpt-5"

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

    # --- Embedding & reranker (models + providers) ---
    # Embedding model — a model name (proxy) or a local file path (EMBEDDING_PROVIDER=local).
    embedding_model: str = Field(
        "multilingual-e5-large", validation_alias=AliasChoices("EMBEDDING_MODEL", "TSG_EMBEDDING_MODEL"))
    # Reranker model — same rule as embedding_model.
    reranker_model: str = Field(
        "bge-reranker-v2-m3", validation_alias=AliasChoices("RERANKER_MODEL", "TSG_RERANKER_MODEL"))
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

    # --- Local model runtime (only used when embedding/reranker provider = 'local') ---
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
    # These cutoffs are MODEL-SPECIFIC. Leave them UNSET (the normal case): the app then
    # auto-calibrates a pair for the configured embedding+reranker models from the live threat
    # library and stores it per model pair, so a model change can never silently run on numbers
    # tuned for a different model (grounding.resolve_thresholds). Setting either one explicitly
    # in env pins BOTH to these static values and disables auto-calibration — the manual escape
    # hatch, e.g. after a labelled run of scripts/calibrate_grounding.py.
    grounding_confirm_threshold: float = 60.0
    grounding_grounded_threshold: float = 75.0
    # How many of the closest-matching library entries get a closer, second-pass check.
    grounding_shortlist_k: int = 10

    # --- Step 4: control library mapping (control_mapping.map_controls / grounding.ground_control_queries) ---
    # Most controls kept per scenario ("up to K", never padded with weak matches) — also the
    # cap on how many control suggestions the scenario prompt asks the LLM for.
    control_map_top_k: int = Field(5, ge=1)
    # A suggestion whose best library match reranks below the cutoff is dropped — the LLM's
    # idea has no good library counterpart, and force-fitting the least-bad control is worse
    # than an honest empty list. LEAVE UNSET (the normal case): the effective cutoff then
    # follows the per-(embedding, reranker)-pair CONFIRM threshold grounding.resolve_thresholds
    # maintains, so a model swap in UAT/prod re-derives it automatically. Setting this in env
    # pins a static cutoff instead (control_mapping._min_score) — the manual escape hatch.
    control_map_min_score: float = Field(60.0, ge=0.0, le=100.0)
    # How many remote rerank calls llm.rerank_many runs at once (LOCAL politeness cap only —
    # every call still acquires its own _llm_slot, so the Redis semaphore stays the global
    # authority; excess workers just wait there). Irrelevant for the local reranker, which
    # batches all pairs into one model dispatch instead.
    rerank_concurrency: int = Field(8, ge=1)

    # --- Threat proposal volume ---
    # Most candidate threats the AI can propose for ONE ASSET in a single call (asset-centric
    # restructure — this used to be per supporting system; `TSG_MAX_THREATS_PER_SUBSYSTEM` still
    # works as a back-compat env var, but now bounds the per-asset count).
    max_threats_per_asset: int = Field(
        10, validation_alias=AliasChoices("TSG_MAX_THREATS_PER_ASSET", "TSG_MAX_THREATS_PER_SUBSYSTEM"))

    # --- Threat-scoping selection cutoff ---
    # A threat scoring below this doesn't get a full scenario written for it.
    scoping_score_threshold: float | None = Field(55.0, ge=0.0, le=100.0)

    # Only the highest-scoring N unique threats get a scenario written. None = no limit.
    # 5 scenarios from 10 candidates = 2x headroom, so catalogue-dedup reliably still hits 5.
    scoping_top_n: int | None = Field(5, ge=1)

    # --- Threat-library import (admin) ---
    # Max size of an uploaded library file (POST /v1/tsg/threat-library/import's
    # file_content), in MB. Real ATT&CK/CAPEC STIX bundles run tens of MB, so the
    # default is deliberately generous, not tight.
    threat_library_import_max_upload_mb: int = Field(50, ge=1)

    # --- Session capacity limits ---
    # Most sessions the app processes at the same time. New requests are rejected past this.
    max_active_sessions: int = 100

    # Most sessions any ONE entity can have active at once. 0 (default) = no per-entity cap,
    # only the global max_active_sessions above applies. Without this, one entity creating
    # sessions in a loop can exhaust the entire global ceiling for every other entity in the
    # same tenant — this bounds that blast radius to a deliberate, reportable event instead.
    max_active_sessions_per_entity: int = 0

    # How many seconds to tell a client to wait before retrying, when the app is at capacity.
    capacity_retry_after_seconds: int = 10

    # --- LLM concurrency slots (shared across all workers via Redis) ---
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

    # --- Stage lease, reaper & retries ---
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

    # Most times a crashed piece of work can be retried before it's given up on for good.
    stage_max_attempts: int = 5

    # --- Health monitoring / self-check ---
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

    # --- SSE (live session updates to the browser) ---
    # How often a "still here" signal is sent to a browser watching a session live.
    sse_ping_seconds: int = 15

    # After a live-update fails to send, how long to pause before trying again.
    sse_breaker_cooldown_seconds: float = 30.0

    # How long a background worker waits for the live-update server to respond.
    sse_publish_timeout_seconds: float = 1.0

    # How long the API waits when a browser connects to watch a session live.
    sse_subscribe_connect_timeout_seconds: float = 2.0

    # --- Admin API ---
    # Secret key that unlocks the admin-only threat-library endpoints. Empty (default) = disabled.
    admin_api_key: str = Field(
        "", validation_alias=AliasChoices("ADMIN_API_KEY", "TSG_ADMIN_API_KEY"))

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
        """scoping_top_n (scenarios written) can never exceed max_threats_per_asset (threats
        the AI is even allowed to propose) — the pipeline can't write more UNIQUE scenarios than it
        identifies threats. Hard-fail at startup on that inversion. Also emit a startup WARNING (not
        an error) when the headroom is thin (< 1.25x candidates per target scenario): catalogue
        dedup can then under-shoot scoping_top_n when the model repeats itself, and the operator
        should widen the gap. The gap IS the headroom knob — no separate setting. (tasks.write_
        scenarios additionally clamps min(scoping_top_n, max_threats_per_asset) at runtime.)"""
        top_n = self.scoping_top_n
        if top_n is None:
            return self
        if top_n > self.max_threats_per_asset:
            raise ValueError(
                f"scoping_top_n ({top_n}) exceeds max_threats_per_asset "
                f"({self.max_threats_per_asset}) — the pipeline can never write more unique "
                "scenarios than it identifies threats. Lower scoping_top_n or raise "
                "max_threats_per_asset.")
        if self.max_threats_per_asset < top_n * 1.25:
            # Lazy import avoids a config<->logging import cycle (logging imports config); by the
            # time any Settings() is built, both modules are fully defined.
            from app.core.logging import get_logger
            get_logger(__name__).warning(
                "config.thin_dedup_headroom", scoping_top_n=top_n,
                max_threats_per_asset=self.max_threats_per_asset,
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

    @model_validator(mode="after")
    def _validate_llm_slot_heartbeat_margin(self) -> "Settings":
        """llm_slot_heartbeat_seconds must stay comfortably below llm_slot_stale_after_seconds —
        _llm_slot's heartbeat thread only renews a ticket every `heartbeat` seconds (its first
        renewal fires AFTER the first full interval, not before), so a still-legitimately-running
        call can have its ticket pruned by another caller's staleness check before ever renewing
        once, if the two settings are too close together. Same class of safety floor as
        _derive_stage_lease_seconds above, applied to this setting pair instead."""
        if self.llm_slot_stale_after_seconds < self.llm_slot_heartbeat_seconds * 2:
            raise ValueError(
                f"llm_slot_stale_after_seconds ({self.llm_slot_stale_after_seconds}s) is too close "
                f"to llm_slot_heartbeat_seconds ({self.llm_slot_heartbeat_seconds}s) — a still-"
                "running call's ticket could be pruned before its first heartbeat renews it. "
                "Keep stale_after at least 2x heartbeat.")
        return self

    @model_validator(mode="after")
    def _validate_grounding_threshold_order(self) -> "Settings":
        """grounding_confirm_threshold must stay below grounding_grounded_threshold —
        grounding.label_match_from_score checks the grounded threshold FIRST, so an inverted pair
        would silently make the confirm band unreachable (every score that should land "confirm"
        would instead be classified "grounded" and auto-accepted with no human review)."""
        if self.grounding_confirm_threshold >= self.grounding_grounded_threshold:
            raise ValueError(
                f"grounding_confirm_threshold ({self.grounding_confirm_threshold}) must be lower "
                f"than grounding_grounded_threshold ({self.grounding_grounded_threshold}) — "
                "otherwise the 'confirm' band becomes unreachable.")
        return self


@lru_cache
def get_settings() -> Settings:
    """The one shared settings object every part of the app reads from. Built once, then reused."""
    return Settings()


def assert_security_posture(settings: Settings | None = None) -> None:
    """Startup safety check: with AUTH_DEV_MODE on, skip every check below (there is no login to
    verify) so it works as a deliberate opt-in outside dev too; with it off, staging/prod still
    require JWT verification to be fully configured."""
    s = settings or get_settings()
    if s.auth_dev_mode:
        return
    prod_like = s.app_env in ("staging", "prod")
    if prod_like:
        # security.validate_jwt already fails closed per-request on a missing issuer/audience,
        # but an unset JWKS URL only surfaces as every request 401-ing on a key fetch of "".
        # Fail at boot instead, naming exactly which env vars are missing.
        missing = [env for env, value in (("TSG_JWT_JWKS_URL", s.jwt_jwks_url),
                                        ("TSG_JWT_ISSUER", s.jwt_issuer),
                                        ("TSG_JWT_AUDIENCE", s.jwt_audience)) if not value]
        if missing:
            raise RuntimeError(
                f"APP_ENV={s.app_env} requires JWT verification to be fully configured; "
                f"missing: {', '.join(missing)}. Refusing to start.")
