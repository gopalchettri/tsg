# Application configuration. Every setting is read from the environment (via a .env file),
# never hard-coded elsewhere. One shared Settings object: injected in the API, imported
# directly by Celery workers.
#
# env_prefix="TSG_" maps each field to TSG_<FIELD_NAME uppercased>; extra spellings are listed
# via AliasChoices. Each field's comment starts with its env variable name. Keep the env files
# in sync: python -m app.core.env_selfcheck
from __future__ import annotations

import os
import socket
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# TSG_ENV_FILE if set, else .env. A missing TSG_ENV_FILE fails loudly rather than silently
# falling back to another environment's config.
def _env_file() -> str:
    chosen = os.environ.get("TSG_ENV_FILE", "").strip()
    if not chosen:
        return ".env"
    if not Path(chosen).is_file():
        raise RuntimeError(
            f"TSG_ENV_FILE={chosen!r} does not exist (cwd={Path.cwd()}) — refusing to fall back "
            "to .env, which would silently start this deployment on another environment's config")
    return chosen


# Longest control_name / control_description the API accepts (500 + ": " + 3400 fits the default
# max_embed_chars of 4000). DELIBERATELY not validated against max_embed_chars at boot: that
# coupling floored max_embed_chars at 3902; an oversized row now degrades to one skipped control.
CONTROL_NAME_MAX_CHARS = 500
CONTROL_DESCRIPTION_MAX_CHARS = 3400

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TSG_", env_file=_env_file(), extra="ignore", populate_by_name=True)

    # --- 1. Core app -----------------------------------------------------------
    application_name: str = Field(
        "Threat Scenario Generator", validation_alias=AliasChoices("APPLICATION_NAME", "TSG_APPLICATION_NAME")
    )
    application_version: str = Field(
        "1.0", validation_alias=AliasChoices("APPLICATION_VERSION", "TSG_APPLICATION_VERSION")
    )
    application_description: str = Field(
        "AI-assisted STRIDE threat identification and scenario generation for OT/IT assets",
        validation_alias=AliasChoices("APPLICATION_DESCRIPTION", "TSG_APPLICATION_DESCRIPTION")
    )

    # TSG_TENANT_ID — the customer/organization this instance serves (one at a time).
    tenant_id: str = "DESC"

    # TSG_API_MODULE — this deployment's module identity; an API_Client key authenticates ONLY
    # for its own Module. min_length guards a blank that would 401 everything.
    api_module: str = Field(
        "tsg", min_length=1, validation_alias=AliasChoices("API_MODULE", "TSG_API_MODULE"))

    # APP_ENV — deployment environment; gates dev-only routes and posture warnings.
    app_env: Literal["local", "dev", "staging", "prod"] = Field(
        "prod", validation_alias=AliasChoices("APP_ENV", "TSG_APP_ENV"))
    # LOG_LEVEL — logging verbosity.
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO", validation_alias=AliasChoices("LOG_LEVEL", "TSG_LOG_LEVEL"))
    # TRACE_SINKS — comma list of console|log|file for the step trace (app.core.tracing);
    # empty (default) = off. RESTART-ONLY: get_settings() is @lru_cache'd.
    trace_sinks: str = Field(
        "", validation_alias=AliasChoices("TRACE_SINKS", "TSG_TRACE_SINKS"))
    # TSG_TRACE_DIR — where file sinks (and log_file) write; relative = PROJECT ROOT, never CWD.
    trace_dir: str = Field(
        "logs/trace", validation_alias=AliasChoices("TRACE_DIR", "TSG_TRACE_DIR"))
    # TRACE_MAX_BYTES / TRACE_BACKUPS — rotation, PER PROCESS (files carry the writer's pid;
    # shared files rotate wrongly on Linux and never on Windows). Disk = procs x bytes x backups.
    trace_max_bytes: int = Field(
        52_428_800, ge=1024,
        validation_alias=AliasChoices("TRACE_MAX_BYTES", "TSG_TRACE_MAX_BYTES"))
    trace_backups: int = Field(
        5, ge=0, validation_alias=AliasChoices("TRACE_BACKUPS", "TSG_TRACE_BACKUPS"))
    # LOG_FILE — tee EVERY app log line into app-<pid>.jsonl under trace_dir (Promtail -> Loki).
    # Leave off in containers: stdout is already rotated there and files die with the pod.
    log_file: bool = Field(
        False, validation_alias=AliasChoices("LOG_FILE", "TSG_LOG_FILE"))

    # --- 2. Database (MSSQL) ---------------------------------------------------

    # TSG_DB_DSN — main application DB; placeholder default so a missing value fails loudly.
    db_dsn: str = (
        r"mssql+pyodbc://@CONFIGURE_TSG_DB_DSN_IN_ENV\SQLEXPRESS/CONFIGURE_TSG_DB_DSN_IN_ENV?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes"
    )

    # TSG_DB_POOL_SIZE — persistent connections per process.
    db_pool_size: int = 50
    # TSG_DB_MAX_OVERFLOW — extra connections openable under heavy load.
    db_max_overflow: int = 10
    # TSG_DB_POOL_TIMEOUT — seconds a request waits for a free connection.
    db_pool_timeout: int = 30
    # TSG_DB_CONNECT_TIMEOUT_SECONDS — TCP/login timeout for new connections.
    db_connect_timeout_seconds: int = 5
    # TSG_DB_STATEMENT_TIMEOUT_SECONDS — per-statement query timeout.
    db_statement_timeout_seconds: int = 30

    # --- 3. Redis & Celery -----------------------------------------------------

    # TSG_REDIS_URL — main Redis: SSE pub/sub, LLM slots, embedding locks.
    redis_url: str = Field(
        "redis://127.0.0.1:6379/0", validation_alias=AliasChoices("REDIS_URL", "TSG_REDIS_URL"))

    # TSG_REDIS_CELERY_BROKER_URL — the job queue; falls back to redis_url when unset.
    celery_broker_url: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_BROKER_URL", "TSG_CELERY_BROKER_URL", "TSG_REDIS_CELERY_BROKER_URL"))

    # TSG_REDIS_CELERY_RESULT_BACKEND — finished-job result store; same fallback as the broker.
    celery_result_backend: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_RESULT_BACKEND", "TSG_CELERY_RESULT_BACKEND", "TSG_REDIS_CELERY_RESULT_BACKEND"))

    # TSG_RESULT_EXPIRES_SECONDS — how long task results are kept.
    result_expires_seconds: int = 3600

    # --- 4. MongoDB (embedding cache) ------------------------------------------

    # TSG_MONGO_URL — caches AI-generated vectors so the same text is never re-embedded.
    mongo_url: str = "mongodb://localhost:27017"
    # TSG_MONGO_DB — database name (separate per environment so vectors never mix).
    mongo_db: str = "tsg_embeddings"
    # TSG_MONGO_CONNECT_TIMEOUT_MS — connection timeout.
    mongo_connect_timeout_ms: int = 3000

    # --- 5. Live threat intel (open feeds cached in Mongo; enrichment is fail-open) ---

    # TSG_INTEL_ENABLED — master switch for the daily intel-refresh task.
    intel_enabled: bool = True
    # TSG_INTEL_TTL_DAYS — purges only items a feed has DROPPED; present items never expire.
    intel_ttl_days: int = 30
    # TSG_INTEL_REFRESH_INTERVAL_SECONDS — refresh cadence (default daily).
    intel_refresh_interval_seconds: int = 86400

    # TSG_INTEL_KEV_ENABLED / _URL — CISA Known Exploited Vulnerabilities feed (no auth).
    intel_kev_enabled: bool = True
    intel_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # TSG_INTEL_ICS_ADVISORIES_ENABLED / _URL — CISA ICS advisories via the official GitHub CSAF
    # mirror (cisa.gov's own endpoint bot-blocks non-browser TLS stacks).
    intel_ics_advisories_enabled: bool = True
    intel_ics_advisories_url: str = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv"

    # TSG_INTEL_URLHAUS_ENABLED / _URL — URLhaus malicious-URL IOC feed (cached, not prompted).
    intel_urlhaus_enabled: bool = False
    intel_urlhaus_url: str = "https://urlhaus.abuse.ch/downloads/json_recent/"

    # OTX_API_KEY — AlienVault OTX; the fetcher is skipped while empty.
    intel_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "TSG_INTEL_OTX_API_KEY"))
    # TSG_INTEL_OTX_URL — pulses endpoint.
    intel_otx_url: str = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    # TSG_INTEL_OTX_PAGE_SIZE — OTX's hard cap; larger values are ignored by OTX.
    intel_otx_page_size: int = 50
    # TSG_INTEL_OTX_MAX_PAGES — safety bound on the paginated walk (~178 real pages today).
    intel_otx_max_pages: int = 200
    # TSG_INTEL_OTX_SYNC_SECONDS — per-run time budget (resumes from a stored cursor); keep well
    # under the task's 600s soft limit.
    intel_otx_sync_seconds: int = 400
    # TSG_INTEL_OTX_FRESH_PAGES — head pages re-read EVERY run so new pulses don't wait ~9 days
    # for the rolling cursor.
    intel_otx_fresh_pages: int = 2

    # TSG_INTEL_TAXII_SERVERS — TAXII 2.1 sources as a JSON list of
    # {"label", "url", "collection"} objects.
    intel_taxii_servers: str = ""

    # --- 6. LLM chat provider ----------------------------------------------------

    # LLM_PROVIDER — which AI service handles chat.
    llm_provider: Literal["litellm_proxy", "azure_openai", "openai"] = Field(
        "azure_openai", validation_alias=AliasChoices("LLM_PROVIDER", "TSG_LLM_PROVIDER"))

    # AZURE_OPENAI_* — Azure OpenAI credentials; only read when llm_provider=azure_openai.
    azure_openai_api_key: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_API_KEY", "TSG_AZURE_OPENAI_API_KEY"))
    azure_openai_endpoint: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_ENDPOINT", "TSG_AZURE_OPENAI_ENDPOINT"))
    azure_openai_deployment_name: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_DEPLOYMENT_NAME", "TSG_AZURE_OPENAI_DEPLOYMENT_NAME"))
    azure_openai_api_version: str = Field(
        "2024-12-01-preview", validation_alias=AliasChoices("AZURE_OPENAI_API_VERSION", "TSG_AZURE_OPENAI_API_VERSION"))

    # OPENAI_API_KEY / TSG_OPENAI_BASE_URL — OpenAI-direct; only when llm_provider=openai.
    openai_api_key: str = Field("", validation_alias=AliasChoices("OPENAI_API_KEY", "TSG_OPENAI_API_KEY"))
    openai_base_url: str = ""

    # TSG_LITELLM_BASE_URL / _API_KEY — litellm proxy; only when llm_provider=litellm_proxy.
    litellm_base_url: str = "http://localhost:4000"
    litellm_api_key: str = "sk-local"

    # LITELLM_API_KEY_HEADER — optional ALTERNATE header for the key (e.g. "x-litellm-api-key")
    # when a gateway consumes Authorization; the key is then sent in BOTH headers.
    litellm_api_key_header: str = Field(
        "", validation_alias=AliasChoices("LITELLM_API_KEY_HEADER", "TSG_LITELLM_API_KEY_HEADER"))

    # TSG_LITELLM_BYPASS_PROXY — true (default) sets NO_PROXY for litellm traffic; set false only
    # where the network requires routing litellm through the corporate proxy.
    litellm_bypass_proxy: bool = Field(
        True, validation_alias=AliasChoices("LITELLM_BYPASS_PROXY", "TSG_LITELLM_BYPASS_PROXY"))

    # TSG_INFERENCE_MODEL — chat model name (litellm/OpenAI; Azure uses the deployment name).
    inference_model: str = "gpt-5"

    # TSG_INFERENCE_FALLBACK_MODEL — second model the SAME call retries ONCE on a retryable
    # failure; empty (default) = off. Never under azure_openai; calls that pin an explicit model
    # are exempt. Every use is logged and recorded in Provenance.fallback_from.
    inference_fallback_model: str = ""


    # TSG_LLM_TIMEOUT_SECONDS / TSG_LLM_MAX_RETRIES — per-call timeout and retry cap. NOTE:
    # these feed the stage-lease/treatment-staleness derivation (_derive_stage_lease_seconds).
    llm_timeout_seconds: float = 90.0
    llm_max_retries: int = 3

    # LLM_JSON_MODE — ask the provider to guarantee valid JSON (not every provider supports it).
    llm_json_mode: bool = Field(False, validation_alias=AliasChoices("LLM_JSON_MODE", "TSG_LLM_JSON_MODE"))

    # LLM_TEMPERATURE — 0 = consistent, 2 = varied; unset = provider default.
    llm_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices("LLM_TEMPERATURE", "TSG_LLM_TEMPERATURE"))

    # THREAT_IDENTIFICATION_TEMPERATURE — 0 so the same asset yields the same threats each run.
    threat_identification_temperature: float | None = Field(
        0.0, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "THREAT_IDENTIFICATION_TEMPERATURE", "TSG_THREAT_IDENTIFICATION_TEMPERATURE"))

    # SCENARIO_GENERATION_TEMPERATURE — deliberately NOT pinned to 0: the same call serves
    # variant generation, where 0 works against "meaningfully different" siblings.
    scenario_generation_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "SCENARIO_GENERATION_TEMPERATURE", "TSG_SCENARIO_GENERATION_TEMPERATURE"))

    # LLM_REASONING_EFFORT — reasoning-model effort hint; unset = provider default.
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        None, validation_alias=AliasChoices("LLM_REASONING_EFFORT", "TSG_LLM_REASONING_EFFORT"))

    # --- 7. Risk treatment plans (docs/RISK_TREATMENT_PLAN_SDD.md) ----------------

    # TSG_RISK_MODULE_ENABLED — off (default) = the treatment routes are not mounted at all.
    risk_module_enabled: bool = Field(
        False, validation_alias=AliasChoices("RISK_MODULE_ENABLED", "TSG_RISK_MODULE_ENABLED"))

    # TSG_TREATMENT_TEMPERATURE — 0 = repeatable plans for identical inputs.
    treatment_temperature: float | None = Field(
        0.0, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "TREATMENT_TEMPERATURE", "TSG_TREATMENT_TEMPERATURE"))

    # TSG_TREATMENT_STALE_SECONDS — a RUNNING plan with no progress for this long is abandoned.
    # Leave unset to derive from llm timeout x retries.
    treatment_stale_seconds: int = Field(
        900, ge=60, validation_alias=AliasChoices(
            "TREATMENT_STALE_SECONDS", "TSG_TREATMENT_STALE_SECONDS"))

    # --- 8. Optional proxy-side safety (litellm only, off by default) -------------

    # LLM_MODERATION_ENABLED — a soft flag for a reviewer, NEVER a hard block: this app's job is
    # describing attacks, which some moderation categories would misfire on.
    llm_moderation_enabled: bool = Field(
        False, validation_alias=AliasChoices("LLM_MODERATION_ENABLED", "TSG_LLM_MODERATION_ENABLED"))
    # LLM_MODERATION_MODEL — unset = the proxy's default moderation model.
    llm_moderation_model: str | None = Field(
        None, validation_alias=AliasChoices("LLM_MODERATION_MODEL", "TSG_LLM_MODERATION_MODEL"))
    # LLM_GUARDRAILS — proxy-side safety filter names run on every chat call.
    llm_guardrails: list[str] | None = Field(
        None, validation_alias=AliasChoices("LLM_GUARDRAILS", "TSG_LLM_GUARDRAILS"))

    # --- 9. Embeddings & reranker --------------------------------------------------

    # EMBEDDING_MODEL — model name (proxy) or local file path (provider=local).
    embedding_model: str = Field(
        "multilingual-e5-large", validation_alias=AliasChoices("EMBEDDING_MODEL", "TSG_EMBEDDING_MODEL"))
    # RERANKER_MODEL — the precise second-pass scorer; name or local path.
    reranker_model: str = Field(
        "bge-reranker-v2-m3", validation_alias=AliasChoices("RERANKER_MODEL", "TSG_RERANKER_MODEL"))
    # EMBEDDING_PROVIDER — leave unset to follow llm_provider (_derive_embedding_reranker_provider).
    embedding_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("EMBEDDING_PROVIDER", "TSG_EMBEDDING_PROVIDER"))
    # EMBEDDING_DIMENSIONS — vector size; MUST match the active model or comparisons corrupt.
    embedding_dimensions: int = Field(
        1024, validation_alias=AliasChoices("EMBEDDING_DIMENSIONS", "TSG_EMBEDDING_DIMENSIONS"))
    # EMBEDDING_STORE — 'mongo' survives restarts; falls back to memory if Mongo is unreachable.
    embedding_store: Literal["memory", "mongo"] = Field(
        "mongo", validation_alias=AliasChoices("EMBEDDING_STORE", "TSG_EMBEDDING_STORE"))
    # EMBEDDING_PREFIX_STYLE — 'auto' adds the query:/passage: prefixes for e5-family models.
    embedding_prefix_style: Literal["auto", "e5", "none"] = Field(
        "auto", validation_alias=AliasChoices("EMBEDDING_PREFIX_STYLE", "TSG_EMBEDDING_PREFIX_STYLE"))
    # SEMANTIC_MATCH_THRESHOLD — similarity 0-1 a library entry needs to be shortlisted at all.
    semantic_match_threshold: float = Field(
        0.60, validation_alias=AliasChoices("SEMANTIC_MATCH_THRESHOLD", "TSG_SEMANTIC_MATCH_THRESHOLD"))
    # RERANKER_PROVIDER — same "follows llm_provider unless set" rule as embedding_provider.
    reranker_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("RERANKER_PROVIDER", "TSG_RERANKER_PROVIDER"))

    # TSG_LOCAL_MODEL_CACHE_SIZE — loaded local models kept in memory.
    local_model_cache_size: int = 4
    # TSG_LOCAL_MODEL_THREADPOOL_SIZE — gevent native-thread pool for local model calls.
    local_model_threadpool_size: int = 10

    # --- 10. Matching & grounding ---------------------------------------------------

    # TSG_GROUNDING_MATCH_THRESHOLD — trust gate 0-100: at/above = 'verified' (library wording
    # and ids adopted); below = 'unverified'. BOOTSTRAP only: a stored calibration for the model
    # pair always wins (grounding.resolve_thresholds, DB-first since 2026-08).
    grounding_match_threshold: float = 75.0
    # TSG_GROUNDING_SHORTLIST_K — shortlisted entries sent to the precise scorer.
    grounding_shortlist_k: int = 10

    # --- 11. Controls mapping (Step 4) ------------------------------------------------

    # TSG_CONTROL_MAP_TOP_K — most controls kept per scenario ("up to K", never padded).
    control_map_top_k: int = Field(5, ge=1)
    # TSG_CONTROL_MAP_MIN_SCORE — drop matches reranking below this. SET EXPLICITLY once
    # measured (python scripts/measure_control_map_scores.py — read-only, runs the real path):
    # the query is a scenario PARAGRAPH, and the unset fallback was calibrated label-vs-label,
    # risking every match silently dropped (controls=[] reading as a healthy "library gap").
    control_map_min_score: float = Field(60.0, ge=0.0, le=100.0)

    # TSG_CONTROL_MAP_SHORTLIST_K — controls reaching the RERANKER per scenario. SEPARATE from
    # grounding_shortlist_k on purpose (scenario paragraph vs short label; grounding's thresholds
    # are calibrated at its own K). At the old shared K=10 only 14-20 of 557 OT controls were
    # ever reranked and real matches were discarded unscored — never set it back to 10.
    # Cost: remote reranker = payload per request; local = CPU work scales ~linearly with K.
    control_map_shortlist_k: int = Field(60, ge=1)

    # TSG_CONTROL_MAP_SWEEP_INTERVAL_SECONDS — retry-queue drain cadence (tsg.map_controls_sweep
    # is the "next run" for outputs mapping deliberately left unstamped). Ticking faster than
    # stage_lease_seconds buys nothing.
    control_map_sweep_interval_seconds: float = 300.0
    # TSG_RERANK_CONCURRENCY — concurrent REMOTE rerank calls (local reranker ignores this).
    rerank_concurrency: int = Field(8, ge=1)
    # TSG_SCENARIO_GENERATION_CONCURRENCY — scenarios generated at once per write_scenarios
    # batch (1 = strictly sequential). A LOCAL politeness cap only: every call still takes its
    # own Redis _llm_slot, so max_concurrent_llm_calls stays the global authority.
    scenario_generation_concurrency: int = Field(5, ge=1, le=32)

    # --- 12. Threat volume & scenario coverage ------------------------------------------

    # TSG_MAX_THREATS_PER_ASSET — most threats the AI may propose PER IDENTIFICATION CALL;
    # next-set shortfalls may run more calls per session.
    max_threats_per_asset: int = Field(
        10, validation_alias=AliasChoices("TSG_MAX_THREATS_PER_ASSET", "TSG_MAX_THREATS_PER_SUBSYSTEM"))

    # TSG_GAP_GENERATION_BUFFER — threats REQUESTED per new one needed: dedup eats re-proposals,
    # so asking for exactly the shortfall under-delivers. 2.0 absorbs a 50% repeat rate;
    # 1.0 disables the buffer.
    gap_generation_buffer: float = Field(2.0, ge=1.0)

    # TSG_MAX_ACTORS_PER_THREAT — caps actor names per threat (candidate rows + triage work).
    max_actors_per_threat: int = Field(10, ge=1)

    # TSG_VALIDATOR_BATCH_SIZE — library candidates judged per LLM validation call.
    validator_batch_size: int = Field(20, ge=1)

    # TSG_COVERAGE_ATTEMPT_SLACK — extra generation attempts beyond a threat's coverage target
    # (its AI-declared plausible entry points). A non-termination guard, not a depth policy.
    coverage_attempt_slack: int = Field(2, ge=0)

    # TSG_EXCLUSIONS_CHAR_BUDGET — maximum characters used for prior threat labels in a prompt.
    exclusions_char_budget: int = Field(24_000, ge=1)

    # TSG_VARIANT_SIBLING_PROMPT_K — a threat's existing scenarios quoted into the variant
    # prompt (prompt width only, not analysis depth).
    variant_sibling_prompt_k: int = Field(3, ge=1)

    # TSG_NEXT_SET_SIZE — scenarios served/generated per "generate next set" click.
    next_set_size: int = Field(5, ge=1)

    # TSG_SEMANTIC_NEAR_DUPLICATE_THRESHOLD — session-tunable FLOOR of the dedup bar; pairs are
    # judged at max(cross_category, this), so values below 0.98 are inert; 1.0 disables.
    semantic_near_duplicate_threshold: float = Field(0.92, ge=0.0, le=1.0)

    # TSG_SEMANTIC_CROSS_CATEGORY_THRESHOLD — BASE of that bar, whatever the categories.
    # 0.98 sits above the measured 0.969 trap (two REAL threats one word apart).
    semantic_cross_category_threshold: float = Field(0.98, ge=0.0, le=1.0)

    # --- 13. Scoring & scoping ------------------------------------------------------

    # TSG_SCOPING_SCORE_THRESHOLD — a threat scoring below this gets no scenario.
    scoping_score_threshold: float | None = Field(55.0, ge=0.0, le=100.0)

    # TSG_BASE_SCORE — every threat's starting score; coupled to the threshold by
    # _validate_scoring_floor_invariant.
    base_score: float = Field(50.0, ge=0.0, le=100.0)
    # TSG_SIBLING_SIMILARITY_RATIO — text similarity that flags a scenario for the reviewer
    # (warning, never a rejection).
    sibling_similarity_ratio: float = Field(0.85, ge=0.0, le=1.0)
    # TSG_PROMPT_INTEL_LIMIT — advisories injected per scenario prompt (raises token spend).
    prompt_intel_limit: int = Field(5, ge=0)
    # TSG_INTEL_MIN_TERM_LENGTH — shortest word used in intel keyword search.
    intel_min_term_length: int = Field(4, ge=1)
    # TSG_NEAR_DUPLICATE_SCORE — rerank score at/above which two LIBRARY entries count as
    # near-twins (reported as curation work by calibration).
    near_duplicate_score: float = Field(99.0, ge=0.0, le=100.0)
    # TSG_SCOPING_TOP_N — only the best N unique threats get scenarios; None (default) = no cap.
    scoping_top_n: int | None = Field(None, ge=1)

    # --- 15. Session capacity ----------------------------------------------------------

    # TSG_MAX_ACTIVE_SESSIONS — most concurrent sessions overall; 0 = unlimited.
    max_active_sessions: int = 0
    # TSG_MAX_ACTIVE_SESSIONS_PER_ENTITY — per-entity ceiling; 0 = only the global cap applies.
    max_active_sessions_per_entity: int = 0
    # TSG_CAPACITY_RETRY_AFTER_SECONDS — Retry-After hint on capacity rejections.
    capacity_retry_after_seconds: int = 10

    # --- 16. LLM concurrency slots (shared across workers via Redis) --------------------

    # TSG_MAX_CONCURRENT_LLM_CALLS — ceiling on simultaneous AI calls; 0 = unlimited.
    max_concurrent_llm_calls: int = 0
    # TSG_LLM_SLOT_WAIT_TIMEOUT_SECONDS — how long a call waits for a slot before retrying.
    llm_slot_wait_timeout_seconds: float = 30.0
    # TSG_LLM_SLOT_HEARTBEAT_SECONDS — liveness signal interval for a held slot.
    llm_slot_heartbeat_seconds: float = 10.0
    # TSG_LLM_SLOT_STALE_AFTER_SECONDS — no signal for this long = crashed; slot is freed.
    llm_slot_stale_after_seconds: float = 30.0
    # TSG_LLM_SLOTS_WARN_RATIO — warn when slot usage passes this fraction.
    llm_slots_warn_ratio: float = 0.8
    # TSG_LLM_SLOT_REDIS_TIMEOUT_SECONDS — Redis op timeout inside the slot machinery.
    llm_slot_redis_timeout_seconds: float = 3.0

    # --- 17. Stage lease, reaper & retries ----------------------------------------------

    # TSG_STAGE_LEASE_SECONDS — how long one work step may run before it's assumed crashed.
    # LEAVE UNSET: derived from llm timeout x retries (_derive_stage_lease_seconds).
    stage_lease_seconds: int = 300
    # TSG_REAPER_INTERVAL_SECONDS — crashed/abandoned-session sweep cadence.
    reaper_interval_seconds: float = 60.0
    # TSG_REAPER_STALE_GRACE_SECONDS — how long a lease-less session must sit untouched before
    # it counts as abandoned; unset = follows stage_lease_seconds (via model_fields_set).
    reaper_stale_grace_seconds: float = 300.0
    # TSG_STAGE_MAX_ATTEMPTS — retry cap per stage before it is abandoned.
    stage_max_attempts: int = 5
    # --- 19. Health monitoring / self-check ----------------------------------------------

    # TSG_SELF_CHECK_INTERVAL_SECONDS — periodic self-check cadence.
    self_check_interval_seconds: float = 300.0
    # TSG_TEMPDB_VERSION_STORE_WARN_MB / TSG_TEMPDB_LONG_TXN_WARN_SECONDS — MSSQL tempdb warns.
    tempdb_version_store_warn_mb: int = 1024
    tempdb_long_txn_warn_seconds: int = 300
    # TSG_ACTIVE_SESSIONS_WARN_RATIO / TSG_POOL_UTILIZATION_WARN_RATIO — capacity warnings.
    active_sessions_warn_ratio: float = 0.9
    pool_utilization_warn_ratio: float = 0.9

    # --- 20. SSE (live session updates to the browser) ------------------------------------

    # TSG_SSE_PING_SECONDS — keepalive ping interval (0 floods; negative 500s every connect).
    sse_ping_seconds: int = Field(15, gt=0)
    # TSG_SSE_BREAKER_COOLDOWN_SECONDS — publish circuit-breaker cooldown.
    sse_breaker_cooldown_seconds: float = 30.0
    # TSG_SSE_PUBLISH_TIMEOUT_SECONDS — max wait to publish one event.
    sse_publish_timeout_seconds: float = 1.0
    # TSG_SSE_SUBSCRIBE_CONNECT_TIMEOUT_SECONDS — subscriber connect timeout.
    sse_subscribe_connect_timeout_seconds: float = 2.0
    # TSG_SSE_MAX_CONCURRENT_STREAMS — sizes BOTH the Redis subscriber pool and the semaphore
    # gating session_events(), so streams can never outnumber pool connections.
    sse_max_concurrent_streams: int = 180
    # TSG_SSE_SEND_TIMEOUT_SECONDS — a stalled consumer is force-closed within this long.
    sse_send_timeout_seconds: float = 30.0
    # TSG_SSE_SHUTDOWN_GRACE_SECONDS — drain window on shutdown (under gunicorn's 30s graceful).
    sse_shutdown_grace_seconds: float = 25.0
    # TSG_SSE_SUBSCRIBER_SOCKET_TIMEOUT_SECONDS / _HEALTH_CHECK_INTERVAL_SECONDS — subscriber
    # pool read timeout and liveness check.
    sse_subscriber_socket_timeout_seconds: float = 10.0
    sse_subscriber_health_check_interval_seconds: float = 30.0

    # --- 21. HTTP & auth -------------------------------------------------------------------

    # TSG_CORS_ALLOWED_ORIGINS — JSON list of origins; empty (default) = no cross-origin access.
    cors_allowed_origins: list[str] = Field(default_factory=list)

    # ADMIN_API_KEY / TSG_ADMIN_API_KEY — unlocks the admin routes; empty (default) = disabled.
    admin_api_key: str = Field(
        "", validation_alias=AliasChoices("ADMIN_API_KEY", "TSG_ADMIN_API_KEY"))

    # VERIFY_MEMBERSHIP — OFF by design, and expected to stay off. X-API-Key is the credential;
    # the identity headers are request input the calling service supplies. True would add a
    # per-request user_scope_assignment check. Kept as the migration path if per-user entity
    # scoping is ever wanted — not because the current model is unfinished.
    verify_membership: bool = Field(
        False, validation_alias=AliasChoices("VERIFY_MEMBERSHIP", "TSG_VERIFY_MEMBERSHIP"))

    # TSG_ALLOW_REMOTE_IN_DEV — deliberate escape hatch: lets APP_ENV=local/dev point at
    # non-loopback DB/Redis, which assert_security_posture otherwise refuses.
    allow_remote_in_dev: bool = Field(
        False, validation_alias=AliasChoices("ALLOW_REMOTE_IN_DEV", "TSG_ALLOW_REMOTE_IN_DEV"))

    # FLOWER_BASIC_AUTH — "user:password" for Flower's --basic-auth. Read by
    # docker/compose.prod.yml and start.ps1, never by Python; declared here so env_selfcheck
    # keeps it documented in every template.
    flower_basic_auth: str = Field(
        "", validation_alias=AliasChoices("FLOWER_BASIC_AUTH", "TSG_FLOWER_BASIC_AUTH"))

    # (Auth is the header model — X-API-Key + X-User-Id + X-Entity-Id, see app/api/deps.py.
    # The old jwt_*/auth_dev_mode settings no longer exist; extra='ignore' swallows them.)

    # --- 22. Former hardcoded module constants (defaults unchanged from the old values) ------

    # TSG_CALIBRATION_SAMPLE_SIZE — library entries sampled by threshold auto-calibration.
    calibration_sample_size: int = Field(100, ge=5)
    # TSG_CALIBRATION_PARAPHRASES_PER_NAME — LLM rewordings generated per sampled name.
    calibration_paraphrases_per_name: int = Field(2, ge=1)
    # TSG_CALIBRATION_STALE_AFTER_SECONDS — how long a `running` calibration row is believed
    # before it reads as abandoned (a killed worker must not block all future sweeps). Keep
    # comfortably above a real 10-15 minute sweep.
    calibration_stale_after_seconds: int = Field(3600, ge=60)

    # TSG_EMBEDDING_GROUP_LOCK_TTL_SECONDS — Redis mutex TTL for a group's cache rebuild.
    # MUST stay an int: redis-py rejects a float for EXPIRE.
    embedding_group_lock_ttl_seconds: int = Field(30, ge=1)
    # TSG_MONGO_BREAKER_COOLDOWN_SECONDS — cooldown before retrying Mongo after a failure.
    mongo_breaker_cooldown_seconds: float = Field(30.0, ge=0.0)
    # TSG_EMBEDDING_BATCH_SIZE — max texts per PROVIDER REQUEST. 32 is the per-request cap of
    # uat/prod's proxy-served embedding model; the boot probe (_verify_embedding_dimensions)
    # sends exactly this many and refuses to start if the provider rejects it.
    embedding_batch_size: int = Field(32, ge=1)
    # TSG_EMBEDDING_CONCURRENCY — get_vectors batches in flight at once (1 = sequential). Each
    # call still takes its own _llm_slot, so max_concurrent_llm_calls stays the global authority.
    # Step up 4 -> 8 while watching for 429s (a 429 retries the whole Celery task).
    embedding_concurrency: int = Field(1, ge=1, le=32)

    # TSG_LLM_SLOT_POLL_SECONDS / _POLL_JITTER_SECONDS — slot-wait poll interval; jitter avoids
    # synchronized thundering-herd wakeups.
    llm_slot_poll_seconds: float = Field(0.25, gt=0.0)
    llm_slot_poll_jitter_seconds: float = Field(0.1, ge=0.0)
    # TSG_MAX_EMBED_CHARS / TSG_MAX_CHAT_CHARS — safety caps against pathological input.
    max_embed_chars: int = Field(4000, ge=1)
    max_chat_chars: int = Field(60_000, ge=1)

    # TSG_TREATMENT_FREE_TEXT_CAP — per-field cap on UI-supplied free text at snapshot time.
    treatment_free_text_cap: int = Field(2000, ge=1)

    # TSG_REAPER_SQL_IN_CHUNK_SIZE — max ids per SQL IN-list chunk (well under MSSQL's ~2100
    # parameter hard limit).
    reaper_sql_in_chunk_size: int = Field(1000, ge=1, le=2000)

    # TSG_LLM_VERIFY_MAX_ATTEMPTS / _RETRY_BACKOFF_SECONDS — worker-boot warm-up check retries.
    llm_verify_max_attempts: int = Field(3, ge=1)
    llm_verify_retry_backoff_seconds: float = Field(5.0, ge=0.0)

    # TSG_ADMIN_EMBEDDING_MAX_RETRIES — embedding-admin job retries on slot shortage (0 = fail
    # on first). Read once at import — worker restart to change.
    admin_embedding_max_retries: int = Field(10, ge=0)

    # TSG_ACCEPT_NAMED_IN_MESSAGE — offending ids named in the human-readable accept 404 message.
    accept_named_in_message: int = Field(3, ge=1)


    # TSG_MAX_PROPOSAL_CHARS — max combined type+name chars for a usable LLM threat proposal;
    # kept <= max_embed_chars by the validator below.
    max_proposal_chars: int = Field(3500, ge=1)

    # --- Boot validators: coupled-setting invariants (raise = refuse to start) ---------------

    # embed() errors (never truncates) over the limit, which would lose the whole batch.
    @model_validator(mode="after")
    def _validate_proposal_below_embed_cap(self) -> Settings:
        if self.max_proposal_chars > self.max_embed_chars:
            raise ValueError(
                f"max_proposal_chars ({self.max_proposal_chars}) must not exceed max_embed_chars "
                f"({self.max_embed_chars}) — embed() errors on an over-limit text instead of "
                "truncating it, which would lose every threat in the batch.")
        return self

    # One scenario-text query per output draws its top-K from a single reranked shortlist, so a
    # shortlist smaller than top_k silently caps every scenario below the configured count.
    @model_validator(mode="after")
    def _validate_shortlist_covers_control_top_k(self) -> Settings:
        if self.control_map_shortlist_k < self.control_map_top_k:
            raise ValueError(
                f"control_map_shortlist_k ({self.control_map_shortlist_k}) must be >= "
                f"control_map_top_k ({self.control_map_top_k}) — one scenario-text query per "
                "output draws its top-K controls from a single shortlist, so a smaller "
                "shortlist silently caps every scenario's mapped controls below the "
                "configured count.")
        return self

    # Unset embedding/reranker providers follow llm_provider=litellm_proxy; explicit values win.
    @model_validator(mode="after")
    def _derive_embedding_reranker_provider(self) -> Settings:
        if self.llm_provider == "litellm_proxy":
            if "embedding_provider" not in self.model_fields_set:
                self.embedding_provider = "litellm_proxy"
            if "reranker_provider" not in self.model_fields_set:
                self.reranker_provider = "litellm_proxy"
        return self

    # Progress clocks must outlast a full LLM retry chain, or a slow-but-live worker is reaped:
    # unset -> derive (floor x 2); explicitly below the floor -> refuse to start.
    @model_validator(mode="after")
    def _derive_stage_lease_seconds(self) -> Settings:
        # A fallback model doubles the worst case: the primary's full retry chain, then the
        # fallback's, with the same timeout/retry budget each. Azure ignores the fallback.
        chains = 2 if (self.inference_fallback_model
                    and self.llm_provider != "azure_openai") else 1
        floor = self.llm_timeout_seconds * (self.llm_max_retries + 1) * chains
        if "stage_lease_seconds" not in self.model_fields_set:
            self.stage_lease_seconds = int(floor * 2)
        elif self.stage_lease_seconds < floor:
            raise ValueError(
                f"stage_lease_seconds ({self.stage_lease_seconds}s) is below the safe floor "
                f"({floor:.0f}s = llm_timeout_seconds * (llm_max_retries + 1)) — a genuinely "
                "slow (not crashed) call could be wrongly reaped. Raise it above the floor.")
        if "treatment_stale_seconds" not in self.model_fields_set:
            self.treatment_stale_seconds = max(self.treatment_stale_seconds, int(floor * 2))
        elif self.treatment_stale_seconds < floor:
            raise ValueError(
                f"treatment_stale_seconds ({self.treatment_stale_seconds}s) is below the safe "
                f"floor ({floor:.0f}s = llm_timeout_seconds * (llm_max_retries + 1)) — a "
                "slow-but-live plan attempt would be superseded and re-run in parallel. "
                "Raise it above the floor.")
        return self

    # scoping_top_n can never exceed max_threats_per_asset; thin dedup headroom only warns.
    @model_validator(mode="after")
    def _bind_scenario_count_to_threat_count(self) -> Settings:
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
            from app.core.logging import get_logger  # lazy: logging imports config
            get_logger(__name__).warning(
                "config.thin_dedup_headroom", scoping_top_n=top_n,
                max_threats_per_asset=self.max_threats_per_asset,
                note="fewer than 1.25x candidate threats per target scenario — catalogue dedup "
                    "may under-shoot scoping_top_n when the model repeats threats")
        return self

    # Valid-but-operationally-useless coverage settings: warn only, never refuse to boot.
    @model_validator(mode="after")
    def _validate_coverage_knobs(self) -> Settings:
        from app.core.logging import get_logger  # lazy: logging imports config
        if self.semantic_near_duplicate_threshold < 0.5:
            get_logger(__name__).warning(
                "config.semantic_threshold_floods",
                semantic_near_duplicate_threshold=self.semantic_near_duplicate_threshold,
                note="below ~0.5 nearly every threat pair matches — the near-duplicate log stops "
                    "being a signal and cannot be used to calibrate a real cutoff")
        return self

    # Unset reaper grace follows stage_lease_seconds (must run AFTER _derive_stage_lease_seconds
    # so it reads the derived value, not the class default).
    @model_validator(mode="after")
    def _derive_reaper_stale_grace_seconds(self) -> Settings:
        if "reaper_stale_grace_seconds" not in self.model_fields_set:
            self.reaper_stale_grace_seconds = self.stage_lease_seconds
        return self

    # Cross-category dedup ceiling must sit at/above the same-category threshold.
    @model_validator(mode="after")
    def _validate_semantic_threshold_ordering(self) -> Settings:
        if self.semantic_cross_category_threshold < self.semantic_near_duplicate_threshold:
            raise ValueError(
                f"semantic_cross_category_threshold ({self.semantic_cross_category_threshold}) is "
                f"below semantic_near_duplicate_threshold ({self.semantic_near_duplicate_threshold}) "
                "— cross-class pairs would merge more eagerly than same-class ones. Raise the "
                "cross ceiling above the same-category threshold (and keep it above the measured "
                "0.969 cross-class trap).")
        return self

    # scoping_score_threshold must sit below base_score + the smallest grounding-confidence
    # weight, or every NOVEL threat is dropped before a curator ever sees it.
    @model_validator(mode="after")
    def _validate_scoring_floor_invariant(self) -> Settings:
        _min_confidence_weight = 15.0  # scoping._CONFIDENCE_WEIGHT[unverified]; not imported —
        #                                config must not depend on the pipeline package
        if self.scoping_score_threshold is None:
            return self  # None = "no cutoff, keep everything, rank only"
        if self.base_score + _min_confidence_weight <= self.scoping_score_threshold:
            raise ValueError(
                f"scoping_score_threshold ({self.scoping_score_threshold}) is at or above "
                f"base_score ({self.base_score}) + the unverified confidence weight "
                f"({_min_confidence_weight}) = {self.base_score + _min_confidence_weight} — "
                "every novel (unverified) threat would be silently dropped. Lower the "
                "threshold or raise base_score.")
        if self.scoping_score_threshold <= self.base_score:
            from app.core.logging import get_logger  # lazy: logging imports config
            get_logger(__name__).warning(
                "config.scoping_floor_never_rejects",
                scoping_score_threshold=self.scoping_score_threshold,
                base_score=self.base_score,
                note="threshold <= base_score: every threat clears the floor — it ranks but "
                    "never rejects. Set scoping_score_threshold above base_score to make the "
                    "floor real, or leave as-is if keep-everything is intended.")
        return self

    @model_validator(mode="after")
    def _validate_llm_slot_heartbeat_margin(self) -> Settings:
        if self.llm_slot_stale_after_seconds < self.llm_slot_heartbeat_seconds * 2:
            raise ValueError(
                f"llm_slot_stale_after_seconds ({self.llm_slot_stale_after_seconds}s) is too close "
                f"to llm_slot_heartbeat_seconds ({self.llm_slot_heartbeat_seconds}s) — a still-"
                "running call's ticket could be pruned before its first heartbeat renews it. "
                "Keep stale_after at least 2x heartbeat.")
        return self

@lru_cache
def get_settings() -> Settings:
    return Settings()


#: Hosts that mean "this developer's own machine". Anything else is shared infrastructure.
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]", "host.docker.internal", ""})

#: This machine's own short name, lower-cased. socket.gethostname() is a local syscall - no DNS
#: lookup, nothing that can hang at import (unlike socket.getfqdn()).
_OWN_HOSTNAME = socket.gethostname().strip().lower().split(".", 1)[0]


def _is_own_machine(host: str) -> bool:
    r"""Does this host mean "the box this process is running on"?

    _LOOPBACK_HOSTS alone did not cover the most ordinary case on Windows: a SQL Server Express
    instance addressed as `MACHINENAME\SQLEXPRESS` rather than `localhost\SQLEXPRESS`. Same
    instance, same data, same machine - but the gate below saw a non-loopback host and refused
    to boot BOTH the API and the Celery worker.

    This is NOT a weakening of the gate. That identical database is already reachable through
    `localhost`, which has always been allowed, so admitting the machine's own name adds no
    target a developer could not already point at. It only stops the gate firing on a
    distinction that carries no meaning.

    Compares the SHORT name, so `xwf8tnjr3.corp.example.com` matches `xwf8tnjr3` without
    paying for a resolver call."""
    host = host.strip().lower()
    return host in _LOOPBACK_HOSTS or host.split(".", 1)[0] == _OWN_HOSTNAME


def _dsn_host(url: str) -> str:
    r"""Best-effort host out of a SQLAlchemy DSN or a redis:// URL.

    Deliberately string-level, not urlparse: an ODBC DSN can carry a backslashed instance name
    (``@HOST\SQLEXPRESS``) and a password full of URL-hostile characters, both of which make
    urlparse either raise or return nonsense. Returns "" when nothing host-shaped is found, and
    "" is treated as loopback so an unparseable DSN can never HARD-FAIL a boot on its own.
    """
    tail = url.split("://", 1)[-1]
    authority = tail.split("/", 1)[0].split("?", 1)[0]
    host = authority.rsplit("@", 1)[-1]          # strip user:password@
    for sep in ("\\", ","):                      # instance name / MSSQL port separator
        host = host.split(sep, 1)[0]
    if host.startswith("["):                      # bracketed IPv6
        return host.split("]", 1)[0] + "]"
    return host.split(":", 1)[0].strip().lower()


# Startup posture check: two HARD gates plus the membership warning. Called first in the FastAPI
# lifespan, so it is the earliest gate there is (the >=1-API-key gate lives in db.invariants).
def assert_security_posture(settings: Settings | None = None) -> None:
    s = settings or get_settings()

    # GATE 1 — a dev/local build must not run against shared infrastructure. APP_ENV is a
    # switch, not a label: at local/dev the app echoes raw exception text to clients, mounts
    # /dev/sse-test, skips the active-API_Client boot check, and silences the membership
    # warning — four protections off at once, so pointing such a build at real infra is refused.
    if s.app_env in ("local", "dev") and not s.allow_remote_in_dev:
        remote = {name: host for name, host in
                (("TSG_DB_DSN", _dsn_host(s.db_dsn)), ("TSG_REDIS_URL", _dsn_host(s.redis_url)))
                if not _is_own_machine(host)}
        if remote:
            targets = ", ".join(f"{k} -> {v}" for k, v in sorted(remote.items()))
            raise RuntimeError(
                f"APP_ENV={s.app_env} but this process points at NON-LOOPBACK infrastructure "
                f"({targets}). At local/dev the app returns raw exception text to clients, mounts "
                f"the /dev/sse-test page, and skips the active-API_Client boot check — none of "
                f"which may run against shared data. Either set APP_ENV=staging|prod (the real "
                f"posture), or set TSG_ALLOW_REMOTE_IN_DEV=true to state deliberately that you "
                f"are developing against shared infrastructure.")

    # GATE 2 — TLS posture: TrustServerCertificate=yes skips certificate verification (MITM
    # undetectable). Hard-fail in prod only; staging may legitimately run self-signed.
    if "trustservercertificate=yes" in s.db_dsn.lower():
        if s.app_env == "prod":
            raise RuntimeError(
                "TSG_DB_DSN sets TrustServerCertificate=yes with APP_ENV=prod: the server "
                "certificate is not validated, so the connection is not MITM-resistant. Install a "
                "trusted certificate on the SQL Server and set TrustServerCertificate=no.")
        if s.app_env == "staging":
            from app.core.logging import get_logger
            get_logger(__name__).warning(
                "db.tls_certificate_unverified", app_env=s.app_env,
                note="TSG_DB_DSN sets TrustServerCertificate=yes — the server certificate is not "
                    "validated. Acceptable on a self-signed staging box; this is a HARD FAILURE "
                    "at APP_ENV=prod, so fix it before promoting.")

    # INFO, not a warning, and deliberately so. This is the ACCEPTED auth model, not a pending
    # remediation — the previous text told every reader to "set TSG_VERIFY_MEMBERSHIP=true once
    # the prod scope table is confirmed", an instruction nobody will ever act on. A warning that
    # fires on every boot and can never be resolved only trains operators to skip this channel,
    # which also carries db.tls_certificate_unverified above. Stated once, at the right level.
    if s.app_env in ("staging", "prod") and not s.verify_membership:
        from app.core.logging import get_logger
        get_logger(__name__).info(
            "auth.posture_api_key_only",
            app_env=s.app_env,
            note="X-API-Key is the credential. X-User-Id/X-Entity-Id are request INPUT the "
                "calling service is trusted to populate, not verified against "
                "user_scope_assignment. One key therefore reaches every entity in every tenant, "
                "so keys are server-side only — never shipped to a browser or mobile client.")


# Startup check that graceful SSE shutdown still works: sse_starlette finds the running uvicorn
# Server by introspecting the live SIGTERM handler, which only works when uvicorn's Server.serve()
# drives this process. Run the SAME introspection at boot so a drift to another worker class
# fails loudly instead of silently losing SSE drain-on-shutdown.
def assert_sse_graceful_shutdown_wired(get_signal_handler=None) -> None:
    import signal as _signal

    handler = (get_signal_handler or _signal.getsignal)(_signal.SIGTERM)
    server = getattr(handler, "__self__", None)
    if server is None or not hasattr(server, "should_exit"):
        raise RuntimeError(
            "SSE graceful shutdown depends on sse_starlette's uvicorn signal-handler "
            "introspection (sse_starlette.sse._get_uvicorn_server), but "
            f"signal.getsignal(signal.SIGTERM) is not a bound uvicorn Server method (got "
            f"{handler!r}). Open SSE streams will NOT drain gracefully on shutdown. Run under "
            "uvicorn (bare `uvicorn app.main:app`, or gunicorn -k "
            "uvicorn.workers.UvicornWorker) — see the comment above this function.")
