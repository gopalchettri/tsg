"""Application configuration. Every setting is read from the environment (via a .env file),
never hard-coded elsewhere. One shared Settings object: injected in the API, imported directly
by Celery workers.
"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _env_file() -> str:
    """`TSG_ENV_FILE` if set, else `.env`. A missing TSG_ENV_FILE fails loudly — falling back
    would silently run this deployment on another environment's config."""
    chosen = os.environ.get("TSG_ENV_FILE", "").strip()
    if not chosen:
        return ".env"
    if not Path(chosen).is_file():
        raise RuntimeError(
            f"TSG_ENV_FILE={chosen!r} does not exist (cwd={Path.cwd()}) — refusing to fall back "
            "to .env, which would silently start this deployment on another environment's config")
    return chosen


# Settings that USED to exist. `extra="ignore"` below is required — a shared .env legitimately
# carries variables for other tools — but it also means deleting a setting turns every deployment
# that still sets it into a silent no-op: the operator reads their own .env, believes the value is
# in force, and the behaviour it used to control has quietly changed underneath them. That is a
# defect of the DELETION, not of the operator, so every removal is recorded here and fails loudly
# at startup naming what replaced it. Add an entry whenever a setting is retired; never just
# delete the field.
_RETIRED_SETTINGS: dict[str, str] = {
    "TSG_MAX_SCENARIOS_PER_THREAT": (
        "scenario depth is no longer a fixed cap. A threat now earns one scenario per supporting "
        "system that could credibly carry it to the asset (its plausible entry points), derived "
        "per threat by dal.variant_eligible_primaries — a 2-system asset finishes in two, an "
        "8-system one earns eight. Delete this variable. To bound retries when the model keeps "
        "re-using one entry point, set TSG_COVERAGE_ATTEMPT_SLACK instead."),
    # Auth moved from JWT to the header model (X-API-Key + X-User-Id + X-Entity-Id). These no
    # longer exist; a live value means the deployment still thinks it is doing JWT/dev-mode auth.
    "AUTH_DEV_MODE": "the dev bypass is gone; the header model authenticates every request. Remove it.",
    "TSG_AUTH_DEV_MODE": "the dev bypass is gone; the header model authenticates every request. Remove it.",
    "TSG_JWT_ISSUER": "TSG no longer validates JWTs — it uses X-API-Key. Remove it.",
    "TSG_JWT_AUDIENCE": "TSG no longer validates JWTs — it uses X-API-Key. Remove it.",
    "TSG_JWT_JWKS_URL": "TSG no longer validates JWTs — it uses X-API-Key. Remove it.",
    "TSG_JWT_SECRET": "TSG no longer validates JWTs — it uses X-API-Key. Remove it.",
    "TSG_JWT_ALGORITHMS": "TSG no longer validates JWTs — it uses X-API-Key. Remove it.",
    "TSG_JWT_ENTITIES_CLAIM": "TSG no longer reads a JWT entities claim — the entity is X-Entity-Id, verified in the DB. Remove it.",
}


def _reject_retired_settings() -> None:
    """Fail startup when the environment still sets a setting that no longer exists. Reads
    os.environ AND the .env file — pydantic discards unknown keys before a validator sees them."""
    present = {name for name in _RETIRED_SETTINGS if os.environ.get(name) is not None}
    env_path = Path(_env_file())
    if env_path.is_file():
        try:
            for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if line.startswith("#") or "=" not in line:
                    continue  # commented-out documentation is fine — only a LIVE line is a lie
                key = line.split("=", 1)[0].strip()
                if key in _RETIRED_SETTINGS:
                    present.add(key)
        except OSError:  # an unreadable .env is _env_file()'s problem, not this guard's
            pass
    if present:
        raise RuntimeError(
            "This deployment sets settings that no longer exist, so they are doing nothing:\n"
            + "\n".join(f"  - {n}: {_RETIRED_SETTINGS[n]}" for n in sorted(present))
            + "\nRemove them from the environment and from the .env file.")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="TSG_", env_file=_env_file(), extra="ignore", populate_by_name=True)

    # --- Identity ---
    # The customer/organization this instance serves. TSG only supports one at a time.
    tenant_id: str = "DESC"

    # This deployment's module identity. An API_Client key authenticates ONLY for its own Module
    # (a 'chatbot' key can't open TSG). Fixed per deployment; the request never carries it — it is
    # implied by which app receives the call. min_length guards a blank value that would silently
    # 401 every request. See app/db/dal.API_MODULE and app/api/deps.verify_api_key.
    api_module: str = Field(
        "tsg", min_length=1, validation_alias=AliasChoices("API_MODULE", "TSG_API_MODULE"))

    # Blocks the dev-only login bypass from running in staging/prod.
    app_env: Literal["local", "dev", "staging", "prod"] = Field(
        "prod", validation_alias=AliasChoices("APP_ENV", "TSG_APP_ENV"))
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO", validation_alias=AliasChoices("LOG_LEVEL", "TSG_LOG_LEVEL"))

    # --- Database (MSSQL) ---
    # A placeholder, not a real database — if TSG_DB_DSN is missing from .env the app fails
    # loudly instead of silently connecting to the wrong database.
    db_dsn: str = (
        r"mssql+pyodbc://@CONFIGURE_TSG_DB_DSN_IN_ENV\SQLEXPRESS/CONFIGURE_TSG_DB_DSN_IN_ENV?driver=ODBC+Driver+17+for+SQL+Server&Trusted_Connection=yes&TrustServerCertificate=yes"  # noqa: E501
    )

    db_pool_size: int = 50
    db_max_overflow: int = 10       # extra connections openable under heavy load
    db_pool_timeout: int = 30       # how long a request waits for a free connection
    db_connect_timeout_seconds: int = 5
    db_statement_timeout_seconds: int = 30

    # --- Redis (live updates + background job queue) ---
    redis_url: str = Field(
        "redis://127.0.0.1:6379/0", validation_alias=AliasChoices("REDIS_URL", "TSG_REDIS_URL"))

    # Optional separate Redis for the job queue. Falls back to redis_url if unset.
    celery_broker_url: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_BROKER_URL", "TSG_CELERY_BROKER_URL", "TSG_REDIS_CELERY_BROKER_URL"))

    # Where a finished job's result is stored. Same fallback as celery_broker_url.
    celery_result_backend: str = Field(
        "", validation_alias=AliasChoices(
            "CELERY_RESULT_BACKEND", "TSG_CELERY_RESULT_BACKEND", "TSG_REDIS_CELERY_RESULT_BACKEND"))

    result_expires_seconds: int = 3600

    # --- MongoDB (caches AI-generated vectors so the same text is never processed twice) ---
    mongo_url: str = "mongodb://localhost:27017"
    mongo_db: str = "tsg_embeddings"
    mongo_connect_timeout_ms: int = 3000

    # --- Live threat intel (open feeds cached in Mongo 'threat_intel'; enrichment is fail-open) ---
    # Master switch for the daily intel-refresh beat task (app/intel/fetchers.py).
    intel_enabled: bool = True

    # TTL only purges items a feed has DROPPED (or a whole decommissioned feed): items still
    # present get their timestamp refreshed on every run and never expire.
    intel_ttl_days: int = 30

    intel_refresh_interval_seconds: int = 86400

    # CISA Known Exploited Vulnerabilities — actively exploited CVEs (IT + OT), no auth.
    intel_kev_enabled: bool = True
    intel_kev_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    # CISA ICS advisories — the primary live OT intel source, no auth. Read from CISA's official
    # CSAF mirror on GitHub: www.cisa.gov's own RSS endpoint bot-blocks non-browser TLS stacks
    # (Akamai 403); the mirror serves identical data.
    intel_ics_advisories_enabled: bool = True
    intel_ics_advisories_url: str = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/changes.csv"

    # URLhaus recent malicious URLs (IOC feed; cached but not used in prompt enrichment).
    intel_urlhaus_enabled: bool = False
    intel_urlhaus_url: str = "https://urlhaus.abuse.ch/downloads/json_recent/"

    # AlienVault OTX pulses — the fetcher is skipped while the free API key is empty.
    intel_otx_api_key: str = Field("", validation_alias=AliasChoices("OTX_API_KEY", "TSG_INTEL_OTX_API_KEY"))
    intel_otx_url: str = "https://otx.alienvault.com/api/v1/pulses/subscribed"
    # OTX pagination (app/intel/otx.py). ~8.9k pulses over ~178 pages, and deep pages are slow
    # (measured 1.8s at page 1, 35-46s past page 40), so ONE run cannot walk it all — each run
    # works for a time budget and the next resumes from the stored cursor.
    intel_otx_page_size: int = 50        # OTX's hard cap; larger `limit` values are ignored
    intel_otx_max_pages: int = 200       # safety bound on the walk (178 pages real today)
    # MUST stay well under intel_refresh_feed_task's soft_time_limit (600s): the deadline is checked
    # between pages, and one deep page can take 45s — or the 120s socket timeout if OTX stalls.
    intel_otx_sync_seconds: int = 400
    # Head pages re-read on EVERY run. The rolling cursor reaches page 1 only once per cycle
    # (~9 days at the daily cadence), so without this a pulse published today would not be cached
    # until the cursor came back around.
    intel_otx_fresh_pages: int = 2

    # Generic TAXII 2.1 sources — JSON list like
    # [{"label": "org-opencti", "url": "https://cti.example.org/taxii2/root/", "collection": "<id>"}].
    # An org OpenCTI/MISP instance later is one entry here, no code change.
    intel_taxii_servers: str = ""

    # --- LLM provider (which AI service handles chat, and its credentials) ---
    llm_provider: Literal["litellm_proxy", "azure_openai", "openai"] = Field(
        "azure_openai", validation_alias=AliasChoices("LLM_PROVIDER", "TSG_LLM_PROVIDER"))

    # Azure OpenAI — only used when llm_provider=azure_openai.
    azure_openai_api_key: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_API_KEY", "TSG_AZURE_OPENAI_API_KEY"))
    azure_openai_endpoint: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_ENDPOINT", "TSG_AZURE_OPENAI_ENDPOINT"))
    azure_openai_deployment_name: str = Field(
        "", validation_alias=AliasChoices("AZURE_OPENAI_DEPLOYMENT_NAME", "TSG_AZURE_OPENAI_DEPLOYMENT_NAME"))
    azure_openai_api_version: str = Field(
        "2024-12-01-preview", validation_alias=AliasChoices("AZURE_OPENAI_API_VERSION", "TSG_AZURE_OPENAI_API_VERSION"))

    # OpenAI — only used when llm_provider=openai.
    openai_api_key: str = Field("", validation_alias=AliasChoices("OPENAI_API_KEY", "TSG_OPENAI_API_KEY"))
    openai_base_url: str = ""

    # litellm proxy — only used when llm_provider=litellm_proxy.
    litellm_base_url: str = "http://localhost:4000"
    litellm_api_key: str = "sk-local"

    # Optional ALTERNATE header to carry the key, e.g. "x-litellm-api-key". Empty (default) =
    # standard `Authorization: Bearer <key>`. Set it when a gateway in front of litellm
    # consumes/rewrites `Authorization` (symptom: every call 401s). The key is then sent in BOTH
    # headers, so it works either side of such a gateway.
    litellm_api_key_header: str = Field(
        "", validation_alias=AliasChoices("LITELLM_API_KEY_HEADER", "TSG_LITELLM_API_KEY_HEADER"))

    # --- LLM behaviour (chat model + tuning, all providers) ---
    # litellm proxy or plain OpenAI only — Azure uses a deployment name instead.
    inference_model: str = "gpt-5"

    llm_timeout_seconds: float = 90.0
    llm_max_retries: int = 3

    # Ask the provider to guarantee valid JSON. Off by default — not every provider supports it.
    llm_json_mode: bool = Field(False, validation_alias=AliasChoices("LLM_JSON_MODE", "TSG_LLM_JSON_MODE"))

    # 0 = consistent, 2 = varied. Unset = provider's default.
    llm_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices("LLM_TEMPERATURE", "TSG_LLM_TEMPERATURE"))

    # 0 so the same asset gets the same list of threats each time it's run.
    threat_identification_temperature: float | None = Field(
        0.0, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "THREAT_IDENTIFICATION_TEMPERATURE", "TSG_THREAT_IDENTIFICATION_TEMPERATURE"))

    # Unset falls back to llm_temperature, then the provider's default — deliberately NOT 0.0 like
    # the threat step: the same call serves variant generation, where a pinned-0 temperature works
    # against the "MEANINGFULLY DIFFERENT" sibling steering.
    scenario_generation_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "SCENARIO_GENERATION_TEMPERATURE", "TSG_SCENARIO_GENERATION_TEMPERATURE"))

    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        None, validation_alias=AliasChoices("LLM_REASONING_EFFORT", "TSG_LLM_REASONING_EFFORT"))

    # --- Risk Treatment Plan generation (docs/RISK_TREATMENT_PLAN_SDD.md) ---
    # Off (default) = the treatment-plan routes are not mounted at all. On = routes mount; nothing
    # else is armed — the register's risk data arrives in the request body.
    risk_module_enabled: bool = Field(
        False, validation_alias=AliasChoices("RISK_MODULE_ENABLED", "TSG_RISK_MODULE_ENABLED"))

    # 0 = repeatable plans for identical inputs — these land in a risk register.
    treatment_temperature: float | None = Field(
        0.0, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "TREATMENT_TEMPERATURE", "TSG_TREATMENT_TEMPERATURE"))

    # A RUNNING plan row whose UpdatedAt is older than this is treated as abandoned. UpdatedAt is
    # bumped before every LLM attempt, so this measures "no progress", not wall time.
    # ponytail: staleness-on-next-POST instead of a reaper sweep; add a sweep if operators need
    # stuck plans auto-flipped to ERROR without a user click.
    treatment_stale_seconds: int = Field(
        900, ge=60, validation_alias=AliasChoices(
            "TREATMENT_STALE_SECONDS", "TSG_TREATMENT_STALE_SECONDS"))

    # --- Optional safety features (litellm proxy only, both off by default) ---
    # A soft flag for a human reviewer, NEVER a hard block — this app's whole job is describing
    # attacks and breaches, which some moderation categories would misfire on.
    llm_moderation_enabled: bool = Field(
        False, validation_alias=AliasChoices("LLM_MODERATION_ENABLED", "TSG_LLM_MODERATION_ENABLED"))

    # Unset = let the proxy pick its default.
    llm_moderation_model: str | None = Field(
        None, validation_alias=AliasChoices("LLM_MODERATION_MODEL", "TSG_LLM_MODERATION_MODEL"))

    # Proxy-side safety filters (e.g. prompt-injection detectors) run on every chat call.
    llm_guardrails: list[str] | None = Field(
        None, validation_alias=AliasChoices("LLM_GUARDRAILS", "TSG_LLM_GUARDRAILS"))

    # --- Embedding & reranker (models + providers) ---
    # A model name (proxy) or a local file path (EMBEDDING_PROVIDER=local).
    embedding_model: str = Field(
        "multilingual-e5-large", validation_alias=AliasChoices("EMBEDDING_MODEL", "TSG_EMBEDDING_MODEL"))
    reranker_model: str = Field(
        "bge-reranker-v2-m3", validation_alias=AliasChoices("RERANKER_MODEL", "TSG_RERANKER_MODEL"))
    # Leave unset to follow llm_provider automatically (_derive_embedding_reranker_provider below).
    embedding_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("EMBEDDING_PROVIDER", "TSG_EMBEDDING_PROVIDER"))
    embedding_dimensions: int = Field(
        1024, validation_alias=AliasChoices("EMBEDDING_DIMENSIONS", "TSG_EMBEDDING_DIMENSIONS"))
    # 'mongo' survives restarts; 'memory' is this process only. Falls back to memory automatically
    # if Mongo is unreachable.
    embedding_store: Literal["memory", "mongo"] = Field(
        "mongo", validation_alias=AliasChoices("EMBEDDING_STORE", "TSG_EMBEDDING_STORE"))
    # Some models expect a "query:"/"passage:" prefix. 'auto' turns this on for e5-family models.
    embedding_prefix_style: Literal["auto", "e5", "none"] = Field(
        "auto", validation_alias=AliasChoices("EMBEDDING_PREFIX_STYLE", "TSG_EMBEDDING_PREFIX_STYLE"))
    # How similar (0-1) an AI-proposed threat must be to a library entry to be a possible match.
    semantic_match_threshold: float = Field(
        0.60, validation_alias=AliasChoices("SEMANTIC_MATCH_THRESHOLD", "TSG_SEMANTIC_MATCH_THRESHOLD"))
    # Same "follows llm_provider unless set" rule as embedding_provider above.
    reranker_provider: Literal["litellm_proxy", "local"] = Field(
        "local", validation_alias=AliasChoices("RERANKER_PROVIDER", "TSG_RERANKER_PROVIDER"))

    # --- Local model runtime (only when embedding/reranker provider = 'local') ---
    local_model_cache_size: int = 4
    # gevent's native thread pool (local_models.py::_offload); 10 is gevent's own default.
    # Independent of Celery's -c.
    local_model_threadpool_size: int = 10

    # --- Grounding: how much to trust an AI-proposed threat's match to the library (0-100) ---
    # ONE cutoff, two bands: at or above it a threat is `verified`; below it `unverified` (novel —
    # still scenario-generated, and the input to library promotion on accept).
    # MODEL-SPECIFIC. Leave it UNSET (the normal case): the app auto-calibrates per
    # embedding+reranker model from the live library (grounding.resolve_thresholds), so a model
    # change can never silently run on a number tuned for a different model. Setting it in env
    # disables auto-calibration.
    grounding_match_threshold: float = 75.0
    # How many of the closest-matching library entries get a second-pass check.
    grounding_shortlist_k: int = 10

    # --- Library curation: which threats get promoted into the shared library on accept ---
    # A SEPARATE knob from grounding_match_threshold on purpose — the two answer unrelated
    # questions: that one asks "do we trust this match enough to use the library's wording and
    # ids?", this one asks "should this threat be ADDED to the library permanently?". accept.py
    # selects on SCORE against this value, never on the grounding band.
    library_promotion_threshold: float = 75.0

    # --- Step 4: control library mapping (control_mapping.map_controls / grounding.ground_control_queries) ---
    # Most controls kept per scenario ("up to K", never padded with weak matches) — also the cap on
    # how many control suggestions the scenario prompt asks the LLM for.
    control_map_top_k: int = Field(5, ge=1)
    # A suggestion whose best library match reranks below this is dropped — an honest empty list
    # beats force-fitting the least-bad control. LEAVE UNSET: the cutoff then follows the
    # per-(embedding, reranker)-pair MATCH threshold, so a model swap re-derives it. Setting this in
    # env pins a static cutoff (control_mapping._min_score); the 60.0 is only that pinned value's
    # default, never the unset fallback.
    control_map_min_score: float = Field(60.0, ge=0.0, le=100.0)
    # How many remote rerank calls llm.rerank_many runs at once (LOCAL politeness cap only — every
    # call still takes its own _llm_slot, so the Redis semaphore stays the global authority).
    # Irrelevant for the local reranker, which batches all pairs into one dispatch.
    rerank_concurrency: int = Field(8, ge=1)

    # --- Threat proposal volume ---
    # Most candidate threats the AI can propose for ONE ASSET in a single call.
    # `TSG_MAX_THREATS_PER_SUBSYSTEM` still works as a back-compat env var for the same value.
    max_threats_per_asset: int = Field(
        10, validation_alias=AliasChoices("TSG_MAX_THREATS_PER_ASSET", "TSG_MAX_THREATS_PER_SUBSYSTEM"))

    # How many scenarios one threat identity accumulates is NOT configured — it is DERIVED, in
    # dal.variant_eligible_primaries, as the number of supporting systems that could credibly carry
    # that threat to the asset. A 2-system asset finishes in two scenarios, an 8-system one earns eight.
    #
    # This slack is a NON-TERMINATION GUARD, not a depth policy: nothing binds the model to the
    # entry point it was asked to write about, so it can answer every request with the same one and
    # leave a cell open forever. An identity therefore stops at (its own plausible-entry-point count
    # + this slack). Raising it gives the model more chances to reach an awkward entry point; it can
    # never make analysis shallower.
    coverage_attempt_slack: int = Field(2, ge=0)

    # How many of a threat's existing scenarios are quoted back into the variant prompt, newest
    # first. A prompt-WIDTH bound ("how many examples does the model need to write something
    # different"), deliberately separate from generation depth above and from grounding_shortlist_k
    # — sharing either would mean tuning one silently reshapes the other.
    variant_sibling_prompt_k: int = Field(3, ge=1)

    # Batch size of one "generate next set" click (scenarios served/generated per call).
    next_set_size: int = Field(5, ge=1)

    # Session-tunable FLOOR into the single semantic-dedup bar. The effective cutoff every pair is
    # judged at is max(semantic_cross_category_threshold, this) — category-blind by design: a shared
    # STRIDE category is a ~1-in-6 coincidence, and judging same-category pairs at a lower bar
    # merged distinct threats that merely share vocabulary. Set to 1.0 to disable the gate without
    # a deploy — new sessions snapshot it, running ones keep the value they started with.
    # EMBEDDING-MODEL-SPECIFIC: a value tuned for e5-large@1024 means nothing on qwen3-8b@4096.
    semantic_near_duplicate_threshold: float = Field(0.92, ge=0.0, le=1.0)

    # BASE of that same bar: cosine at or above which a proposed threat is DROPPED as a restatement
    # of one the session already has, whatever the categories involved. The identity fold above it
    # is exact/ID-only, so without this gate the same threat in different words survives as two
    # rows and costs two paid generations. 0.98 sits safely above the measured 0.969 trap —
    # 'Unauthorized disclosure of X' vs 'Unauthorized modification of X', two REAL threats one word
    # apart (embeddings weigh shared words heavily) — while still catching true paraphrases and
    # relabelled restatements. Must stay ABOVE both 0.969 and the tunable floor above — the
    # validator below enforces the ordering at boot.
    semantic_cross_category_threshold: float = Field(0.98, ge=0.0, le=1.0)

    # --- Threat-scoping selection cutoff ---
    # A threat scoring below this doesn't get a full scenario written for it.
    scoping_score_threshold: float | None = Field(55.0, ge=0.0, le=100.0)

    # --- Scoring & calibration (business values — no literals in pipeline code) ---
    # Every threat's score starts here. Coupled to scoping_score_threshold and default_rule_weight
    # by _validate_scoring_floor_invariant below — read that before changing any of the three.
    base_score: float = Field(50.0, ge=0.0, le=100.0)
    # relevance_* rule delta when the rule's Metadata carries no explicit {"weight": N}.
    default_rule_weight: float = Field(10.0)
    # difflib ratio at/above which a scenario is flagged as a near-duplicate of a sibling or of
    # another threat's scenario (a reviewer warning, not a rejection).
    sibling_similarity_ratio: float = Field(0.85, ge=0.0, le=1.0)
    # Advisories injected per scenario prompt. Raising it raises tokens per LLM call.
    prompt_intel_limit: int = Field(5, ge=0)
    # Shortest word (chars) that participates in intel keyword search; shorter terms only add noise.
    intel_min_term_length: int = Field(4, ge=1)
    # Weight of the auto-written OT relevance rules (threat_library_import.apply_ot_rules).
    # Boost-only by design — auto-rules never write a tech_gate.
    auto_ot_relevance_weight: float = Field(10.0)
    # Reranker score at/above which two CATALOGUE entries are treated as the same idea during
    # threshold auto-calibration (grounding.resolve_thresholds gives up separating them).
    near_duplicate_score: float = Field(99.0, ge=0.0, le=100.0)
    # Library-promotion triage bands: cosine of a candidate generic name to its nearest active
    # catalogue entry. >= reject band → auto-reject (same idea, reworded); < approve band →
    # auto-approve; between → human review. EMBEDDING-MODEL-SPECIFIC estimates — recalibrate from
    # the accept-time audit rows after any embedding model change.
    triage_auto_reject_cosine: float = Field(0.95, ge=0.0, le=1.0)
    triage_auto_approve_cosine: float = Field(0.80, ge=0.0, le=1.0)

    # Only the highest-scoring N unique threats get a scenario written. None (default) = no limit.
    #
    # Be honest about what the default leaves running: with None here, the ONLY things that drop a
    # threat are its tech_gate and the identity/semantic dedup in find_threats. The duplicate branch
    # in tasks._select_unique_top_n is an invariant alarm that should never fire (duplicates are
    # folded upstream), and scoping_score_threshold (55) sits below the lowest reachable score
    # (base 50 + unverified 15 = 65) with no negative rule weight seeded anywhere — so it rejects
    # nothing either.
    scoping_top_n: int | None = Field(None, ge=1)

    # --- Threat-library import (admin) ---
    # Max size of an uploaded library file, in MB. Sized against the largest source:
    # enterprise-attack.json is ~51 MB raw and larger again JSON-escaped into a body, so anything
    # near 50 makes the air-gapped upload path unusable (413 in BodySizeLimitMiddleware, before
    # parsing). A guard against an accidental huge upload, not a memory bound — the file rides the
    # Redis broker as a string either way (api/threat_library_import.py::_enqueue).
    threat_library_import_max_upload_mb: int = Field(128, ge=1)

    # --- Session capacity limits ---
    # Most sessions processed at the same time. New requests are rejected past this.
    max_active_sessions: int = 0 # 100

    # Most sessions any ONE entity can have active at once. 0 (default) = no per-entity cap, only
    # the global ceiling above applies — one entity looping on session creation can then exhaust it
    # for every other entity in the tenant.
    max_active_sessions_per_entity: int = 0

    capacity_retry_after_seconds: int = 10

    # --- LLM concurrency slots (shared across all workers via Redis) ---
    # Ceiling on concurrent AI calls across all workers. 0 = no limit (default).
    max_concurrent_llm_calls: int = 0

    # How long an AI call waits for a free slot before it's rejected (and retried automatically).
    llm_slot_wait_timeout_seconds: float = 30.0
    llm_slot_heartbeat_seconds: float = 10.0
    # Without a signal for this long, a call is assumed crashed and its slot freed.
    llm_slot_stale_after_seconds: float = 30.0
    llm_slots_warn_ratio: float = 0.8
    llm_slot_redis_timeout_seconds: float = 3.0

    # --- Stage lease, reaper & retries ---
    # How long one step of work can run before it's assumed crashed and cleaned up. Derived from
    # llm_timeout_seconds/llm_max_retries unless set explicitly (_derive_stage_lease_seconds below).
    stage_lease_seconds: int = 300

    reaper_interval_seconds: float = 60.0

    # How long a session with NO live lease (never started, or its lease already cleared) must sit
    # untouched before the cleanup job treats it as abandoned. Defaults to stage_lease_seconds.
    # "Was it set explicitly" is answered via `model_fields_set`, not a None sentinel — hence the
    # plain `float` default rather than `float | None`.
    reaper_stale_grace_seconds: float = 300.0

    stage_max_attempts: int = 5

    # --- Library-promotion retry (accept.py's isolated Phase 2 / reaper.py's promotion sweep) ---
    promotion_retry_interval_seconds: float = 60.0

    # A session stops being auto-retried after this many failed attempts, staying visible via the
    # admin API for manual follow-up. Read ONLY by the sweep's candidate query — never inside
    # retry_one_promotion itself, so a manual admin retry is never blocked by this cap.
    promotion_max_attempts: int = 5

    # True (default): the periodic sweep retries a failed promotion automatically. False: failures
    # only wait for an admin to retry them via POST /v1/tsg/sessions/promotions/{id}/retry.
    promotion_auto_retry_enabled: bool = True

    # Max sessions one sweep pass retries — bounds a single pass's runtime; any remainder is
    # picked up on the next scheduled tick rather than growing one pass unboundedly.
    promotion_sweep_batch_limit: int = 200

    # Also the admin list endpoint's default page size (bounded separately per-request up to
    # promotion_list_max_limit) — same "don't return something unbounded" reasoning either way.
    promotion_list_max_limit: int = 500

    # False (default): a "genuinely novel" triage verdict queues for admin review instead of
    # minting into the shared library immediately. True restores today's auto-mint behavior.
    promotion_auto_approve_enabled: bool = False

    # --- Health monitoring / self-check ---
    self_check_interval_seconds: float = 300.0
    tempdb_version_store_warn_mb: int = 1024
    tempdb_long_txn_warn_seconds: int = 300
    active_sessions_warn_ratio: float = 0.9
    pool_utilization_warn_ratio: float = 0.9

    # --- SSE (live session updates to the browser) ---
    sse_ping_seconds: int = Field(15, gt=0)  # 0 floods pings; negative 500s every connect
    sse_breaker_cooldown_seconds: float = 30.0
    sse_publish_timeout_seconds: float = 1.0
    sse_subscribe_connect_timeout_seconds: float = 2.0
    # Sizes BOTH the shared Redis connection pool (bus.py) and the per-process semaphore gating
    # session_events() — one value, not two, so the semaphore can never admit more streams than
    # the pool has connections for.
    sse_max_concurrent_streams: int = 180
    # A stalled SSE consumer is force-closed within this long, not left open for ~15 minutes.
    sse_send_timeout_seconds: float = 30.0
    # Bounded drain window on shutdown — under gunicorn's 30s graceful-timeout (with margin), so
    # open streams get a chance to close cleanly instead of an instant cut on every rollout.
    sse_shutdown_grace_seconds: float = 25.0
    # Read timeout / liveness check on the shared subscriber connection pool.
    sse_subscriber_socket_timeout_seconds: float = 10.0
    sse_subscriber_health_check_interval_seconds: float = 30.0

    # --- CORS (browser-based external consumers) ---
    # Empty (default) = no cross-origin browser access. Set per environment.
    cors_allowed_origins: list[str] = Field(default_factory=list)

    # --- Admin API ---
    # Unlocks the admin-only threat-library endpoints. Empty (default) = disabled.
    admin_api_key: str = Field(
        "", validation_alias=AliasChoices("ADMIN_API_KEY", "TSG_ADMIN_API_KEY"))

    # --- API authentication (Shield -> TSG, header model) ---
    # Shield sends X-API-Key (authenticates the caller) + X-User-Id + X-Entity-Id on every call.
    # When True, each request's (user, entity) pair is additionally verified against
    # user_scope_assignment (defence-in-depth). Default False: authenticate the caller by
    # X-API-Key only and take the identity headers on trust. Flip to True once the production
    # user_scope_assignment / scope_type mapping is confirmed. See app/api/deps.get_principal.
    verify_membership: bool = Field(
        False, validation_alias=AliasChoices("VERIFY_MEMBERSHIP", "TSG_VERIFY_MEMBERSHIP"))

    # --- Celery task dashboard (Flower) ---
    # "user:password" for Flower's --basic-auth. Read by docker/compose.prod.yml and start.ps1,
    # never by Python — Flower is a separate `celery flower` process, not part of this app. It
    # lives here anyway so config stays discoverable in one surface and env_selfcheck enforces
    # its presence in every .env template.
    # Flower has NO auth by default and exposes task revoke/terminate, so the prod compose
    # service refuses to start while this is empty. Local dev binds to 127.0.0.1 and may leave
    # it unset.
    flower_basic_auth: str = Field(
        "", validation_alias=AliasChoices("FLOWER_BASIC_AUTH", "TSG_FLOWER_BASIC_AUTH"))

    # (Auth is the header model — X-API-Key + X-User-Id + X-Entity-Id, see app/api/deps.py.
    # The old jwt_* / auth_dev_mode settings are retired in _RETIRED_SETTINGS above.)

    # --- Promoted from hardcoded module constants (each default is UNCHANGED from its former
    # hardcoded value, so leaving these unset in env reproduces prior behaviour exactly) ---

    # app/pipeline/grounding.py::_auto_calibrate — how many library entries the boot-time
    # threshold auto-calibration samples. _auto_calibrate itself already requires >=5 to attempt
    # anything.
    calibration_sample_size: int = Field(100, ge=5)
    # app/pipeline/grounding.py::_paraphrase — LLM rewordings generated per sampled name
    # (the auto-labelled calibration POSITIVES).
    calibration_paraphrases_per_name: int = Field(2, ge=1)

    # app/pipeline/embeddings.py::_group_lock — Redis mutex TTL guarding a group's embedding
    # cache rebuild. MUST stay an int: redis-py rejects a float for SET's ex=/EXPIRE (DataError).
    embedding_group_lock_ttl_seconds: int = Field(30, ge=1)
    # app/pipeline/embeddings.py::_store_if_healthy — circuit-breaker cooldown before retrying
    # the Mongo vector store after a connection failure.
    mongo_breaker_cooldown_seconds: float = Field(30.0, ge=0.0)
    # app/pipeline/embeddings.py::_embed_missing (also app/pipeline/control_mapping.py's own
    # query-priming loop) — max texts per external embed() call, so one oversized batch can't
    # exceed a provider's own limit and fail an entire group with zero progress.
    embedding_batch_size: int = Field(100, ge=1)

    # app/pipeline/llm.py::_llm_slot — poll interval / jitter while waiting for a free LLM
    # concurrency slot. Jitter avoids synchronized thundering-herd wakeups.
    llm_slot_poll_seconds: float = Field(0.25, gt=0.0)
    llm_slot_poll_jitter_seconds: float = Field(0.1, ge=0.0)
    # app/pipeline/llm.py::embed()/chat() — safety caps against pathological input (e.g. a whole
    # document routed into a short field). Not expected to trip on real text.
    max_embed_chars: int = Field(4000, ge=1)
    max_chat_chars: int = Field(60_000, ge=1)

    # app/pipeline/treatment.py — per-field cap on UI-supplied free text at snapshot time.
    # Defense-in-depth behind the Pydantic max_length bounds already enforced at the API boundary.
    treatment_free_text_cap: int = Field(2000, ge=1)

    # app/pipeline/reaper.py::_split_into_batches — max ids per SQL IN-list chunk when
    # batch-processing crashed sessions. Bounded well under SQL Server's ~2100-param hard limit.
    reaper_sql_in_chunk_size: int = Field(1000, ge=1, le=2000)

    # app/pipeline/celery_app.py::_init_worker — retry count/backoff for the litellm-model and
    # grounding-threshold warm-up checks at worker boot.
    llm_verify_max_attempts: int = Field(3, ge=1)
    llm_verify_retry_backoff_seconds: float = Field(5.0, ge=0.0)

    # app/pipeline/accept.py::_unacceptable_subset — max offending ids named in the human-
    # readable 404 message (details.unacceptable in the response always carries every one).
    accept_named_in_message: int = Field(3, ge=1)

    # app/pipeline/threat_library_import.py::_is_abandoned — window after which a "running"
    # import row is treated as abandoned. Should match the Celery broker's visibility_timeout
    # (currently 3600s, set directly in celery_app.py's conf.update) — past it, the message has
    # already been redelivered or abandoned, so no live worker still holds the row.
    library_import_stale_after_seconds: int = Field(3600, ge=1)
    # app/pipeline/threat_library_import.py::run_import — max skipped-item entries returned in an
    # import result payload (full counts are always reported; this only bounds a huge STIX bundle
    # from ballooning the Celery result backend payload).
    library_import_skipped_cap: int = Field(50, ge=0)

    # app/pipeline/tasks.py::_usable_proposal — max combined type+name chars for an LLM-proposed
    # threat to be usable. Kept <= max_embed_chars by the validator below: embed() errors (never
    # truncates) over that limit, which would lose every threat in the batch, not just the long one.
    max_proposal_chars: int = Field(3500, ge=1)

    @model_validator(mode="after")
    def _validate_proposal_below_embed_cap(self) -> "Settings":
        """max_proposal_chars must stay <= max_embed_chars: embed() errors (never truncates) on
        an over-limit text, which would lose every threat in the batch, not just the long one."""
        if self.max_proposal_chars > self.max_embed_chars:
            raise ValueError(
                f"max_proposal_chars ({self.max_proposal_chars}) must not exceed max_embed_chars "
                f"({self.max_embed_chars}) — embed() errors on an over-limit text instead of "
                "truncating it, which would lose every threat in the batch.")
        return self

    @model_validator(mode="after")
    def _derive_embedding_reranker_provider(self) -> "Settings":
        """Unset embedding/reranker providers follow llm_provider=litellm_proxy, so one setting
        switches the whole deployment. Setting either explicitly always overrides."""
        if self.llm_provider == "litellm_proxy":
            if "embedding_provider" not in self.model_fields_set:
                self.embedding_provider = "litellm_proxy"
            if "reranker_provider" not in self.model_fields_set:
                self.reranker_provider = "litellm_proxy"
        return self

    @model_validator(mode="after")
    def _derive_stage_lease_seconds(self) -> "Settings":
        """Both progress clocks must outlast a full retry chain, or a healthy slow worker reads as
        crashed. Unset → derive; explicit-but-below-floor → refuse to start."""
        floor = self.llm_timeout_seconds * (self.llm_max_retries + 1)
        if "stage_lease_seconds" not in self.model_fields_set:
            self.stage_lease_seconds = int(floor * 2)
        elif self.stage_lease_seconds < floor:
            raise ValueError(
                f"stage_lease_seconds ({self.stage_lease_seconds}s) is below the safe floor "
                f"({floor:.0f}s = llm_timeout_seconds * (llm_max_retries + 1)) — a genuinely "
                "slow (not crashed) call could be wrongly reaped. Raise it above the floor.")
        # Same floor for the treatment-plan clock: below it, a live worker's row gets superseded and
        # a SECOND paid LLM call runs in parallel.
        if "treatment_stale_seconds" not in self.model_fields_set:
            self.treatment_stale_seconds = max(self.treatment_stale_seconds, int(floor * 2))
        elif self.treatment_stale_seconds < floor:
            raise ValueError(
                f"treatment_stale_seconds ({self.treatment_stale_seconds}s) is below the safe "
                f"floor ({floor:.0f}s = llm_timeout_seconds * (llm_max_retries + 1)) — a "
                "slow-but-live plan attempt would be superseded and re-run in parallel. "
                "Raise it above the floor.")
        return self

    @model_validator(mode="after")
    def _bind_scenario_count_to_threat_count(self) -> "Settings":
        """scoping_top_n can never exceed max_threats_per_asset. Thin headroom (< 1.25x candidates
        per target scenario) only warns — the gap IS the headroom knob, no separate setting."""
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
            # Lazy import avoids a config<->logging import cycle (logging imports config).
            from app.core.logging import get_logger
            get_logger(__name__).warning(
                "config.thin_dedup_headroom", scoping_top_n=top_n,
                max_threats_per_asset=self.max_threats_per_asset,
                note="fewer than 1.25x candidate threats per target scenario — catalogue dedup "
                    "may under-shoot scoping_top_n when the model repeats threats")
        return self

    @model_validator(mode="after")
    def _validate_coverage_knobs(self) -> "Settings":
        """A coverage knob setting can be valid but operationally useless. Warn only."""
        from app.core.logging import get_logger  # lazy: logging imports config
        if self.semantic_near_duplicate_threshold < 0.5:
            get_logger(__name__).warning(
                "config.semantic_threshold_floods",
                semantic_near_duplicate_threshold=self.semantic_near_duplicate_threshold,
                note="below ~0.5 nearly every threat pair matches — the near-duplicate log stops "
                    "being a signal and cannot be used to calibrate a real cutoff")
        # Same 1.25 headroom rule the scoping_top_n validator applies. Warning, never a raise:
        # a config that boots today must keep booting.
        if self.max_threats_per_asset < self.next_set_size * 1.25:
            get_logger(__name__).warning(
                "config.thin_next_set_headroom",
                next_set_size=self.next_set_size,
                max_threats_per_asset=self.max_threats_per_asset,
                note="cascade._buffered_ask caps the additive ask at max_threats_per_asset, so a "
                    "next-set click loses its 2x dedup cushion and will under-deliver more often")
        return self

    @model_validator(mode="after")
    def _derive_reaper_stale_grace_seconds(self) -> "Settings":
        """Unset → follows stage_lease_seconds. Must stay ordered AFTER _derive_stage_lease_seconds
        to read that field's DERIVED value, not its 300-second class default."""
        if "reaper_stale_grace_seconds" not in self.model_fields_set:
            self.reaper_stale_grace_seconds = self.stage_lease_seconds
        return self

    @model_validator(mode="after")
    def _validate_semantic_threshold_ordering(self) -> "Settings":
        """Cross-category ceiling must sit at or above the same-category threshold — inverted, the
        0.969 disclosure/modification pair silently folds into one threat."""
        if self.semantic_cross_category_threshold < self.semantic_near_duplicate_threshold:
            raise ValueError(
                f"semantic_cross_category_threshold ({self.semantic_cross_category_threshold}) is "
                f"below semantic_near_duplicate_threshold ({self.semantic_near_duplicate_threshold}) "
                "— cross-class pairs would merge more eagerly than same-class ones. Raise the "
                "cross ceiling above the same-category threshold (and keep it above the measured "
                "0.969 cross-class trap).")
        return self

    @model_validator(mode="after")
    def _validate_scoring_floor_invariant(self) -> "Settings":
        """scoping_score_threshold must sit between base_score and base_score + default_rule_weight,
        so the rule stays "no rule vouched → drop; any rule vouched → keep". Breaking that from .env
        silently drops threats a rule DID match, so it hard-fails. Fix 9's session-snapshot resolver
        re-runs the same arithmetic on Config_Tuning overrides."""
        if self.scoping_score_threshold is None:
            return self  # None = "no cutoff, keep everything, rank only" — neither check applies
        if self.base_score + self.default_rule_weight <= self.scoping_score_threshold:
            raise ValueError(
                f"scoping_score_threshold ({self.scoping_score_threshold}) is at or above "
                f"base_score ({self.base_score}) + default_rule_weight "
                f"({self.default_rule_weight}) = {self.base_score + self.default_rule_weight} — "
                "a threat that a scoping rule DID match would still be dropped. Lower the "
                f"threshold below {self.base_score + self.default_rule_weight}, or raise the "
                "weight.")
        if self.scoping_score_threshold <= self.base_score:
            # Legitimate ("keep everything, rank only") but almost certainly unintended —
            # every threat starts at base_score, so this floor can never reject anything.
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
    def _validate_triage_bands(self) -> "Settings":
        """approve < reject — the gap between them IS the human-review band. Equal or inverted
        bands auto-approve and auto-reject the same cosine on a shared global library."""
        if self.triage_auto_approve_cosine >= self.triage_auto_reject_cosine:
            raise ValueError(
                f"triage_auto_approve_cosine ({self.triage_auto_approve_cosine}) must be below "
                f"triage_auto_reject_cosine ({self.triage_auto_reject_cosine}) — the gap between "
                "them IS the human-review band; equal or inverted bands make automation "
                "contradict itself.")
        return self

    @model_validator(mode="after")
    def _validate_llm_slot_heartbeat_margin(self) -> "Settings":
        """stale_after must be >= 2x heartbeat: the heartbeat thread's FIRST renewal fires after a
        full interval, so any closer and a live call's ticket is pruned before it ever renews."""
        if self.llm_slot_stale_after_seconds < self.llm_slot_heartbeat_seconds * 2:
            raise ValueError(
                f"llm_slot_stale_after_seconds ({self.llm_slot_stale_after_seconds}s) is too close "
                f"to llm_slot_heartbeat_seconds ({self.llm_slot_heartbeat_seconds}s) — a still-"
                "running call's ticket could be pruned before its first heartbeat renews it. "
                "Keep stale_after at least 2x heartbeat.")
        return self

    @model_validator(mode="after")
    def _validate_promotion_below_match(self) -> "Settings":
        """promotion <= match, or a `verified` threat gets promoted, duplicating the entry it just
        matched. Defence in depth only: this compares STATIC settings, while the runtime cutoff is
        auto-calibrated per model pair. The structural guards are grounding withholding a
        ThreatCatalogueID unless the name match verified, and accept.py never minting a
        Threat_Catalogue row from a proposed name."""
        if self.library_promotion_threshold > self.grounding_match_threshold:
            raise ValueError(
                f"library_promotion_threshold ({self.library_promotion_threshold}) must not exceed "
                f"grounding_match_threshold ({self.grounding_match_threshold}) — otherwise a "
                "`verified` threat gets promoted, duplicating the library entry it just matched.")
        return self


@lru_cache
def get_settings() -> Settings:
    """The one shared settings object, built once. The retired-setting check runs here rather than
    as a validator because pydantic discards unknown keys before a validator sees them."""
    _reject_retired_settings()
    return Settings()


def assert_security_posture(settings: Settings | None = None) -> None:
    """Startup safety check for the header auth model. The real gate — that at least one API key
    is provisioned — is a DB check in db.invariants.verify_startup (it needs the engine). Here we
    only surface the one silent-misconfiguration risk that has no other alarm: running in
    staging/prod with the defence-in-depth (user, entity) DB check turned OFF."""
    s = settings or get_settings()
    if s.app_env in ("staging", "prod") and not s.verify_membership:
        # Not fatal — Phase A (key-only) is a legitimate posture — but it must never be silent.
        from app.core.logging import get_logger
        get_logger(__name__).warning(
            "auth.membership_check_disabled",
            app_env=s.app_env,
            note="TSG_VERIFY_MEMBERSHIP is OFF: X-User-Id/X-Entity-Id are trusted, not verified "
                "against user_scope_assignment. Set TSG_VERIFY_MEMBERSHIP=true once the prod "
                "scope table is confirmed.")


def assert_sse_graceful_shutdown_wired(get_signal_handler=None) -> None:
    """Startup safety check for item 21. sse_starlette's own graceful-shutdown fallback
    (`_shutdown_watcher`/`_get_uvicorn_server` in sse_starlette/sse.py) is already correct given
    the current server — it works by introspecting the LIVE SIGTERM handler,
    `signal.getsignal(signal.SIGTERM).__self__`, to find the running uvicorn `Server` instance
    when its own monkey-patch of `Server.handle_exit` hasn't taken. That introspection depends on
    this process actually being driven by uvicorn's `Server.serve()` (bare uvicorn, or gunicorn
    via `uvicorn.workers.UvicornWorker` — both install the SIGTERM handler in
    `Server.capture_signals()` before the ASGI lifespan startup we run from ever fires). We run
    the EXACT SAME introspection here, at boot, so a future switch away from that worker class
    (e.g. a plain WSGI/sync gunicorn worker, or some other ASGI server) fails loudly instead of
    silently losing graceful SSE shutdown.

    Deliberately NOT "is uvicorn importable": uvicorn is a hard dependency of this app regardless
    of which worker class actually drives the event loop (gunicorn's `-k` flag just names a
    class), so an import check would pass even after the worker class drifted away from uvicorn —
    exactly the silent failure this assertion exists to catch."""
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
            "uvicorn.workers.UvicornWorker) — see this function's docstring.")
