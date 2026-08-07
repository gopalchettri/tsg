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

    Fails LOUDLY when TSG_ENV_FILE names a file that does not exist: falling back to `.env`
    would silently run this deployment on another environment's config (dev provider, dev
    model, AUTH_DEV_MODE on) with nothing erroring."""
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
}


def _reject_retired_settings() -> None:
    """Fail startup when the environment still sets a setting that no longer exists.

    Reads os.environ AND the resolved .env file: pydantic has merged both by the time a validator
    could run, but it discards unknown keys, so by then the evidence that the operator set
    anything is already gone."""
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
    intel_enabled: bool = True

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
    # OTX pagination (app/intel/otx.py). The subscription is ~8.9k pulses over ~178 pages and
    # deep pages are slow (measured 1.8s at page 1, 35-46s past page 40), so ONE run cannot walk
    # it all — each run works for a time budget and the next resumes from the stored cursor.
    intel_otx_page_size: int = 50        # OTX's hard cap; larger `limit` values are ignored
    intel_otx_max_pages: int = 200       # safety bound on the walk (178 pages real today)
    # Per-run wall-clock budget. MUST stay well under intel_refresh_feed_task's soft_time_limit
    # (600s): the deadline is checked between pages and a single deep page can take 45s, or up to
    # the 120s socket timeout when OTX stalls.
    intel_otx_sync_seconds: int = 400
    # Head pages re-read on EVERY run. The rolling cursor reaches page 1 only once per cycle
    # (~9 days at the daily cadence), so without this a pulse published today would not be
    # cached until the cursor came back around.
    intel_otx_fresh_pages: int = 2

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

    # Optional ALTERNATE header to carry that key, e.g. "x-litellm-api-key". Empty (default) =
    # standard `Authorization: Bearer <key>`. Set it when a gateway in front of litellm
    # consumes/rewrites `Authorization` (symptom: every call 401s). The key is then sent in BOTH
    # headers, so it works either side of such a gateway.
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

    # Same idea, for the scenario-writing step. Unset (default) = provider's default, NOT 0.0
    # like the threat step: the same call serves variant generation, where a pinned-0
    # temperature works against the "MEANINGFULLY DIFFERENT" sibling steering.
    scenario_generation_temperature: float | None = Field(
        None, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "SCENARIO_GENERATION_TEMPERATURE", "TSG_SCENARIO_GENERATION_TEMPERATURE"))

    # How much "thinking effort" the AI spends per reply. Unset = provider's own default.
    llm_reasoning_effort: Literal["low", "medium", "high"] | None = Field(
        None, validation_alias=AliasChoices("LLM_REASONING_EFFORT", "TSG_LLM_REASONING_EFFORT"))

    # --- Risk Treatment Plan generation (docs/RISK_TREATMENT_PLAN_SDD.md) ---
    # Master switch. Off (default) = the treatment-plan routes are not mounted at all. On =
    # routes mount; nothing else is armed — the register's risk data arrives in the request
    # body, so no external tables are required.
    risk_module_enabled: bool = Field(
        False, validation_alias=AliasChoices("RISK_MODULE_ENABLED", "TSG_RISK_MODULE_ENABLED"))

    # Same idea as threat_identification_temperature, for the treatment-plan step. 0 = repeatable
    # plans for identical inputs — these land in a risk register, consistency beats creativity.
    treatment_temperature: float | None = Field(
        0.0, ge=0.0, le=2.0, validation_alias=AliasChoices(
            "TREATMENT_TEMPERATURE", "TSG_TREATMENT_TEMPERATURE"))

    # A RUNNING plan row whose UpdatedAt is older than this is treated as abandoned: the next
    # POST may supersede it, a redelivery may re-claim it, and the GET presents it as timed out.
    # UpdatedAt is bumped before every LLM attempt, so this measures "no progress", not wall time.
    # ponytail: staleness-on-next-POST instead of a reaper sweep; add a sweep if operators need
    # stuck plans auto-flipped to ERROR without a user click.
    treatment_stale_seconds: int = Field(
        900, ge=60, validation_alias=AliasChoices(
            "TREATMENT_STALE_SECONDS", "TSG_TREATMENT_STALE_SECONDS"))

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
    # How many local embedding/reranker calls run at once (gevent's native thread pool — see
    # local_models.py::_offload). 10 is gevent's own default. Independent of Celery's -c.
    local_model_threadpool_size: int = 10

    # --- Grounding: how much to trust an AI-proposed threat's match to the library (0-100 scale) ---
    # ONE cutoff, two bands: at or above it a threat is `verified` (it matched an approved library
    # entry); below it `unverified` (novel — still scenario-generated, and the input to library
    # promotion on accept).
    # This cutoff is MODEL-SPECIFIC. Leave it UNSET (the normal case): the app auto-calibrates a
    # value per embedding+reranker model from the live library (grounding.resolve_thresholds), so
    # a model change can never silently run on a number tuned for a different model. Setting it in
    # env disables auto-calibration.
    grounding_match_threshold: float = 75.0
    # How many of the closest-matching library entries get a closer, second-pass check.
    grounding_shortlist_k: int = 10

    # --- Library curation: which threats get promoted into the shared library on accept ---
    # A SEPARATE knob from grounding_match_threshold on purpose. The two answer unrelated
    # questions: the match threshold asks "do we trust this match enough to use the library's
    # wording and ids?", this one asks "should this threat be ADDED to the library permanently?".
    # They were one number by accident — three bands happened to separate them — so tuning
    # matching silently changed curation volume. accept.py selects on SCORE against this value,
    # never on the grounding band, so the two can now move independently.
    library_promotion_threshold: float = 75.0

    # --- Step 4: control library mapping (control_mapping.map_controls / grounding.ground_control_queries) ---
    # Most controls kept per scenario ("up to K", never padded with weak matches) — also the
    # cap on how many control suggestions the scenario prompt asks the LLM for.
    control_map_top_k: int = Field(5, ge=1)
    # A suggestion whose best library match reranks below the cutoff is dropped — an honest
    # empty list beats force-fitting the least-bad control. LEAVE UNSET: the cutoff then follows
    # the per-(embedding, reranker)-pair MATCH threshold, so a model swap re-derives it. Setting
    # this in env pins a static cutoff (control_mapping._min_score) — the 60.0 below is only ever
    # used as that pinned value's default, never as the unset fallback.
    control_map_min_score: float = Field(60.0, ge=0.0, le=100.0)
    # How many remote rerank calls llm.rerank_many runs at once (LOCAL politeness cap only —
    # every call still takes its own _llm_slot, so the Redis semaphore stays the global
    # authority). Irrelevant for the local reranker, which batches all pairs into one dispatch.
    rerank_concurrency: int = Field(8, ge=1)

    # --- Threat proposal volume ---
    # Most candidate threats the AI can propose for ONE ASSET in a single call.
    # `TSG_MAX_THREATS_PER_SUBSYSTEM` still works as a back-compat env var for the same value.
    max_threats_per_asset: int = Field(
        10, validation_alias=AliasChoices("TSG_MAX_THREATS_PER_ASSET", "TSG_MAX_THREATS_PER_SUBSYSTEM"))

    # How many scenarios one threat identity accumulates is NOT configured — it is DERIVED, in
    # dal.variant_eligible_primaries, as the number of supporting systems the model judged could
    # credibly carry that threat to the asset (its plausible entry points). A 2-system asset
    # finishes in two scenarios, an 8-system one earns eight. This replaced
    # `max_scenarios_per_threat`, a single constant that claimed every threat in every asset in
    # every sector deserved exactly the same depth of analysis.
    #
    # This is the ONLY number left, and it is a non-termination guard, not a depth policy:
    # nothing binds the model to the entry point it was asked to write about, so it can answer
    # every request with the same one and leave a cell open forever. An identity therefore stops
    # at (its own plausible-entry-point count + this slack). Raise it to give the model more
    # chances to reach an awkward entry point; it can never make analysis shallower.
    coverage_attempt_slack: int = Field(2, ge=0)

    # How many of a threat's existing scenarios are quoted back into the variant prompt, newest
    # first. A SEPARATE knob from max_scenarios_per_threat on purpose: that one is a generation
    # policy ("how much analysis does this threat deserve"), this one is a prompt-width bound
    # ("how many examples does the model need in order to write something different"). They were
    # the same number only by accident — the cap happened to bound the prompt too — so raising
    # analysis depth silently inflated every variant and regen prompt. Deliberately NOT
    # grounding_shortlist_k either: that is a library-matching knob, and sharing it would mean
    # tuning retrieval quietly changes prompt width.
    variant_sibling_prompt_k: int = Field(3, ge=1)

    # Batch size of one "generate next set" click (scenarios served/generated per call).
    next_set_size: int = Field(5, ge=1)

    # Ceiling on the already-covered threat names fed to the additive find_threats prompt — the one
    # prompt input that GROWS with every accumulated next-set round. Steering only, never
    # enforcement: tasks.py's identity-fold dedup silently drops any re-proposed active threat, so
    # truncating this list can cost a wasted proposal but never admits a duplicate row. Raise it if
    # long-running sessions start burning proposals on threats they already have.
    coverage_exclusions_max: int = Field(50, ge=1)

    # Cosine at or above which a proposed threat is LOGGED as a probable paraphrase of one the
    # session already has. Observation only — nothing is ever rejected on this number, and it
    # must stay that way until production logs show a cutoff that separates real paraphrases from
    # genuinely distinct threats (tasks._log_semantic_near_duplicates explains why a wrong merge
    # is unrecoverable). EMBEDDING-MODEL-SPECIFIC: a value tuned for e5-large@1024 means nothing
    # on qwen3-8b@4096, so re-derive it from the logs after any embedding model change.
    semantic_near_duplicate_threshold: float = Field(0.92, ge=0.0, le=1.0)

    # --- Threat-scoping selection cutoff ---
    # A threat scoring below this doesn't get a full scenario written for it.
    scoping_score_threshold: float | None = Field(55.0, ge=0.0, le=100.0)

    # --- Scoring & calibration (business values — no literals in pipeline code) ---
    # Every threat's score starts here; grounding confidence and rule weights add on top.
    # Coupled to scoping_score_threshold and default_rule_weight by
    # _validate_scoring_floor_invariant below — read that before changing any of the three.
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
    # Library-promotion triage bands (Fix 6): cosine of a candidate generic name to its nearest
    # active catalogue entry. >= reject band → auto-reject (same idea, reworded); < approve band
    # → auto-approve; between → human review. EMBEDDING-MODEL-SPECIFIC estimates — recalibrate
    # from the accept-time audit rows after any embedding model change (see
    # semantic_near_duplicate_threshold's warning, which is the same discipline).
    triage_auto_reject_cosine: float = Field(0.95, ge=0.0, le=1.0)
    triage_auto_approve_cosine: float = Field(0.80, ge=0.0, le=1.0)

    # Only the highest-scoring N unique threats get a scenario written. None (default) = no
    # limit: every unique threat that clears scoping_score_threshold gets a scenario —
    # tasks._select_unique_top_n still demotes duplicates, the threshold still drops weak ones.
    # The old default of 5 silently abandoned the other half of every 10-threat round.
    scoping_top_n: int | None = Field(None, ge=1)

    # --- Threat-library import (admin) ---
    # Max size of an uploaded library file (the file_content field of
    # POST /v1/tsg/threat-library/sources/{source}/import), in MB. Sized against the largest
    # source: enterprise-attack.json is ~51 MB raw and larger again JSON-escaped into a body,
    # so anything near 50 makes the air-gapped upload path unusable (413 in
    # BodySizeLimitMiddleware, before parsing). A guard against an accidental huge upload, not
    # a memory bound — the file rides the Redis broker as a string either way (see
    # api/threat_library_import.py::_enqueue).
    threat_library_import_max_upload_mb: int = Field(128, ge=1)

    # --- Session capacity limits ---
    # Most sessions the app processes at the same time. New requests are rejected past this.
    max_active_sessions: int = 0 # 100

    # Most sessions any ONE entity can have active at once. 0 (default) = no per-entity cap,
    # only the global max_active_sessions above applies — one entity looping on session
    # creation can then exhaust the global ceiling for every other entity in the tenant.
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
    # cleared) must sit untouched before the cleanup job treats it as abandoned. Defaults to
    # stage_lease_seconds (see _derive_reaper_stale_grace_seconds below). "Was it set
    # explicitly" is answered via `model_fields_set`, not a None sentinel — hence the plain
    # `float` default rather than `float | None`.
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

    # Shared HS256 secret. When set, token signatures are verified with it and the
    # JWKS URL is not used (EY Shield WebAPI issues HS256 tokens with a shared key).
    jwt_secret: str = ""

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
        # Same floor, same reasoning, for the treatment-plan progress clock: one plan attempt
        # is one LLM call, whose touch_plan bump precedes up to (llm_max_retries + 1) litellm
        # tries. Below the floor, a healthy in-flight worker reads as stale — its row gets
        # superseded/re-claimed and a SECOND paid LLM call runs in parallel. Unset → derive
        # (so raising LLM_TIMEOUT_SECONDS alone can never brick a boot); explicit-but-unsafe
        # → refuse to start.
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
        """scoping_top_n can never exceed max_threats_per_asset — the pipeline can't write more
        UNIQUE scenarios than it identifies threats; hard-fail at startup on that inversion.
        Thin headroom (< 1.25x candidates per target scenario) only WARNS: catalogue dedup can
        then under-shoot scoping_top_n when the model repeats itself. The gap IS the headroom
        knob — no separate setting."""
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
        """The three coverage knobs have no cross-field inversion to hard-fail on, but two have a
        setting that is technically valid and operationally useless, so they warn.

        A near-duplicate threshold low enough to match unrelated threats turns an observation log
        into a flood and destroys the calibration data it exists to produce — cosine over real
        threat labels sits well above 0.5 even for unrelated pairs, so anything below that flags
        essentially every pair. A sibling-prompt width far above the exclusions cap means the
        variant prompt carries more history than the threat prompt is even steered by, which is
        prompt spend with nothing behind it."""
        from app.core.logging import get_logger  # lazy: logging imports config
        if self.semantic_near_duplicate_threshold < 0.5:
            get_logger(__name__).warning(
                "config.semantic_threshold_floods",
                semantic_near_duplicate_threshold=self.semantic_near_duplicate_threshold,
                note="below ~0.5 nearly every threat pair matches — the near-duplicate log stops "
                    "being a signal and cannot be used to calibrate a real cutoff")
        if self.variant_sibling_prompt_k > self.coverage_exclusions_max:
            get_logger(__name__).warning(
                "config.sibling_prompt_width_exceeds_coverage",
                variant_sibling_prompt_k=self.variant_sibling_prompt_k,
                coverage_exclusions_max=self.coverage_exclusions_max,
                note="the variant prompt quotes more sibling scenarios than the threat prompt is "
                    "steered away from — tokens spent with no coverage behind them")
        return self

    @model_validator(mode="after")
    def _derive_reaper_stale_grace_seconds(self) -> "Settings":
        """If not set explicitly, follows stage_lease_seconds. Must stay ordered AFTER
        _derive_stage_lease_seconds so it reads that field's DERIVED value, not its unresolved
        300-second class default, when both are left unset."""
        if "reaper_stale_grace_seconds" not in self.model_fields_set:
            self.reaper_stale_grace_seconds = self.stage_lease_seconds
        return self

    @model_validator(mode="after")
    def _validate_scoring_floor_invariant(self) -> "Settings":
        """scoping_score_threshold is not an independent number: it sits between base_score and
        base_score + default_rule_weight BY DESIGN, so the rule is "no scoping rule vouched for
        this threat → drop it; any rule vouched → keep it". Breaking that arithmetic from .env
        (e.g. TSG_DEFAULT_RULE_WEIGHT=3 → 50+3=53 < 55) silently drops threats a rule DID match,
        and the operator only sees "the AI found fewer threats today" — so it hard-fails.

        Runs against the values as configured; Fix 9's session-snapshot resolver re-runs the
        same arithmetic on Config_Tuning-overridden values at session creation."""
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
        """The two promotion-triage bands must leave the middle band (human review) intact:
        approve < reject. Inverted or equal bands would auto-approve and auto-reject the same
        cosine — silent, contradictory automation on a shared global library."""
        if self.triage_auto_approve_cosine >= self.triage_auto_reject_cosine:
            raise ValueError(
                f"triage_auto_approve_cosine ({self.triage_auto_approve_cosine}) must be below "
                f"triage_auto_reject_cosine ({self.triage_auto_reject_cosine}) — the gap between "
                "them IS the human-review band; equal or inverted bands make automation "
                "contradict itself.")
        return self

    @model_validator(mode="after")
    def _validate_llm_slot_heartbeat_margin(self) -> "Settings":
        """llm_slot_heartbeat_seconds must stay comfortably below llm_slot_stale_after_seconds —
        _llm_slot's heartbeat thread renews a ticket only every `heartbeat` seconds, and its
        FIRST renewal fires after a full interval, so if the two are too close another caller's
        staleness check can prune a still-running call's ticket before it ever renews once."""
        if self.llm_slot_stale_after_seconds < self.llm_slot_heartbeat_seconds * 2:
            raise ValueError(
                f"llm_slot_stale_after_seconds ({self.llm_slot_stale_after_seconds}s) is too close "
                f"to llm_slot_heartbeat_seconds ({self.llm_slot_heartbeat_seconds}s) — a still-"
                "running call's ticket could be pruned before its first heartbeat renews it. "
                "Keep stale_after at least 2x heartbeat.")
        return self

    @model_validator(mode="after")
    def _validate_promotion_below_match(self) -> "Settings":
        """library_promotion_threshold must not exceed grounding_match_threshold. Above it, a
        threat that scored high enough to be `verified` — i.e. it MATCHED a real library entry
        and is carrying that entry's ThreatCatalogueID — would still fall under the promotion
        cutoff and be promoted, minting a near-duplicate of the very entry it just matched. That
        is the failure mode that made threshold auto-calibration unwinnable, so it fails closed.

        KNOWN LIMIT: this compares the STATIC settings. The match cutoff actually applied at
        runtime is per-model-pair (grounding.resolve_thresholds auto-calibrates when this field
        is left unset), so a calibrated value below library_promotion_threshold re-opens the same
        window. Two later changes close it structurally, so this validator is now defence in
        depth rather than the only guard: grounding withholds a ThreatCatalogueID unless the name
        match itself verified, and accept.py never creates a Threat_Catalogue row from a proposed
        name at all (it queues the name for curation instead)."""
        if self.library_promotion_threshold > self.grounding_match_threshold:
            raise ValueError(
                f"library_promotion_threshold ({self.library_promotion_threshold}) must not exceed "
                f"grounding_match_threshold ({self.grounding_match_threshold}) — otherwise a "
                "`verified` threat gets promoted, duplicating the library entry it just matched.")
        return self


@lru_cache
def get_settings() -> Settings:
    """The one shared settings object every part of the app reads from. Built once, then reused.

    The retired-setting check runs HERE rather than as a model_validator because pydantic has
    already discarded unknown keys by the time a validator sees the model. It is inside the
    lru_cache, so it costs one .env read per process, not one per call."""
    _reject_retired_settings()
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
        missing = [env for env, value in (("TSG_JWT_ISSUER", s.jwt_issuer),
                                        ("TSG_JWT_AUDIENCE", s.jwt_audience)) if not value]
        if not (s.jwt_jwks_url or s.jwt_secret):
            # Either verification mode will do: JWKS (asymmetric) or shared secret (HS256).
            missing.append("TSG_JWT_JWKS_URL or TSG_JWT_SECRET")
        if missing:
            raise RuntimeError(
                f"APP_ENV={s.app_env} requires JWT verification to be fully configured; "
                f"missing: {', '.join(missing)}. Refusing to start.")
