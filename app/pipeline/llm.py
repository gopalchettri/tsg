"""litellm adapter — the single boundary to all AI models.

WHAT THIS FILE IS, IN ONE SENTENCE: this is the ONE place in the whole app
that actually talks to an AI model. Every other file that needs an AI
response goes through the functions here instead of calling Azure OpenAI /
OpenAI / litellm directly — so swapping providers, adding a safety rule, or
changing retry behavior only ever needs to happen in this one file, never in
every caller scattered across the codebase.

There is NOT one single - "which AI provider" switch. There are THREE independent switches:
- `LLM_PROVIDER`       — controls chat() (azure_openai / openai / litellm proxy)
- `EMBEDDING_PROVIDER` — controls embed()  (local in-process / litellm proxy)
- `RERANKER_PROVIDER`  — controls rerank() (local in-process / litellm proxy)
These are completely independent of each other. A real, valid setup can have
chat going through Azure while embeddings run locally on this machine and
reranking goes through the proxy — any combination is allowed. If something
here isn't behaving the way you expect, always check which of these three
settings is actually driving the code path you're looking at.

WHY EVERY CALL HAS A TIMEOUT + RETRIES: AI providers are a network
call to someone else's server, which can hang or fail. Every single call out
of this file (chat/embed/rerank) is wrapped with a bounded timeout and a
bounded retry count — so a slow/broken provider can never freeze the whole
pipeline forever; it fails after a known amount of time instead.

WHY EVERY CALL RECORDS "PROVENANCE": whenever this file gets an answer
back from an AI model, it also records exactly WHICH model answered and with
what settings (see the `Provenance` class below). This is for audit and
reproducibility — if someone asks "why did the AI say X," you can look up
exactly which model version and configuration produced that answer.

WHY THE PIPELINE TALKS TO `LLMClient` (below), NOT TO litellm DIRECTLY: the
rest of the app is written against the `LLMClient` Protocol (an interface),
never against `litellm` or `LiteLLMClient` by name. This means the test suite
can swap in a completely fake, deterministic `StubLLMClient` (defined
elsewhere, in the tests) that returns canned answers instantly with no
network call and no real AI involved — so the tests run fast, free, and
identically every time, while still exercising all the same pipeline code
that would run against a real model in production.
"""
from __future__ import annotations

import os
import random
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Protocol, Sequence
from urllib.parse import urlparse

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger(__name__)

_SLOTS_KEY = "tsg:llm:inflight"
_POLL_SECONDS = 0.25
_POLL_JITTER_SECONDS = 0.1

# Safety caps against pathological input (a bug routing a document/long field somewhere a
# short value was expected) — never expected to trip on real production text, see the
# raise sites in embed()/chat() below for the reasoning behind each number.
_MAX_EMBED_CHARS = 4000
_MAX_CHAT_CHARS = 60_000

# KEYS[1] = _SLOTS_KEY (a ZSET, one member per in-flight call); ARGV = now, stale_cutoff,
# limit, token. Single Redis-side script so "prune stale tickets, count, admit" is ATOMIC —
# no other caller can observe the count between the prune and the ZADD. Doing this as two
# separate round-trips (ZCARD then ZADD) has two bugs: (1) a waiter's own ZADD, done BEFORE
# checking capacity, counts against the very limit it's waiting to get under, so a freed slot
# never actually reaches a waiter; (2) two waiters can both see room in the same instant and
# both proceed (an admit race). One Lua script closes both at once (Redis runs it single-
# threaded, so "prune+count+decide+register" can never be interleaved with another caller's).
_ADMIT_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', ARGV[2])
local n = redis.call('ZCARD', KEYS[1])
if n < tonumber(ARGV[3]) then
    redis.call('ZADD', KEYS[1], ARGV[1], ARGV[4])
    return 1
end
return 0
"""


class LLMSlotUnavailable(Exception):
    """Raised only when _llm_slot waited the full llm_slot_wait_timeout_seconds and Redis
    POSITIVELY CONFIRMED the concurrent-call limit is still exhausted — never raised for an
    unreachable/erroring Redis (that fails open instead, see _llm_slot). Callers
    (tasks.py/cascade.py) let this propagate past their generic per-subsystem exception
    handler so Celery's autoretry_for (celery_app.py) retries the whole stage shortly,
    resuming via the same claim_stage CAS logic crash-redelivery already relies on."""


@lru_cache
def _slot_redis():
    """Cached sync Redis client DEDICATED to the LLM-slot ZSET/heartbeat traffic — deliberately
    NOT app.sse.bus._redis(), whose 1s-timeout/zero-retry tuning is right for best-effort SSE
    publish but wrong here: this traffic is a liveness signal an entire admission-control
    mechanism depends on, so a brief Redis blip must not silently kill a heartbeat and cause a
    false-stale eviction of a call that's still genuinely running."""
    import redis
    from redis.backoff import NoBackoff
    from redis.retry import Retry

    s = get_settings()
    timeout = s.llm_slot_redis_timeout_seconds
    return redis.Redis.from_url(
        s.redis_url, decode_responses=True,
        socket_connect_timeout=timeout, socket_timeout=timeout,
        retry=Retry(NoBackoff(), 1))  # one immediate retry, unlike bus._redis()'s zero


def current_llm_slot_count() -> int:
    """Current in-flight LLM-call count (post-prune) — for selfcheck.py's observability check
    only. Returns 0 if Redis is unreachable; this is an informational read, never worth
    failing a self-check over."""
    try:
        r = _slot_redis()
        now = time.time()
        r.zremrangebyscore(_SLOTS_KEY, "-inf", now - get_settings().llm_slot_stale_after_seconds)
        return r.zcard(_SLOTS_KEY)
    except Exception:  # noqa: BLE001 — observability read, never raises
        return 0


def _try_admit(r, limit: int, stale_after: float, token: str) -> bool:
    """One atomic round-trip: prune stale tickets, then admit `token` iff there's room.
    Returns whether THIS call was admitted. Exceptions propagate — the caller decides how to
    treat a Redis failure (always fail-open, never "confirmed over capacity")."""
    now = time.time()
    return bool(r.eval(_ADMIT_SCRIPT, 1, _SLOTS_KEY, now, now - stale_after, limit, token))


def _heartbeat_loop(r, token: str, interval: float, stop_event: threading.Event) -> None:
    """Runs on a background thread for the lifetime of one admitted call: refreshes the
    ticket's score every `interval` seconds so staleness pruning (_try_admit's
    ZREMRANGEBYSCORE) never mistakes a still-running call for a crashed one, REGARDLESS of
    how long the call legitimately takes. `stop_event.wait(interval)` both sleeps and gives an
    instant wake-up on release, instead of sleeping the full interval past when it's needed."""
    while not stop_event.wait(interval):
        try:
            r.zadd(_SLOTS_KEY, {token: time.time()})
        except Exception:  # noqa: BLE001 — a missed beat self-heals next tick; never worth crashing the call over
            log.warning("llm.slot_heartbeat_failed", exc_info=True)


@contextmanager
def _llm_slot(s: Settings):
    """Caps concurrent outbound chat/embed/rerank calls ACROSS EVERY WORKER REPLICA sharing
    this Redis (`max_concurrent_llm_calls`, 0 = disabled — today's unbounded behavior).
    `max_active_sessions` only counts sessions; this is the piece that actually protects the
    shared Azure/GPU backend from being overwhelmed when workers scale out.

    A Redis-side ZSET semaphore, admitted via one atomic Lua script (see _ADMIT_SCRIPT), with
    a heartbeat thread keeping an admitted call's ticket alive for exactly as long as it
    legitimately runs — duration and aliveness are different things, so staleness is detected
    by MISSED HEARTBEATS (llm_slot_stale_after_seconds), never by a guessed fixed duration.

    Any Redis error anywhere in this function — building the client, one admit attempt, or a
    later poll — fails OPEN (log once, proceed unlimited for this call): an infra fault is not
    evidence of being over capacity. LLMSlotUnavailable is raised ONLY when Redis positively
    responds "still full" for the entire wait window — a confirmed, not inferred, condition.
    """
    limit = s.max_concurrent_llm_calls
    if not limit:
        yield
        return

    token = str(uuid.uuid4())
    try:
        r = _slot_redis()
    except Exception:  # noqa: BLE001 — can't even build the client → fail open
        log.warning("llm.slot_redis_unavailable_fail_open", exc_info=True)
        yield
        return

    waited = 0.0
    while True:
        try:
            admitted = _try_admit(r, limit, s.llm_slot_stale_after_seconds, token)
        except Exception:  # noqa: BLE001 — Redis error (at first attempt OR mid-poll) → fail open, never "confirmed over capacity"
            log.warning("llm.slot_redis_error_fail_open", exc_info=True)
            yield
            return
        if admitted:
            break
        if waited >= s.llm_slot_wait_timeout_seconds:
            raise LLMSlotUnavailable(
                f"no free LLM call slot after waiting {waited:.0f}s (limit={limit})")
        time.sleep(_POLL_SECONDS + random.uniform(0, _POLL_JITTER_SECONDS))  # jitter avoids synchronized thundering-herd wakeups
        waited += _POLL_SECONDS

    stop_event = threading.Event()
    # plain threading.Thread, not gevent.spawn: under the gevent-patched Celery worker,
    # monkey-patched `threading` already makes this cooperative (same reasoning
    # local_models.py's own _offload comment documents); outside gevent (plain pytest) it's a
    # harmless real OS thread doing near-nothing. Portable, no new gevent import here.
    hb_thread = threading.Thread(
        target=_heartbeat_loop, args=(r, token, s.llm_slot_heartbeat_seconds, stop_event), daemon=True)
    hb_thread.start()
    try:
        yield
    finally:
        # Stop + join the heartbeat BEFORE releasing the ticket: if the ticket were removed
        # first, a heartbeat tick still in flight could re-add a now-orphaned entry that
        # nothing would ever clean up.
        stop_event.set()
        hb_thread.join(timeout=s.llm_slot_heartbeat_seconds)
        try:
            r.zrem(_SLOTS_KEY, token)
        except Exception:  # noqa: BLE001 — best-effort release; a leaked slot self-heals via staleness pruning
            pass


@dataclass
class Provenance:
    """The audit record described above: exactly which AI model answered a
    call, and with what settings, so a stored result can always be traced
    back to what actually produced it.

    Fields:
    model         — the model name/deployment that was REQUESTED.
    model_version — what the provider says it ACTUALLY served (can differ
                    from `model` — see chat()'s comment on this below).
    params        — a dict of the relevant call settings (provider,
                    timeout, retry count, etc.) — see chat() for exactly
                    what goes in here and why.
    prompt_version — NOT set by this file; the pipeline code that calls
                    chat() fills this in afterward, so one record can tie
                    together both "which prompt template" and "which model"
                    produced a given answer.
    """
    model: str
    model_version: str = ""
    params: dict[str, Any] = field(default_factory=dict)
    prompt_version: str = ""  # set by the pipeline caller (prompt + model provenance)


class LLMClient(Protocol):
    """The interface (contract) described in the module docstring above: any
    class that implements these three methods with these signatures can be
    used anywhere the pipeline needs an AI client — the real `LiteLLMClient`
    below, or a test-only `StubLLMClient` that never makes a real network
    call. The pipeline code never checks "is this the real one or the stub
    one" — it just calls `.chat()`/`.embed()`/`.rerank()` and doesn't care
    which implementation is behind it.
    """

    def chat(self, messages: list[dict], *, model: str | None = None,
            temperature: float | None = None) -> tuple[str, Provenance]:
        """Single chat completion; returns (text, Provenance) so callers can persist model+params
        alongside the output without threading litellm-specific response shapes around.
        `temperature`, like `model`, is a per-call override — None means "use the configured
        default" (Settings.llm_temperature or the provider's own)."""
        ...

    def embed(self, texts: Sequence[str], *, model: str | None = None, kind: str = "query") -> list[list[float]]:
        """Batch embed; `kind` distinguishes query vs. passage text so e5-style models can apply
        the right prefix (see `_apply_embed_prefix`)."""
        ...

    def rerank(self, query: str, docs: Sequence[str], *, model: str | None = None) -> list[float]:
        """Relevance scores for `docs` against `query`, same length/order as `docs` 0-100 scale."""
        ...

    def rerank_many(self, items: Sequence[tuple[str, Sequence[str]]],
                    *, model: str | None = None) -> list[list[float] | None]:
        """Many (query, docs) reranks at once — one batched local model dispatch, or
        bounded-concurrent remote calls. Per item: the scores list, or None if that item's
        rerank failed (logged); raises only when EVERY item failed (systemic)."""
        ...


def _litellm_key_header(s: Settings) -> dict[str, Any]:
    """`{"extra_headers": {...}}` carrying the litellm key in an ALTERNATE header, or `{}`.

    litellm authenticates with `Authorization: Bearer <key>`, which is correct against a bare
    proxy. When the proxy sits behind a gateway that consumes or rewrites `Authorization`, that
    header never reaches litellm and every call 401s — while the same key works when sent as
    `x-litellm-api-key` (confirmed against the UAT proxy). Sending BOTH is safe: litellm reads
    whichever arrives, and a bare proxy ignores the extra header.

    Spread into the call kwargs so it is a no-op unless LITELLM_API_KEY_HEADER is configured."""
    if not s.litellm_api_key_header:
        return {}
    return {"extra_headers": {s.litellm_api_key_header: s.litellm_api_key}}


def _litellm_http_headers(s: Settings) -> dict[str, str]:
    """Headers for this file's OWN httpx calls to the proxy (/v1/models, /model/info, /key/info)
    — the same dual-header reasoning as _litellm_key_header above, which covers the litellm SDK
    calls instead."""
    headers = {"Authorization": f"Bearer {s.litellm_api_key}"}
    if s.litellm_api_key_header:
        headers[s.litellm_api_key_header] = s.litellm_api_key
    return headers


def _apply_embed_prefix(s: Settings, texts: list[str], kind: str) -> list[str]:
    """Some embedding models (the "e5" family) were TRAINED expecting a short
    tag stuck in front of every piece of text, so they know whether they're
    looking at a search QUERY or a document to be searched (a PASSAGE). If
    you don't add this tag, an e5 model still runs, but its results are
    measurably worse — the model wasn't trained on unprefixed text.

    CONCRETE EXAMPLE: calling `_apply_embed_prefix(s, ["ransomware attack"], "query")`
    on an e5 model returns `["query: ransomware attack"]`. The same text with
    `kind="passage"` (e.g. embedding a threat-library entry to be searched
    against) returns `["passage: ransomware attack"]` instead.

    This is provider-agnostic — it runs the exact same way whether the e5
    model is served locally on this machine or through the remote litellm
    proxy, because the MODEL needs the prefix either way, regardless of
    where it happens to be running.

    Controlled by the `embedding_prefix_style` setting:
    - "auto" (the default): look at the configured model's name — if it
        contains "e5", treat it as an e5 model and add the prefix.
    - "none": don't touch the text at all — return it completely unchanged.

    "auto" with a model name that doesn't contain "e5" is AMBIGUOUS, not a
    signal to skip the prefix: the name might just be an opaque litellm-proxy
    deployment alias (e.g. "prod-embed-v2") that's actually serving an e5
    model underneath. EMBEDDING_PROVIDER=local has its own startup-time
    version of this same check (local_models._check_embedding_prefix_style),
    but that one is gated on the local path only — it never runs for
    EMBEDDING_PROVIDER=litellm_proxy. This check runs here instead, for BOTH
    providers (this function is the shared prefix logic each one calls),
    so an ambiguous config fails loud on the first embed() call rather than
    silently resolving to "none" and dropping the prefix with no log line
    anywhere.
    """
    style = s.embedding_prefix_style
    if style == "auto":
        if "e5" not in s.embedding_model.lower():
            raise RuntimeError(
                f"EMBEDDING_PREFIX_STYLE=auto cannot infer the prefix scheme from "
                f"'{s.embedding_model}'. Set EMBEDDING_PREFIX_STYLE explicitly to 'e5' or 'none' "
                "so prefixes aren't silently dropped.")
        style = "e5"
    if style != "e5":
        return texts
    prefix = {"query": "query: ", "passage": "passage: "}.get(kind, "")
    return [prefix + t for t in texts]


class LiteLLMClient:
    """THE REAL, PRODUCTION implementation of `LLMClient` above — this is the
    class that actually reaches out over the network to Azure OpenAI /
    OpenAI / a self-hosted litellm proxy. (The test-only stub that mimics
    this interface without any real network call lives elsewhere, in the
    test suite.)

    `# Thin wrapper over litellm` — this class deliberately does
    almost nothing clever on its own. The heavy lifting (choosing which
    actual backend server to call, retrying on transient failures, falling
    back between models, rate-limiting) is handled by the `litellm` library
    and/or the litellm PROXY server it talks to — this class's job is just
    to pick the right settings for whichever provider is configured and hand
    the call off.
    """

    def __init__(self, settings: Settings | None = None):
        """Accepts an explicit `Settings` for tests; production callers rely on `get_llm()`
        which leaves this as None and falls back to the cached global settings."""
        self.s = settings or get_settings()

    def _chat_kwargs(self, model: str | None = None, temperature: float | None = None) -> dict[str, Any]:
        """THE PROVIDER-DISPATCH POINT FOR chat() — this is the one function
        that decides "which actual AI backend am I about to call, and what
        connection details does it need." It's called exactly once, at the
        very top of `chat()` below.

        How it decides, based on the `llm_provider` setting (an env var):

        llm_provider == "azure_openai"
            → talk to an Azure OpenAI deployment. Azure addresses a
            DEPLOYMENT NAME (something an admin configured on the Azure
            side), not a generic model name — so if a caller passed a
            `model=` argument to chat(), THAT ARGUMENT IS SILENTLY IGNORED
            here; only `s.azure_openai_deployment_name` (from settings) is
            ever used for Azure. A debug log line is written so this
            surprising behavior is at least visible if you go looking for
            it, but the caller's requested model name never wins.

        llm_provider == "openai"
            → talk to OpenAI's API directly (or a self-hosted
            OpenAI-compatible server, if `openai_base_url` is set).
            Here the caller's `model=` argument DOES apply (falling back
            to `s.inference_model` if none was given).

        anything else (the default)
            → talk to the litellm PROXY server (a separate service this app
            is configured to route through). Same model-argument-applies
            behavior as the OpenAI branch above.

        Every branch also gets these common settings merged in:
        - `timeout` / `num_retries` — the bounded timeout/retry
            budget mentioned in the module docstring, applied identically
            regardless of which provider was chosen.
        - `response_format: {"type": "json_object"}` — ONLY added if the
            `llm_json_mode` setting is turned on (it's off by default). When
            on, this tells the provider to enforce that its reply is valid
            JSON at the API level, instead of just hoping the model's plain
            text happens to parse as JSON.
        - `temperature` — the per-call `temperature` argument wins if given (e.g.
            find_threats's threat_identification_temperature); otherwise falls back to the
            operator-set LLM_TEMPERATURE (unset/None by default — see config.py). Neither
            set → litellm/the provider picks its own default.
        - `reasoning_effort` — ONLY added if an operator explicitly set
            LLM_REASONING_EFFORT (unset/None by default). Left unset, litellm/the
            provider picks its own default.
        """
        s = self.s
        common: dict[str, Any] = {"timeout": s.llm_timeout_seconds, "num_retries": s.llm_max_retries}
        if s.llm_json_mode:  # API-enforced JSON output; off by default (see config.py)
            common["response_format"] = {"type": "json_object"}
        # per-call `temperature` (e.g. find_threats pinning threat_identification_temperature)
        # wins over the global llm_temperature default, same precedence `model` already has.
        effective_temperature = temperature if temperature is not None else s.llm_temperature
        if effective_temperature is not None:
            common["temperature"] = effective_temperature
        # Some deployments reject a pinned param the model doesn't allow — e.g. gpt-5 rejects
        # temperature=0.0 (find_threats' threat_identification_temperature default) with
        # litellm.UnsupportedParamsError "only 1 is supported", which would fail EVERY real
        # threat-identification call. drop_params lets litellm drop a per-model-unsupported param
        # instead of failing the call; deployments that DO accept the value keep it. The requested
        # value is still recorded in Provenance.params below (what we asked for), consistent with
        # the model-vs-model_version "requested vs served" distinction this file already draws.
        common["drop_params"] = True
        # Declare non-streaming ON THE WIRE, every call. chat() parses a completed message; a
        # proxy model entry that pins `"stream": true` in its litellm_params (glm-5's does) would
        # otherwise decide the response shape server-side. Belt half of the fix — chat() also
        # braces for a stream coming back anyway (see _ensure_completed_response).
        common["stream"] = False
        if s.llm_reasoning_effort is not None:  # operator-pinned; unset by default (see config.py)
            common["reasoning_effort"] = s.llm_reasoning_effort
        if s.llm_provider == "azure_openai":
            if model:  # Azure addresses a DEPLOYMENT, not a model name — a per-call model can't apply here
                log.debug("llm.azure_ignores_per_call_model", requested=model,
                        deployment=s.azure_openai_deployment_name)
            return {"model": f"azure/{s.azure_openai_deployment_name}", "api_base": s.azure_openai_endpoint,
                    "api_key": s.azure_openai_api_key, "api_version": s.azure_openai_api_version, **common}
        if s.llm_provider == "openai":
            kw = {"model": model or s.inference_model, "api_key": s.openai_api_key, **common}
            if s.openai_base_url:
                kw["api_base"] = s.openai_base_url
            return kw
        # default: litellm proxy
        kw = {"model": model or s.inference_model, "api_base": s.litellm_base_url,
            "api_key": s.litellm_api_key, **_litellm_key_header(s), **common}
        # operator-pinned guardrail name(s), pre-registered on the proxy itself; unset by
        # default. Proxy-only — no azure_openai/openai equivalent, so this branch only.
        if s.llm_guardrails:
            kw["guardrails"] = s.llm_guardrails
        return kw

    def chat(self, messages, *, model=None, temperature=None):
        """Sends a conversation (a list of role/content message dicts, the
        same shape every AI chat API expects) to whichever provider
        `_chat_kwargs()` above selects, and returns a tuple of
        (the model's text reply, a Provenance record of what actually
        answered).

        STEP BY STEP:
        1. Import `litellm` LOCALLY (inside the function, not at the top
            of the file) — this means a test run that only ever uses the
            fake `StubLLMClient` never needs the real `litellm` package
            installed at all, since this line of code is simply never
            reached in that case.
        2. Call `_chat_kwargs(model)` to get the provider-specific
            connection details (see that method's own comment above for
            the full azure_openai / openai / litellm-proxy breakdown).
        3. Make the actual call: `litellm.completion(messages=..., **kwargs)`.
            `litellm` itself handles the timeout/retry logic using the
            `timeout`/`num_retries` values baked into `kwargs`.
        4. Pull the reply text out of the response shape every provider
            normalizes to: `resp["choices"][0]["message"]["content"]`.
        5. Build and return the `Provenance` record (see field-by-field
            notes below) alongside that text.

        A NON-OBVIOUS DETAIL — `model` vs. `model_version`: `model=kwargs["model"]`
        is what we ASKED for (e.g. the deployment/model name from
        `_chat_kwargs`). `model_version=resp.get("model")` is what the
        provider says it ACTUALLY used to answer — these can legitimately
        differ (e.g. a provider silently serving a dated snapshot or a
        fallback model instead of the exact one requested), which is
        precisely why BOTH are recorded separately instead of just one.

        ANOTHER NON-OBVIOUS DETAIL — temperature/reasoning_effort only show up
        in the `params` dict below when they're actually pinned: either a per-call
        `temperature=` override (e.g. find_threats's threat_identification_temperature) or an
        operator-set LLM_TEMPERATURE/LLM_REASONING_EFFORT (see config.py). Left unset,
        litellm/the provider picks its own default and neither key appears —
        so the provenance record only ever lists settings that are ACTUALLY
        being controlled, not settings left to whatever the default happens
        to be.

        A LENGTH GUARD, CHECKED BEFORE ANY PROVIDER WORK: unlike embed()'s guard, a long
        chat prompt isn't inherently a bug — several allowlisted context fields (e.g.
        technology_used, incident_description) are free text a user could legitimately
        write a few paragraphs into, and the smallest known chat model's context window
        (glm-5, 131k tokens) is enormous next to that. `_MAX_CHAT_CHARS` is set far above
        any realistic legitimate prompt, purely as a safety net against genuinely
        pathological input (a document landing in a field that expected a short value, a
        bug duplicating content) — same fail-loud-not-silent reasoning as embed()'s guard.
        """
        import litellm

        total_chars = sum(len(m.get("content") or "") for m in messages)
        if total_chars > _MAX_CHAT_CHARS:
            raise ValueError(
                f"chat() received a {total_chars}-char prompt, over the {_MAX_CHAT_CHARS}-char "
                "safety cap — check for an unexpectedly large free-text field (e.g. "
                "technology_used, incident_description, cii_asset_description)")

        kwargs = self._chat_kwargs(model, temperature)
        with _llm_slot(self.s):
            resp = litellm.completion(messages=messages, **kwargs)
            # Suspenders half of the stream fix (_chat_kwargs sends stream=False as the belt): if
            # the server streamed anyway — a proxy model entry pinning `"stream": true` overrides
            # what the client asked for — assemble the chunks into the completed response the
            # parsing below expects. chat()'s contract must never depend on a server-side config
            # knob. Inside the _llm_slot: the stream is still an in-flight LLM call until drained.
            if isinstance(resp, litellm.CustomStreamWrapper):
                resp = litellm.stream_chunk_builder(list(resp), messages=messages)
                if resp is None:  # empty stream — fail loud, same posture as the parse guards
                    raise RuntimeError("chat provider returned an empty stream")
        return resp["choices"][0]["message"]["content"], Provenance(
            model=kwargs["model"],
            # record the model the proxy ACTUALLY served (resp["model"] may be a dated
            # snapshot / fallback of the requested name), not just what we asked for.
            model_version=str(resp.get("model", "") or ""),
            params={
                "provider": self.s.llm_provider,
                "timeout": self.s.llm_timeout_seconds,
                "num_retries": self.s.llm_max_retries,
                "json_mode": self.s.llm_json_mode,
                # temperature/reasoning_effort only appear here when actually pinned — either a
                # per-call override (e.g. find_threats's threat_identification_temperature) or an
                # operator-pinned LLM_TEMPERATURE/LLM_REASONING_EFFORT; read back from `kwargs`
                # (the resolved, effective value _chat_kwargs already computed) rather than
                # re-deriving the same precedence here a second time.
                **({"temperature": kwargs["temperature"]} if "temperature" in kwargs else {}),
                **({"reasoning_effort": self.s.llm_reasoning_effort}
                if self.s.llm_reasoning_effort is not None else {}),
            },
        )

    # embed()/rerank() have their OWN provider switch (EMBEDDING_PROVIDER /
    # RERANKER_PROVIDER), independent of LLM_PROVIDER — see the module
    # docstring's "three independent switches" callout above. 'local' runs
    # the model in-process on this machine (no network call at all); the
    # default 'litellm_proxy' calls out to the proxy service (or a
    # TEI/embedding-serving backend behind it) over the network instead.
    def embed(self, texts, *, model=None, kind="query"):
        """Turns a batch of plain-text strings into a batch of numeric
        vectors ("embeddings") — the representation used for semantic
        search/similarity matching elsewhere in the pipeline.

        STEP BY STEP:
        1. Apply the e5 query:/passage: prefix if needed (`_apply_embed_prefix`,
            explained in detail above) — this happens BEFORE routing to
            either provider, since both need the prefix if the model is e5.
        2. Check `embedding_provider`:
            - "local"  → hand the (already-prefixed) texts straight to
                `local_models.embed()`, which runs the model in-process on
                this machine. No network call happens at all here, so the
                timeout/retry settings simply don't apply to this path
                — there's nothing to time out or retry.
            - anything else (the default) → import `litellm` locally
                (same reasoning as in `chat()` — keeps the dependency
                optional for stub-only test runs) and call
                `litellm.embedding(...)` with the same [R8] timeout/retry
                bounds used everywhere else in this file.

        A REAL CORRECTNESS FIX, NOT JUST STYLE (the last line of this
        method): the litellm proxy's response can come back with its
        embeddings in a DIFFERENT ORDER than the input texts were sent in.
        If you naively did `[d["embedding"] for d in resp["data"]]`, you
        could end up pairing text #1 with the vector that actually belongs
        to text #3 — silently wrong data, no error raised anywhere.
        Instead, each returned item carries an `"index"` field saying which
        input position it corresponds to, so the code explicitly SORTS the
        results by that index before extracting the vectors — guaranteeing
        the output list lines up position-for-position with the input
        `texts` list, exactly the way every caller of this method assumes.
        (The `rerank()` method below has the exact same class of problem,
        solved the same way — see its comment for details.)

        A LENGTH GUARD, CHECKED BEFORE EITHER PROVIDER BRANCH: every real caller of this
        method embeds a short label for similarity matching against the threat library —
        either a name already in the library (≤500 chars in the DB schema that stores it) or
        the AI's own proposed type/name text (unbounded at the schema level, but the prompt
        that produces it explicitly asks for a short label, not a document — see
        prompts.threats_prompt). Either way it's a label, never a document. Something over
        `_MAX_EMBED_CHARS` is never legitimate content, always a bug (a document/description
        routed here instead of a name), so it's rejected outright
        rather than silently truncated — truncating a name changes its meaning without
        anyone noticing, which is worse than a clear, immediate error. Checked once here,
        ahead of the local/remote split, so it protects both providers without duplicating
        the check in each branch.
        """
        texts = _apply_embed_prefix(self.s, list(texts), kind)  # e5 prefixes, both providers
        too_long = [t for t in texts if len(t) > _MAX_EMBED_CHARS]
        if too_long:
            raise ValueError(
                f"embed() received {len(too_long)} text(s) over {_MAX_EMBED_CHARS} chars "
                f"(longest {max(len(t) for t in too_long)}) — refusing to send to the embedding "
                "model; this is never legitimate input for a short library-matching label")
        if self.s.embedding_provider == "local":
            from app.pipeline import local_models

            return local_models.embed(texts)  # in-process — no network timeout/retry applies
        import litellm

        model = model or self.s.embedding_model
        with _llm_slot(self.s):
            resp = litellm.embedding(
                model=model, input=texts,
                api_base=self.s.litellm_base_url, api_key=self.s.litellm_api_key,
                **_litellm_key_header(self.s),  # gateway-safe alternate auth header, when configured
                timeout=self.s.llm_timeout_seconds, num_retries=self.s.llm_max_retries,  # same bounds as chat
            )
        # `data` MAY come back out of input order; sort by index so positional callers
        # (embeddings.get_vectors's zip) never cache a text against the wrong vector. cf. rerank().
        return [d["embedding"] for d in sorted(resp["data"], key=lambda d: d["index"])]

    def rerank(self, query, docs, *, model=None):
        """Given one search query and a list of candidate documents, scores
        how relevant EACH document is to that query, on a 0 (unrelated) to
        100 (a strong match) scale — used elsewhere in the pipeline to
        re-order/filter a rough first-pass shortlist of candidates down to
        the genuinely best matches.

        Routes on the `reranker_provider` setting, completely independently
        of `llm_provider`/`embedding_provider` (same "local in-process" vs.
        "remote litellm proxy" choice as `embed()` above, including the same
        timeout/retry caveat: the local path makes no network call, so
        those settings simply don't apply there).

        THE SAME OUT-OF-ORDER PROBLEM AS embed() ABOVE, SOLVED THE SAME WAY:
        the remote reranking API can return its results in a different
        order than `docs` was given in, and each result also comes back as a
        RAW score in some provider-specific range rather than the 0-100
        scale this method promises callers. So the code below:
        1. Reads each result's `"index"` field (which input document it
            corresponds to) and writes the score into THAT exact position
            — never just appending results in the order the API happened
            to return them.
        2. Multiplies each raw relevance score by 100 (§8.4) to normalize
            it onto the promised 0-100 scale.
        3. Fails loud if the response doesn't cover every index in `docs`
            (a truncated/partial reply, a documents-limit being hit, a
            transient provider glitch) instead of defaulting the missing
            document(s) to a fabricated 0.0 — a fake worst-possible score
            would silently mispair scores to candidates with no log line
            or exception anywhere pointing at the cause (this is what lets
            grounding.find_closest_match's own `len(rr) != len(docs)` guard
            actually fire, instead of it being unreachable dead code).
        The end result always lines up position-for-position with the input
        `docs` list, and is always on a 0-100 scale, regardless of what the
        underlying provider's raw response shape happens to look like.
        """
        if self.s.reranker_provider == "local":
            from app.pipeline import local_models

            return local_models.rerank(query, docs)  # in-process — no network timeout/retry applies
        import litellm

        model = model or self.s.reranker_model
        with _llm_slot(self.s):
            resp = litellm.rerank(
                model=model, query=query, documents=list(docs),
                api_base=self.s.litellm_base_url, api_key=self.s.litellm_api_key,
                **_litellm_key_header(self.s),  # gateway-safe alternate auth header, when configured
                timeout=self.s.llm_timeout_seconds, num_retries=self.s.llm_max_retries,  # same bounds as chat
            )
        by_index = {r["index"]: float(r["relevance_score"]) * 100.0 for r in resp["results"]}
        missing = [i for i in range(len(docs)) if i not in by_index]
        if missing:
            raise RuntimeError(
                f"rerank returned {len(by_index)} scores for {len(docs)} docs "
                f"(missing index(es): {missing})")
        return [by_index[i] for i in range(len(docs))]

    def rerank_many(self, items, *, model=None):
        """Many (query, docs) reranks in one go — see the LLMClient protocol stub.

        LOCAL provider: cross-encoders score each (query, doc) pair independently, so ALL
        items' pairs flatten into ONE local_models.rerank_pairs dispatch (score-identical to
        per-item calls, minus 1-per-item model-dispatch overhead); a failure here is systemic
        by construction (one call = every item), so it propagates.

        REMOTE provider: rerank APIs take one query per request, so the win is concurrency,
        not batching — a bounded thread pool (gevent patches these to greenlets on the
        worker; plain threads in the API process — both fine for blocking HTTP) runs the
        existing self.rerank per item, so retries/timeouts/slot handling are reused, not
        reimplemented. rerank_concurrency is only a LOCAL politeness cap: each call still
        acquires its own _llm_slot, so the Redis semaphore remains the global authority and
        excess workers just wait there. Per-item failure (incl. LLMSlotUnavailable after the
        slot wait timeout) -> None for that item + a warning, raising only if EVERY item
        failed — one starved call must not wipe out a whole mapping run."""
        items = list(items)
        if not items:
            return []
        if self.s.reranker_provider == "local":
            from app.pipeline import local_models

            pairs = [(q, d) for q, docs in items for d in docs]
            scores = local_models.rerank_pairs(pairs)
            if len(scores) != len(pairs):  # same fail-loud posture as rerank() above
                raise RuntimeError(f"rerank_pairs returned {len(scores)} scores for {len(pairs)} pairs")
            out: list[list[float] | None] = []
            pos = 0
            for _, docs in items:
                out.append(scores[pos:pos + len(docs)])
                pos += len(docs)
            return out
        from concurrent.futures import ThreadPoolExecutor

        results: list[list[float] | None] = [None] * len(items)
        failures = 0
        with ThreadPoolExecutor(max_workers=min(self.s.rerank_concurrency, len(items))) as pool:
            futures = {pool.submit(self.rerank, q, docs, model=model): i
                       for i, (q, docs) in enumerate(items)}
        for fut, i in futures.items():  # pool exited -> all futures done; order restored via i
            try:
                results[i] = fut.result()
            except Exception:  # noqa: BLE001 — per-item fail-open, see docstring
                failures += 1
                log.warning("rerank_many.item_failed", index=i, exc_info=True)
        if failures == len(items):
            raise RuntimeError(f"rerank_many: all {len(items)} rerank calls failed")
        return results


@dataclass
class ModerationResult:
    """Outcome of one moderation check (see `moderate` below) — always returned, never raises,
    so a scenario's ValidationJSON can always record what happened. `checked=False` covers
    BOTH "the feature is off" and "the call itself failed" — `error` distinguishes the two;
    either way, "not checked" must never be conflated with "checked and came back clean"."""
    checked: bool
    flagged: bool = False
    categories: list[str] = field(default_factory=list)
    error: str | None = None


def moderate(text: str, *, settings: Settings | None = None) -> ModerationResult:
    """Content-moderation check for one piece of AI-generated text, via the litellm proxy's
    OpenAI-compatible /moderations endpoint. Off by default (LLM_MODERATION_ENABLED) — not
    every deployment's proxy has a moderation model registered, and this app's whole job is
    writing about attacks/breaches/sabotage, exactly what moderation categories are tuned to
    flag, so this is advisory (see the caller in tasks.py), never a hard gate.

    NOT on the `LLMClient` Protocol: moderation has exactly one real backend (the proxy),
    unlike chat/embed/rerank's genuine provider-swap design (azure/openai/proxy, local/proxy)
    — putting it on the Protocol would force a dead `.moderate()` onto the test-only
    `StubLLMClient` for no reason. A free function, same shape as `verify_litellm_models`.

    WHY THIS BYPASSES litellm.moderation() ENTIRELY: its sync `moderation()` does not thread
    `timeout`/`num_retries` into the `openai.OpenAI()` client it builds internally — passing
    them as kwargs is silently ignored, which would break this file's "every call is bounded"
    rule. It also falls back to a GLOBAL `litellm.api_key`/`OPENAI_API_KEY` env var if
    `api_key` isn't passed explicitly, which could silently hit real OpenAI instead of the
    configured proxy. Building and calling `openai.OpenAI` directly here is the same "route
    around a litellm limitation, call the documented client API directly" move
    `verify_litellm_models` already makes for `/v1/models` via `httpx.Client`.

    NEVER RAISES (except `LLMSlotUnavailable`, same "temporary, not a bug" contract as
    chat/embed/rerank): a moderation-service failure must never block scenario generation —
    moderation is a secondary safety net on top of the primary `chat()` call that wrote the
    text, not equally critical. Every other failure returns `checked=False` with `error` set.

    [REVIEW-FIX] applies `_ensure_litellm_proxy_bypassed` before constructing the client —
    moderation's target host (`s.litellm_base_url`) is independent of `llm_provider`/
    `embedding_provider`/`reranker_provider` (moderation has exactly one backend, unlike
    those three), so a deployment using moderation WITHOUT routing chat/embed/rerank through
    the proxy (e.g. llm_provider=azure_openai, moderation on) would never otherwise call the
    bypass fix anywhere in the process — hitting the exact CONNECT-hang bug it exists to
    solve, on every single moderation call, silently degrading to "always unavailable" with
    only a warning log to notice by.
    """
    s = settings or get_settings()
    if not s.llm_moderation_enabled:
        return ModerationResult(checked=False)

    _ensure_litellm_proxy_bypassed(s)
    kwargs: dict[str, Any] = {"input": text}
    if s.llm_moderation_model:
        kwargs["model"] = s.llm_moderation_model
    try:
        client = _moderation_client(s.litellm_api_key, f"{s.litellm_base_url.rstrip('/')}/v1",
                                    s.llm_timeout_seconds, s.llm_max_retries)
        with _llm_slot(s):
            resp = client.moderations.create(**kwargs)
        # [REVIEW-FIX] parsing moved INSIDE the try: an empty resp.results (or any other
        # unexpected response shape) previously raised IndexError past this function's own
        # "never raises" contract, uncaught anywhere below tasks.py — silently turning a
        # malformed moderation response into a full subsystem ERROR, exactly the outcome
        # moderation being advisory-only was supposed to prevent.
        result = resp.results[0]
        flagged_categories = [cat for cat, is_flagged in result.categories.model_dump().items() if is_flagged]
    except LLMSlotUnavailable:
        raise
    except Exception:  # noqa: BLE001 — a moderation-service failure must never block generation
        log.warning("llm.moderation_call_failed", exc_info=True)
        return ModerationResult(checked=False, error="moderation_unavailable")

    return ModerationResult(checked=True, flagged=result.flagged, categories=flagged_categories)


@lru_cache
def _moderation_client(api_key: str, base_url: str, timeout: float, max_retries: int):
    """[REVIEW-FIX] `moderate()` runs on the real generation hot path (once per scenario, via
    `tasks.py::_moderation_report`) — unlike `verify_litellm_models`/`log_litellm_key_info`/
    `check_litellm_proxy_health`, which each construct their own low-frequency (boot-time or
    once-per-self-check-interval) client. Constructing a fresh `openai.OpenAI` on every call
    would mean a fresh TCP/TLS handshake per scenario with no connection reuse — cached here
    the same way `LiteLLMClient` itself is cached via `get_llm()`'s `@lru_cache`. Keyed on the
    scalar values that actually determine client identity (not the whole `Settings` object,
    which isn't hashable) — different `Settings` instances with the same values correctly
    share one client; different values (e.g. a test's fake base_url) correctly get their own.

    [REVIEW-FIX considered and rejected] moving `_ensure_litellm_proxy_bypassed` in here
    (cache-populating path only, vs. every `moderate()` call) was considered to cut a redundant
    call — but that call takes the `Settings` object, and this function only receives scalar
    values, not the object itself. Reaching for `get_settings()` here instead of the exact `s`
    `moderate()` was given would use the GLOBAL settings even when a caller (e.g. a test)
    explicitly passed a different one — a real correctness bug traded for a no-op optimization
    (the call is in-memory string/dict work, not I/O; its cost is unmeasurable next to the
    network round-trip this function's result is used for). Left in `moderate()` as-is."""
    import openai

    return openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=max_retries)


def verify_litellm_models(settings: Settings | None = None) -> None:
    """Fail-fast at worker startup: confirm every model this deployment is actually
    configured to reach THROUGH THE LITELLM PROXY is really registered there — same
    "don't silently run broken" discipline as local_models.validate_local_models for the
    in-process path (same `settings: Settings | None = None` override-for-tests shape too),
    called alongside it in celery_app.py's _init_worker.

    Only checks the providers actually set to 'litellm_proxy' — llm_provider defaults to
    'azure_openai' and embedding_provider/reranker_provider both default to 'local', so in
    a deployment that never points any of the three at the proxy (e.g. a dev environment
    with no proxy access), `wanted` ends up empty and this makes no network call at all.

    Applies the same proxy-bypass fix `get_llm()` applies (`_ensure_litellm_proxy_bypassed`)
    BEFORE making its own network call below — this function is called from `_init_worker`
    at worker boot, strictly before any task (and therefore before any `get_llm()` call)
    could possibly have run in that process, so it can't rely on `get_llm()` having already
    set the env var. Without this, a worker behind a broken internal proxy would hang/fail
    right here at startup — the worst-case version of the bug the fix exists to solve.
    """
    s = settings or get_settings()
    _ensure_litellm_proxy_bypassed(s)
    # [REVIEW-FIX] the litellm_proxy-specific checks below only ever ran for that one provider —
    # azure_openai/openai (the documented default) had no reachability check anywhere. Runs
    # regardless of whether `wanted` (below) ends up empty, since this is orthogonal to it.
    if s.llm_provider != "litellm_proxy":
        _verify_chat_provider_reachable(s)
    wanted: dict[str, str] = {}
    if s.llm_provider == "litellm_proxy":
        wanted["inference_model"] = s.inference_model
    if s.embedding_provider == "litellm_proxy":
        wanted["embedding_model"] = s.embedding_model
    if s.reranker_provider == "litellm_proxy":
        wanted["reranker_model"] = s.reranker_model
    if not wanted:
        return

    import httpx

    # Retries + a clear, wrapped error message here for the same reason every other LLM call
    # in this codebase gets them (litellm.completion/embedding/rerank all pass num_retries) —
    # this runs at worker startup, so a brief network blip (e.g. the proxy mid-rolling-deploy)
    # must not hard-fail the whole worker the way an unretried single attempt would.
    try:
        with httpx.Client(transport=httpx.HTTPTransport(retries=s.llm_max_retries)) as client:
            resp = client.get(f"{s.litellm_base_url}/v1/models",
                            headers=_litellm_http_headers(s),
                            timeout=s.llm_timeout_seconds)
            resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"litellm proxy at {s.litellm_base_url} was unreachable or rejected the request "
            f"while verifying configured model(s) {sorted(wanted.values())}: {exc}") from exc

    available = {m["id"] for m in resp.json()["data"]}
    missing = {setting: model for setting, model in wanted.items() if model not in available}
    if missing:
        raise RuntimeError(
            f"litellm proxy at {s.litellm_base_url} does not have the configured model(s) "
            f"registered: {missing} — check {', '.join(missing)} against the proxy's own model list")

    if s.embedding_provider == "litellm_proxy":
        _verify_embedding_dimensions(s)

    if s.llm_provider == "litellm_proxy":
        # Registration is NOT the same as "answers usably". /v1/models above proves the proxy
        # LISTS the model; it cannot prove the model returns something chat() can parse. A proxy
        # entry that pins `"stream": true` in its litellm_params (glm-5 does) hands back a
        # streaming wrapper where chat() expects a completed message — registered, reachable, and
        # broken on the first real pipeline run. Run one real completion here so that fails the
        # DEPLOYMENT instead of a user's first session. Runs after the checks above so a missing
        # model still reports the clearer "not registered" error first.
        _verify_chat_provider_reachable(s)

    # Observability, not verification: log each wanted model's configured rate limit (if any)
    # so a later rate-limit incident can be cross-checked against what was actually configured
    # AT DEPLOY TIME, in this worker's own startup log — instead of relying on someone's memory
    # of a config value that can silently drift. There's no `Settings` field for an "expected"
    # rpm to assert against (none has ever been needed), so this never raises — a failure here
    # only means the log line is missing, never that the worker fails to start.
    try:
        with httpx.Client(transport=httpx.HTTPTransport(retries=s.llm_max_retries)) as client:
            info_resp = client.get(f"{s.litellm_base_url}/model/info",
                                    headers=_litellm_http_headers(s),
                                    timeout=s.llm_timeout_seconds)
            info_resp.raise_for_status()
        by_name = {m.get("model_name"): m for m in info_resp.json().get("data", [])}
        for model in wanted.values():
            rpm = by_name.get(model, {}).get("litellm_params", {}).get("rpm")
            log.info("llm.model_config", model=model, rpm=rpm)
    except Exception:  # noqa: BLE001 — informational only, must never block worker boot
        log.warning("llm.model_config_check_failed", exc_info=True)


def _verify_chat_provider_reachable(s: Settings) -> None:
    """One real chat completion at worker boot, for EVERY provider — azure_openai/openai (which
    had no reachability check at all) and litellm_proxy alike.

    [REVIEW-FIX] originally direct-providers-only, on the reasoning that the proxy path was
    already covered by the /v1/models registration check. It isn't: registration proves the model
    is LISTED, never that it answers something chat() can parse. A proxy entry pinning
    `"stream": true` (glm-5's does) returns a streaming wrapper to a caller expecting a completed
    message — registered, reachable, and broken on the first real pipeline run. An expired Azure
    key or a decommissioned deployment is the same class of problem on the other path.

    Reuses LiteLLMClient.chat() itself (the exact same azure_openai/openai dispatch path a real
    session uses — see _chat_kwargs) rather than re-implementing provider-specific reachability
    logic, and discards the result; this is a real, minimal call, same "pay for one real call at
    boot" tradeoff _verify_embedding_dimensions above already makes for the embedding path.
    Deliberately a boot-time-only check, not also wired into the periodic self-check — unlike
    check_litellm_proxy_health's free `/health/readiness` ping, there's no cheap non-billed
    reachability probe for a direct Azure/OpenAI chat deployment; repeating a real completion
    call every self_check_interval_seconds (five minutes, by default) forever would be a real,
    ongoing cost for a boot-time-class problem.

    [REVIEW-FIX] the message must contain the literal word "json" — when the operator has
    LLM_JSON_MODE on, _chat_kwargs() adds response_format={"type": "json_object"} to EVERY
    chat() call including this one, and OpenAI/Azure OpenAI's Chat Completions API rejects any
    json_object request with a 400 unless "json" appears somewhere in the messages. A plain
    "ping" satisfied that on litellm_proxy (which doesn't enforce it) but 400'd on every direct
    azure_openai/openai boot once JSON mode was enabled — this wording is a no-op for reachability
    but keeps the call valid under either json_mode setting."""
    try:
        LiteLLMClient(s).chat([{"role": "user", "content": 'Reply with any valid json, e.g. {"ok": true}.'}])
    except LLMSlotUnavailable:
        # Must stay itself: celery_app._init_worker retries `except LLMSlotUnavailable` precisely so
        # a coordinated restart/scale-out — many replicas booting at once under a configured
        # max_concurrent_llm_calls cap — backs off instead of failing every worker. Wrapping it in
        # RuntimeError here would make that boot-retry unreachable, turning the highest-contention
        # moment the slot mechanism exists to survive into a fleet-wide boot failure.
        raise
    except Exception as exc:
        raise RuntimeError(
            f"{s.llm_provider} chat provider was unreachable or rejected a startup "
            f"verification call: {exc}") from exc


def _verify_embedding_dimensions(s: Settings) -> None:
    """[Fix] `local_models.validate_local_models` already fails fast if the LOCAL embedding
    model's real output dimension doesn't match `EMBEDDING_DIMENSIONS` — but that check is
    gated on `embedding_provider == "local"` and never ran for `litellm_proxy`. That gap was a
    real, live landmine: `EMBEDDING_DIMENSIONS` defaults to 1024 (sized for the local default
    model), but a proxy-routed model like `qwen3-embedding-8b-mig` actually returns 4096-dim
    vectors (confirmed via live testing). Nothing anywhere enforced this — vectors are stored
    in Mongo as a schema-less JSON array (`embeddings.py`'s `_stage_for_write`), with no
    fixed-width column or dimension check on read. The actual corruption mechanism:
    `grounding.how_similar`'s `zip(a, b)` silently truncates to the shorter vector on a length
    mismatch — no exception, no log line, just a numerically plausible but meaningless cosine
    score feeding real threat-grounding decisions.

    Fail-fast here mirrors `local_models.py`'s exact contract: costs one real embedding call
    (not just a GET) at worker boot — same cadence/cost `validate_local_models` already pays
    to load and warm the real local model when that path is active instead.
    """
    import litellm

    with _llm_slot(s):
        resp = litellm.embedding(
            model=s.embedding_model, input=["dimension check"],
            api_base=s.litellm_base_url, api_key=s.litellm_api_key,
            **_litellm_key_header(s),  # gateway-safe alternate auth header, when configured
            timeout=s.llm_timeout_seconds, num_retries=s.llm_max_retries,
        )
    dim = len(resp["data"][0]["embedding"])
    if dim != s.embedding_dimensions:
        raise RuntimeError(
            f"EMBEDDING_DIMENSIONS={s.embedding_dimensions} but litellm proxy model "
            f"'{s.embedding_model}' actually returns {dim}-dimensional vectors — fix "
            f"EMBEDDING_DIMENSIONS in .env before starting; a stale mismatch here would "
            f"otherwise corrupt threat-grounding similarity scores silently (see "
            f"grounding.how_similar)")


def log_litellm_key_info(settings: Settings | None = None) -> None:
    """Observability, same spirit as the model-config logging in `verify_litellm_models`
    (called alongside it in `_init_worker`): logs what the litellm proxy says THIS deployment's
    own API key is actually configured with (rate limit, budget, etc.), so `max_concurrent_llm_calls`
    tuning is eventually checkable against the proxy's real ceiling instead of a guess.

    The `/key/info` response shape isn't confirmed against a real proxy from this dev
    environment (no live access) — parsed defensively below (`.get()` chains, never assumes a
    nested path exists) so an unexpected shape degrades to "log the raw body" rather than a
    crash. Never raises: this is a log line, not a gate — a failure here must never block a
    worker from starting.
    """
    s = settings or get_settings()
    # [REVIEW-FIX] includes llm_moderation_enabled, matching _ensure_litellm_proxy_bypassed's
    # own gate below — moderation's key is the same litellm_api_key this logs, and a
    # moderation-only deployment (no provider routed through the proxy) previously skipped
    # this log line entirely, even though moderate() itself does reach the proxy.
    if not (s.llm_provider == "litellm_proxy" or s.embedding_provider == "litellm_proxy"
            or s.reranker_provider == "litellm_proxy" or s.llm_moderation_enabled):
        return

    # [REVIEW-FIX] this function's own httpx.Client() call never goes through get_llm() —
    # same reasoning as verify_litellm_models/check_litellm_proxy_health: self-apply the fix
    # rather than rely on call order (today it happens to run right after
    # verify_litellm_models in _init_worker, which already applies it — but that's an
    # accident of call order, not something this function should depend on).
    _ensure_litellm_proxy_bypassed(s)
    import httpx

    try:
        with httpx.Client(transport=httpx.HTTPTransport(retries=s.llm_max_retries)) as client:
            resp = client.get(f"{s.litellm_base_url}/key/info",
                            headers=_litellm_http_headers(s),
                            timeout=s.llm_timeout_seconds)
            resp.raise_for_status()
        body = resp.json()
        info = body.get("info") if isinstance(body, dict) else None
        if isinstance(info, dict):
            log.info("llm.key_info", rpm_limit=info.get("rpm_limit"), tpm_limit=info.get("tpm_limit"),
                    max_budget=info.get("max_budget"), spend=info.get("spend"))
        else:  # [REVIEW-FIX] shape didn't match what was expected — logging the raw body here was
            # itself a leak risk (an unconfirmed future litellm response shape could carry
            # something more sensitive than rpm_limit/tpm_limit/max_budget/spend, with no
            # redact() applied). Log only that the shape was unexpected, never the body itself.
            log.warning("llm.key_info_unexpected_shape")
    except Exception:  # noqa: BLE001 — informational only, must never block worker boot
        log.warning("llm.key_info_check_failed", exc_info=True)


def _ensure_litellm_proxy_bypassed(s: Settings) -> None:
    """Jumpserver-confirmed bug, fixed here at its root: an internal HTTP_PROXY/HTTPS_PROXY
    that httpx (which litellm/openai use internally) auto-routes through by default never
    completes the CONNECT tunnel to the litellm proxy host, hanging every chat/embed/rerank
    call until timeout. `litellm.completion()`/`embedding()`/`rerank()` don't expose a
    `trust_env`/`http_client` override the way constructing an `httpx.Client` directly would
    — so the fix has to work at the environment-variable layer instead: `NO_PROXY` is honored
    by virtually every Python HTTP library, regardless of which one litellm uses internally
    (today's httpx, or a future replacement).

    Only runs when something is actually configured to reach the proxy — either one of the
    three chat/embed/rerank providers, OR moderation (`moderate()`'s only backend IS the
    proxy, independent of those three — [REVIEW-FIX] a deployment can enable moderation
    without routing chat/embed/rerank through the proxy at all, and this gate must reflect
    every real reason to reach it, not just the original three). Merges into any existing
    `NO_PROXY`/`no_proxy` value rather than overwriting it, since an operator may already
    have legitimate other entries there.
    """
    if not (s.llm_provider == "litellm_proxy" or s.embedding_provider == "litellm_proxy"
            or s.reranker_provider == "litellm_proxy" or s.llm_moderation_enabled):
        return
    host = urlparse(s.litellm_base_url).hostname
    if not host:
        # urlparse only recognizes a netloc/hostname when the string starts with "//" — a
        # scheme-less value (an operator pasting "host:port" instead of "https://host:port"
        # into LITELLM_BASE_URL) parses with hostname=None otherwise. Retry with a "//" prefix
        # before giving up, so this common misconfiguration doesn't silently skip the fix.
        host = urlparse(f"//{s.litellm_base_url}").hostname
    if not host:
        log.warning("llm.proxy_bypass_no_hostname", litellm_base_url=s.litellm_base_url)
        return
    for var in ("NO_PROXY", "no_proxy"):
        existing = [h for h in os.environ.get(var, "").split(",") if h]
        if host not in existing:
            os.environ[var] = ",".join([*existing, host])


@lru_cache
def get_llm() -> LLMClient:
    """Hands back THE ONE SHARED AI-client object that every part of the app
    should use — never construct your own `LiteLLMClient()` directly
    elsewhere in the codebase; always call this function instead.

    The `@lru_cache` decorator above is what makes this a process-wide
    singleton: the FIRST time `get_llm()` is called anywhere in the running
    process, it builds a real `LiteLLMClient()` (which reads `Settings`
    once) and `lru_cache` remembers that result. Every SUBSEQUENT call to
    `get_llm()` — from any pipeline stage, anywhere — just returns that same
    already-built instance instantly, instead of re-reading `Settings` and
    constructing a brand new client object every single time an AI call is
    needed. That's also why the proxy-bypass env-var fix below only needs to
    run here, once per process, rather than on every individual call.
    """
    _ensure_litellm_proxy_bypassed(get_settings())
    return LiteLLMClient()
