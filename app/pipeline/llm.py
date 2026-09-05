"""litellm adapter — the single boundary to all AI models.

Three INDEPENDENT provider switches, not one: `LLM_PROVIDER` drives chat(),
`EMBEDDING_PROVIDER` drives embed(), `RERANKER_PROVIDER` drives rerank(). Any
combination is valid — always check which one drives the path you're looking at.

Callers depend on the `LLMClient` Protocol, never on litellm directly, so tests can
swap in a deterministic StubLLMClient with no network call.
"""
from __future__ import annotations

import os
import random
import threading
import time
import uuid
from collections.abc import Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Protocol
from urllib.parse import urlparse

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.core.tracing import trace_step

log = get_logger(__name__)

_SLOTS_KEY = "tsg:llm:inflight"
# Poll interval/jitter now live in Settings.llm_slot_poll_seconds /
# Settings.llm_slot_poll_jitter_seconds (defaults unchanged: 0.25 / 0.1).

# Safety caps against pathological input (a document routed into a short field), never expected
# to trip on real text — see the raise sites in embed()/chat(). Now Settings.max_embed_chars /
# Settings.max_chat_chars (defaults unchanged: 4000 / 60_000).

# KEYS[1] = _SLOTS_KEY (a ZSET, one member per in-flight call); ARGV = now, stale_cutoff,
# limit, token. Must stay ONE script: split into ZCARD-then-ZADD it has two bugs — (1) a
# waiter's own ticket counts against the very limit it's waiting to get under, so a freed slot
# never reaches it; (2) two waiters can both see room in the same instant. Redis runs a script
# single-threaded, so prune+count+decide+register can never interleave.
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
    """Temporary "no AI capacity right now — retry, don't fail". Two confirmed sources, same
    semantic: (1) Redis POSITIVELY CONFIRMED the concurrent-call limit is still exhausted for
    the full wait window — never an unreachable/erroring Redis (that fails open, see _llm_slot);
    (2) the PROVIDER answered 429 (rate limit) even after litellm's own num_retries — e.g.
    kimi-k2.5's platform-wide rpm=192 being consumed by other teams (_provider_429_retryable).
    Callers let it propagate past their per-subsystem handler so Celery's autoretry_for retries
    the whole stage via the same claim_stage CAS crash-redelivery uses."""


class LLMResponseTruncated(Exception):
    """The provider stopped at the output cap (finish_reason == "length"): the reply is cut off
    or — on a reasoning model whose hidden thinking is charged against the same cap — entirely
    EMPTY. Raised instead of returning the stump so the failure is named for what it is (a
    budget), not misreported downstream as "the model wrote bad JSON". Carries the numbers the
    operator needs to size TSG_LLM_MAX_OUTPUT_TOKENS / LLM_REASONING_EFFORT."""

    def __init__(self, *, max_tokens: int | None, completion_tokens: int | None,
                 reasoning_tokens: int | None):
        self.max_tokens, self.completion_tokens, self.reasoning_tokens = (
            max_tokens, completion_tokens, reasoning_tokens)
        super().__init__(
            f"the model hit its output cap (max_tokens={max_tokens}, "
            f"completion_tokens={completion_tokens}, reasoning_tokens={reasoning_tokens})")


class LLMRefusal(Exception):
    """Structured Outputs' refusal shape: `message.refusal` set, `content` null. A safety
    refusal, not a malformed reply — classified as a guardrail block (content_blocked, the one
    reason a client must NOT auto-retry), never as invalid_plan."""


@contextmanager
def _provider_429_retryable():
    """Maps a provider-side rate limit onto LLMSlotUnavailable, so a 429 that survives litellm's
    own num_retries lands in the SAME retry-not-fail machinery the internal slot limiter already
    has (Celery autoretry_for on every task, errors.py's 429+Retry-After for inline calls) —
    instead of a generic exception that _record_failure turns into a permanent session ERROR.
    The concrete case: kimi-k2.5's rpm=192 is shared across every team on the proxy, so TSG can
    be throttled by someone else's traffic; that must delay work, never fail it.

    openai.RateLimitError is the right catch for all four call paths: litellm.RateLimitError
    subclasses it (chat/embed/rerank). moderate() swallows it internally — advisory work
    after a billed call must never trigger a generation retry.
    Imported lazily, same pattern as the per-method litellm imports — a stub-only test run
    never needs the package."""
    import openai

    try:
        yield
    except openai.RateLimitError as exc:
        raise LLMSlotUnavailable(f"provider rate limit (429) persisted through retries: {exc}") from exc


@lru_cache
def _slot_redis():
    """Sync Redis client dedicated to LLM-slot traffic — deliberately NOT app.sse.bus._redis(),
    whose zero-retry tuning is right for best-effort SSE publish but would let a brief blip kill
    a heartbeat and falsely evict a call that is still running."""
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
    """Current in-flight LLM-call count (post-prune), for selfcheck.py observability only."""
    try:
        r = _slot_redis()
        now = time.time()
        r.zremrangebyscore(_SLOTS_KEY, "-inf", now - get_settings().llm_slot_stale_after_seconds)
        return r.zcard(_SLOTS_KEY)
    except Exception:  # noqa: BLE001 — observability read, never raises
        return 0


def _try_admit(r, limit: int, stale_after: float, token: str) -> bool:
    """One atomic round-trip: prune stale tickets, then admit `token` iff there's room.
    Exceptions propagate — the caller must treat a Redis failure as fail-open, never as
    "confirmed over capacity"."""
    now = time.time()
    return bool(r.eval(_ADMIT_SCRIPT, 1, _SLOTS_KEY, now, now - stale_after, limit, token))


def _heartbeat_loop(r, token: str, interval: float, stop_event: threading.Event) -> None:
    """Refreshes an admitted ticket's score so staleness pruning never mistakes a still-running
    call for a crashed one, however long the call legitimately takes — aliveness is detected by
    missed heartbeats, never by a guessed duration."""
    while not stop_event.wait(interval):
        try:
            r.zadd(_SLOTS_KEY, {token: time.time()})
        except Exception:
            log.warning("llm.slot_heartbeat_failed", exc_info=True)


@contextmanager
def _llm_slot(s: Settings):
    """Caps concurrent outbound chat/embed/rerank calls ACROSS EVERY WORKER REPLICA sharing
    this Redis (`max_concurrent_llm_calls`, 0 = disabled). `max_active_sessions` only counts
    sessions; this is what protects the shared Azure/GPU backend when workers scale out.

    Any Redis error anywhere here — building the client, one admit attempt, a later poll —
    fails OPEN: an infra fault is not evidence of being over capacity. LLMSlotUnavailable is
    raised ONLY when Redis positively answers "still full" for the whole wait window.
    """
    limit = s.max_concurrent_llm_calls
    if not limit:
        yield
        return

    token = str(uuid.uuid4())
    try:
        r = _slot_redis()
    except Exception:
        log.warning("llm.slot_redis_unavailable_fail_open", exc_info=True)
        yield
        return

    waited = 0.0
    while True:
        try:
            admitted = _try_admit(r, limit, s.llm_slot_stale_after_seconds, token)
        except Exception:
            log.warning("llm.slot_redis_error_fail_open", exc_info=True)
            yield
            return
        if admitted:
            break
        if waited >= s.llm_slot_wait_timeout_seconds:
            raise LLMSlotUnavailable(
                f"no free LLM call slot after waiting {waited:.0f}s (limit={limit})")
        time.sleep(s.llm_slot_poll_seconds + random.uniform(0, s.llm_slot_poll_jitter_seconds))  # jitter avoids synchronized thundering-herd wakeups
        waited += s.llm_slot_poll_seconds

    stop_event = threading.Event()
    # plain threading.Thread, not gevent.spawn: under the gevent-patched worker, monkey-patched
    # `threading` already makes this cooperative; outside gevent it's a harmless OS thread.
    hb_thread = threading.Thread(
        target=_heartbeat_loop, args=(r, token, s.llm_slot_heartbeat_seconds, stop_event), daemon=True)
    hb_thread.start()
    try:
        yield
    finally:
        # Stop + join the heartbeat BEFORE releasing the ticket: released first, a tick still in
        # flight could re-add an orphaned entry nothing would ever clean up.
        stop_event.set()
        hb_thread.join(timeout=s.llm_slot_heartbeat_seconds)
        try:
            r.zrem(_SLOTS_KEY, token)
        except Exception:  # noqa: BLE001 — best-effort release; a leaked slot self-heals via staleness pruning
            pass


@lru_cache(maxsize=1)
def _db_key_scan_pattern():
    """Regex matching an excluded DB key used as a JSON key in an outgoing message.

    Built from prompts._EXCLUDE_DB_KEY_TO_PROMPT, MINUS the bare name `id`: two characters that
    occur in ordinary prose and model output ('the incident was identified'), so scanning raw
    text for it would false-positive and raise on legitimate data. `id` is still removed
    structurally by prompts._scrub_db_keys — this scan is the net for keys that never went
    through it, where the distinctive `*_id` names carry effectively zero false-positive risk.
    Imported lazily: app.pipeline must not import app.db (via prompts) at module load."""
    import re

    from app.pipeline.prompts import _EXCLUDE_DB_KEY_TO_PROMPT

    names = sorted(k for k in _EXCLUDE_DB_KEY_TO_PROMPT if k != "id")
    return re.compile(r'"(' + "|".join(re.escape(n) for n in names) + r')"\s*:')


def _assert_no_db_keys(messages: list[dict], settings: Settings) -> None:
    """LAST LINE: no table primary key leaves the process, whatever built the prompt.

    prompts._scrub_db_keys runs at payload CONSTRUCTION — six sites to remember, and a new
    prompt that assembles its own dict and calls chat() directly (the pattern
    grounding._paraphrase already uses) bypasses every one of them. chat() is the single
    function every prompt in the system must call, so the guarantee belongs here.

    Raises outside production so a bug fails loudly in dev/test/CI; logs and continues in
    production, because a leaked surrogate id is a hygiene defect rather than a secret and
    killing a user's generation over it is the worse outcome. The error log is the prod control.
    """
    hits: set[str] = set()
    for m in messages:
        hits.update(_db_key_scan_pattern().findall(m.get("content") or ""))
    if not hits:
        return
    log.error("prompt.db_key_leak", keys=sorted(hits), app_env=settings.app_env,
            hint="payload bypassed prompts._scrub_db_keys / _context_message")
    if str(settings.app_env).lower() not in ("prod", "production"):
        raise ValueError(
            f"prompt carries database primary keys {sorted(hits)} — build the payload through "
            "prompts._context_message (or _scrub_db_keys) instead of json.dumps")


@dataclass
class Provenance:
    """Which model answered a call and with what settings, so a stored result is traceable."""
    model: str
    model_version: str = ""  # what the provider says it ACTUALLY served; may differ from `model`
    params: dict[str, Any] = field(default_factory=dict)
    prompt_version: str = ""  # set by the pipeline caller (prompt + model provenance)


def _usage_field(obj: Any, name: str) -> Any:
    """Read one usage field off litellm's Usage object OR a plain dict (test stubs); None when
    the provider sent no usage at all."""
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


class LLMClient(Protocol):
    """Contract every AI client implements — the real `LiteLLMClient` below, or a test-only
    `StubLLMClient`. Pipeline code never checks which one it holds."""

    def chat(self, messages: list[dict], *, model: str | None = None,
            temperature: float | None = None,
            expected_type: type | None = None,
            response_schema: type | None = None) -> tuple[str, Provenance]:
        """Single chat completion; returns (text, Provenance) so callers can persist model+params
        without threading litellm-specific response shapes around. `temperature`, like `model`,
        is a per-call override — None means "use the configured default".

        `expected_type` is the top-level JSON type the caller will parse (dict or list). It is
        what decides whether provider-side JSON mode is requested: `{"type":"json_object"}`
        forces an OBJECT, which is wrong for a caller expecting an array. Passing the parser's
        own declaration here makes the two impossible to contradict.

        `response_schema` (optional, a Pydantic model class) is the exact reply shape — strict
        Structured Outputs where the model is known to honour them, plain JSON mode elsewhere
        (Settings.llm_structured_output). Only meaningful with expected_type=dict."""
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
        """Many (query, docs) reranks at once. Per item: the scores list, or None if that item's
        rerank failed (logged); raises only when EVERY item failed (systemic)."""
        ...


def _litellm_key_header(s: Settings) -> dict[str, Any]:
    """`{"extra_headers": {...}}` carrying the litellm key in an ALTERNATE header, or `{}`.

    litellm authenticates with `Authorization: Bearer <key>`, which a gateway in front of the
    proxy may consume or rewrite — then every call 401s, while the same key works as
    `x-litellm-api-key`. Sending both is safe: a bare proxy ignores the extra header."""
    if not s.litellm_api_key_header:
        return {}
    return {"extra_headers": {s.litellm_api_key_header: s.litellm_api_key}}


def _litellm_http_headers(s: Settings) -> dict[str, str]:
    """Same dual-header reasoning as _litellm_key_header, for this file's own httpx calls."""
    headers = {"Authorization": f"Bearer {s.litellm_api_key}"}
    if s.litellm_api_key_header:
        headers[s.litellm_api_key_header] = s.litellm_api_key
    return headers


def _apply_embed_prefix(s: Settings, texts: list[str], kind: str) -> list[str]:
    """Prepend the e5 family's trained-on `query: ` / `passage: ` tag. Provider-agnostic — the
    MODEL needs it whether it runs locally or behind the proxy; without it results degrade
    silently.

    "auto" with a name that doesn't contain "e5" is AMBIGUOUS, not a signal to skip: the name
    may be an opaque proxy deployment alias serving an e5 model underneath. Fail loud rather
    than resolve to "none" and drop the prefix with no log line anywhere.
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
    """Production `LLMClient`: a thin wrapper over litellm. Backend selection, retries, model
    fallback and rate limiting are litellm's / the proxy's job — this class just picks the right
    settings for the configured provider and hands the call off."""

    def __init__(self, settings: Settings | None = None):
        """Accepts an explicit `Settings` for tests; production goes through `get_llm()`."""
        self.s = settings or get_settings()

    def _chat_kwargs(self, model: str | None = None, temperature: float | None = None,
                    expected_type: type | None = None,
                    response_schema: type | None = None) -> dict[str, Any]:
        """Provider dispatch for chat(): azure_openai / openai / (default) litellm proxy, plus
        the timeout+retry budget every call in this file shares. Every branch returns through
        _with_response_format, which needs the RESOLVED model name to decide json_schema vs
        json_object — hence it runs last."""
        s = self.s
        common: dict[str, Any] = {"timeout": s.llm_timeout_seconds, "num_retries": s.llm_max_retries}
        # JSON mode is gated on the CALLER'S declared shape, not on the flag alone.
        # `{"type":"json_object"}` forces a top-level OBJECT. find_threats and
        # grounding._paraphrase both parse a top-level ARRAY, so sending it there instructs the
        # provider to produce exactly what parse_json will then reject — a guaranteed
        # LLMResponseParseError, and only in environments that enable the flag
        # (.env.prod.example does). Driving it from expected_type — the same value the parser
        # asserts on — makes the two impossible to disagree. expected_type=None (a caller with
        # no JSON contract) also opts out. Applied in _with_response_format, once the model is
        # known.
        effective_temperature = temperature if temperature is not None else s.llm_temperature
        if effective_temperature is not None:
            common["temperature"] = effective_temperature
        # Some deployments reject a pinned param: gpt-5 rejects temperature=0.0 (find_threats'
        # default) with UnsupportedParamsError, which would fail EVERY threat-identification
        # call. drop_params lets litellm drop it instead; Provenance still records what we asked.
        common["drop_params"] = True
        # Declare non-streaming ON THE WIRE every call: a proxy model entry pinning
        # `"stream": true` in its litellm_params (glm-5's does) would otherwise decide the
        # response shape server-side. Belt; chat() also braces for a stream coming back anyway.
        common["stream"] = False
        if s.llm_reasoning_effort is not None:
            common["reasoning_effort"] = s.llm_reasoning_effort
        # Bounded cost per call (SDD §16.2 "limit output size"): without it a model in a
        # repetition loop generates until the 90s timeout. drop_params above covers a provider
        # that rejects the parameter; litellm maps it to max_completion_tokens where required.
        if s.llm_max_output_tokens is not None:
            common["max_tokens"] = s.llm_max_output_tokens
        if s.llm_provider == "azure_openai":
            if model:  # Azure addresses a DEPLOYMENT, not a model name — a per-call model can't apply here
                log.debug("llm.azure_ignores_per_call_model", requested=model,
                        deployment=s.azure_openai_deployment_name)
            return self._with_response_format(
                {"model": f"azure/{s.azure_openai_deployment_name}", "api_base": s.azure_openai_endpoint,
                 "api_key": s.azure_openai_api_key, "api_version": s.azure_openai_api_version, **common},
                expected_type, response_schema)
        if s.llm_provider == "openai":
            kw = {"model": model or s.inference_model, "api_key": s.openai_api_key, **common}
            if s.openai_base_url:
                kw["api_base"] = s.openai_base_url
            return self._with_response_format(kw, expected_type, response_schema)
        # default: litellm proxy. custom_llm_provider is required, not cosmetic: litellm's own
        # get_llm_provider() can't infer a provider from an arbitrary proxy-side model alias
        # (e.g. "glm-5") even with api_base set, and raises BadRequestError instead of guessing.
        kw = {"model": model or s.inference_model, "api_base": s.litellm_base_url,
            "api_key": s.litellm_api_key, "custom_llm_provider": "litellm_proxy",
            **_litellm_key_header(s), **common}
        if s.llm_guardrails:  # names pre-registered on the proxy itself — proxy-only, no direct-provider equivalent
            kw["guardrails"] = s.llm_guardrails
        return self._with_response_format(kw, expected_type, response_schema)

    def _with_response_format(self, kw: dict[str, Any], expected_type: type | None,
                              response_schema: type | None) -> dict[str, Any]:
        """Last step of _chat_kwargs. JSON mode is gated on the caller's declared shape (see the
        comment there); WHICH form goes on the wire depends on the RESOLVED model:
        - a declared schema, on a model known to honour it -> strict Structured Outputs (litellm
          turns the Pydantic class into {"type":"json_schema","json_schema":{...,"strict":true}}
          generically, before provider dispatch);
        - otherwise -> {"type":"json_object"}, today's request — so a proxy alias whose upstream
          knows only json_object (glm-5 / kimi-k2.5 native APIs document nothing else) never
          sees a parameter it would 400 on."""
        if self.s.llm_json_mode and expected_type is dict:
            use_schema = response_schema is not None and self._schema_allowed(
                kw["model"], kw.get("custom_llm_provider"))
            kw["response_format"] = response_schema if use_schema else {"type": "json_object"}
        return kw

    def _schema_allowed(self, model: str, provider: str | None) -> bool:
        """Settings.llm_structured_output: on/off are explicit; auto asks litellm's own model
        table (True for azure/gpt-5-mini, False for an unknown proxy alias). Defensive on
        purpose: the test-suite stubs litellm with a namespace that lacks the probe, and
        "unknown" must land on the safe side — json_object."""
        mode = self.s.llm_structured_output
        if mode != "auto":
            return mode == "on"
        import litellm
        probe = getattr(litellm, "supports_response_schema", None)
        try:
            return bool(probe(model=model, custom_llm_provider=provider)) if probe else False
        except Exception:  # noqa: BLE001 — capability probe; "unknown" must land on json_object
            return False

    def chat(self, messages, *, model=None, temperature=None, expected_type=None,
             response_schema=None):
        """One completion → (text, Provenance). litellm is imported locally so a stub-only test
        run never needs the package installed.

        Unlike embed()'s guard, a long chat prompt isn't inherently a bug — free-text context
        fields can legitimately run long against a 131k-token window. `max_chat_chars` sits far
        above that, purely as a net for pathological input (a document landing in a field that
        expected a short value).

        `expected_type` drives provider-side JSON mode — see _chat_kwargs; `response_schema`
        picks strict Structured Outputs over plain JSON mode where the model allows it — see
        _with_response_format. A reply stopped at the output cap raises LLMResponseTruncated; a
        Structured Outputs refusal raises LLMRefusal — neither is ever returned as text.
        """
        import litellm

        max_chat_chars = self.s.max_chat_chars
        total_chars = sum(len(m.get("content") or "") for m in messages)
        if total_chars > max_chat_chars:
            raise ValueError(
                f"chat() received a {total_chars}-char prompt, over the {max_chat_chars}-char "
                "safety cap — check for an unexpectedly large free-text field (e.g. "
                "technology_used, incident_description, cii_asset_description)")

        _assert_no_db_keys(messages, self.s)
        kwargs = self._chat_kwargs(model, temperature, expected_type, response_schema)
        # THE trace hook for model calls, placed HERE rather than on tasks._ask_ai because two
        # callers bypass that wrapper entirely — grounding._paraphrase (threshold calibration,
        # run at worker boot) and this module's own selfcheck. One hook on the client covers
        # every chat completion the process makes, including those two.
        def _complete(kw: dict[str, Any]):
            resp = litellm.completion(messages=messages, **kw)
            # Suspenders to _chat_kwargs' stream=False belt: if the server streamed anyway (a
            # proxy model entry pinning `"stream": true` overrides the client), assemble the
            # chunks — chat()'s contract must never depend on a server-side config knob.
            # Inside the slot: the stream is still an in-flight call until drained.
            if isinstance(resp, litellm.CustomStreamWrapper):
                resp = litellm.stream_chunk_builder(list(resp), messages=messages)
                if resp is None:  # empty stream — fail loud, same posture as the parse guards
                    raise RuntimeError("chat provider returned an empty stream")
            return resp

        fallback_from = ""
        with trace_step("LLM CALL", None, model=kwargs.get("model"),
                        messages=len(messages), prompt_chars=total_chars,
                        expected_type=getattr(expected_type, "__name__", None),
                        response_schema=getattr(response_schema, "__name__", None)) as _t:
            with _llm_slot(self.s), _provider_429_retryable():
                try:
                    resp = _complete(kwargs)
                except Exception as exc:
                    # APP-SIDE model fallback (inference_fallback_model): retry THIS call once
                    # on the second model, inside the same slot (still one in-flight call).
                    # Only for calls that did not pin an explicit model — a pinned model is a
                    # deliberate choice (boot probes, calibration) that must fail as itself.
                    # If the fallback also rate-limits, the raise lands in
                    # _provider_429_retryable and becomes LLMSlotUnavailable exactly as before.
                    fb = self.s.inference_fallback_model
                    if model is not None or not self._fallback_applies(fb, kwargs["model"], exc):
                        raise
                    log.warning("llm.fallback_model_used", primary=kwargs["model"], fallback=fb,
                                error=f"{type(exc).__name__}: {exc}")
                    fallback_from = kwargs["model"]
                    kwargs = self._chat_kwargs(fb, temperature, expected_type, response_schema)
                    try:
                        resp = _complete(kwargs)
                    except Exception as fb_exc:
                        # The fallback could not rescue the call: re-raise the PRIMARY's error —
                        # it is the truthful signal for the retry machinery. A primary 429 must
                        # still become LLMSlotUnavailable (retry later), not whatever unrelated
                        # class the fallback happened to fail with, which would turn a transient
                        # saturation into a permanent stage ERROR.
                        log.warning("llm.fallback_also_failed", fallback=fb,
                                    error=f"{type(fb_exc).__name__}: {fb_exc}")
                        raise exc from fb_exc
            choice = resp["choices"][0]
            msg = choice["message"]
            content = msg.get("content")
            finish_reason = choice.get("finish_reason")
            usage = resp.get("usage")
            completion_tokens = _usage_field(usage, "completion_tokens")
            reasoning_tokens = _usage_field(_usage_field(usage, "completion_tokens_details"),
                                            "reasoning_tokens")
            _t.result(served_model=str(resp.get("model", "") or ""),
                    response_chars=len(content or ""), finish_reason=finish_reason,
                    completion_tokens=completion_tokens, reasoning_tokens=reasoning_tokens)
            # A reply cut at the cap is a BUDGET failure, not a JSON one — and on a reasoning
            # model it is usually an EMPTY string (the thinking spent the whole cap). Name it.
            if finish_reason == "length":
                raise LLMResponseTruncated(max_tokens=kwargs.get("max_tokens"),
                                           completion_tokens=completion_tokens,
                                           reasoning_tokens=reasoning_tokens)
            # Structured Outputs' refusal shape: no content, a `refusal` string instead.
            refusal = msg.get("refusal")
            if not content and refusal:
                raise LLMRefusal(str(refusal))
        rf = kwargs.get("response_format")
        rf_label = (None if rf is None
                    else f"json_schema:{rf.__name__}" if rf is response_schema else "json_object")
        return content, Provenance(
            model=kwargs["model"],
            # what the proxy ACTUALLY served (may be a dated snapshot / fallback of the
            # requested name), not just what we asked for.
            model_version=str(resp.get("model", "") or ""),
            params={
                "provider": self.s.llm_provider,
                "timeout": self.s.llm_timeout_seconds,
                "num_retries": self.s.llm_max_retries,
                "json_mode": self.s.llm_json_mode,
                # which JSON contract actually went on the wire for THIS call (see
                # _with_response_format) — a receipt must say whether the schema was enforced.
                **({"response_format": rf_label} if rf_label else {}),
                # only recorded when actually pinned; read back from `kwargs` (the resolved
                # value) rather than re-deriving _chat_kwargs' precedence a second time.
                **({"temperature": kwargs["temperature"]} if "temperature" in kwargs else {}),
                **({"max_tokens": kwargs["max_tokens"]} if "max_tokens" in kwargs else {}),
                **({"reasoning_effort": self.s.llm_reasoning_effort}
                if self.s.llm_reasoning_effort is not None else {}),
                # Only present when the fallback actually served this answer — provenance is
                # how a stored result stays traceable to the model that wrote it.
                **({"fallback_from": fallback_from} if fallback_from else {}),
            },
        )

    def _fallback_applies(self, fb: str, primary: str, exc: Exception) -> bool:
        """Should this failed primary chat call be retried on `inference_fallback_model`?

        Only for failures a DIFFERENT healthy model could plausibly answer: timeouts and
        connection drops, a 429 that survived litellm's own num_retries (the primary is
        saturated — its shared rpm may be consumed by other teams), and 5xx. Any other 4xx
        (auth, bad request, content policy) fails identically on every model — falling back
        would double the cost of the same error and hide its cause. Azure is excluded
        wholesale: _chat_kwargs addresses a fixed DEPLOYMENT and ignores per-call models, so a
        "fallback" there would silently re-call the same deployment and learn nothing.
        """
        if not fb or fb == primary or self.s.llm_provider == "azure_openai":
            return False
        import openai

        if isinstance(exc, openai.RateLimitError):  # checked before APIStatusError: 429 < 500
            return True
        if isinstance(exc, openai.APIConnectionError):  # includes APITimeoutError
            return True
        if isinstance(exc, openai.APIStatusError):
            return exc.status_code >= 500
        # litellm wraps statuses it has no specific mapping for (501/505, CDN/gateway 520-524)
        # in litellm.APIError, which subclasses openai.APIError but NOT APIStatusError — a
        # gateway melting down in front of the proxy is exactly the failure a second model can
        # answer. It always carries status_code; anything below 500 (or absent) stays no-fallback.
        if isinstance(exc, openai.APIError):
            return (getattr(exc, "status_code", 0) or 0) >= 500
        return False

    def embed(self, texts, *, model=None, kind="query"):
        """Batch text → vectors, via `embedding_provider` ('local' runs in-process, so the
        network timeout/retry settings simply don't apply there).

        Every real caller embeds a SHORT LABEL (a library name, or the model's proposed type
        name), never a document. Anything over `max_embed_chars` is a bug upstream, so reject
        rather than truncate — a truncated name changes meaning with nobody noticing.

        The provider caps texts PER REQUEST (32 for qwen3-embedding-8b-mig), so the list goes out
        in `embedding_batch_size` chunks. That cap belongs HERE, not in the callers: every embed
        path routes through this method, and five callers used to hand it unbounded lists and
        swallow the provider's rejection into a silently worse answer (keyword-only ranking, a
        dedup pass that reports "no duplicates", ...).
        """
        texts = list(texts)
        if not texts:
            # Before ANY other work: no prefixing (which can raise on an ambiguous prefix style),
            # no validation, and no LLM slot. Matches local_models.embed's []-in-[]-out.
            return []

        # Validate the CALLER'S text, before prefixing. max_embed_chars is a contract about what
        # the caller may hand us; `passage: ` is our own internal addition that the caller cannot
        # see or budget for. Checking after prefixing rejected callers who had correctly truncated
        # to exactly max_embed_chars — threat_retrieval.py:296 does exactly that, and the ValueError
        # was swallowed there into permanent keyword-only ranking.
        max_embed_chars = self.s.max_embed_chars
        too_long = [t for t in texts if len(t) > max_embed_chars]
        if too_long:
            raise ValueError(
                f"embed() received {len(too_long)} text(s) over {max_embed_chars} chars "
                f"(longest {max(len(t) for t in too_long)}) — refusing to send to the embedding "
                "model; this is never legitimate input for a short library-matching label")
        # Prefixing stays OUTSIDE the chunk loop below: prefixing a slice of the already-prefixed
        # list would double it ("query: query: foo"). Validating up front keeps the all-or-nothing
        # contract too — one over-long text still costs zero calls.
        texts = _apply_embed_prefix(self.s, texts, kind)  # e5 prefixes, both providers
        if self.s.embedding_provider == "local":
            from app.pipeline import local_models

            # embed() applies no cap here: there is no per-request limit in-process, and encode()
            # mini-batches internally. A caller may still invoke this in batches for its OWN
            # reasons (get_vectors does, to persist as it goes) — that is the caller's choice,
            # never a cap enforced on this path.
            return local_models.embed(texts)  # in-process — no network timeout/retry applies

        model = model or self.s.embedding_model
        batch = self.s.embedding_batch_size
        vecs: list[list[float]] = []
        # One slot per INVOCATION, covering every chunk of it — never one per chunk.
        # llm_slot_wait_timeout_seconds is a per-call budget, so re-acquiring inside this loop
        # would multiply it by the chunk count; the slot's heartbeat is what covers the whole span.
        #
        # How coarsely to invoke this is the CALLER's decision, and embeddings.get_vectors
        # deliberately goes the other way — it calls once per batch so each batch is persisted as
        # it lands. That buys durability at the price of more acquisitions, and it is safe
        # precisely because a preemption there costs only the batch in flight. Do not "optimise"
        # that caller back into a single call without also moving its write-back.
        with _llm_slot(self.s), _provider_429_retryable():
            for i in range(0, len(texts), batch):
                vecs.extend(self._embed_one_batch(texts[i:i + batch], model))
        return vecs

    def _embed_one_batch(self, texts: list[str], model: str) -> list[list[float]]:
        """One provider request, already sliced to the batch cap. Caller holds the LLM slot."""
        import litellm

        resp = litellm.embedding(
            model=model, input=texts, custom_llm_provider="litellm_proxy",  # see _chat_kwargs
            api_base=self.s.litellm_base_url, api_key=self.s.litellm_api_key,
            **_litellm_key_header(self.s),  # gateway-safe alternate auth header, when configured
            timeout=self.s.llm_timeout_seconds, num_retries=self.s.llm_max_retries,  # same bounds as chat
        )
        # `data` MAY come back out of input order, so vectors are PLACED by their own `index`,
        # never appended in arrival order — identical posture to rerank() below.
        #
        # Placing by index rather than sorting is what makes this safe: a sort would happily
        # accept duplicate indices ([0, 0, 2] for three texts passes any count check) and hand
        # texts[1] the wrong vector. _stage_for_write's zip would then persist that pairing in
        # Mongo under the wrong key — silently, permanently, poisoning every later cosine score.
        # The missing-index check below catches duplicates, short responses and out-of-range
        # indices in one go.
        #
        # `index` is PER-REQUEST — it restarts at 0 for every chunk — which is exactly why this
        # happens HERE, per chunk, before embed() concatenates.
        by_index = {d["index"]: d["embedding"] for d in resp["data"]}
        missing = [i for i in range(len(texts)) if i not in by_index]
        if missing:
            raise RuntimeError(
                f"embed returned {len(by_index)} usable vectors for {len(texts)} texts "
                f"(model {model!r}, missing index(es): {missing}) — refusing to return a "
                "misaligned batch")
        return [by_index[i] for i in range(len(texts))]

    def rerank(self, query, docs, *, model=None):
        """Score each doc's relevance to `query`, 0-100, aligned position-for-position with
        `docs`. Routes on `reranker_provider`, independently of the other two switches.

        Same out-of-order hazard as embed(): results are placed by their `"index"` field, never
        appended in arrival order, and raw scores are scaled x100 (§8.4). A response that misses
        an index fails loud rather than defaulting to a fabricated 0.0 — a fake worst score would
        mispair silently (and makes grounding.find_closest_match's length guard reachable).
        """
        if self.s.reranker_provider == "local":
            from app.pipeline import local_models

            return local_models.rerank(query, docs)  # in-process — no network timeout/retry applies
        import litellm

        model = model or self.s.reranker_model
        with _llm_slot(self.s), _provider_429_retryable():
            resp = litellm.rerank(
                model=model, query=query, documents=list(docs),
                custom_llm_provider="litellm_proxy",  # see _chat_kwargs
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

        LOCAL: cross-encoders score each pair independently, so all items' pairs flatten into ONE
        dispatch (score-identical to per-item calls). A failure there is systemic by construction,
        so it propagates.

        REMOTE: rerank APIs take one query per request, so the win is concurrency, not batching —
        a bounded pool reuses self.rerank per item so retries/timeouts/slot handling aren't
        reimplemented. rerank_concurrency is only a local politeness cap; each call still takes
        its own _llm_slot, so the Redis semaphore stays the global authority. Per-item failure
        (incl. LLMSlotUnavailable) -> None + warning; raise only if EVERY item failed, so one
        starved call can't wipe out a whole mapping run."""
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
            except Exception:
                failures += 1
                log.warning("rerank_many.item_failed", index=i, exc_info=True)
        if failures == len(items):
            raise RuntimeError(f"rerank_many: all {len(items)} rerank calls failed")
        return results


@dataclass
class ModerationResult:
    """Outcome of one moderation check — always returned, never raises. `checked=False` covers
    BOTH "the feature is off" and "the call failed" (`error` distinguishes them); "not checked"
    must never be conflated with "checked and came back clean"."""
    checked: bool
    flagged: bool = False
    categories: list[str] = field(default_factory=list)
    error: str | None = None


def moderate(text: str, *, settings: Settings | None = None) -> ModerationResult:
    """Content-moderation check via the litellm proxy's /moderations endpoint. Off by default —
    this app's whole job is writing about attacks and sabotage, exactly what moderation
    categories flag, so it is advisory (see tasks.py), never a hard gate.

    NOT on the `LLMClient` Protocol: moderation has exactly one backend, so adding it would force
    a dead `.moderate()` onto `StubLLMClient`. A free function, like `verify_litellm_models`.

    Bypasses litellm.moderation() deliberately: it silently ignores `timeout`/`num_retries` on
    the `openai.OpenAI()` client it builds internally (breaking this file's "every call is
    bounded" rule) and falls back to a GLOBAL api key env var, which could hit real OpenAI
    instead of the configured proxy.

    NEVER RAISES, full stop: a moderation failure must never block (or re-run) generation.
    That includes `LLMSlotUnavailable` — moderation runs AFTER the paid chat call, so letting
    the slot signal escape made Celery autoretry throw away and re-bill a finished
    generation. Slot exhaustion returns `checked=False, error="moderation_slots_exhausted"`;
    every other failure returns `checked=False, error="moderation_unavailable"`.

    Applies `_ensure_litellm_proxy_bypassed` itself because moderation's target host is
    independent of the three provider switches — a moderation-only deployment would otherwise
    never apply the CONNECT-hang fix anywhere in the process.
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
        with _llm_slot(s), _provider_429_retryable():
            resp = client.moderations.create(**kwargs)
        # Parsing stays INSIDE the try: an empty resp.results (or any unexpected shape) would
        # otherwise raise past this function's never-raises contract, turning a malformed
        # response into a full subsystem ERROR.
        result = resp.results[0]
        flagged_categories = [cat for cat, is_flagged in result.categories.model_dump().items() if is_flagged]
    except LLMSlotUnavailable:
        # Advisory call, made AFTER the billed generation — swallowing the retry signal here
        # is what keeps a moderation slot shortage from discarding finished work upstream.
        log.warning("llm.moderation_slots_exhausted")
        return ModerationResult(checked=False, error="moderation_slots_exhausted")
    except Exception:
        log.warning("llm.moderation_call_failed", exc_info=True)
        return ModerationResult(checked=False, error="moderation_unavailable")

    return ModerationResult(checked=True, flagged=result.flagged, categories=flagged_categories)


@lru_cache
def _moderation_client(api_key: str, base_url: str, timeout: float, max_retries: int):
    """`moderate()` runs on the generation hot path (once per scenario), so the client is cached
    to reuse the TCP/TLS connection instead of handshaking per scenario. Keyed on the scalars
    that determine client identity because `Settings` isn't hashable."""
    import openai

    return openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout, max_retries=max_retries)


def verify_litellm_models(settings: Settings | None = None) -> None:
    """Fail-fast at worker startup: confirm every model reached THROUGH THE PROXY is really
    registered there — same discipline as local_models.validate_local_models for the in-process
    path, called alongside it in celery_app.py's _init_worker.

    Only checks providers actually set to 'litellm_proxy', so a deployment with no proxy access
    makes no network call at all.

    Applies `_ensure_litellm_proxy_bypassed` itself: this runs before any task (and so before
    any `get_llm()`) in the process, so it can't rely on get_llm() having set the env var.
    Without it, a worker behind a broken internal proxy hangs right here at boot.
    """
    s = settings or get_settings()
    _ensure_litellm_proxy_bypassed(s)
    if s.llm_provider != "litellm_proxy":  # direct providers have no registration check below
        # openai-direct pins the model so a configured fallback cannot mask a broken primary
        # (azure keeps None — it addresses a deployment and would only log the ignored model).
        _verify_chat_provider_reachable(
            s, model=s.inference_model if s.llm_provider == "openai" else None)
        if s.inference_fallback_model and s.llm_provider == "openai":
            _verify_fallback_model(s)
    wanted: dict[str, str] = {}
    if s.llm_provider == "litellm_proxy":
        wanted["inference_model"] = s.inference_model
        # inference_fallback_model is deliberately NOT in `wanted`: it is a resilience layer,
        # and a missing/broken fallback must never block a boot whose primary is healthy —
        # _verify_fallback_model probes it warn-only instead.
    if s.embedding_provider == "litellm_proxy":
        wanted["embedding_model"] = s.embedding_model
    if s.reranker_provider == "litellm_proxy":
        wanted["reranker_model"] = s.reranker_model
    if not wanted:
        return

    import httpx

    # Retries here for the same reason every other call in this file gets them: this runs at
    # worker startup, so a blip (the proxy mid-rolling-deploy) must not hard-fail the worker.
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
        # Registration is NOT "answers usably": /v1/models proves the model is LISTED, never that
        # it returns something chat() can parse. Runs after the checks above so a missing model
        # still reports the clearer "not registered" error first. Both probes PIN their model
        # explicitly: chat() never falls back on a pinned model, so a broken primary cannot hide
        # behind a healthy fallback here (and vice versa).
        _verify_chat_provider_reachable(s, model=s.inference_model)
        if s.inference_fallback_model:
            _verify_fallback_model(s)

    # Observability, not verification: log each model's configured rate limit AT DEPLOY TIME so a
    # later rate-limit incident is checkable against real config instead of someone's memory.
    # Never raises — a failure here only costs the log line.
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
    except Exception:
        log.warning("llm.model_config_check_failed", exc_info=True)


def _verify_fallback_model(s: Settings) -> None:
    """Probe `inference_fallback_model` — WARN-ONLY, never a boot failure.

    The fallback is a resilience layer, and fail-closed here would INVERT the feature: a
    down/throttled fallback crash-looping workers whose primary is perfectly healthy is
    strictly worse than having no fallback at all. Failures warn (llm.fallback_model_unverified)
    and boot continues; the runtime guard — chat() re-raising the PRIMARY's error when the
    fallback also fails — keeps live traffic correct even if the fallback stays broken."""
    try:
        _verify_chat_provider_reachable(s, model=s.inference_fallback_model)
    except Exception:
        log.warning("llm.fallback_model_unverified", model=s.inference_fallback_model,
                    exc_info=True)


def _verify_chat_provider_reachable(s: Settings, model: str | None = None) -> None:
    """One real chat completion at worker boot, for EVERY provider. Registration/reachability is
    not enough: a proxy entry pinning `"stream": true` (glm-5's does) returns a streaming wrapper
    where chat() expects a completed message; an expired Azure key or decommissioned deployment
    is the same class of problem on the direct path.

    Reuses LiteLLMClient.chat() so this exercises the exact dispatch a real session uses.
    Boot-time only, deliberately not in the periodic self-check — there's no free reachability
    probe for a direct chat deployment, and a real billed completion every five minutes forever
    is a lot to pay for a boot-time-class problem.

    The message must contain the literal word "json": with LLM_JSON_MODE on, _chat_kwargs adds
    response_format={"type": "json_object"} to this call too, and OpenAI/Azure reject a
    json_object request with 400 unless "json" appears in the messages."""
    try:
        LiteLLMClient(s).chat(
            [{"role": "user", "content": 'Reply with any valid json, e.g. {"ok": true}.'}],
            model=model)  # pinned by litellm-proxy callers so fallback can't mask this probe
    except LLMSlotUnavailable:
        # Must stay itself: celery_app._init_worker retries `except LLMSlotUnavailable` so a
        # coordinated restart — many replicas booting at once under max_concurrent_llm_calls —
        # backs off. Wrapping it in RuntimeError makes that boot-retry unreachable and turns the
        # highest-contention moment the slot mechanism exists for into a fleet-wide boot failure.
        raise
    except Exception as exc:
        raise RuntimeError(
            f"{s.llm_provider} chat provider ({model or s.inference_model}) was unreachable or "
            f"rejected a startup verification call: {exc}") from exc


def _verify_embedding_dimensions(s: Settings) -> None:
    """`local_models.validate_local_models` only dimension-checks the LOCAL path; a proxy-routed
    model can return a different width than EMBEDDING_DIMENSIONS (qwen3-embedding-8b-mig returns
    4096 against the 1024 default) and nothing downstream enforces it — vectors are stored as a
    schema-less Mongo array, and a stale mismatched vector wouldn't crash: `hybrid_search.cosine`
    returns a flat 0.0 for any length mismatch rather than raising, so it would just silently
    score as an ordinary no-match, masking a real dimension drift instead of surfacing an error.

    Costs one real embedding call at boot — same cadence validate_local_models already pays.

    The probe deliberately sends a FULL `embedding_batch_size` batch rather than one text, so it
    also proves the configured batch fits under the provider's per-request cap. A too-large batch
    then fails HERE, at worker boot with the setting named, instead of inside a background
    embedding job where _for_each_group would bury it. Note this is a COUNT check: identical short
    strings cannot probe a token-budget limit, and it only guards the Celery worker — app/main.py's
    lifespan does not call verify_litellm_models, so the API process (eager_embed_promoted) relies
    on LiteLLMClient.embed's chunking instead.
    """
    import litellm

    probe = [f"dimension check {i}" for i in range(s.embedding_batch_size)]
    try:
        # _provider_429_retryable, same as embed(): without it a boot-time rate limit surfaces as
        # a raw RateLimitError that nobody catches. Mapped to LLMSlotUnavailable it becomes a
        # retry _init_worker already knows how to back off on — which matters most when a whole
        # replica set boots at once and contends for the same proxy.
        with _llm_slot(s), _provider_429_retryable():
            resp = litellm.embedding(
                model=s.embedding_model, input=probe,
                custom_llm_provider="litellm_proxy",  # see _chat_kwargs
                api_base=s.litellm_base_url, api_key=s.litellm_api_key,
                **_litellm_key_header(s),  # gateway-safe alternate auth header, when configured
                timeout=s.llm_timeout_seconds, num_retries=s.llm_max_retries,
            )
    except LLMSlotUnavailable:
        # Must stay itself so celery_app._init_worker's boot-retry still backs off — same
        # reasoning as _verify_chat_provider_reachable's own re-raise.
        raise
    except Exception as exc:
        # Deliberately NEUTRAL about the cause: an auth failure, a decommissioned deployment and a
        # network timeout all land here too, and naming only the batch size would send an operator
        # after the wrong knob at boot, where diagnosis is hardest. Batch size is offered as ONE
        # candidate because it is the one this probe uniquely exercises.
        raise RuntimeError(
            f"litellm proxy model '{s.embedding_model}' failed a {len(probe)}-text embedding "
            f"probe: {exc} — check the model is reachable and the key is valid; if the provider "
            f"rejected the request for its size, lower TSG_EMBEDDING_BATCH_SIZE (currently "
            f"{s.embedding_batch_size}) to its per-request cap") from exc
    if len(resp["data"]) != len(probe):
        raise RuntimeError(
            f"litellm proxy model '{s.embedding_model}' returned {len(resp['data'])} vectors for "
            f"a {len(probe)}-text batch — TSG_EMBEDDING_BATCH_SIZE={s.embedding_batch_size} is "
            "above what this provider serves in one request; lower it before starting")
    dim = len(resp["data"][0]["embedding"])
    if dim != s.embedding_dimensions:
        raise RuntimeError(
            f"EMBEDDING_DIMENSIONS={s.embedding_dimensions} but litellm proxy model "
            f"'{s.embedding_model}' actually returns {dim}-dimensional vectors — fix "
            f"EMBEDDING_DIMENSIONS in .env before starting; a stale mismatch here would "
            f"otherwise silently mask as an ordinary threat-grounding no-match instead of "
            f"surfacing an error (see hybrid_search.cosine)")


def log_litellm_key_info(settings: Settings | None = None) -> None:
    """Logs what the proxy says this deployment's own key is configured with (rate limit,
    budget), so `max_concurrent_llm_calls` tuning is checkable against the real ceiling.

    The `/key/info` shape is unconfirmed against a live proxy, so it's parsed defensively and
    never raises — this is a log line, not a gate.
    """
    s = settings or get_settings()
    # includes llm_moderation_enabled: moderation uses the same key and can be the only thing
    # reaching the proxy, so gating on the three providers alone would skip this log line.
    if not (s.llm_provider == "litellm_proxy" or s.embedding_provider == "litellm_proxy"
            or s.reranker_provider == "litellm_proxy" or s.llm_moderation_enabled):
        return

    # Self-apply the bypass rather than rely on _init_worker's call order.
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
        else:  # never log the raw body: an unconfirmed future shape could carry something more
            # sensitive than these four fields, with no redact() applied.
            log.warning("llm.key_info_unexpected_shape")
    except Exception:
        log.warning("llm.key_info_check_failed", exc_info=True)


def _ensure_litellm_proxy_bypassed(s: Settings) -> None:
    """Jumpserver-confirmed: an internal HTTP_PROXY/HTTPS_PROXY that httpx auto-routes through
    never completes the CONNECT tunnel to the litellm proxy host, hanging every call until
    timeout. litellm.completion/embedding/rerank expose no `trust_env`/`http_client` override, so
    the fix has to be at the env-var layer — `NO_PROXY` is honored by virtually every Python HTTP
    library, whichever one litellm uses internally.

    Gated on anything that actually reaches the proxy, INCLUDING moderation (its only backend is
    the proxy, independent of the three provider switches). Merges into any existing NO_PROXY
    rather than overwriting an operator's other entries.

    Set settings.litellm_bypass_proxy=False when the deployment's proxy is REQUIRED for litellm
    traffic (not broken) — otherwise this bypass silently defeats it.
    """
    if not s.litellm_bypass_proxy:
        return
    if not (s.llm_provider == "litellm_proxy" or s.embedding_provider == "litellm_proxy"
            or s.reranker_provider == "litellm_proxy" or s.llm_moderation_enabled):
        return
    host = urlparse(s.litellm_base_url).hostname
    if not host:
        # urlparse only finds a hostname when the string starts with "//" — a scheme-less
        # LITELLM_BASE_URL ("host:port") parses with hostname=None. Retry prefixed so this
        # common misconfiguration doesn't silently skip the fix.
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
    """The one shared AI client — never construct `LiteLLMClient()` elsewhere. `@lru_cache` makes
    it a process-wide singleton, which is also why the proxy-bypass fix only runs once here."""
    _ensure_litellm_proxy_bypassed(get_settings())
    return LiteLLMClient()


