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


class LLMClient(Protocol):
    """Contract every AI client implements — the real `LiteLLMClient` below, or a test-only
    `StubLLMClient`. Pipeline code never checks which one it holds."""

    def chat(self, messages: list[dict], *, model: str | None = None,
            temperature: float | None = None,
            expected_type: type | None = None) -> tuple[str, Provenance]:
        """Single chat completion; returns (text, Provenance) so callers can persist model+params
        without threading litellm-specific response shapes around. `temperature`, like `model`,
        is a per-call override — None means "use the configured default".

        `expected_type` is the top-level JSON type the caller will parse (dict or list). It is
        what decides whether provider-side JSON mode is requested: `{"type":"json_object"}`
        forces an OBJECT, which is wrong for a caller expecting an array. Passing the parser's
        own declaration here makes the two impossible to contradict."""
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
                    expected_type: type | None = None) -> dict[str, Any]:
        """Provider dispatch for chat(): azure_openai / openai / (default) litellm proxy, plus
        the timeout+retry budget every call in this file shares."""
        s = self.s
        common: dict[str, Any] = {"timeout": s.llm_timeout_seconds, "num_retries": s.llm_max_retries}
        # JSON mode is gated on the CALLER'S declared shape, not on the flag alone.
        # `{"type":"json_object"}` forces a top-level OBJECT. find_threats and
        # grounding._paraphrase both parse a top-level ARRAY, so sending it there instructs the
        # provider to produce exactly what parse_json will then reject — a guaranteed
        # LLMResponseParseError, and only in environments that enable the flag
        # (.env.prod.example does). Driving it from expected_type — the same value the parser
        # asserts on — makes the two impossible to disagree. expected_type=None (a caller with
        # no JSON contract) also opts out.
        if s.llm_json_mode and expected_type is dict:
            common["response_format"] = {"type": "json_object"}
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
        # default: litellm proxy. custom_llm_provider is required, not cosmetic: litellm's own
        # get_llm_provider() can't infer a provider from an arbitrary proxy-side model alias
        # (e.g. "glm-5") even with api_base set, and raises BadRequestError instead of guessing.
        kw = {"model": model or s.inference_model, "api_base": s.litellm_base_url,
            "api_key": s.litellm_api_key, "custom_llm_provider": "litellm_proxy",
            **_litellm_key_header(s), **common}
        if s.llm_guardrails:  # names pre-registered on the proxy itself — proxy-only, no direct-provider equivalent
            kw["guardrails"] = s.llm_guardrails
        return kw

    def chat(self, messages, *, model=None, temperature=None, expected_type=None):
        """One completion → (text, Provenance). litellm is imported locally so a stub-only test
        run never needs the package installed.

        Unlike embed()'s guard, a long chat prompt isn't inherently a bug — free-text context
        fields can legitimately run long against a 131k-token window. `max_chat_chars` sits far
        above that, purely as a net for pathological input (a document landing in a field that
        expected a short value).

        `expected_type` drives provider-side JSON mode — see _chat_kwargs.
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
        kwargs = self._chat_kwargs(model, temperature, expected_type)
        with _llm_slot(self.s), _provider_429_retryable():
            resp = litellm.completion(messages=messages, **kwargs)
            # Suspenders to _chat_kwargs' stream=False belt: if the server streamed anyway (a
            # proxy model entry pinning `"stream": true` overrides the client), assemble the
            # chunks — chat()'s contract must never depend on a server-side config knob. Inside
            # the slot: the stream is still an in-flight call until drained.
            if isinstance(resp, litellm.CustomStreamWrapper):
                resp = litellm.stream_chunk_builder(list(resp), messages=messages)
                if resp is None:  # empty stream — fail loud, same posture as the parse guards
                    raise RuntimeError("chat provider returned an empty stream")
        return resp["choices"][0]["message"]["content"], Provenance(
            model=kwargs["model"],
            # what the proxy ACTUALLY served (may be a dated snapshot / fallback of the
            # requested name), not just what we asked for.
            model_version=str(resp.get("model", "") or ""),
            params={
                "provider": self.s.llm_provider,
                "timeout": self.s.llm_timeout_seconds,
                "num_retries": self.s.llm_max_retries,
                "json_mode": self.s.llm_json_mode,
                # only recorded when actually pinned; read back from `kwargs` (the resolved
                # value) rather than re-deriving _chat_kwargs' precedence a second time.
                **({"temperature": kwargs["temperature"]} if "temperature" in kwargs else {}),
                **({"reasoning_effort": self.s.llm_reasoning_effort}
                if self.s.llm_reasoning_effort is not None else {}),
            },
        )

    def embed(self, texts, *, model=None, kind="query"):
        """Batch text → vectors, via `embedding_provider` ('local' runs in-process, so the
        network timeout/retry settings simply don't apply there).

        Every real caller embeds a SHORT LABEL (a library name, or the model's proposed type
        name), never a document. Anything over `max_embed_chars` is a bug upstream, so reject
        rather than truncate — a truncated name changes meaning with nobody noticing.
        """
        max_embed_chars = self.s.max_embed_chars
        texts = _apply_embed_prefix(self.s, list(texts), kind)  # e5 prefixes, both providers
        too_long = [t for t in texts if len(t) > max_embed_chars]
        if too_long:
            raise ValueError(
                f"embed() received {len(too_long)} text(s) over {max_embed_chars} chars "
                f"(longest {max(len(t) for t in too_long)}) — refusing to send to the embedding "
                "model; this is never legitimate input for a short library-matching label")
        if self.s.embedding_provider == "local":
            from app.pipeline import local_models

            return local_models.embed(texts)  # in-process — no network timeout/retry applies
        import litellm

        model = model or self.s.embedding_model
        with _llm_slot(self.s), _provider_429_retryable():
            resp = litellm.embedding(
                model=model, input=texts, custom_llm_provider="litellm_proxy",  # see _chat_kwargs
                api_base=self.s.litellm_base_url, api_key=self.s.litellm_api_key,
                **_litellm_key_header(self.s),  # gateway-safe alternate auth header, when configured
                timeout=self.s.llm_timeout_seconds, num_retries=self.s.llm_max_retries,  # same bounds as chat
            )
        # `data` MAY come back out of input order; sort by index so positional callers
        # (embeddings.get_vectors's zip) never cache a text against the wrong vector. cf. rerank().
        return [d["embedding"] for d in sorted(resp["data"], key=lambda d: d["index"])]

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
        # still reports the clearer "not registered" error first.
        _verify_chat_provider_reachable(s)

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


def _verify_chat_provider_reachable(s: Settings) -> None:
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
        LiteLLMClient(s).chat([{"role": "user", "content": 'Reply with any valid json, e.g. {"ok": true}.'}])
    except LLMSlotUnavailable:
        # Must stay itself: celery_app._init_worker retries `except LLMSlotUnavailable` so a
        # coordinated restart — many replicas booting at once under max_concurrent_llm_calls —
        # backs off. Wrapping it in RuntimeError makes that boot-retry unreachable and turns the
        # highest-contention moment the slot mechanism exists for into a fleet-wide boot failure.
        raise
    except Exception as exc:
        raise RuntimeError(
            f"{s.llm_provider} chat provider was unreachable or rejected a startup "
            f"verification call: {exc}") from exc


def _verify_embedding_dimensions(s: Settings) -> None:
    """`local_models.validate_local_models` only dimension-checks the LOCAL path; a proxy-routed
    model can return a different width than EMBEDDING_DIMENSIONS (qwen3-embedding-8b-mig returns
    4096 against the 1024 default) and nothing downstream enforces it — vectors are stored as a
    schema-less Mongo array, and `grounding.how_similar`'s `zip(a, b)` silently truncates to the
    shorter vector, producing a plausible but meaningless cosine score.

    Costs one real embedding call at boot — same cadence validate_local_models already pays.
    """
    import litellm

    with _llm_slot(s):
        resp = litellm.embedding(
            model=s.embedding_model, input=["dimension check"],
            custom_llm_provider="litellm_proxy",  # see _chat_kwargs
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


