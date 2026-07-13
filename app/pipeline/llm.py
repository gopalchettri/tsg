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

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Protocol, Sequence

from app.core.config import Settings, get_settings
from app.core.logging import get_logger

log = get_logger(__name__)


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

    def chat(self, messages: list[dict], *, model: str | None = None) -> tuple[str, Provenance]:
        """Single chat completion; returns (text, Provenance) so callers can persist model+params
        alongside the output without threading litellm-specific response shapes around."""
        ...

    def embed(self, texts: Sequence[str], *, model: str | None = None, kind: str = "query") -> list[list[float]]:
        """Batch embed; `kind` distinguishes query vs. passage text so e5-style models can apply
        the right prefix (see `_apply_embed_prefix`)."""
        ...

    def rerank(self, query: str, docs: Sequence[str], *, model: str | None = None) -> list[float]:
        """Relevance scores for `docs` against `query`, same length/order as `docs` 0-100 scale."""
        ...


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

    def _chat_kwargs(self, model: str | None = None) -> dict[str, Any]:
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
        - `temperature` / `reasoning_effort` — ONLY added if an operator
            explicitly set LLM_TEMPERATURE / LLM_REASONING_EFFORT (both
            unset/None by default — see config.py). Left unset, litellm/the
            provider picks its own default for each.
        """
        s = self.s
        common: dict[str, Any] = {"timeout": s.llm_timeout_seconds, "num_retries": s.llm_max_retries}
        if s.llm_json_mode:  # API-enforced JSON output; off by default (see config.py)
            common["response_format"] = {"type": "json_object"}
        if s.llm_temperature is not None:  # operator-pinned; unset by default (see config.py)
            common["temperature"] = s.llm_temperature
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
        return {"model": model or s.inference_model, "api_base": s.litellm_base_url,
                "api_key": s.litellm_api_key, **common}

    def chat(self, messages, *, model=None):
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
        in the `params` dict below when an operator has explicitly pinned them
        via LLM_TEMPERATURE/LLM_REASONING_EFFORT (see config.py). Left unset,
        litellm/the provider picks its own default and neither key appears —
        so the provenance record only ever lists settings that are ACTUALLY
        being controlled, not settings left to whatever the default happens
        to be.
        """
        import litellm

        kwargs = self._chat_kwargs(model)
        resp = litellm.completion(messages=messages, **kwargs)
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
                # temperature/reasoning_effort only appear here when an operator actually
                # pinned them (LLM_TEMPERATURE/LLM_REASONING_EFFORT); otherwise litellm/the
                # provider picks its own default and this dict stays unchanged.
                **({"temperature": self.s.llm_temperature} if self.s.llm_temperature is not None else {}),
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
        """
        texts = _apply_embed_prefix(self.s, list(texts), kind)  # e5 prefixes, both providers
        if self.s.embedding_provider == "local":
            from app.pipeline import local_models

            return local_models.embed(texts)  # in-process — no network timeout/retry applies
        import litellm

        model = model or self.s.embedding_model
        resp = litellm.embedding(
            model=model, input=texts,
            api_base=self.s.litellm_base_url, api_key=self.s.litellm_api_key,
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
        resp = litellm.rerank(
            model=model, query=query, documents=list(docs),
            api_base=self.s.litellm_base_url, api_key=self.s.litellm_api_key,
            timeout=self.s.llm_timeout_seconds, num_retries=self.s.llm_max_retries,  # same bounds as chat
        )
        by_index = {r["index"]: float(r["relevance_score"]) * 100.0 for r in resp["results"]}
        missing = [i for i in range(len(docs)) if i not in by_index]
        if missing:
            raise RuntimeError(
                f"rerank returned {len(by_index)} scores for {len(docs)} docs "
                f"(missing index(es): {missing})")
        return [by_index[i] for i in range(len(docs))]


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
    needed.
    """
    return LiteLLMClient()
