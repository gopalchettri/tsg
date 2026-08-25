"""LiteLLMClient.embed's provider batch cap, and the honesty of a failed embedding job.

The bug these pin: the UAT proxy model (qwen3-embedding-8b-mig) accepts at most 32 texts per
request, the app sent 100, and the failure surfaced as `state=SUCCESS` on the admin job — so
nobody saw it. The cap now lives in `embed()` itself, the only place EVERY caller routes through
(five of them used to pass unbounded lists straight to the provider).

Settings is constructed explicitly rather than via get_settings(): the developer's .env sets
EMBEDDING_PROVIDER=local, which returns before the proxy path and would make every assertion
here vacuous. Same reasoning as tests/test_security_posture.py.
"""
from __future__ import annotations

import contextlib
import sys
import threading
import time
import types

import httpx
import pytest

from app.core.config import Settings
from app.pipeline import embeddings
from app.pipeline.llm import LiteLLMClient, LLMSlotUnavailable, _verify_embedding_dimensions

BATCH = 8  # small, so a handful of texts already spans several chunks


def _settings(**over) -> Settings:
    # merged into a dict first so a test can OVERRIDE a default here rather than collide with it
    kwargs = {
        "embedding_provider": "litellm_proxy",
        "embedding_model": "qwen3-embedding-8b-mig",
        # 'auto' raises for any model name without "e5" in it — pin it so the prefix logic
        # doesn't shadow what these tests are actually about.
        "embedding_prefix_style": "none",
        "embedding_batch_size": BATCH,
        "max_concurrent_llm_calls": 0,  # _llm_slot no-ops, so no Redis is needed here
    }
    return Settings(**(kwargs | over))


def _install_fake(monkeypatch, *, reverse=True, drop=0, indices=None, raises=None):
    """Stub `litellm` in sys.modules; return the list of `input` lists embed() sent it.

    A STUB MODULE, never the real litellm: importing litellm calls load_dotenv() as an import
    side effect, which injects this repo's .env straight into os.environ. That silently overrides
    any TSG_* variable a later test sets with monkeypatch.setenv — which is exactly how this file
    broke test_litellm_proxy_bypass_toggle (it sorts after this one) when it first imported the
    real module. Stubbing keeps the session clean, and skips a slow import besides.

    `reverse=True` returns each response's data in REVERSE order (with correct per-request
    `index` values) — a client that appended in arrival order, or that sorted only after
    concatenating chunks, fails. `drop` truncates a response (short reply). `indices` overrides
    the `index` values outright, to forge duplicate/out-of-range responses. `raises` makes the
    provider raise the given exception.
    """
    calls: list[list[str]] = []

    def fake_embedding(*, model, input, **kwargs):
        calls.append(list(input))
        if raises is not None:
            raise raises
        # the vector encodes its own text's length, so a misaligned pairing is detectable
        idx = indices if indices is not None else list(range(len(input)))
        data = [{"index": idx[i], "embedding": [float(len(t)), float(i)]}
                for i, t in enumerate(input)]
        if drop:
            data = data[:-drop]
        return {"data": list(reversed(data)) if reverse else data}

    stub = types.ModuleType("litellm")
    stub.embedding = fake_embedding
    monkeypatch.setitem(sys.modules, "litellm", stub)  # restored by monkeypatch at teardown
    return calls


# --- the cap itself ---

def test_no_request_exceeds_the_batch_size(monkeypatch):
    """THE UAT regression: 100 texts must never leave as one over-limit request."""
    calls = _install_fake(monkeypatch)
    texts = [f"threat-{i}" for i in range(100)]

    LiteLLMClient(_settings()).embed(texts, kind="passage")

    assert calls, "provider was never called"
    assert max(len(c) for c in calls) <= BATCH
    assert sum(len(c) for c in calls) == 100       # every text sent exactly once
    assert [t for c in calls for t in c] == texts  # and in order, no drops or repeats


def test_order_is_preserved_across_chunk_boundaries(monkeypatch):
    """`index` restarts at 0 each request, so sorting after concatenation would interleave
    chunks and pair texts past the first chunk with the wrong vectors — silently."""
    _install_fake(monkeypatch, reverse=True)
    # distinct lengths make each text's expected vector unique and position-sensitive
    texts = [("x" * n) for n in range(1, 21)]

    vecs = LiteLLMClient(_settings()).embed(texts, kind="query")

    assert len(vecs) == len(texts)
    # vecs[i][0] is len(texts[i]) per the fake — proves text i got ITS OWN vector
    assert [v[0] for v in vecs] == [float(len(t)) for t in texts]


def test_short_provider_response_raises_instead_of_misaligning(monkeypatch):
    """A chunk one vector short would shift every later chunk by a position. The zip() callers
    would then cache text -> wrong vector with no error anywhere."""
    _install_fake(monkeypatch, drop=1)

    with pytest.raises(RuntimeError, match="refusing to return a misaligned batch"):
        LiteLLMClient(_settings()).embed([f"t{i}" for i in range(10)], kind="query")


@pytest.mark.parametrize("indices", [[0, 0, 2], [0, 2, 2]])
def test_duplicate_index_raises_instead_of_mispairing(monkeypatch, indices):
    """The subtle one, and the reason vectors are PLACED by index rather than sorted.

    A response carrying a duplicate index has the RIGHT COUNT, so a count-only guard passes it.
    Sorting then silently swaps vectors between texts whenever the response also arrives out of
    order — which is the very case the ordering logic exists for. Measured on ["a","bb","ccc"]
    expecting [1.0, 2.0, 3.0]: sort-and-zip returns [2.0, 1.0, 3.0] for [0,0,2] and
    [1.0, 3.0, 2.0] for [0,2,2]. _stage_for_write's zip would persist that pairing in Mongo under
    the wrong key — permanently, with no error anywhere.
    """
    _install_fake(monkeypatch, reverse=True, indices=indices)

    with pytest.raises(RuntimeError, match="missing index"):
        LiteLLMClient(_settings()).embed(["a", "bb", "ccc"], kind="query")


def test_out_of_range_index_raises(monkeypatch):
    """An index outside 0..len-1 cannot be placed; it must fail rather than drop a text."""
    _install_fake(monkeypatch, reverse=False, indices=[0, 1, 99])

    with pytest.raises(RuntimeError, match="missing index"):
        LiteLLMClient(_settings()).embed(["a", "bb", "ccc"], kind="query")


def test_empty_input_makes_no_provider_call(monkeypatch):
    """Previously this sent input=[] and took a provider 400; now it matches local_models.embed's
    []-in-[]-out contract — and returns BEFORE taking an LLM slot, so it costs no Redis round
    trip either."""
    calls = _install_fake(monkeypatch)

    assert LiteLLMClient(_settings()).embed([], kind="query") == []
    assert calls == []


def test_empty_input_returns_before_taking_a_slot(monkeypatch):
    """The slot is a Redis acquire that can even raise LLMSlotUnavailable — never pay it to send
    zero texts. max_concurrent_llm_calls=0 makes _llm_slot a no-op, so this asserts on the real
    thing: the slot helper is never entered."""
    _install_fake(monkeypatch)
    entered = []
    monkeypatch.setattr("app.pipeline.llm._llm_slot",
                        lambda s: entered.append(1) or contextlib.nullcontext())

    assert LiteLLMClient(_settings()).embed([], kind="query") == []
    assert entered == [], "embed([]) acquired an LLM slot for zero work"


def test_text_at_exactly_max_embed_chars_is_accepted(monkeypatch):
    """max_embed_chars is a contract about the CALLER's text. The e5 prefix is our own internal
    addition the caller cannot budget for, so validating after prefixing rejected callers who had
    correctly truncated to exactly the cap — threat_retrieval.py:296 does precisely that, and the
    resulting ValueError was swallowed into permanent keyword-only ranking."""
    calls = _install_fake(monkeypatch)
    cap = 200
    text = "T: " + ("d" * (cap - 3))          # exactly cap chars, as the caller truncates to
    assert len(text) == cap

    vecs = LiteLLMClient(_settings(max_embed_chars=cap, max_proposal_chars=cap // 2,
                                   embedding_prefix_style="e5")).embed([text], kind="passage")

    assert len(vecs) == 1
    assert calls[0][0].startswith("passage: ")     # prefix still applied on the wire
    assert len(calls[0][0]) == cap + len("passage: ")


def test_text_over_max_embed_chars_still_rejected(monkeypatch):
    """The cap must still bite for genuinely over-long caller input — and before any network call."""
    calls = _install_fake(monkeypatch)

    with pytest.raises(ValueError, match="over 200 chars"):
        LiteLLMClient(_settings(max_embed_chars=200, max_proposal_chars=100)).embed(
            ["x" * 201], kind="passage")
    assert calls == [], "rejected input must cost zero provider calls"


def test_legacy_error_string_in_a_stored_result_does_not_500():
    """admin.py builds EmbeddingJobStatus in the route body from a Celery result that may predate
    the deploy. A job queued before the FAILURE-reporting change can still carry a per-group
    "error: ..." string inside a SUCCESS payload; rejecting it would turn a succeeded job's poll
    into a 500 for the length of the result TTL."""
    from app.api.schemas import EmbeddingJobStatus

    got = EmbeddingJobStatus(state="SUCCESS",
                             rows_processed={"threat_type": 12, "control_library": "error: boom"})
    assert got.rows_processed["threat_type"] == 12
    assert got.rows_processed["control_library"] == "error: boom"


def test_prefix_is_applied_once_not_per_chunk(monkeypatch):
    """Prefixing must stay outside the chunk loop — slicing an already-prefixed list and
    re-prefixing would produce 'query: query: foo'."""
    calls = _install_fake(monkeypatch)
    texts = [f"t{i}" for i in range(20)]

    LiteLLMClient(_settings(embedding_prefix_style="e5")).embed(texts, kind="query")

    sent = [t for c in calls for t in c]
    assert all(t.startswith("query: ") for t in sent)
    assert not any(t.startswith("query: query: ") for t in sent)


# --- a failed group must not report SUCCESS ---

def test_for_each_group_attempts_all_groups_then_raises():
    """Isolate-then-raise: a mid-list failure must not stop later groups, but the job still has
    to fail. Returning the dict with an 'error: ...' string in it (the old behaviour) is what
    made the admin job report state=SUCCESS for a recreate that embedded nothing."""
    attempted: list[str] = []

    def fn(group: str) -> int:
        attempted.append(group)
        if group == "threat_catalogue":
            raise RuntimeError("batch size exceeded")
        return 7

    with pytest.raises(embeddings.EmbeddingGroupsFailed) as exc:
        embeddings._for_each_group(None, fn)

    assert attempted == sorted(embeddings._GROUPS)  # nothing was skipped
    # the per-group detail must survive in the message: Celery serializes results as JSON and
    # EmbeddingJobStatus.rows_processed is populated on SUCCESS only, so str() is all an
    # operator gets on a failed job
    assert exc.value.results["threat_catalogue"].startswith("error: ")
    assert exc.value.results["threat_type"] == 7
    assert "threat_catalogue" in str(exc.value)
    assert "succeeded" in str(exc.value)


def test_for_each_group_returns_normally_when_every_group_succeeds():
    out = embeddings._for_each_group(None, lambda g: 3)
    assert out == dict.fromkeys(embeddings._GROUPS, 3)


def test_failure_survives_celerys_result_backend():
    """The admin API renders a failed job as str(result.result), and Celery rebuilds the exception
    as cls(*args) — with the MESSAGE STRING, not the dict. An __init__ that only accepts the dict
    makes exception_to_python fall back to a generic Exception, and the operator polling
    GET .../embeddings/status/{job_id} sees a mangled "<class '...'>(('...',))" wrapper instead of
    which group actually failed."""
    from celery.backends.base import Backend

    exc = embeddings.EmbeddingGroupsFailed(
        {"threat_type": 12, "threat_catalogue": "error: batch size exceeded"})
    backend = Backend.__new__(Backend)

    restored = backend.exception_to_python(backend.prepare_exception(exc, serializer="json"))

    assert isinstance(restored, embeddings.EmbeddingGroupsFailed)
    assert "threat_catalogue" in str(restored)   # the operator can still see WHICH group broke
    assert "threat_type" in str(restored)        # ...and that the others succeeded


# --- durable progress: a late failure must not discard everything already paid for ---

def test_vectors_are_persisted_per_batch_not_only_at_the_end(monkeypatch):
    """~1100 texts go out in ~37 provider calls. Writing to Mongo only after ALL of them means a
    timeout on the last call throws away every vector already bought, and the Celery retry
    re-embeds the lot. Each batch must be persisted as it completes."""
    written: list[str] = []
    monkeypatch.setattr(embeddings, "_l2_write", lambda docs: written.extend(d["text"] for d in docs))
    monkeypatch.setattr(embeddings, "_l2_read", lambda *a, **k: True)  # pretend Mongo is reachable
    monkeypatch.setattr(embeddings, "get_settings",
                        lambda: _settings(embedding_store="mongo"))

    class _FailsOnSecondBatch:
        def __init__(self):
            self.batches = 0

        def embed(self, texts, *, kind="query"):
            self.batches += 1
            if self.batches == 2:
                raise RuntimeError("provider timeout on the second batch")
            return [[float(len(t))] for t in texts]

    texts = [f"text-{i}" for i in range(BATCH * 2)]  # exactly two batches
    with pytest.raises(RuntimeError, match="second batch"):
        embeddings.get_vectors(_FailsOnSecondBatch(), texts, model_id="m", group="threat_type")

    # the first batch's vectors are already durable — a retry re-embeds only the tail
    assert written == texts[:BATCH]


# --- concurrency: get_vectors may overlap batches, but never beyond its bounds ---

def _concurrency_probe(monkeypatch, conc, *, fail_on=None):
    """Drive get_vectors through a fake LLM that records overlap.

    Returns (peak_in_flight, batch_sizes, persisted_texts, result_or_exception).
    """
    lock, state = threading.Lock(), {"now": 0, "peak": 0}
    sizes, persisted = [], []

    class _Probe:
        def embed(self, texts, *, kind="query"):
            with lock:
                state["now"] += 1
                state["peak"] = max(state["peak"], state["now"])
                sizes.append(len(texts))
            try:
                time.sleep(0.05)                       # long enough for real overlap to show
                if fail_on is not None and fail_on in texts:
                    raise RuntimeError("provider blew up on this batch")
                return [[float(len(t))] for t in texts]
            finally:
                with lock:
                    state["now"] -= 1

    monkeypatch.setattr(embeddings, "_l2_write",
                        lambda docs: persisted.extend(d["text"] for d in docs))
    monkeypatch.setattr(embeddings, "_l2_read", lambda *a, **k: True)
    monkeypatch.setattr(embeddings, "get_settings",
                        lambda: _settings(embedding_concurrency=conc, embedding_store="mongo"))
    embeddings._L1.clear()
    texts = [f"text-{i}" for i in range(BATCH * 5)]     # 5 batches
    try:
        out = embeddings.get_vectors(_Probe(), texts, model_id="m", group="threat_type")
    except Exception as exc:  # noqa: BLE001 — the probe REPORTS the failure; callers assert on it
        return state["peak"], sizes, persisted, exc
    return state["peak"], sizes, persisted, out


def test_concurrency_1_stays_strictly_sequential(monkeypatch):
    """The default must be byte-for-byte today's behaviour: one request in flight, ever."""
    peak, sizes, _, out = _concurrency_probe(monkeypatch, 1)
    assert peak == 1, f"concurrency=1 overlapped {peak} calls"
    assert max(sizes) <= BATCH
    assert len(out) == BATCH * 5


def test_concurrency_overlaps_but_respects_its_bound(monkeypatch):
    """Raised concurrency must actually overlap AND never exceed the configured ceiling — that
    ceiling is what keeps the provider's request rate predictable."""
    peak, sizes, _, out = _concurrency_probe(monkeypatch, 3)
    assert peak > 1, "concurrency=3 never overlapped; the pool is not being used"
    assert peak <= 3, f"peak in-flight {peak} exceeded the configured 3"
    assert max(sizes) <= BATCH, "a concurrent run must still respect the provider batch cap"
    assert len(out) == BATCH * 5
    assert all(out[t][0] == float(len(t)) for t in out), "concurrency mispaired a text"


def test_concurrent_failure_still_persists_the_batches_that_succeeded(monkeypatch):
    """Durability must survive concurrency: a failing batch raises, but its siblings' vectors are
    already in Mongo, so the retry re-embeds only the tail."""
    _, _, persisted, exc = _concurrency_probe(monkeypatch, 3, fail_on="text-0")

    assert isinstance(exc, RuntimeError) and "blew up" in str(exc)
    assert persisted, "sibling batches were lost — the retry would redo all the work"
    assert "text-0" not in persisted                   # the failed batch persisted nothing


# --- the worker-boot guard: a too-large batch must never reach production traffic ---

def test_boot_probe_sends_a_full_batch(monkeypatch):
    """The probe embeds `embedding_batch_size` texts, not one, so a batch the provider won't
    accept fails at worker boot rather than inside a background job."""
    calls = _install_fake(monkeypatch, reverse=False)
    s = _settings(embedding_dimensions=2)

    _verify_embedding_dimensions(s)

    assert len(calls) == 1
    assert len(calls[0]) == BATCH


def test_boot_probe_names_the_setting_when_the_provider_rejects_the_batch(monkeypatch):
    """The whole point of the guard: the operator is told which knob to turn."""
    _install_fake(monkeypatch)

    import litellm  # the stub installed above

    def reject(*, model, input, **kwargs):
        raise RuntimeError("400: batch size exceeds maximum of 32")

    monkeypatch.setattr(litellm, "embedding", reject)

    with pytest.raises(RuntimeError, match="TSG_EMBEDDING_BATCH_SIZE"):
        _verify_embedding_dimensions(_settings(embedding_dimensions=2))


def test_boot_probe_still_catches_a_dimension_mismatch(monkeypatch):
    """Widening the probe must not cost the check it already performed."""
    _install_fake(monkeypatch, reverse=False)  # fake returns 2-wide vectors

    with pytest.raises(RuntimeError, match="EMBEDDING_DIMENSIONS"):
        _verify_embedding_dimensions(_settings(embedding_dimensions=4096))


def test_boot_probe_passes_a_rate_limit_through_for_retry(monkeypatch):
    """A boot-time 429 is transient — _init_worker retries LLMSlotUnavailable with backoff, which
    matters most when a whole replica set boots at once and contends for the same proxy. It must
    NOT be reported as a batch-size problem, which would send an operator after the wrong knob."""
    import openai

    _install_fake(monkeypatch, raises=openai.RateLimitError(
        "429", response=httpx.Response(429, request=httpx.Request("POST", "http://x")), body=None))

    with pytest.raises(LLMSlotUnavailable):
        _verify_embedding_dimensions(_settings(embedding_dimensions=2))


def test_boot_probe_does_not_blame_batch_size_for_every_failure(monkeypatch):
    """An auth failure, a dead deployment and a timeout all land in the same except. The message
    has to stay neutral about the cause while still naming batch size as one candidate."""
    _install_fake(monkeypatch, raises=RuntimeError("401 invalid api key"))

    with pytest.raises(RuntimeError) as exc:
        _verify_embedding_dimensions(_settings(embedding_dimensions=2))

    assert "reachable" in str(exc.value) and "key is valid" in str(exc.value)
    assert "401 invalid api key" in str(exc.value)   # the real cause is not swallowed
