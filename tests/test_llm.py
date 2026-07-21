"""LLM provider swap (add-on) — offline: `_chat_kwargs` builds the right litellm
call per `LLM_PROVIDER`, with no network."""
from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.pipeline.llm import LiteLLMClient, _apply_embed_prefix


@pytest.fixture(autouse=True)
def _clear_moderation_client_cache():
    # [REVIEW-FIX] _moderation_client is @lru_cache'd (see llm.py) keyed on
    # (api_key, base_url, timeout, max_retries) — several moderate() tests below share the
    # same default Settings values, so without clearing this between tests, a later test
    # would silently get an earlier test's cached fake client instead of its own.
    from app.pipeline.llm import _moderation_client

    _moderation_client.cache_clear()
    yield
    _moderation_client.cache_clear()


def test_chat_kwargs_azure():
    s = Settings(llm_provider="azure_openai", azure_openai_deployment_name="gpt-5-mini",
                 azure_openai_endpoint="https://x.azure.com/", azure_openai_api_key="secret",
                 azure_openai_api_version="2024-12-01-preview")
    kw = LiteLLMClient(s)._chat_kwargs()
    assert kw["model"] == "azure/gpt-5-mini"
    assert kw["api_base"] == "https://x.azure.com/"
    assert kw["api_version"] == "2024-12-01-preview"
    assert kw["api_key"] == "secret"


def test_chat_kwargs_proxy_default():
    s = Settings(llm_provider="litellm_proxy", litellm_base_url="http://proxy:4000", inference_model="gpt-5")
    kw = LiteLLMClient(s)._chat_kwargs()
    assert kw["model"] == "gpt-5"
    assert kw["api_base"] == "http://proxy:4000"
    assert "api_version" not in kw


def test_chat_kwargs_drop_params_on():
    # gpt-5 rejects temperature=0.0 (find_threats' threat_identification_temperature default) with
    # UnsupportedParamsError; drop_params lets litellm drop a per-model-unsupported param instead of
    # failing every real threat-identification call. Present on every provider, even with temp pinned.
    for s in (Settings(llm_provider="azure_openai", azure_openai_deployment_name="gpt-5-mini",
                       azure_openai_endpoint="https://x.azure.com/", azure_openai_api_key="secret",
                       azure_openai_api_version="2024-12-01-preview"),
              Settings(llm_provider="litellm_proxy", litellm_base_url="http://proxy:4000",
                       inference_model="gpt-5")):
        assert LiteLLMClient(s)._chat_kwargs(temperature=0.0)["drop_params"] is True


def test_chat_kwargs_json_mode_off_by_default():
    # default OFF: the fallback provider (glm-5) may not support response_format,
    # and an unsupported param would fail every call deterministically
    s = Settings(llm_provider="litellm_proxy", llm_json_mode=False)
    assert "response_format" not in LiteLLMClient(s)._chat_kwargs()


def test_chat_kwargs_json_mode_opt_in():
    s = Settings(llm_provider="litellm_proxy", llm_json_mode=True)
    assert LiteLLMClient(s)._chat_kwargs()["response_format"] == {"type": "json_object"}
    # applies across provider branches (shared `common` dict)
    az = Settings(llm_provider="azure_openai", llm_json_mode=True, azure_openai_deployment_name="d")
    assert LiteLLMClient(az)._chat_kwargs()["response_format"] == {"type": "json_object"}


def test_chat_kwargs_and_provenance_omit_temperature_reasoning_by_default(monkeypatch):
    s = Settings(llm_provider="litellm_proxy")
    kw = LiteLLMClient(s)._chat_kwargs()
    assert "temperature" not in kw and "reasoning_effort" not in kw

    import litellm

    def fake_completion(*, messages, **kwargs):
        return {"choices": [{"message": {"content": "ok"}}], "model": "gpt-5-x"}

    monkeypatch.setattr(litellm, "completion", fake_completion)
    _, prov = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert "temperature" not in prov.params and "reasoning_effort" not in prov.params


def test_chat_kwargs_and_provenance_include_temperature_reasoning_when_set(monkeypatch):
    s = Settings(llm_provider="litellm_proxy", llm_temperature=0.2, llm_reasoning_effort="low")
    kw = LiteLLMClient(s)._chat_kwargs()
    assert kw["temperature"] == 0.2 and kw["reasoning_effort"] == "low"

    import litellm

    def fake_completion(*, messages, **kwargs):
        return {"choices": [{"message": {"content": "ok"}}], "model": "gpt-5-x"}

    monkeypatch.setattr(litellm, "completion", fake_completion)
    _, prov = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert prov.params["temperature"] == 0.2
    assert prov.params["reasoning_effort"] == "low"


def test_llm_temperature_reasoning_effort_bare_env_alias(monkeypatch):
    # CONFIRMED finding: env_prefix="TSG_" means an unaliased field only binds
    # TSG_-prefixed names. These two fields must accept the bare operator-facing
    # names too, matching the sibling convention (llm_json_mode, llm_provider).
    monkeypatch.setenv("LLM_TEMPERATURE", "0.3")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "high")
    s = Settings(llm_provider="litellm_proxy")
    assert s.llm_temperature == 0.3
    assert s.llm_reasoning_effort == "high"


def test_provenance_prompt_version_defaults_empty():
    from app.pipeline.llm import Provenance

    assert Provenance(model="x").prompt_version == ""


def test_embedding_provider_local_dispatch(monkeypatch):
    captured = {}

    def fake_embed(texts):  # local_models.embed no longer takes kind (prefix applied upstream)
        captured["texts"] = list(texts)
        return [[1.0]]

    monkeypatch.setattr("app.pipeline.local_models.embed", fake_embed)
    s = Settings(embedding_provider="local", embedding_model="/models/e5")  # 'e5' → auto prefix
    out = LiteLLMClient(s).embed(["hello"], kind="passage")
    assert out == [[1.0]]
    assert captured["texts"] == ["passage: hello"]  # local path + e5 passage prefix applied once


def test_proxy_embed_reorders_by_index(monkeypatch):
    # H1: the OpenAI-compatible response MAY return `data` out of input order; embed()
    # must re-sort by `index`, else positional callers (embeddings.get_vectors's zip)
    # cache each text against the wrong vector. Fake returns data REVERSED.
    import litellm

    def fake_embedding(*, model, input, **_):
        data = [{"index": i, "embedding": [float(i)]} for i in range(len(input))]
        return {"data": list(reversed(data))}

    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    s = Settings(embedding_provider="litellm_proxy", embedding_model="bge-m3",
                 embedding_prefix_style="none")
    out = LiteLLMClient(s).embed(["a", "b", "c"])
    assert out == [[0.0], [1.0], [2.0]]  # restored to input order despite reversed data


def test_chat_provenance_records_served_model_and_params(monkeypatch):
    # LOW-2/LOW-3: provenance must capture the model the proxy ACTUALLY served
    # (resp["model"], which can differ from the requested name) plus the params used,
    # so a persisted scenario is reproducible/auditable (§8.5).
    import litellm

    def fake_completion(*, messages, **kwargs):
        return {"choices": [{"message": {"content": "ok"}}], "model": "glm-4.6-0725"}

    monkeypatch.setattr(litellm, "completion", fake_completion)
    s = Settings(llm_provider="litellm_proxy", inference_model="glm-4.6",
                 llm_timeout_seconds=30, llm_max_retries=2)
    text, prov = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert text == "ok"
    assert prov.model == "glm-4.6"                # what we requested
    assert prov.model_version == "glm-4.6-0725"   # what the proxy resolved/served
    assert prov.params["num_retries"] == 2 and prov.params["provider"] == "litellm_proxy"


def test_rerank_and_embed_carry_r8_timeout_and_retries(monkeypatch):
    # [R8] every call family gets the chat path's per-call timeout + bounded retries —
    # rerank had neither and proxy embed had no retries until the 2026-07-03 audit fix.
    import litellm

    captured: dict = {}

    def fake_rerank(**kwargs):
        captured["rerank"] = kwargs
        return {"results": [{"index": 0, "relevance_score": 0.5}]}

    def fake_embedding(**kwargs):
        captured["embed"] = kwargs
        return {"data": [{"index": 0, "embedding": [0.0]}]}

    monkeypatch.setattr(litellm, "rerank", fake_rerank)
    monkeypatch.setattr(litellm, "embedding", fake_embedding)
    s = Settings(embedding_provider="litellm_proxy", reranker_provider="litellm_proxy",
                 embedding_prefix_style="none", llm_timeout_seconds=42.0, llm_max_retries=4)
    client = LiteLLMClient(s)
    client.rerank("q", ["doc"])
    client.embed(["a"])
    for family in ("rerank", "embed"):
        assert captured[family]["timeout"] == 42.0, family
        assert captured[family]["num_retries"] == 4, family


def test_reranker_provider_local_dispatch(monkeypatch):
    monkeypatch.setattr("app.pipeline.local_models.rerank", lambda q, docs: [88.0])
    s = Settings(reranker_provider="local", reranker_model="/models/bge")
    assert LiteLLMClient(s).rerank("q", ["d"]) == [88.0]


def test_rerank_scales_to_0_100_and_clamps(monkeypatch):
    # bge-reranker (num_labels==1) already sigmoids in predict → local_models.rerank scales
    # ×100 and CLAMPS to [0,100], never sigmoiding again. Sub-zero / over-one raw scores must
    # saturate at the band edges, else the §8.4 60/75 gates read garbage. The dispatch test above
    # stubs the whole function, so this exact math is otherwise never exercised.
    from app.pipeline import local_models

    class _FakeReranker:
        def predict(self, pairs):
            return [-0.1, 0.5, 1.2][: len(pairs)]  # below 0, mid, above 1

    monkeypatch.setattr(local_models, "_reranker", lambda path: _FakeReranker())
    assert local_models.rerank("q", ["a", "b", "c"]) == [0.0, 50.0, 100.0]


def test_embed_empty_input_short_circuits_before_model_load(monkeypatch):
    # empty batch must return [] WITHOUT loading the model (no torch, no threadpool hop);
    # _embedder is booby-trapped to prove it's never reached.
    from app.pipeline import local_models

    monkeypatch.setattr(local_models, "_embedder",
                        lambda path: pytest.fail("model must not load on empty input"))
    assert local_models.embed([]) == []


def test_rerank_empty_docs_short_circuits_before_model_load(monkeypatch):
    from app.pipeline import local_models

    monkeypatch.setattr(local_models, "_reranker",
                        lambda path: pytest.fail("model must not load on empty docs"))
    assert local_models.rerank("q", []) == []


def test_apply_embed_prefix():
    e5 = Settings(embedding_model="/models/multilingual-e5-large")  # auto → e5
    assert _apply_embed_prefix(e5, ["x"], "query") == ["query: x"]
    assert _apply_embed_prefix(e5, ["x"], "passage") == ["passage: x"]
    plain = Settings(embedding_model="bge-m3", embedding_prefix_style="none")
    assert _apply_embed_prefix(plain, ["x"], "query") == ["x"]  # no prefix for non-e5 / 'none'


def test_invalid_provider_rejected():
    with pytest.raises(ValidationError):  # Literal → boot-time rejection, not silent proxy fallthrough
        Settings(embedding_provider="bogus")


def test_local_embed_threadpool_offload(monkeypatch):
    class _Vec(list):
        def tolist(self):
            return list(self)

    class _FakeEmbedder:
        def encode(self, texts, **_):
            return [_Vec([1.0, 2.0]) for _ in texts]

    monkeypatch.setattr("app.pipeline.local_models._embedder", lambda path: _FakeEmbedder())
    from app.pipeline import local_models

    assert local_models.embed(["a", "b"]) == [[1.0, 2.0], [1.0, 2.0]]  # offload is transparent


def test_validate_local_models_missing_path():
    from app.pipeline.local_models import validate_local_models

    s = Settings(embedding_provider="local", embedding_model="/definitely/not/here")
    with pytest.raises(RuntimeError):  # fail-fast at startup, not deep in the pipeline
        validate_local_models(s, warm=False)


def test_validate_local_rejects_ambiguous_prefix(tmp_path):
    from app.pipeline.local_models import validate_local_models

    # path exists but name has no 'e5' and style is auto → fail-fast rather than silently drop prefixes
    s = Settings(embedding_provider="local", embedding_model=str(tmp_path), embedding_prefix_style="auto")
    with pytest.raises(RuntimeError, match="EMBEDDING_PREFIX_STYLE"):
        validate_local_models(s, warm=False)


def test_validate_local_rejects_dimension_mismatch(monkeypatch, tmp_path):
    # warm load must catch EMBEDDING_DIMENSIONS ≠ what the model reports, rather than letting
    # a wrong-width vector reach the index later where it fails cryptically (or silently).
    from app.pipeline import local_models
    from app.pipeline.local_models import validate_local_models

    class _FakeEmbedder:
        def get_sentence_embedding_dimension(self):
            return 768

    monkeypatch.setattr(local_models, "_embedder", lambda path: _FakeEmbedder())
    monkeypatch.setattr("importlib.util.find_spec", lambda name: object())  # pretend installed
    s = Settings(embedding_provider="local", embedding_model=str(tmp_path),
                 embedding_prefix_style="e5", embedding_dimensions=1024)
    with pytest.raises(RuntimeError, match="EMBEDDING_DIMENSIONS"):
        validate_local_models(s, warm=True)


def test_validate_local_warm_requires_sentence_transformers(monkeypatch, tmp_path):
    # warm start with a 'local' provider but the extra not installed → fail fast at boot,
    # not on the first request deep in the pipeline.
    from app.pipeline.local_models import validate_local_models

    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    s = Settings(embedding_provider="local", embedding_model=str(tmp_path),
                 embedding_prefix_style="e5")
    with pytest.raises(RuntimeError, match="sentence-transformers"):
        validate_local_models(s, warm=True)


def test_auth_dev_mode(monkeypatch):
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    monkeypatch.setenv("APP_ENV", "dev")
    from app.core.config import get_settings

    get_settings.cache_clear()
    try:
        from app.api.deps import get_principal

        p = get_principal(authorization="", x_dev_entities="5, 8", x_dev_user="alice")
        assert p.entities == {"5", "8"} and p.user_id == "alice"  # header-driven, no JWT
    finally:
        get_settings.cache_clear()


def test_security_posture_blocks_dev_auth_in_prod():
    from app.core.config import Settings, assert_security_posture

    s = Settings(app_env="prod", auth_dev_mode=True)
    with pytest.raises(RuntimeError, match="AUTH_DEV_MODE"):
        assert_security_posture(s)


def test_security_posture_allows_dev():
    from app.core.config import Settings, assert_security_posture

    assert_security_posture(Settings(app_env="dev", auth_dev_mode=True))  # no raise


class _FakeRedis:
    """In-memory ZSET stand-in for the LLM-slot Redis primitives — mimics _ADMIT_SCRIPT's
    prune+count+admit logic in plain Python (no real Redis/Lua needed for a unit test)."""
    def __init__(self):
        self.zset: dict[str, float] = {}

    def eval(self, script, numkeys, key, now, stale_cutoff, limit, token):
        # Named `eval` to match redis.Redis.eval()'s real method signature (sends a Lua
        # script to the server) — this is a test double, not Python's eval() builtin; no
        # string is ever executed as code here, `script` is accepted but ignored.
        self.zset = {t: sc for t, sc in self.zset.items() if sc >= stale_cutoff}
        if len(self.zset) < int(limit):
            self.zset[token] = now
            return 1
        return 0

    def zadd(self, key, mapping):
        self.zset.update(mapping)

    def zrem(self, key, token):
        self.zset.pop(token, None)

    def zremrangebyscore(self, key, lo, hi):
        lo = float("-inf") if lo == "-inf" else float(lo)
        hi = float("inf") if hi == "+inf" else float(hi)
        self.zset = {t: sc for t, sc in self.zset.items() if not (lo <= sc <= hi)}

    def zcard(self, key):
        return len(self.zset)


def _fake_chat_ok(monkeypatch):
    import litellm
    monkeypatch.setattr(litellm, "completion",
                        lambda *, messages, **kw: {"choices": [{"message": {"content": "ok"}}], "model": "x"})


def _patch_slot_redis(monkeypatch, fake):
    monkeypatch.setattr("app.pipeline.llm._slot_redis", lambda: fake)


def test_llm_slot_acquires_and_releases_around_a_call(monkeypatch):
    fake = _FakeRedis()
    _patch_slot_redis(monkeypatch, fake)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy", max_concurrent_llm_calls=1)
    LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert fake.zset == {}  # released after the call, not leaked


def test_llm_slot_raises_when_genuinely_full_after_wait_timeout(monkeypatch):
    # A FRESH (not stale) holder occupies the only slot for the whole wait — this must now
    # be a real rejection (LLMSlotUnavailable), not the old "wait then proceed anyway".
    from app.pipeline.llm import LLMSlotUnavailable

    fake = _FakeRedis()
    fake.zset["holder"] = time.time()
    _patch_slot_redis(monkeypatch, fake)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy", max_concurrent_llm_calls=1,
                llm_slot_wait_timeout_seconds=0.05, llm_slot_stale_after_seconds=30.0)
    with pytest.raises(LLMSlotUnavailable):
        LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])


def test_llm_slot_prunes_stale_ticket_and_reclaims_its_slot(monkeypatch):
    fake = _FakeRedis()
    fake.zset["dead-worker"] = time.time() - 1000  # long past any reasonable staleness window
    _patch_slot_redis(monkeypatch, fake)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy", max_concurrent_llm_calls=1, llm_slot_stale_after_seconds=30.0)
    text, _ = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert text == "ok"
    assert "dead-worker" not in fake.zset  # pruned, its slot reclaimed


def test_llm_slot_two_waiters_admitted_promptly_once_capacity_frees(monkeypatch):
    # Regression test for the confirmed self-counting bug: previously a waiter's own
    # reservation counted against the very capacity it was waiting to get under, so with
    # multiple waiters queued, freed capacity never actually reached them (they'd cluster
    # toward a timeout instead). Two waiters + one real holder at limit=1 exercises this.
    import threading

    fake = _FakeRedis()
    fake.zset["holder"] = time.time()
    _patch_slot_redis(monkeypatch, fake)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy", max_concurrent_llm_calls=1,
                llm_slot_wait_timeout_seconds=2.0, llm_slot_stale_after_seconds=100.0)

    results = []

    def waiter():
        text, _ = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
        results.append(text)

    t1, t2 = threading.Thread(target=waiter), threading.Thread(target=waiter)
    t1.start()
    t2.start()
    time.sleep(0.3)
    fake.zset.pop("holder", None)  # the real holder finishes and releases normally
    t1.join(timeout=2.0)
    t2.join(timeout=2.0)
    assert results == ["ok", "ok"]  # both admitted well within the timeout, not stuck


def test_llm_slot_redis_error_mid_poll_fails_open(monkeypatch):
    # A Redis exception on a LATER poll (not just the very first attempt) must still fail
    # open — never get misclassified as "confirmed over capacity".
    fake = _FakeRedis()
    fake.zset["holder"] = time.time()
    calls = {"n": 0}
    real_eval = fake.eval

    def flaky_eval(*a, **kw):
        calls["n"] += 1
        if calls["n"] == 2:
            raise ConnectionError("redis blip")
        return real_eval(*a, **kw)

    fake.eval = flaky_eval
    _patch_slot_redis(monkeypatch, fake)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy", max_concurrent_llm_calls=1, llm_slot_wait_timeout_seconds=2.0)
    text, _ = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert text == "ok"  # proceeded despite the mid-poll Redis error
    assert calls["n"] >= 2


def test_llm_slot_fails_open_when_redis_unavailable(monkeypatch):
    def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr("app.pipeline.llm._slot_redis", _boom)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy", max_concurrent_llm_calls=5)
    text, _ = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert text == "ok"  # a down Redis must never block an LLM call


def test_llm_slot_disabled_by_default_never_touches_redis(monkeypatch):
    def _boom():
        pytest.fail("Redis must not be touched when max_concurrent_llm_calls=0 (default)")

    monkeypatch.setattr("app.pipeline.llm._slot_redis", _boom)
    _fake_chat_ok(monkeypatch)
    s = Settings(llm_provider="litellm_proxy")  # max_concurrent_llm_calls defaults to 0
    text, _ = LiteLLMClient(s).chat([{"role": "user", "content": "hi"}])
    assert text == "ok"


def test_current_llm_slot_count_prunes_then_counts(monkeypatch):
    from app.pipeline.llm import current_llm_slot_count

    fake = _FakeRedis()
    fake.zset["alive"] = time.time()
    fake.zset["stale"] = time.time() - 1000
    _patch_slot_redis(monkeypatch, fake)
    s = Settings(llm_slot_stale_after_seconds=30.0)
    monkeypatch.setattr("app.pipeline.llm.get_settings", lambda: s)
    assert current_llm_slot_count() == 1  # stale entry pruned first, only "alive" counted


def test_current_llm_slot_count_returns_zero_on_redis_error(monkeypatch):
    from app.pipeline.llm import current_llm_slot_count

    monkeypatch.setattr("app.pipeline.llm._slot_redis", lambda: (_ for _ in ()).throw(ConnectionError("down")))
    assert current_llm_slot_count() == 0


def test_heartbeat_loop_refreshes_ticket_score_periodically():
    # Direct, fast unit test of the heartbeat mechanism itself: proves a ticket's score
    # keeps advancing while the background thread runs — the "mixed call duration" proof
    # (a call's own liveness, not a guessed fixed lease, is what keeps its slot alive).
    import threading

    from app.pipeline.llm import _heartbeat_loop

    fake = _FakeRedis()
    fake.zset["tok"] = 0.0
    stop = threading.Event()
    t = threading.Thread(target=_heartbeat_loop, args=(fake, "tok", 0.05, stop))
    t.start()
    time.sleep(0.18)
    stop.set()
    t.join(timeout=1.0)
    assert fake.zset["tok"] > 0.0  # refreshed at least once since the initial 0.0


def _real_redis_reachable(url: str) -> bool:
    import redis

    try:
        redis.Redis.from_url(url, socket_connect_timeout=0.5).ping()
        return True
    except Exception:  # noqa: BLE001 — reachability probe, not a real assertion
        return False


@pytest.mark.skipif(
    not _real_redis_reachable(Settings().redis_url),
    reason="no live Redis reachable at settings.redis_url — every other _llm_slot test above "
        "exercises a scripted fake; this is the one proof against the real Lua/ZSET server")
def test_llm_slot_against_real_redis_end_to_end():
    """Live-Redis integration test. Uses the real Lua-script admit + heartbeat + staleness
    pruning against an actual Redis server — closes the previously-flagged gap that only a
    fake mirrored these semantics. Runs `_llm_slot` directly (not through LiteLLMClient.chat)
    so no litellm stub is needed either."""
    from app.pipeline.llm import _SLOTS_KEY, LLMSlotUnavailable, _llm_slot, _slot_redis, current_llm_slot_count

    s = Settings(max_concurrent_llm_calls=1, llm_slot_wait_timeout_seconds=1.0,
                llm_slot_heartbeat_seconds=0.2, llm_slot_stale_after_seconds=0.6)
    r = _slot_redis()
    r.delete(_SLOTS_KEY)  # clean slate regardless of anything left over from a prior run
    try:
        # 1) normal acquire/release leaves no ticket behind
        with _llm_slot(s):
            assert current_llm_slot_count() == 1
        assert current_llm_slot_count() == 0

        # 2) a call legitimately running LONGER than the staleness window survives because its
        #    own heartbeat keeps refreshing the ticket — duration and aliveness really are
        #    different things, proven against the real server this time, not the fake's math.
        with _llm_slot(s):
            time.sleep(1.2)  # > llm_slot_stale_after_seconds (0.6s)
            assert current_llm_slot_count() == 1
        assert current_llm_slot_count() == 0

        # 3) genuinely full (a second concurrent holder) -> LLMSlotUnavailable after the wait
        with _llm_slot(s):
            with pytest.raises(LLMSlotUnavailable):
                with _llm_slot(s):
                    pass
    finally:
        try:
            r.delete(_SLOTS_KEY)
        except Exception:  # noqa: BLE001 — best-effort cleanup, never mask the real assertion
            pass


def test_embedding_reranker_provider_follows_llm_provider_when_unset():
    # [Seamless flip] flipping LLM_PROVIDER alone is enough — embedding/reranker follow it
    # automatically when left unset, instead of needing all three variables kept in sync.
    s = Settings(llm_provider="litellm_proxy")
    assert s.embedding_provider == "litellm_proxy"
    assert s.reranker_provider == "litellm_proxy"


def test_embedding_reranker_provider_stays_local_for_non_proxy_llm_provider():
    s = Settings(llm_provider="azure_openai")
    assert s.embedding_provider == "local"
    assert s.reranker_provider == "local"
    s2 = Settings(llm_provider="openai")
    assert s2.embedding_provider == "local"
    assert s2.reranker_provider == "local"


def test_embedding_reranker_provider_explicit_override_wins_for_a_hybrid_setup():
    # A genuine hybrid — chat via the proxy, embeddings kept local — must stay possible by
    # setting embedding_provider explicitly, even with llm_provider=litellm_proxy.
    s = Settings(llm_provider="litellm_proxy", embedding_provider="local")
    assert s.embedding_provider == "local"       # explicit — untouched
    assert s.reranker_provider == "litellm_proxy"  # not set explicitly — still follows


def test_stage_lease_seconds_derives_a_safe_default():
    # [REVIEW-FIX] left unset, must comfortably exceed llm_timeout_seconds*(llm_max_retries+1)
    # — the real worst-case duration of one legitimate call — not a guessed flat literal.
    s = Settings(llm_timeout_seconds=90.0, llm_max_retries=3)
    assert s.stage_lease_seconds == 90 * 4 * 2


def test_stage_lease_seconds_rejects_unsafe_explicit_override():
    with pytest.raises(ValidationError, match="stage_lease_seconds"):
        Settings(llm_timeout_seconds=90.0, llm_max_retries=3, stage_lease_seconds=10)


def test_stage_lease_seconds_accepts_a_safe_explicit_override():
    s = Settings(llm_timeout_seconds=10.0, llm_max_retries=1, stage_lease_seconds=100)
    assert s.stage_lease_seconds == 100  # above the floor (10*2=20) — respected, not overridden


def test_reaper_stale_grace_seconds_follows_derived_stage_lease_by_default():
    # [REVIEW-FIX] left unset, must follow stage_lease_seconds' DERIVED value (90*4*2=720), not
    # its unresolved 300s class default — proves _derive_reaper_stale_grace_seconds runs after
    # _derive_stage_lease_seconds, not before.
    s = Settings(llm_timeout_seconds=90.0, llm_max_retries=3)
    assert s.reaper_stale_grace_seconds == s.stage_lease_seconds == 90 * 4 * 2


def test_reaper_stale_grace_seconds_accepts_an_explicit_override():
    s = Settings(llm_timeout_seconds=90.0, llm_max_retries=3, reaper_stale_grace_seconds=45.0)
    assert s.reaper_stale_grace_seconds == 45.0  # decoupled — does not follow stage_lease_seconds
    assert s.stage_lease_seconds == 90 * 4 * 2  # ...which is itself untouched by the override


class _FakeModelsResponse:
    def __init__(self, model_ids):
        self._model_ids = model_ids

    def raise_for_status(self):
        pass

    def json(self):
        return {"data": [{"id": m} for m in self._model_ids]}


class _FakeHttpClient:
    """Stands in for httpx.Client(transport=...) — a context manager whose .get() either
    returns a canned response or raises a canned exception, matching verify_litellm_models'
    actual call shape (a Client instance, not the bare httpx.get convenience function)."""
    def __init__(self, result):
        self._result = result

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def get(self, *a, **k):
        if isinstance(self._result, BaseException):
            raise self._result
        return self._result


def test_verify_litellm_models_noop_on_proxy_check_when_no_provider_uses_the_proxy(monkeypatch):
    # defaults: llm_provider=azure_openai, embedding/reranker_provider=local. The
    # litellm_proxy-specific /v1/models check makes no network call — but [REVIEW-FIX] a
    # DIFFERENT check now fires for the direct azure_openai path (see the next two tests).
    import httpx
    import litellm

    from app.pipeline.llm import verify_litellm_models

    calls = []
    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: calls.append(1) or _FakeHttpClient(_FakeModelsResponse([])))
    monkeypatch.setattr(litellm, "completion",
                        lambda *, messages, **kwargs: {"choices": [{"message": {"content": "ok"}}], "model": "x"})
    verify_litellm_models(Settings(azure_openai_deployment_name="d"))
    assert calls == []  # no /v1/models call — nothing routes through the proxy


def test_verify_litellm_models_raises_when_direct_provider_unreachable(monkeypatch):
    # [REVIEW-FIX] an expired Azure key/decommissioned deployment must be caught at boot,
    # not silently pass through to a real user's first pipeline session.
    import litellm

    from app.pipeline.llm import verify_litellm_models

    def fake_completion(*, messages, **kwargs):
        raise RuntimeError("401 Unauthorized")

    monkeypatch.setattr(litellm, "completion", fake_completion)
    with pytest.raises(RuntimeError, match="azure_openai chat provider was unreachable"):
        verify_litellm_models(Settings(azure_openai_deployment_name="d"))


def test_verify_litellm_models_direct_provider_check_survives_json_mode(monkeypatch):
    # [REVIEW-FIX] the boot-time ping must stay valid even when LLM_JSON_MODE is on: _chat_kwargs
    # adds response_format={"type": "json_object"} to every call, and the real OpenAI/Azure API
    # rejects that with a 400 unless "json" appears in the message text. A literal "ping" would
    # 400 on every worker boot for this (real, supported) provider+json_mode combination — this
    # fake reproduces that same content-validation rule to prove the fix's wording satisfies it.
    import litellm

    from app.pipeline.llm import verify_litellm_models

    def fake_completion(*, messages, **kwargs):
        if kwargs.get("response_format") == {"type": "json_object"}:
            text = " ".join(m["content"] for m in messages).lower()
            if "json" not in text:
                raise RuntimeError("400 'messages' must contain the word 'json' in some form")
        return {"choices": [{"message": {"content": "ok"}}], "model": "x"}

    monkeypatch.setattr(litellm, "completion", fake_completion)
    verify_litellm_models(Settings(azure_openai_deployment_name="d", llm_json_mode=True))


def test_verify_litellm_models_direct_provider_check_skipped_for_litellm_proxy(monkeypatch):
    # the direct-provider check is specific to azure_openai/openai — litellm_proxy already
    # gets its own /v1/models-based check above, so this must not fire a second, redundant call.
    import httpx
    import litellm

    from app.pipeline.llm import verify_litellm_models

    completion_calls = []
    monkeypatch.setattr(litellm, "completion", lambda *, messages, **kwargs: completion_calls.append(1))
    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(_FakeModelsResponse(["gpt-5"])))
    verify_litellm_models(Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                                embedding_provider="local", reranker_provider="local"))
    assert completion_calls == []


def test_verify_litellm_models_passes_when_configured_model_is_registered(monkeypatch):
    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(_FakeModelsResponse(["gpt-5", "other-model"])))
    # [Seamless flip] embedding_provider/reranker_provider pinned explicitly here — otherwise
    # they'd now follow llm_provider=litellm_proxy too, and this test's local-path model
    # paths (not real proxy model names) would fail the registration check for the wrong reason.
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                embedding_provider="local", reranker_provider="local")
    verify_litellm_models(s)  # must not raise


def test_verify_litellm_models_raises_when_configured_model_is_missing(monkeypatch):
    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(_FakeModelsResponse(["gpt-5", "other-model"])))
    # [REVIEW-FIX] embedding_provider/reranker_provider pinned explicitly — otherwise they'd
    # now follow llm_provider=litellm_proxy too (see [Seamless flip]), widening `missing` to 3
    # entries (inference/embedding/reranker) instead of the 1 this test actually means to
    # exercise. The match= below would still pass either way (substring match against a wider
    # dict repr), silently testing something less precise than intended — pinning restores it.
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5-not-registered",
                embedding_provider="local", reranker_provider="local")
    with pytest.raises(RuntimeError, match="gpt-5-not-registered"):
        verify_litellm_models(s)


def test_verify_litellm_models_only_checks_providers_actually_set_to_litellm_proxy(monkeypatch):
    # embedding_provider stays 'local' (default) — its model must never be checked,
    # even though llm_provider routes through the proxy.
    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeHttpClient(_FakeModelsResponse(["gpt-5"])))
    # embedding_provider/reranker_provider pinned explicitly to "local" — otherwise they'd
    # now follow llm_provider=litellm_proxy too (see [Seamless flip]), defeating this test's
    # own point.
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5", embedding_provider="local",
                reranker_provider="local", embedding_model="not-a-real-embedding-model")
    verify_litellm_models(s)  # must not raise — embedding_model was never in scope


def test_verify_litellm_models_wraps_connection_failure_in_a_clear_runtimeerror(monkeypatch):
    # [REVIEW-FIX] a raw httpx.ConnectError previously propagated uncaught here — unlike the
    # missing-model case (a clear RuntimeError) and unlike check_litellm_proxy_health (which
    # already wrapped this). A worker crashing on this must at least say WHY in one readable
    # line, not a bare httpx traceback.
    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(httpx.ConnectError("connection refused")))
    # [REVIEW-FIX] embedding_provider/reranker_provider pinned explicitly, matching the other
    # test_verify_litellm_models_* tests — otherwise they'd now follow llm_provider=
    # litellm_proxy too (see [Seamless flip]), widening `wanted` to 3 entries. Currently
    # inert here (the mocked ConnectError fires before `wanted` is ever inspected), but
    # pinning keeps this test's scope explicit rather than accidentally correct.
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                embedding_provider="local", reranker_provider="local")
    with pytest.raises(RuntimeError, match="unreachable or rejected"):
        verify_litellm_models(s)


def test_ensure_litellm_proxy_bypassed_noop_when_no_provider_uses_the_proxy(monkeypatch):
    import os

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    monkeypatch.delenv("NO_PROXY", raising=False)
    s = Settings()  # defaults: llm_provider=azure_openai, embedding/reranker_provider=local
    _ensure_litellm_proxy_bypassed(s)
    assert "NO_PROXY" not in os.environ


def test_ensure_litellm_proxy_bypassed_adds_proxy_host_when_a_provider_uses_the_proxy(monkeypatch):
    import os

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    s = Settings(llm_provider="litellm_proxy", litellm_base_url="https://llmapi.example.com")
    _ensure_litellm_proxy_bypassed(s)
    assert "llmapi.example.com" in os.environ["NO_PROXY"]
    assert "llmapi.example.com" in os.environ["no_proxy"]  # both cases set — different libraries honor different ones


def test_ensure_litellm_proxy_bypassed_gates_on_embedding_and_reranker_providers_too(monkeypatch):
    import os

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    monkeypatch.delenv("NO_PROXY", raising=False)
    s = Settings(embedding_provider="litellm_proxy", litellm_base_url="https://llmapi.example.com")
    _ensure_litellm_proxy_bypassed(s)
    assert "llmapi.example.com" in os.environ["NO_PROXY"]  # llm_provider itself is untouched (default azure)


def test_ensure_litellm_proxy_bypassed_merges_rather_than_overwrites_existing_no_proxy(monkeypatch):
    import os

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    monkeypatch.setenv("NO_PROXY", "existing.example.com")
    s = Settings(reranker_provider="litellm_proxy", litellm_base_url="https://llmapi.example.com")
    _ensure_litellm_proxy_bypassed(s)
    hosts = os.environ["NO_PROXY"].split(",")
    assert "existing.example.com" in hosts and "llmapi.example.com" in hosts


def test_ensure_litellm_proxy_bypassed_is_idempotent(monkeypatch):
    import os

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    monkeypatch.delenv("NO_PROXY", raising=False)
    s = Settings(llm_provider="litellm_proxy", litellm_base_url="https://llmapi.example.com")
    _ensure_litellm_proxy_bypassed(s)
    _ensure_litellm_proxy_bypassed(s)  # called twice — must not duplicate the entry
    assert os.environ["NO_PROXY"].split(",").count("llmapi.example.com") == 1


def test_ensure_litellm_proxy_bypassed_handles_scheme_less_base_url(monkeypatch):
    # [REVIEW-FIX] urlparse only recognizes a hostname when the string starts with "//" — an
    # operator pasting "host:port" into LITELLM_BASE_URL (no scheme) previously made this
    # silently no-op with no log line. Must still bypass the proxy for that host.
    import os

    from app.pipeline.llm import _ensure_litellm_proxy_bypassed

    monkeypatch.delenv("NO_PROXY", raising=False)
    s = Settings(llm_provider="litellm_proxy", litellm_base_url="llmapi.internal:4000")
    _ensure_litellm_proxy_bypassed(s)
    assert "llmapi.internal" in os.environ["NO_PROXY"]


def test_get_llm_applies_proxy_bypass_before_returning_the_client(monkeypatch):
    import os

    from app.pipeline.llm import get_llm

    monkeypatch.delenv("NO_PROXY", raising=False)
    s = Settings(llm_provider="litellm_proxy", litellm_base_url="https://llmapi.example.com")
    monkeypatch.setattr("app.pipeline.llm.get_settings", lambda: s)
    get_llm.cache_clear()
    try:
        get_llm()
        assert "llmapi.example.com" in os.environ["NO_PROXY"]
    finally:
        get_llm.cache_clear()  # don't leak this fake-Settings-backed client into other tests


def test_verify_litellm_models_applies_proxy_bypass_before_its_own_network_call(monkeypatch):
    # [REVIEW-FIX] verify_litellm_models makes its own direct httpx.Client() call and is
    # invoked from _init_worker at worker boot — strictly before get_llm() could have run in
    # that process — so it can't rely on get_llm() having already set NO_PROXY.
    import os

    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(_FakeModelsResponse(["gpt-5"])))
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                embedding_provider="local", reranker_provider="local",
                litellm_base_url="https://llmapi.example.com")
    verify_litellm_models(s)
    assert "llmapi.example.com" in os.environ["NO_PROXY"]


def test_embed_rejects_text_over_the_length_cap():
    from app.pipeline.llm import _MAX_EMBED_CHARS

    s = Settings(embedding_provider="litellm_proxy", embedding_prefix_style="none")
    huge = "x" * (_MAX_EMBED_CHARS + 1)
    with pytest.raises(ValueError, match=str(_MAX_EMBED_CHARS)):
        LiteLLMClient(s).embed([huge])


def test_embed_length_guard_runs_before_the_local_provider_branch_too(monkeypatch):
    # the guard sits ahead of the local/remote split — protects both providers from one check
    from app.pipeline.llm import _MAX_EMBED_CHARS

    monkeypatch.setattr("app.pipeline.local_models.embed",
                        lambda texts: pytest.fail("must reject before ever reaching local_models.embed"))
    s = Settings(embedding_provider="local", embedding_model="/models/e5")
    huge = "x" * (_MAX_EMBED_CHARS + 1)
    with pytest.raises(ValueError):
        LiteLLMClient(s).embed([huge])


def test_embed_accepts_text_at_or_under_the_length_cap(monkeypatch):
    import litellm

    monkeypatch.setattr(litellm, "embedding",
                        lambda **kw: {"data": [{"index": 0, "embedding": [0.0]}]})
    from app.pipeline.llm import _MAX_EMBED_CHARS

    s = Settings(embedding_provider="litellm_proxy", embedding_prefix_style="none")
    at_cap = "x" * _MAX_EMBED_CHARS
    assert LiteLLMClient(s).embed([at_cap]) == [[0.0]]  # must not raise


def test_chat_rejects_prompt_over_the_length_cap():
    from app.pipeline.llm import _MAX_CHAT_CHARS

    s = Settings(llm_provider="litellm_proxy")
    huge = "x" * (_MAX_CHAT_CHARS + 1)
    with pytest.raises(ValueError, match=str(_MAX_CHAT_CHARS)):
        LiteLLMClient(s).chat([{"role": "user", "content": huge}])


def test_chat_length_guard_runs_before_any_provider_work(monkeypatch):
    # must fire before litellm.completion is ever called — no wasted network round-trip
    import litellm

    from app.pipeline.llm import _MAX_CHAT_CHARS

    monkeypatch.setattr(litellm, "completion",
                        lambda *, messages, **kw: pytest.fail("must reject before calling litellm.completion"))
    s = Settings(llm_provider="litellm_proxy")
    huge = "x" * (_MAX_CHAT_CHARS + 1)
    with pytest.raises(ValueError):
        LiteLLMClient(s).chat([{"role": "user", "content": huge}])


def test_chat_length_guard_sums_across_all_messages_not_just_one():
    from app.pipeline.llm import _MAX_CHAT_CHARS

    s = Settings(llm_provider="litellm_proxy")
    half = "x" * (_MAX_CHAT_CHARS // 2 + 1)
    with pytest.raises(ValueError):
        LiteLLMClient(s).chat([{"role": "system", "content": half}, {"role": "user", "content": half}])


class _FakeJsonResponse:
    """A canned httpx-style response for an arbitrary JSON body (unlike _FakeModelsResponse,
    which is shaped specifically for /v1/models) — used for /model/info, /key/info,
    /health/readiness/details, whose real response shapes aren't confirmed against a live
    proxy from this dev environment."""
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


class _UrlRoutingFakeClient:
    """Stands in for httpx.Client(...) — routes .get(url) to a canned response based on which
    endpoint path substring appears in the URL. verify_litellm_models makes TWO sequential
    calls (/v1/models then /model/info), each via its own httpx.Client(...) construction, so a
    single fixed-response fake (like _FakeHttpClient) can't stand in for both at once."""
    def __init__(self, responses: dict):
        self._responses = responses

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def get(self, url, **kwargs):
        for key, result in self._responses.items():
            if key in url:
                if isinstance(result, BaseException):
                    raise result
                return result
        raise AssertionError(f"unexpected URL in fake client: {url}")


def test_verify_embedding_dimensions_passes_when_they_match(monkeypatch):
    import litellm

    from app.pipeline.llm import _verify_embedding_dimensions

    monkeypatch.setattr(litellm, "embedding",
                        lambda **kw: {"data": [{"embedding": [0.0] * 4096}]})
    s = Settings(embedding_provider="litellm_proxy", embedding_model="qwen3-embedding-8b-mig",
                embedding_dimensions=4096)
    _verify_embedding_dimensions(s)  # must not raise


def test_verify_embedding_dimensions_raises_on_a_real_mismatch(monkeypatch):
    # [Fix] the exact landmine this closes: EMBEDDING_DIMENSIONS left at the local-path
    # default (1024) while a 4096-dim proxy model is actually configured.
    import litellm

    from app.pipeline.llm import _verify_embedding_dimensions

    monkeypatch.setattr(litellm, "embedding",
                        lambda **kw: {"data": [{"embedding": [0.0] * 4096}]})
    s = Settings(embedding_provider="litellm_proxy", embedding_model="qwen3-embedding-8b-mig",
                embedding_dimensions=1024)
    with pytest.raises(RuntimeError, match="EMBEDDING_DIMENSIONS=1024"):
        _verify_embedding_dimensions(s)


def test_verify_litellm_models_checks_embedding_dimensions_when_proxy_routed(monkeypatch):
    import httpx
    import litellm

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _UrlRoutingFakeClient({
        "/v1/models": _FakeModelsResponse(["qwen3-embedding-8b-mig"]),
        "/model/info": _FakeJsonResponse({"data": []}),
    }))
    monkeypatch.setattr(litellm, "embedding",
                        lambda **kw: {"data": [{"embedding": [0.0] * 4096}]})
    # [REVIEW-FIX] llm_provider stays at its azure_openai default here (only embedding routes
    # through the proxy) — must mock completion() too, or the new direct-provider reachability
    # check (which now always runs for a non-litellm_proxy llm_provider) fires first and masks
    # the embedding-dimension failure this test actually means to exercise.
    monkeypatch.setattr(litellm, "completion",
                        lambda *, messages, **kw: {"choices": [{"message": {"content": "ok"}}], "model": "x"})
    s = Settings(embedding_provider="litellm_proxy", embedding_model="qwen3-embedding-8b-mig",
                embedding_dimensions=1024, azure_openai_deployment_name="d")  # wrong on purpose — matches the real default gap
    with pytest.raises(RuntimeError, match="EMBEDDING_DIMENSIONS=1024"):
        verify_litellm_models(s)


def test_verify_litellm_models_skips_embedding_dimension_check_when_not_proxy_routed(monkeypatch):
    # default embedding_provider is "local" — must not make a litellm.embedding() call at all.
    import litellm

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(litellm, "embedding",
                        lambda **kw: pytest.fail("must not check embedding dimensions for the local path"))
    # embedding_provider/reranker_provider pinned explicitly — otherwise they'd now follow
    # llm_provider=litellm_proxy too (see [Seamless flip]), which is exactly the case this
    # test excludes.
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                embedding_provider="local", reranker_provider="local")
    import httpx

    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _UrlRoutingFakeClient({
        "/v1/models": _FakeModelsResponse(["gpt-5"]),
        "/model/info": _FakeJsonResponse({"data": []}),
    }))
    verify_litellm_models(s)  # must not raise, must not touch litellm.embedding


def test_verify_litellm_models_logs_model_config_rpm_without_raising(monkeypatch):
    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _UrlRoutingFakeClient({
        "/v1/models": _FakeModelsResponse(["gpt-5"]),
        "/model/info": _FakeJsonResponse(
            {"data": [{"model_name": "gpt-5", "litellm_params": {"rpm": 192}}]}),
    }))
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                embedding_provider="local", reranker_provider="local")
    verify_litellm_models(s)  # must not raise — model registered, model/info call succeeds


def test_verify_litellm_models_model_config_check_failure_does_not_raise(monkeypatch):
    # the /model/info call is purely observational — a failure there must never fail the
    # worker-boot check the way a missing REGISTERED model does.
    import httpx

    from app.pipeline.llm import verify_litellm_models

    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _UrlRoutingFakeClient({
        "/v1/models": _FakeModelsResponse(["gpt-5"]),
        "/model/info": httpx.ConnectError("connection refused"),
    }))
    s = Settings(llm_provider="litellm_proxy", inference_model="gpt-5",
                embedding_provider="local", reranker_provider="local")
    verify_litellm_models(s)  # must not raise despite the /model/info call failing


def test_log_litellm_key_info_applies_proxy_bypass_before_its_own_network_call(monkeypatch):
    # [REVIEW-FIX] this function's own httpx.Client() call never goes through get_llm() —
    # must not rely on some other code path in this process having already applied the fix.
    import os

    import httpx

    from app.pipeline.llm import log_litellm_key_info

    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeHttpClient(_FakeJsonResponse({})))
    s = Settings(llm_provider="litellm_proxy", litellm_base_url="https://llmapi.example.com")
    log_litellm_key_info(s)
    assert "llmapi.example.com" in os.environ["NO_PROXY"]


def test_log_litellm_key_info_fires_when_only_moderation_is_enabled(monkeypatch):
    # [REVIEW-FIX] the gate previously checked only the 3 chat/embed/rerank providers, so a
    # moderation-only deployment (llm_provider=azure_openai, llm_moderation_enabled=True)
    # silently skipped this log line for the exact key moderate() actually uses.
    import httpx

    from app.pipeline.llm import log_litellm_key_info

    calls = []
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: calls.append(1) or _FakeHttpClient(_FakeJsonResponse({})))
    s = Settings(llm_moderation_enabled=True)  # all 3 providers left at default (non-proxy)
    log_litellm_key_info(s)
    assert calls == [1]


def test_log_litellm_key_info_noop_when_no_provider_uses_the_proxy(monkeypatch):
    import httpx

    from app.pipeline.llm import log_litellm_key_info

    calls = []
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: calls.append(1) or _FakeHttpClient(_FakeJsonResponse({})))
    log_litellm_key_info(Settings())  # defaults: llm_provider=azure_openai, embedding/reranker=local
    assert calls == []


def test_log_litellm_key_info_handles_a_normal_shaped_response(monkeypatch):
    import httpx

    from app.pipeline.llm import log_litellm_key_info

    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeHttpClient(
        _FakeJsonResponse({"info": {"rpm_limit": 100, "tpm_limit": 10000, "max_budget": 50.0, "spend": 1.2}})))
    s = Settings(llm_provider="litellm_proxy")
    log_litellm_key_info(s)  # must not raise


def test_log_litellm_key_info_does_not_raise_on_malformed_response(monkeypatch):
    # the real /key/info shape isn't confirmed — must degrade gracefully, never crash
    import httpx

    from app.pipeline.llm import log_litellm_key_info

    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(_FakeJsonResponse(["not", "the", "expected", "shape"])))
    s = Settings(llm_provider="litellm_proxy")
    log_litellm_key_info(s)  # must not raise


def test_log_litellm_key_info_does_not_raise_on_network_failure(monkeypatch):
    import httpx

    from app.pipeline.llm import log_litellm_key_info

    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(httpx.ConnectError("connection refused")))
    s = Settings(llm_provider="litellm_proxy")
    log_litellm_key_info(s)  # must not raise — log-only, never a gate


class _FakeModerationCategories:
    def __init__(self, d):
        self._d = d

    def model_dump(self):
        return self._d


class _FakeModerationResult:
    def __init__(self, flagged, categories):
        self.flagged = flagged
        self.categories = _FakeModerationCategories(categories)


class _FakeModerationResponse:
    def __init__(self, flagged=False, categories=None):
        self.results = [_FakeModerationResult(flagged, categories or {})]


class _FakeModerationsAPI:
    def __init__(self, response):
        self._response = response
        self.create_kwargs: dict | None = None

    def create(self, **kwargs):
        self.create_kwargs = kwargs
        if isinstance(self._response, BaseException):
            raise self._response
        return self._response


class _FakeOpenAIClient:
    """Stands in for openai.OpenAI(...) — captures the constructor kwargs (so tests can
    assert moderate() passes an explicit api_key/base_url/timeout/max_retries rather than
    relying on any global default) and returns/raises a canned moderation response."""
    last_constructor_kwargs: dict | None = None

    def __init__(self, response, **kwargs):
        _FakeOpenAIClient.last_constructor_kwargs = kwargs
        self.moderations = _FakeModerationsAPI(response)


def test_moderate_applies_proxy_bypass_before_constructing_its_client(monkeypatch):
    # [REVIEW-FIX] moderation's target host (litellm_base_url) is independent of
    # llm_provider/embedding_provider/reranker_provider — a deployment could enable
    # moderation without routing chat/embed/rerank through the proxy at all, in which case
    # nothing else in the process would ever call the bypass fix for moderation's own calls.
    import os

    import openai

    from app.pipeline.llm import moderate

    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: _FakeOpenAIClient(_FakeModerationResponse(), **kw))
    s = Settings(llm_moderation_enabled=True, litellm_base_url="https://llmapi.example.com")
    moderate("some text", settings=s)
    assert "llmapi.example.com" in os.environ["NO_PROXY"]


def test_moderate_disabled_by_default_never_constructs_client(monkeypatch):
    import openai

    from app.pipeline.llm import moderate

    monkeypatch.setattr(openai, "OpenAI", lambda **kw: pytest.fail("must not construct a client when disabled"))
    s = Settings(llm_moderation_enabled=False)
    result = moderate("some text", settings=s)
    assert result.checked is False and result.error is None


def test_moderate_enabled_passes_explicit_key_base_timeout_retries(monkeypatch):
    # must never rely on litellm.moderation()'s own global-API-key fallback — every value
    # this call needs must be passed explicitly.
    import openai

    from app.pipeline.llm import moderate

    fake_response = _FakeModerationResponse(flagged=False)
    monkeypatch.setattr(openai, "OpenAI",
                        lambda **kw: _FakeOpenAIClient(fake_response, **kw))
    s = Settings(llm_moderation_enabled=True, litellm_api_key="sk-test", litellm_base_url="https://llmapi.example.com",
                llm_timeout_seconds=42.0, llm_max_retries=4)
    moderate("some text", settings=s)
    kw = _FakeOpenAIClient.last_constructor_kwargs
    assert kw["api_key"] == "sk-test"
    assert kw["base_url"] == "https://llmapi.example.com/v1"
    assert kw["timeout"] == 42.0
    assert kw["max_retries"] == 4


def test_moderate_degrades_gracefully_on_an_empty_results_list(monkeypatch):
    # [REVIEW-FIX] result-parsing (resp.results[0]) previously ran OUTSIDE the try/except —
    # an empty results list raised an uncaught IndexError, violating moderate()'s own "never
    # raises" contract and propagating all the way up to a full subsystem ERROR.
    import openai

    from app.pipeline.llm import moderate

    empty_response = _FakeModerationResponse.__new__(_FakeModerationResponse)
    empty_response.results = []  # the exact malformed shape that used to crash
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: _FakeOpenAIClient(empty_response, **kw))
    s = Settings(llm_moderation_enabled=True)
    result = moderate("some text", settings=s)  # must not raise
    assert result.checked is False
    assert result.error == "moderation_unavailable"


def test_moderate_returns_flagged_categories(monkeypatch):
    import openai

    from app.pipeline.llm import moderate

    fake_response = _FakeModerationResponse(flagged=True, categories={"violence": True, "hate": False})
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: _FakeOpenAIClient(fake_response, **kw))
    s = Settings(llm_moderation_enabled=True)
    result = moderate("some text", settings=s)
    assert result.checked is True
    assert result.flagged is True
    assert result.categories == ["violence"]


def test_moderate_call_failure_returns_checked_false_never_raises(monkeypatch):
    import openai

    from app.pipeline.llm import moderate

    monkeypatch.setattr(openai, "OpenAI",
                        lambda **kw: _FakeOpenAIClient(RuntimeError("proxy exploded"), **kw))
    s = Settings(llm_moderation_enabled=True)
    result = moderate("some text", settings=s)
    assert result.checked is False
    assert result.error == "moderation_unavailable"


def test_moderate_propagates_llm_slot_unavailable(monkeypatch):
    # same "temporary, not a bug" contract as chat/embed/rerank — must NOT be swallowed
    # into a generic checked=False the way a real moderation-service error is.
    import openai

    from app.pipeline.llm import LLMSlotUnavailable, moderate

    def _boom_slot(*a, **k):
        raise LLMSlotUnavailable("no free slot")

    monkeypatch.setattr("app.pipeline.llm._llm_slot", _boom_slot)
    monkeypatch.setattr(openai, "OpenAI",
                        lambda **kw: _FakeOpenAIClient(_FakeModerationResponse(), **kw))
    s = Settings(llm_moderation_enabled=True)
    with pytest.raises(LLMSlotUnavailable):
        moderate("some text", settings=s)


def test_chat_kwargs_guardrails_only_on_litellm_proxy_branch():
    s = Settings(llm_provider="litellm_proxy", llm_guardrails=["pii-detector"])
    assert LiteLLMClient(s)._chat_kwargs()["guardrails"] == ["pii-detector"]

    az = Settings(llm_provider="azure_openai", llm_guardrails=["pii-detector"],
                azure_openai_deployment_name="d")
    assert "guardrails" not in LiteLLMClient(az)._chat_kwargs()


def test_chat_kwargs_guardrails_absent_by_default():
    s = Settings(llm_provider="litellm_proxy")
    assert "guardrails" not in LiteLLMClient(s)._chat_kwargs()


def test_config_local_aliases():
    s = Settings(embedding_provider="local", embedding_model="/m/e5", embedding_dimensions=1024,
                 semantic_match_threshold=0.6, reranker_provider="local", reranker_model="/m/bge")
    assert (s.embedding_provider, s.reranker_provider) == ("local", "local")
    assert (s.embedding_model, s.reranker_model) == ("/m/e5", "/m/bge")
    assert s.embedding_dimensions == 1024 and s.semantic_match_threshold == 0.6
