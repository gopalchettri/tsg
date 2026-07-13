"""LLM provider swap (add-on) — offline: `_chat_kwargs` builds the right litellm
call per `LLM_PROVIDER`, with no network."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.pipeline.llm import LiteLLMClient, _apply_embed_prefix


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


def test_config_local_aliases():
    s = Settings(embedding_provider="local", embedding_model="/m/e5", embedding_dimensions=1024,
                 semantic_match_threshold=0.6, reranker_provider="local", reranker_model="/m/bge")
    assert (s.embedding_provider, s.reranker_provider) == ("local", "local")
    assert (s.embedding_model, s.reranker_model) == ("/m/e5", "/m/bge")
    assert s.embedding_dimensions == 1024 and s.semantic_match_threshold == 0.6
