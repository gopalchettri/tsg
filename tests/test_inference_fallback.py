"""App-side chat model fallback — see LiteLLMClient.chat / _fallback_applies (llm.py).

litellm is STUBBED in sys.modules for every test: chat() imports it lazily, and the real
package's import calls load_dotenv(), polluting os.environ for unrelated tests. Exceptions are
the REAL openai classes — that's exactly what litellm raises and what _fallback_applies types
against."""
from __future__ import annotations

import sys
import types

import httpx
import openai
import pytest

from app.core.config import Settings
from app.pipeline.llm import LiteLLMClient, LLMSlotUnavailable

_REQ = httpx.Request("POST", "http://proxy.test/v1/chat/completions")
_OK = {"model": "served", "choices": [{"message": {"content": "hello"}}]}


def _rate_limit():
    return openai.RateLimitError("429", response=httpx.Response(429, request=_REQ), body=None)


def _auth_401():
    return openai.AuthenticationError("401", response=httpx.Response(401, request=_REQ), body=None)


def _server_500():
    return openai.InternalServerError("500", response=httpx.Response(500, request=_REQ), body=None)


def _timeout():
    return openai.APITimeoutError(request=_REQ)


def _settings(monkeypatch, **overrides) -> Settings:
    env = {"TSG_LLM_PROVIDER": "litellm_proxy", "TSG_INFERENCE_MODEL": "glm-5",
        "TSG_INFERENCE_FALLBACK_MODEL": "kimi-k2.5",
        # 0 disables the Redis slot machinery — these tests must never touch Redis.
        "TSG_MAX_CONCURRENT_LLM_CALLS": "0", "TRACE_SINKS": ""}
    env.update(overrides)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return Settings()


class _StubStream:  # stands in for litellm.CustomStreamWrapper in isinstance checks
    def __iter__(self):  # chat() drains the stream via list(resp) before rebuilding it
        return iter([])


def _stub_litellm(monkeypatch, script: list):
    """Install a litellm stub whose completion() plays `script` in order (Exception = raise).
    Returns the recorded kwargs of every call."""
    calls: list[dict] = []

    def completion(**kw):
        calls.append(kw)
        action = script[len(calls) - 1]
        if isinstance(action, Exception):
            raise action
        return action

    stub = types.SimpleNamespace(completion=completion, CustomStreamWrapper=_StubStream,
                                stream_chunk_builder=lambda chunks, messages=None: None)
    monkeypatch.setitem(sys.modules, "litellm", stub)
    return calls


_MSG = [{"role": "user", "content": "hi"}]


@pytest.mark.parametrize("primary_error", [_rate_limit(), _timeout(), _server_500()],
                        ids=["429", "timeout", "500"])
def test_retryable_primary_failure_falls_back(monkeypatch, primary_error):
    calls = _stub_litellm(monkeypatch, [primary_error, _OK])
    text, prov = LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert text == "hello"
    assert [c["model"] for c in calls] == ["glm-5", "kimi-k2.5"]
    assert prov.model == "kimi-k2.5"  # provenance records who actually answered
    assert prov.params["fallback_from"] == "glm-5"


def test_non_retryable_4xx_never_falls_back(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_auth_401()])
    with pytest.raises(openai.AuthenticationError):
        LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert len(calls) == 1  # auth fails identically on every model — no second billed call


def test_unset_fallback_keeps_existing_behaviour(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_rate_limit()])
    with pytest.raises(LLMSlotUnavailable):  # 429 -> _provider_429_retryable, exactly as before
        LiteLLMClient(_settings(monkeypatch, TSG_INFERENCE_FALLBACK_MODEL="")).chat(_MSG)
    assert len(calls) == 1


def test_both_models_rate_limited_becomes_slot_unavailable(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_rate_limit(), _rate_limit()])
    with pytest.raises(LLMSlotUnavailable):  # fallback's 429 still lands in the retry machinery
        LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert len(calls) == 2


def test_pinned_model_never_falls_back(monkeypatch):
    """Boot probes and calibration pin model= explicitly — a broken primary must fail AS ITSELF
    there, or the fallback masks it and the probe lies."""
    calls = _stub_litellm(monkeypatch, [_rate_limit()])
    with pytest.raises(LLMSlotUnavailable):
        LiteLLMClient(_settings(monkeypatch)).chat(_MSG, model="glm-5")
    assert len(calls) == 1


def test_fallback_equal_to_primary_is_inert(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_rate_limit()])
    with pytest.raises(LLMSlotUnavailable):
        LiteLLMClient(_settings(monkeypatch, TSG_INFERENCE_FALLBACK_MODEL="glm-5")).chat(_MSG)
    assert len(calls) == 1


def test_azure_never_falls_back(monkeypatch):
    """Azure addresses a fixed deployment; a 'fallback' would re-call the same deployment."""
    calls = _stub_litellm(monkeypatch, [_timeout()])
    s = _settings(monkeypatch, TSG_LLM_PROVIDER="azure_openai",
                AZURE_OPENAI_DEPLOYMENT_NAME="dep", AZURE_OPENAI_ENDPOINT="http://a",
                AZURE_OPENAI_API_KEY="k")
    with pytest.raises(openai.APITimeoutError):
        LiteLLMClient(s).chat(_MSG)
    assert len(calls) == 1


# --- fixes from the adversarial review ------------------------------------------------------------
def test_fallback_kwargs_preserve_call_shape(monkeypatch):
    """The rebuilt fallback kwargs must carry the same JSON mode, temperature and timeout as the
    primary's — a fallback that silently drops response_format would trade a 5xx for a parse
    error."""
    calls = _stub_litellm(monkeypatch, [_server_500(), _OK])
    s = _settings(monkeypatch, TSG_LLM_JSON_MODE="true", TSG_LLM_TIMEOUT_SECONDS="180.0")
    LiteLLMClient(s).chat(_MSG, temperature=0.0, expected_type=dict)
    primary, fallback = calls
    for key in ("response_format", "temperature", "timeout", "num_retries"):
        assert fallback.get(key) == primary.get(key), key
    assert fallback["response_format"] == {"type": "json_object"}


def test_fallback_failure_reraises_the_primary_error(monkeypatch):
    """Primary 429 + fallback hard-failing (e.g. decommissioned model, 404/400) must stay a
    retry-later condition: the PRIMARY's error is the truthful signal, so it still becomes
    LLMSlotUnavailable instead of the fallback's unrelated class becoming a permanent ERROR."""
    calls = _stub_litellm(monkeypatch, [_rate_limit(), _auth_401()])
    with pytest.raises(LLMSlotUnavailable):
        LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert len(calls) == 2


def test_fallback_that_streams_is_assembled(monkeypatch):
    """glm pins stream:true proxy-side; kimi's entry could too — the fallback path must unwrap
    a stream exactly like the primary path does."""
    stream = _StubStream()
    calls = _stub_litellm(monkeypatch, [_rate_limit(), stream])
    import sys as _sys
    _sys.modules["litellm"].stream_chunk_builder = lambda chunks, messages=None: _OK
    text, prov = LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert text == "hello" and prov.params["fallback_from"] == "glm-5"
    assert len(calls) == 2


def test_unmapped_5xx_apierror_falls_back(monkeypatch):
    """litellm wraps 501/505/520-524 in litellm.APIError (openai.APIError base, NOT
    APIStatusError) — a CDN/gateway meltdown must still trigger the fallback."""
    exc = openai.APIError("520 origin error", _REQ, body=None)
    exc.status_code = 520
    calls = _stub_litellm(monkeypatch, [exc, _OK])
    text, _ = LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert text == "hello" and len(calls) == 2


def test_stage_lease_floor_doubles_with_active_fallback(monkeypatch):
    """One chat call can run two full retry chains with a fallback active — the derived lease
    must cover both (2 x 4 x 180 = 1440 floor -> 2880 lease), and an explicit lease sized for
    one chain must now be refused."""
    s = _settings(monkeypatch, TSG_LLM_TIMEOUT_SECONDS="180.0", TSG_LLM_MAX_RETRIES="3")
    assert s.stage_lease_seconds == 2880
    s_off = _settings(monkeypatch, TSG_INFERENCE_FALLBACK_MODEL="",
                    TSG_LLM_TIMEOUT_SECONDS="180.0", TSG_LLM_MAX_RETRIES="3")
    assert s_off.stage_lease_seconds == 1440
    monkeypatch.setenv("TSG_STAGE_LEASE_SECONDS", "800")  # fine for one chain, not for two
    with pytest.raises(Exception, match="safe floor"):
        _settings(monkeypatch, TSG_LLM_TIMEOUT_SECONDS="180.0", TSG_LLM_MAX_RETRIES="3")

