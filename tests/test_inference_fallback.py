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
from pydantic import BaseModel

from app.core.config import Settings
from app.pipeline.llm import LiteLLMClient, LLMRefusal, LLMResponseTruncated, LLMSlotUnavailable

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



# --- Structured Outputs: which JSON contract goes on the wire (llm._with_response_format) ---------
class _Schema(BaseModel):
    ok: bool


def _json_settings(monkeypatch, **over) -> Settings:
    return _settings(monkeypatch, TSG_LLM_JSON_MODE="true", **over)


def test_declared_schema_is_sent_when_structured_output_on(monkeypatch):
    """`on`: the Pydantic class itself is handed to litellm (which converts it to a strict
    json_schema generically) — on the primary AND on the fallback re-call, so a fallback can
    never quietly drop the contract. Provenance names the contract that ran."""
    calls = _stub_litellm(monkeypatch, [_server_500(), _OK])
    _, prov = LiteLLMClient(_json_settings(monkeypatch, TSG_LLM_STRUCTURED_OUTPUT="on")).chat(
        _MSG, expected_type=dict, response_schema=_Schema)
    primary, fallback = calls
    assert primary["response_format"] is _Schema and fallback["response_format"] is _Schema
    assert prov.params["response_format"] == "json_schema:_Schema"


def test_auto_degrades_to_json_object_when_litellm_cannot_vouch(monkeypatch):
    """The UAT shape — glm-5 -> kimi-k2.5 through the proxy, whose native APIs document only
    json_object. The stub, like litellm's table for a proxy alias, cannot vouch for the model, so
    `auto` sends exactly today's request on both calls."""
    calls = _stub_litellm(monkeypatch, [_server_500(), _OK])
    _, prov = LiteLLMClient(_json_settings(monkeypatch)).chat(
        _MSG, expected_type=dict, response_schema=_Schema)
    assert [c["response_format"] for c in calls] == [{"type": "json_object"}] * 2
    assert prov.params["response_format"] == "json_object"


def test_auto_sends_the_schema_when_litellm_vouches(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_OK])
    sys.modules["litellm"].supports_response_schema = lambda model, custom_llm_provider=None: True
    LiteLLMClient(_json_settings(monkeypatch)).chat(_MSG, expected_type=dict, response_schema=_Schema)
    assert calls[0]["response_format"] is _Schema


def test_structured_output_off_keeps_json_object(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_OK])
    LiteLLMClient(_json_settings(monkeypatch, TSG_LLM_STRUCTURED_OUTPUT="off")).chat(
        _MSG, expected_type=dict, response_schema=_Schema)
    assert calls[0]["response_format"] == {"type": "json_object"}


def test_no_declared_schema_is_todays_json_object_even_when_on(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_OK])
    LiteLLMClient(_json_settings(monkeypatch, TSG_LLM_STRUCTURED_OUTPUT="on")).chat(
        _MSG, expected_type=dict)
    assert calls[0]["response_format"] == {"type": "json_object"}


def test_json_mode_off_sends_no_response_format_even_with_a_schema(monkeypatch):
    calls = _stub_litellm(monkeypatch, [_OK])
    # BOTH alias names, explicitly: the dev .env enables JSON mode, and a real litellm import
    # elsewhere in the session load_dotenv()s it into os.environ under the un-prefixed name,
    # which AliasChoices consults first.
    _, prov = LiteLLMClient(_settings(monkeypatch, LLM_JSON_MODE="false", TSG_LLM_JSON_MODE="false",
                                      TSG_LLM_STRUCTURED_OUTPUT="on")).chat(
        _MSG, expected_type=dict, response_schema=_Schema)
    assert "response_format" not in calls[0] and "response_format" not in prov.params


# --- finish_reason: a cap stop and a refusal are never returned as text -------------------------
def _reply(content, finish_reason=None, *, refusal=None, usage=None) -> dict:
    msg = {"content": content, **({"refusal": refusal} if refusal is not None else {})}
    choice = {"message": msg, **({"finish_reason": finish_reason} if finish_reason else {})}
    return {"model": "served", "choices": [choice], **({"usage": usage} if usage else {})}


def test_length_stop_raises_truncated_with_the_numbers(monkeypatch):
    """A reasoning model that spends the whole cap thinking returns EMPTY content with
    finish_reason=length — a budget failure, raised as one (with the numbers), never handed
    downstream as '' to be misreported as bad JSON."""
    _stub_litellm(monkeypatch, [_reply("", "length", usage={
        "completion_tokens": 4096, "completion_tokens_details": {"reasoning_tokens": 4096}})])
    with pytest.raises(LLMResponseTruncated) as ei:
        LiteLLMClient(_settings(monkeypatch, TSG_LLM_MAX_OUTPUT_TOKENS="4096")).chat(
            _MSG, expected_type=dict)
    assert (ei.value.max_tokens, ei.value.completion_tokens, ei.value.reasoning_tokens) == (4096, 4096, 4096)
    assert "reasoning_tokens=4096" in str(ei.value)


def test_refusal_raises_llm_refusal(monkeypatch):
    _stub_litellm(monkeypatch, [_reply(None, "stop", refusal="I can't help with that.")])
    with pytest.raises(LLMRefusal, match="can't help"):
        LiteLLMClient(_settings(monkeypatch)).chat(_MSG, expected_type=dict)


def test_stop_reply_with_usage_is_returned_unchanged(monkeypatch):
    _stub_litellm(monkeypatch, [_reply("hello", "stop", usage={"completion_tokens": 12})])
    text, _ = LiteLLMClient(_settings(monkeypatch)).chat(_MSG)
    assert text == "hello"
