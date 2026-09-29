"""A provider outage retries; it does not cancel the session.

THE INCIDENT (29 Sep, session 6174F288). One `litellm.rerank` call to the proxy read-timed out
while grounding the first gap proposal, and the session was cancelled. THREE layers of retry
existed and none of them ran:

  1. litellm's own `num_retries` is SILENTLY IGNORED on embedding and rerank. Measured on the
     installed version with num_retries=2: chat reached the provider 3 times, embedding once,
     rerank once. The budget the boot line advertises held for one of the three call types.
  2. chat() falls back to a second model; embed() and rerank() have no fallback at all.
  3. The stage-level classifier only recognised database errors as transient, so a timeout landed
     in `except Exception` and was recorded as a permanent work failure.

The tests below are split deliberately. The SYMPTOM tests say "a provider hiccup must not cancel a
session" and must survive any future refactor of how that is achieved. The MECHANISM tests pin
today's implementation. If the mechanism ones are ever deleted as redundant, the symptom ones still
fail on a regression; the reverse is not true.

litellm is stubbed in sys.modules (it is imported lazily, and importing the real package calls
load_dotenv(), polluting os.environ for unrelated tests). The exceptions are the REAL openai
classes, which is what litellm actually raises.
"""
from __future__ import annotations

import sys
import types

import httpx
import openai
import pytest

from app.core.config import Settings
from app.pipeline import tasks
from app.pipeline.llm import (
    LiteLLMClient,
    LLMSlotUnavailable,
    TransientProviderError,
    is_transient_provider_error,
)
from app.pipeline.pipeline_common import TRANSIENT_INFRA_ERRORS

_REQ = httpx.Request("POST", "http://proxy.test/v1/rerank")


def _status(cls, code):
    return cls(str(code), response=httpx.Response(code, request=_REQ), body=None)


def _gateway(code):
    """litellm wraps statuses it has no mapping for (501/505, CDN 520-524) in litellm.APIError,
    which subclasses openai.APIError but NOT APIStatusError — `.status_code` is all that
    identifies it."""
    exc = openai.APIError(f"{code} gateway", _REQ, body=None)
    exc.status_code = code
    return exc


def _settings(monkeypatch, **overrides) -> Settings:
    env = {"TSG_LLM_PROVIDER": "litellm_proxy", "TSG_RERANKER_PROVIDER": "litellm_proxy",
        "TSG_EMBEDDING_PROVIDER": "litellm_proxy", "TSG_INFERENCE_FALLBACK_MODEL": "",
        # 0 disables the Redis slot machinery — these tests must never touch Redis.
        "TSG_MAX_CONCURRENT_LLM_CALLS": "0", "TSG_LLM_MAX_RETRIES": "0", "TRACE_SINKS": ""}
    env.update(overrides)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return Settings()


def _stub_litellm(monkeypatch, exc: Exception) -> dict:
    """Install a litellm stub whose embedding/rerank always raise. Returns the call counter."""
    seen = {"calls": 0}

    def _raise(**_kw):
        seen["calls"] += 1
        raise exc

    monkeypatch.setitem(sys.modules, "litellm",
                        types.SimpleNamespace(rerank=_raise, embedding=_raise))
    return seen


# --- SYMPTOM: a provider hiccup never cancels a session --------------------------------------
class _Recorder:
    """_process_all_supporting_systems only commits and rolls back on the paths under test."""

    def commit(self):
        pass

    def rollback(self):
        pass


def _pipeline(monkeypatch, work_raises: Exception) -> list[str]:
    recorded: list[str] = []
    monkeypatch.setattr(tasks.dal, "load_session", lambda *a: {
        "CurrentStage": "THREAT_IDENTIFICATION", "SubsystemsJSON": "[]",
        "AssetContextJSON": "{}", "SessionStatus": "active"})
    monkeypatch.setattr(tasks.dal, "acquire_lock", lambda *a: True)
    monkeypatch.setattr(tasks.dal, "release_lock", lambda *a: True)

    def _boom(*_a, **_k):
        raise work_raises

    monkeypatch.setattr(tasks.dal, "active_category_names", _boom)
    monkeypatch.setattr(tasks, "_record_failure", lambda *a: recorded.append("recorded"))
    monkeypatch.setattr(tasks, "decide_session_outcome", lambda *a: recorded.append("decided"))
    monkeypatch.setattr(tasks, "log_transient_infra_retry", lambda **k: None)
    return recorded


def test_a_provider_hiccup_reaches_celery_instead_of_cancelling(monkeypatch):
    """THE REGRESSION TEST. On the broken code this was swallowed by `except Exception`,
    _record_failure ran, and the session was cancelled while Celery logged the task as succeeded.
    It must escape the function so autoretry_for re-runs the stage."""
    recorded = _pipeline(monkeypatch, TransientProviderError("rerank read-timed out"))
    with pytest.raises(TransientProviderError):
        tasks._process_all_supporting_systems(_Recorder(), "s", llm=None, task_id="t")
    assert recorded == [], "the session was failed instead of being left for the retry"


def test_a_real_bug_still_fails_the_session(monkeypatch):
    """The other half of the contract: widening the transient tuple must not turn genuine bugs
    into an endless retry. A RuntimeError is still recorded and settled, exactly as before."""
    recorded = _pipeline(monkeypatch, RuntimeError("stage failed"))
    tasks._process_all_supporting_systems(_Recorder(), "s", llm=None, task_id="t")
    assert recorded == ["recorded", "decided"]


def test_an_error_class_nobody_has_seen_is_treated_as_temporary():
    """THE TEST THAT PROVES THE CAUSE IS GONE, not just the instance.

    An allowlist of temporary failures can never be finished, and the day one is missing from it a
    session dies. This invents a provider error class that did not exist when the rule was written
    and asserts it is survivable WITHOUT anyone adding it to anything. It fails against any
    allowlist-shaped implementation, including the first draft of this fix."""
    class FutureProviderError(openai.APIError):
        pass

    exc = FutureProviderError("something litellm has not invented yet", _REQ, body=None)
    assert is_transient_provider_error(exc) is True


# --- MECHANISM: the classification, and the budget actually reaching the provider -------------
@pytest.mark.parametrize("exc", [
    openai.APITimeoutError(request=_REQ),                    # the reported failure
    openai.APIConnectionError(request=_REQ),
    _status(openai.InternalServerError, 500),
    _status(openai.RateLimitError, 429),
    _gateway(503), _gateway(520),
    _status(openai.APIStatusError, 408),                     # 4xx, but a gateway timeout
    _status(openai.APIStatusError, 425),
], ids=["timeout", "connection", "500", "429", "503", "gateway-520", "408", "425"])
def test_provider_hiccups_are_transient(exc):
    assert is_transient_provider_error(exc) is True


@pytest.mark.parametrize("exc", [
    _status(openai.AuthenticationError, 401),
    _status(openai.BadRequestError, 400),
    _status(openai.NotFoundError, 404),
    _status(openai.UnprocessableEntityError, 422),
    RuntimeError("rerank returned 3 scores for 10 docs"),    # our own fail-loud guard
    ValueError("not a provider error at all"),
], ids=["401", "400", "404", "422", "our-guard", "not-a-provider-error"])
def test_permanent_failures_are_not_transient(exc):
    """These fail identically on every attempt. Retrying doubles the cost of the same error and
    hides its cause — and the last two are OUR bugs, which must surface immediately."""
    assert is_transient_provider_error(exc) is False


def test_transient_provider_error_joins_the_retry_contract():
    """The tuple is what `autoretry_for=` and every per-subsystem `except` clause key on.
    Membership IS the fix — without it the class is just another Exception."""
    assert isinstance(TransientProviderError("x"), TRANSIENT_INFRA_ERRORS)


@pytest.mark.parametrize("method", ["rerank", "embed"])
def test_the_retry_budget_actually_reaches_the_provider(monkeypatch, method):
    """THE BUDGET IS COUNTED AT THE PROVIDER, not read off the kwargs.

    litellm's `num_retries` is ignored on exactly these two paths, so a test that asserts what we
    PASS would have gone on passing while the reranker got one attempt against a setting that said
    three. That is precisely how this went unnoticed until a session was cancelled."""
    seen = _stub_litellm(monkeypatch, openai.APITimeoutError(request=_REQ))
    client = LiteLLMClient(_settings(monkeypatch, TSG_LLM_MAX_RETRIES="2"))
    with pytest.raises(TransientProviderError):
        client.rerank("q", ["a"]) if method == "rerank" else client.embed(["a"])
    assert seen["calls"] == 3, f"{method}: llm_max_retries=2 must mean 3 attempts at the provider"


@pytest.mark.parametrize("method", ["rerank", "embed"])
def test_a_permanent_error_does_not_burn_the_budget(monkeypatch, method):
    """A bad key must report itself on the first attempt, not after the full retry budget."""
    seen = _stub_litellm(monkeypatch, _status(openai.AuthenticationError, 401))
    client = LiteLLMClient(_settings(monkeypatch, TSG_LLM_MAX_RETRIES="2"))
    with pytest.raises(openai.AuthenticationError):
        client.rerank("q", ["a"]) if method == "rerank" else client.embed(["a"])
    assert seen["calls"] == 1, f"{method}: a 401 must not be retried"


def test_rerank_429_still_becomes_slot_unavailable(monkeypatch):
    """The pre-existing 429 mapping must survive the widening: it carries its own Retry-After
    semantics through errors.py, which TransientProviderError does not."""
    _stub_litellm(monkeypatch, _status(openai.RateLimitError, 429))
    with pytest.raises(LLMSlotUnavailable):
        LiteLLMClient(_settings(monkeypatch)).rerank("q", ["a"])
