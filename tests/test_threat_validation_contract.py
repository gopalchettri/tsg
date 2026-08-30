"""threat_validation's JSON contract — the object shape, the retry, and the fail-open floor.

WHY THIS FILE EXISTS. A real production run lost the verdicts for all 20 candidates in a batch
because azure/gpt-5-mini emitted `{"index:3", ...}` — a transposed quote and colon 499 chars into
an otherwise well-formed 4,882-char reply. It was not truncation, and nothing retried it.

The stage was unprotected for a structural reason: llm._chat_kwargs only requests provider-side
JSON mode when the caller declares `expected_type is dict`, because that mode forces a top-level
object. While this stage parsed a bare ARRAY it opted itself out of the one mechanism that makes
malformed JSON impossible. So the contract moved to {"verdicts": [...]} — and these tests pin
BOTH halves, because either one silently reverting restores the original bug.

No LLM and no database: _validate_candidates is exercised with a stubbed _ask_ai, the same way
the rest of the pipeline suite fakes its model calls.
"""
from __future__ import annotations

import pytest

from app.pipeline import prompts, tasks


def _candidates(n: int = 3) -> list[dict]:
    return [{"catalogue_id": 100 + i, "threat_name": f"threat {i}", "type_name": "t",
             "categories": ["Tampering"]} for i in range(n)]


def _session() -> dict:
    return {"SessionID": "sess-1", "AssetName": "SGI", "TenantID": "t", "EntityID": "78",
            "UserID": "dewa"}


class _FakeSession:
    def rollback(self):  # _validate_candidates rolls back a failed batch before retrying
        pass


def _run(monkeypatch, replies):
    """Drive _validate_candidates with a scripted sequence of _ask_ai outcomes.

    Each entry is either an Exception (raised) or the parsed value to return.
    """
    calls = {"n": 0}

    def fake_ask(sess, llm, messages, **kw):
        i = calls["n"]
        calls["n"] += 1
        assert kw.get("expected_type") is dict, (
            "threat_validation must declare expected_type=dict — that is what turns on "
            "provider-side JSON mode (llm._chat_kwargs); reverting it to list silently "
            "reopens the malformed-JSON hole this stage was fixed for")
        out = replies[min(i, len(replies) - 1)]
        if isinstance(out, Exception):
            raise out
        return out, None

    monkeypatch.setattr(tasks, "_ask_ai", fake_ask)
    kept, summary = tasks._validate_candidates(
        _FakeSession(), object(), _session(), [], {}, _candidates(), 0, 1, "task-1")
    return kept, summary, calls["n"]


def test_prompt_asks_for_an_object_and_says_json():
    """Two requirements in one contract, both load-bearing.

    The object shape is what lets expected_type be dict. The literal word "json" is what keeps
    Azure from rejecting a json_object request with 400 — a cap that lives in the provider, not
    in our code, so only the prompt text can satisfy it.
    """
    messages = prompts.threat_validation_prompt("SGI", {}, [], _candidates())
    system = messages[0]["content"]
    assert '"verdicts"' in system, "the reply must be an OBJECT keyed by verdicts, not a bare array"
    assert "json" in system.lower(), (
        "Azure rejects response_format=json_object unless 'json' appears in the messages")


def test_verdicts_are_read_from_the_object(monkeypatch):
    kept, summary, n = _run(monkeypatch, [{"verdicts": [
        {"index": 1, "verdict": "RELEVANT", "justification": "grounded"},
        {"index": 2, "verdict": "NOT_RELEVANT", "justification": "absent tech"},
        {"index": 3, "verdict": "POTENTIALLY_RELEVANT", "justification": "unclear"},
    ]}])
    assert n == 1, "a good reply must not be retried"
    assert summary["dropped"] and summary["dropped"][0]["catalogue_id"] == 101
    assert [c["validator_verdict"] for c in kept] == ["RELEVANT", "POTENTIALLY_RELEVANT"]
    assert summary["degraded_batches"] == 0


def test_a_malformed_reply_is_retried_once_and_can_succeed(monkeypatch):
    """The exact production failure: one bad reply, then a good one. Verdicts must survive."""
    good = {"verdicts": [{"index": 1, "verdict": "RELEVANT", "justification": "ok"},
                         {"index": 2, "verdict": "RELEVANT", "justification": "ok"},
                         {"index": 3, "verdict": "RELEVANT", "justification": "ok"}]}
    kept, summary, n = _run(monkeypatch, [ValueError("Expecting ':' delimiter"), good])
    assert n == 2, "a malformed reply must be re-asked exactly once"
    assert summary["degraded_batches"] == 0, "a successful retry is not a degraded batch"
    assert all(c["validator_verdict"] == "RELEVANT" for c in kept)


def test_two_malformed_replies_fail_open_and_keep_every_candidate(monkeypatch):
    """The floor: a validator outage must WEAKEN ranking, never shrink coverage."""
    boom = ValueError("Expecting ':' delimiter")
    kept, summary, n = _run(monkeypatch, [boom, boom])
    assert n == 2, "retry is bounded at one extra attempt, not unbounded"
    assert summary["degraded_batches"] == 1
    assert len(kept) == 3, "fail-open must keep every candidate"
    assert all(c["validator_verdict"] == "POTENTIALLY_RELEVANT" for c in kept)
    assert summary["dropped"] == [], "a failed validator must never DROP a candidate"


def test_an_object_without_the_verdicts_key_fails_open_rather_than_crashing(monkeypatch):
    """JSON mode guarantees valid JSON, NOT the right keys. A well-formed object with the wrong
    shape must land on the same fail-open floor instead of raising."""
    kept, summary, _n = _run(monkeypatch, [{"results": []}])
    assert summary["degraded_batches"] == 1
    assert len(kept) == 3
    assert all(c["validator_verdict"] == "POTENTIALLY_RELEVANT" for c in kept)


@pytest.mark.parametrize("bad", [{"verdicts": "not-a-list"}, {"verdicts": None}])
def test_verdicts_that_are_not_a_list_fail_open(monkeypatch, bad):
    kept, summary, _n = _run(monkeypatch, [bad])
    assert summary["degraded_batches"] == 1
    assert len(kept) == 3
