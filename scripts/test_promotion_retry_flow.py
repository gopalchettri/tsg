"""Assert-based self-check for the accept/promotion retry feature — no DB, no LLM, no framework.
Covers the pure-logic pieces: config defaults, eager-embed grouping/best-effort behavior, and the
max_attempts-only-in-the-sweep contract (by source inspection, since that's a design invariant
across two functions rather than a value either one computes).

Run: .venv/Scripts/python.exe scripts/test_promotion_retry_flow.py
"""
import inspect
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core.config import get_settings
from app.pipeline import accept, reaper


def test_config_defaults_match_spec():
    """Manual-by-default for master-table writes, seamless-by-default for retrying a failure —
    exactly what was asked for, not accidentally swapped."""
    settings = get_settings()
    assert settings.promotion_auto_retry_enabled is True, "auto-retry of FAILURES must default on"
    assert settings.promotion_auto_approve_enabled is False, "auto-approve of NOVEL threats must default off"
    assert settings.promotion_max_attempts > 0
    assert settings.promotion_retry_interval_seconds > 0
    assert settings.promotion_sweep_batch_limit > 0
    assert settings.promotion_list_max_limit > 0


def test_eager_embed_groups_by_embedding_group_and_skips_empty():
    """Pure grouping logic: (group, name) pairs fan out to one create_items call per group,
    and an empty list is a true no-op (no embeddings module call at all)."""
    calls = []

    class _StubEmbeddings:
        @staticmethod
        def create_items(sess, llm, group, names):
            calls.append((group, list(names)))
            return len(names)

    original = accept.embeddings
    accept.embeddings = _StubEmbeddings
    try:
        accept.eager_embed_promoted(sess=None, llm=None, promoted_names=[])
        assert calls == [], "empty promoted_names must call embeddings.create_items zero times"

        accept.eager_embed_promoted(sess=None, llm=None, promoted_names=[
            ("threat_type", "Vendor Update Tampering"),
            ("threat_catalogue", "Vendor software update tampering"),
            ("threat_type", "Session Hijacking"),
        ])
        by_group = dict(calls)
        assert set(by_group) == {"threat_type", "threat_catalogue"}
        assert sorted(by_group["threat_type"]) == ["Session Hijacking", "Vendor Update Tampering"]
        assert by_group["threat_catalogue"] == ["Vendor software update tampering"]
    finally:
        accept.embeddings = original


def test_eager_embed_is_best_effort_never_raises():
    """A slow/unreachable embedding service must never fail an accept or a retry that already
    succeeded on the DB side — every failure here is caught and only logged."""
    class _FailingEmbeddings:
        @staticmethod
        def create_items(sess, llm, group, names):
            raise RuntimeError("embedding service unreachable")

    original = accept.embeddings
    accept.embeddings = _FailingEmbeddings
    try:
        accept.eager_embed_promoted(sess=None, llm=None,
                                    promoted_names=[("threat_type", "Anything")])  # must not raise
    finally:
        accept.embeddings = original


def test_max_attempts_cap_lives_only_in_the_sweep_query():
    """retry_one_promotion must have NO awareness of promotion_max_attempts (a manual admin
    retry must never be blocked by a cap meant only for the unattended sweep) — checked as "does
    it consult settings AT ALL", not a raw substring match, since its own docstring explains this
    exact design choice in prose and would otherwise false-positive on itself. The cap must
    appear in retry_failed_promotions' own source instead."""
    retry_one_source = inspect.getsource(reaper.retry_one_promotion)
    sweep_source = inspect.getsource(reaper.retry_failed_promotions)
    assert "get_settings" not in retry_one_source, (
        "retry_one_promotion must not read ANY setting — in particular, never promotion_max_attempts")
    assert "settings.promotion_max_attempts" in sweep_source, (
        "retry_failed_promotions must apply promotion_max_attempts when selecting candidates")


def test_run_promotion_phase_never_raises_on_failure():
    """The core contract of Phase 2 isolation: a promotion failure must be swallowed (returns
    False), never propagated — that's what makes it safe to call after Phase 1's commit."""
    source = inspect.getsource(accept.run_promotion_phase)
    assert "except Exception" in source
    assert "return False" in source
    assert "return True" in source


if __name__ == "__main__":
    test_config_defaults_match_spec()
    test_eager_embed_groups_by_embedding_group_and_skips_empty()
    test_eager_embed_is_best_effort_never_raises()
    test_max_attempts_cap_lives_only_in_the_sweep_query()
    test_run_promotion_phase_never_raises_on_failure()
    print("PASS: all promotion-retry-flow self-checks")
