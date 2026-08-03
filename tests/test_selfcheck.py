"""Operational self-check task (app/pipeline/selfcheck.py)."""
from __future__ import annotations

import httpx
from sqlalchemy import insert

from app.core.config import get_settings
from app.db import models as m
from app.pipeline.selfcheck import (
    check_active_sessions,
    check_ctm_scan_category_names,
    check_dead_threat_rules,
    check_litellm_proxy_health,
    check_llm_slots,
    run_self_checks,
)
from tests.test_slice import _seed_session


def _insert_rule(db, rule_id, rule_key, *, is_active=True, is_deleted=False, rule_value=None):
    db.execute(insert(m.Config_Threat_Rule).values(
        ThreatRuleID=rule_id, RuleType="tech_gate", ThreatTypeID=10, RuleKey=rule_key,
        RuleValue=rule_value, Metadata=None, IsActive=is_active, IsDeleted=is_deleted))


def test_check_dead_threat_rules_quiet_when_all_keys_are_mapped(db):
    _insert_rule(db, 1, "asset_type")
    assert check_dead_threat_rules(db) is None


def test_check_dead_threat_rules_fires_for_an_unmapped_key(db):
    _insert_rule(db, 1, "internet_facing")  # removed from _RULE_KEY_FIELDS on 2026-07-12
    assert check_dead_threat_rules(db) == "dead_threat_rules"


def test_check_dead_threat_rules_ignores_inactive_and_deleted_rows(db):
    _insert_rule(db, 1, "internet_facing", is_active=False)
    _insert_rule(db, 2, "exposure_level", is_deleted=True)
    assert check_dead_threat_rules(db) is None


def test_run_self_checks_reports_dead_threat_rules(db):
    _insert_rule(db, 1, "internet_facing")
    _seed_context_fields(db)  # keep the empty-context-group alarm out of this test's subject
    assert run_self_checks(db) == ["dead_threat_rules"]


# --- check_ctm_scan_category_names: RuleValue vs the real platform table, both read live ---
def test_check_ctm_scan_category_names_quiet_when_the_real_table_covers_every_expected_value(db):
    # db fixture already seeds ctm_scan_category id=1 "Physical infrastructure" — match it,
    # case-insensitively, proving the compare isn't a brittle exact-case match either.
    _insert_rule(db, 1, "asset_type", rule_value="physical infrastructure")
    assert check_ctm_scan_category_names(db) is None


def test_check_ctm_scan_category_names_fires_when_a_rule_value_has_no_real_match(db):
    _insert_rule(db, 1, "asset_type", rule_value="Operational Technology (OT)")
    assert check_ctm_scan_category_names(db) == "ctm_scan_category_asset_type_mismatch"


def test_check_ctm_scan_category_names_ignores_inactive_deleted_and_null_rule_value(db):
    _insert_rule(db, 1, "asset_type", rule_value="Operational Technology (OT)", is_active=False)
    _insert_rule(db, 2, "asset_type", rule_value="Information Technology (IT)", is_deleted=True)
    _insert_rule(db, 3, "asset_type", rule_value=None)
    assert check_ctm_scan_category_names(db) is None


def test_check_ctm_scan_category_names_ignores_blank_rule_value_match_empty_sentinel(db):
    # [REVIEW-FIX] "" is a real curator value (scoping.py: "match subsystems with a blank
    # asset_type"), not a category name to look up — must never be treated as "missing".
    _insert_rule(db, 1, "asset_type", rule_value="")
    assert check_ctm_scan_category_names(db) is None


def test_check_ctm_scan_category_names_tolerates_whitespace_like_the_runtime_match_does(db):
    # [REVIEW-FIX] scoping._matches strips both sides before comparing — this check must mirror
    # that exactly, or it flags false-positive mismatches for rules that work fine at runtime.
    db.execute(insert(m.ctm_scan_category).values(id=2, name="Operational Technology (OT) "))  # trailing space
    _insert_rule(db, 1, "asset_type", rule_value="Operational Technology (OT)")  # no trailing space
    assert check_ctm_scan_category_names(db) is None


# --- check_dead_context_fields: Context_Field_Config rows under an unrecognized ContextGroup ---
def _insert_field(db, group, field_name, *, is_active=True, is_deleted=False):
    db.execute(insert(m.Context_Field_Config).values(
        ContextGroup=group, FieldName=field_name, IsActive=is_active, IsDeleted=is_deleted))


def test_check_dead_context_fields_quiet_for_any_field_under_a_valid_group(db):
    from app.pipeline.selfcheck import check_dead_context_fields

    _insert_field(db, "asset", "critical_service")
    _insert_field(db, "subsystem", "vendor_name")
    # No hardcoded ceiling any more: an unknown FieldName is a curator's business, not drift.
    _insert_field(db, "asset", "critical_srevice")  # typo — inert, not reported
    assert check_dead_context_fields(db) is None


def test_check_dead_context_fields_fires_for_an_unrecognized_context_group(db):
    from app.pipeline.selfcheck import check_dead_context_fields

    _insert_field(db, "Asset", "critical_service")  # wrong case — not a real ContextGroup
    assert check_dead_context_fields(db) == "dead_context_fields"


def test_check_dead_context_fields_ignores_inactive_and_deleted_rows(db):
    from app.pipeline.selfcheck import check_dead_context_fields

    # Active rows in both real groups keep the empty-group alarm quiet; the bad-group rows are
    # inactive/deleted and must not count as drift.
    _insert_field(db, "asset", "critical_service")
    _insert_field(db, "subsystem", "vendor_name")
    _insert_field(db, "Asset", "critical_service", is_active=False)
    _insert_field(db, "SUBSYSTEM", "vendor_name", is_deleted=True)
    assert check_dead_context_fields(db) is None


def test_check_dead_context_fields_fires_when_a_group_has_no_active_rows(db):
    # prompts.py fails closed — a group with no active rows sends nothing to the model — so an
    # unseeded table or an all-off group must alarm instead of degrading quality silently.
    from app.pipeline.selfcheck import check_dead_context_fields

    assert check_dead_context_fields(db) == "empty_context_group"  # unseeded: both groups empty
    _insert_field(db, "asset", "critical_service")
    assert check_dead_context_fields(db) == "empty_context_group"  # subsystem still empty
    _insert_field(db, "subsystem", "vendor_name")
    assert check_dead_context_fields(db) is None  # both groups populated


def test_check_ctm_scan_category_names_quiet_when_no_asset_type_rules_exist(db):
    # nothing to check against yet — must not fire just because the table happens to be empty.
    assert check_ctm_scan_category_names(db) is None


def test_check_active_sessions_below_ceiling_is_quiet(db):
    _seed_session(db, asset_id=100)
    assert check_active_sessions(db) is None  # default ceiling (100) — nowhere near the warn ratio


def test_check_active_sessions_fires_near_ceiling(db, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "max_active_sessions", 1)
    monkeypatch.setattr(s, "active_sessions_warn_ratio", 0.9)
    _seed_session(db, asset_id=100)
    assert check_active_sessions(db) == "active_sessions_high"


def test_check_llm_slots_quiet_when_disabled(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_concurrent_llm_calls", 0)
    assert check_llm_slots() is None  # ceiling is 0 * ratio = 0, but nobody should call this when disabled anyway


def test_check_llm_slots_quiet_when_comfortable(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_concurrent_llm_calls", 10)
    monkeypatch.setattr(get_settings(), "llm_slots_warn_ratio", 0.8)
    monkeypatch.setattr("app.pipeline.llm.current_llm_slot_count", lambda: 1)
    assert check_llm_slots() is None


def test_check_llm_slots_fires_near_ceiling(monkeypatch):
    monkeypatch.setattr(get_settings(), "max_concurrent_llm_calls", 2)
    monkeypatch.setattr(get_settings(), "llm_slots_warn_ratio", 0.5)
    monkeypatch.setattr("app.pipeline.llm.current_llm_slot_count", lambda: 1)  # 1 >= 2*0.5
    assert check_llm_slots() == "llm_slots_high"


def test_run_self_checks_includes_llm_slots_only_when_enabled(db, monkeypatch):
    assert "llm_slots" not in [c for c in run_self_checks(db)]  # disabled by default → not even attempted
    monkeypatch.setattr(get_settings(), "max_concurrent_llm_calls", 1)
    monkeypatch.setattr(get_settings(), "llm_slots_warn_ratio", 0.1)
    monkeypatch.setattr("app.pipeline.llm.current_llm_slot_count", lambda: 1)
    _seed_context_fields(db)  # keep the empty-context-group alarm out of this test's subject
    assert run_self_checks(db) == ["llm_slots_high"]


class _FakeHttpResponse:
    def raise_for_status(self):
        pass


class _FakeHttpClient:
    """Stands in for httpx.Client(transport=...) — a context manager whose .get() either
    returns a canned response or raises a canned exception, so tests don't need a real
    HTTPTransport/retry loop to exercise the code around it."""
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


def test_check_litellm_proxy_health_quiet_when_reachable(monkeypatch):
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeHttpClient(_FakeHttpResponse()))
    assert check_litellm_proxy_health() is None


def test_check_litellm_proxy_health_fires_when_unreachable(monkeypatch):
    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _FakeHttpClient(httpx.ConnectError("connection refused")))
    assert check_litellm_proxy_health() == "litellm_proxy_unreachable"


def test_check_litellm_proxy_health_applies_proxy_bypass_before_its_own_network_call(monkeypatch):
    # [REVIEW-FIX] this check's httpx.Client() call never goes through get_llm() — must apply
    # the NO_PROXY fix (app.pipeline.llm._ensure_litellm_proxy_bypassed) itself rather than
    # assume some other code path in this process already ran it.
    import os

    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setattr(get_settings(), "llm_provider", "litellm_proxy")
    monkeypatch.setattr(get_settings(), "litellm_base_url", "https://llmapi.example.com")
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeHttpClient(_FakeHttpResponse()))
    check_litellm_proxy_health()
    assert "llmapi.example.com" in os.environ["NO_PROXY"]


class _FakeJsonResponse:
    def raise_for_status(self):
        pass

    def __init__(self, body):
        self._body = body

    def json(self):
        return self._body


class _UrlRoutingFakeClient:
    """Routes .get(url) to a canned result (or raises it) based on which endpoint path
    substring appears in the URL — check_litellm_proxy_health makes up to TWO sequential
    httpx.Client() calls (/health/readiness, then /health/readiness/details on failure).
    Dict insertion order matters: the more specific "…/details" key must come first, since
    it's also a substring match for the shorter "/health/readiness" URL otherwise."""
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
        raise AssertionError(f"unexpected URL: {url}")


def test_check_litellm_proxy_health_fetches_details_on_failure_without_changing_the_result(monkeypatch):
    # [REVIEW-FIX] richer diagnostics on top of the plain pass/fail — must not change WHETHER
    # the check fires, only add context to the log line when it does.
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _UrlRoutingFakeClient({
        "/health/readiness/details": _FakeJsonResponse({"db": "down"}),
        "/health/readiness": httpx.ConnectError("connection refused"),
    }))
    assert check_litellm_proxy_health() == "litellm_proxy_unreachable"


def test_check_litellm_proxy_health_details_failure_does_not_change_the_result(monkeypatch):
    # the details call is itself best-effort — its own failure must never become a second
    # failure mode or affect the check's return value.
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _UrlRoutingFakeClient({
        "/health/readiness/details": httpx.ConnectError("also down"),
        "/health/readiness": httpx.ConnectError("connection refused"),
    }))
    assert check_litellm_proxy_health() == "litellm_proxy_unreachable"


def test_check_litellm_proxy_health_never_fetches_details_when_healthy(monkeypatch):
    # the details call is strictly inside the failure path — must not fire on a healthy check.
    # Tracks calls directly rather than raising-if-called: check_litellm_proxy_health's own
    # try/except Exception around the details call would silently swallow a raised sentinel,
    # making that style of assertion a no-op here.
    details_calls: list[str] = []

    class _TrackingClient(_UrlRoutingFakeClient):
        def get(self, url, **kwargs):
            if "/health/readiness/details" in url:
                details_calls.append(url)
            return super().get(url, **kwargs)

    monkeypatch.setattr(httpx, "Client",
                        lambda *a, **k: _TrackingClient({"/health/readiness": _FakeHttpResponse()}))
    assert check_litellm_proxy_health() is None
    assert details_calls == []


def test_run_self_checks_includes_litellm_proxy_health_only_when_a_provider_uses_it(db, monkeypatch):
    # defaults: llm_provider=azure_openai, embedding/reranker_provider=local — none route
    # through the proxy, so this check must not even be attempted (no network call).
    assert "litellm_proxy_health" not in run_self_checks(db)
    monkeypatch.setattr(get_settings(), "llm_provider", "litellm_proxy")
    monkeypatch.setattr(httpx, "Client", lambda *a, **k: _FakeHttpClient(_FakeHttpResponse()))
    _seed_context_fields(db)  # keep the empty-context-group alarm out of this test's subject
    assert run_self_checks(db) == []  # check ran (provider now routes through the proxy) but stayed quiet


def _seed_context_fields(db):
    """Both groups populated, so the empty-context-group alarm stays quiet in tests whose
    subject is a different check."""
    _insert_field(db, "asset", "critical_service")
    _insert_field(db, "subsystem", "vendor_name")


def test_run_self_checks_skips_mssql_only_checks_on_sqlite(db):
    # engine fixture runs on SQLite; the 3 tempdb/pool checks must not even attempt to
    # run there (they'd error against a database with no sys.dm_tran_* views).
    _seed_context_fields(db)
    assert run_self_checks(db) == []


def test_run_self_checks_reports_active_sessions_high_on_sqlite(db, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_active_sessions", 1)
    _seed_session(db, asset_id=100)
    _seed_context_fields(db)
    assert run_self_checks(db) == ["active_sessions_high"]


def test_run_self_checks_isolates_one_check_failure_from_the_rest(db, monkeypatch):
    # A broken check must be logged and skipped, never take down the whole pass.
    monkeypatch.setattr(
        "app.pipeline.selfcheck.check_active_sessions",
        lambda sess: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    _seed_context_fields(db)
    assert run_self_checks(db) == []  # the broken check contributes nothing; no exception propagates


def test_self_check_task_registered_in_beat_schedule():
    from app.pipeline.celery_app import celery_app

    schedule = celery_app.conf.beat_schedule
    assert "operational-self-check" in schedule
    assert schedule["operational-self-check"]["task"] == "tsg.self_check"


def test_self_check_task_roundtrips_through_db_session(engine):
    from app.pipeline.celery_app import self_check_task

    result = self_check_task()
    assert isinstance(result, list)
