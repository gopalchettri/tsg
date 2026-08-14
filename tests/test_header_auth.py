"""Header-model API authentication (app/api/deps.get_principal).

Self-contained: an in-memory SQLite DB stands in for the real one, seeded with an API_Client
row and a couple of user_scope_assignment rows, so the whole auth path runs without MSSQL.
"""
from __future__ import annotations

import hashlib
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.api.deps as deps
from app.core.security import AuthError
from app.db import models as m
from app.db.dal import EntityForbidden

SECRET = "shield-super-secret"                      # the plaintext key Shield would send
KEY_HASH = hashlib.sha256(SECRET.encode()).hexdigest()


class _Settings:
    """Minimal stand-in for get_settings() — get_principal reads verify_membership and, for the
    tenant fallback, tenant_id."""
    def __init__(self, verify_membership: bool):
        self.verify_membership = verify_membership
        self.tenant_id = "DESC"


@pytest.fixture
def db(monkeypatch):
    """SQLite with the two auth tables, seeded, wired into deps via monkeypatch."""
    engine = create_engine("sqlite://")
    m.API_Client.__table__.create(engine)
    m.user_scope_assignment.__table__.create(engine)
    Session = sessionmaker(bind=engine, future=True)
    with Session() as s:
        s.add(m.API_Client(ClientID="shield", KeyHash=KEY_HASH, Name="Shield",
                           Active=True, CreatedAt=datetime.now(timezone.utc)))
        # user 1138 -> entity 86 (scope_type 4 = Entity), active
        s.add(m.user_scope_assignment(id=1, user_id=1138, scope_type=4, ref_id=86, is_active=True))
        # user 1152 -> ref 1720 but scope_type 2 = Sub-Sector (must NOT count as entity access)
        s.add(m.user_scope_assignment(id=2, user_id=1152, scope_type=2, ref_id=1720, is_active=True))
        # user 1138 -> entity 999 but INACTIVE (must NOT count)
        s.add(m.user_scope_assignment(id=3, user_id=1138, scope_type=4, ref_id=999, is_active=False))
        s.commit()

    @contextmanager
    def fake_session():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    monkeypatch.setattr(deps, "db_session", fake_session)
    return Session


def _membership(monkeypatch, on: bool):
    monkeypatch.setattr(deps, "get_settings", lambda: _Settings(on))


# --- API key (authentication) ---

def test_absent_key_is_401(db, monkeypatch):
    _membership(monkeypatch, False)
    with pytest.raises(AuthError):
        deps.get_principal(x_api_key="", x_user_id="1138", x_entity_id="86")


def test_wrong_key_is_401(db, monkeypatch):
    _membership(monkeypatch, False)
    with pytest.raises(AuthError):
        deps.get_principal(x_api_key="not-the-key", x_user_id="1138", x_entity_id="86")


def test_missing_identity_headers_is_401(db, monkeypatch):
    _membership(monkeypatch, False)
    with pytest.raises(AuthError):
        deps.get_principal(x_api_key=SECRET, x_user_id="", x_entity_id="86")


# --- membership OFF (default): key alone is enough, identity taken on trust ---

def test_valid_key_membership_off_passes(db, monkeypatch):
    _membership(monkeypatch, False)
    p = deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="86", x_tenant_id="DESC")
    assert p.entities == {"86"}
    assert p.user_id == "1138"
    assert p.client_id == "shield"
    assert p.tenant_id == "DESC"


def test_tenant_from_header_is_used(db, monkeypatch):
    _membership(monkeypatch, False)
    p = deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="86", x_tenant_id="ACME")
    assert p.tenant_id == "ACME"


def test_missing_tenant_header_is_401(db, monkeypatch):
    # X-Tenant-Id is required, like the user/entity headers.
    _membership(monkeypatch, False)
    with pytest.raises(AuthError):
        deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="86", x_tenant_id="")


def test_membership_off_does_not_verify_pair(db, monkeypatch):
    # entity 4242 is not assigned to anyone — with the check off it still passes.
    _membership(monkeypatch, False)
    p = deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="4242", x_tenant_id="DESC")
    assert p.entities == {"4242"}


# --- membership ON: (user, entity) verified against user_scope_assignment ---

def test_membership_on_real_pair_passes(db, monkeypatch):
    _membership(monkeypatch, True)
    p = deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="86", x_tenant_id="DESC")
    assert p.entities == {"86"}


def test_membership_on_unknown_pair_is_403(db, monkeypatch):
    _membership(monkeypatch, True)
    with pytest.raises(EntityForbidden):
        deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="4242", x_tenant_id="DESC")


def test_membership_on_wrong_scope_level_is_403(db, monkeypatch):
    # user 1152 has ref_id 1720 but at Sub-Sector level (scope_type 2), not Entity.
    _membership(monkeypatch, True)
    with pytest.raises(EntityForbidden):
        deps.get_principal(x_api_key=SECRET, x_user_id="1152", x_entity_id="1720", x_tenant_id="DESC")


def test_membership_on_inactive_assignment_is_403(db, monkeypatch):
    # user 1138 -> entity 999 exists but is_active = False.
    _membership(monkeypatch, True)
    with pytest.raises(EntityForbidden):
        deps.get_principal(x_api_key=SECRET, x_user_id="1138", x_entity_id="999", x_tenant_id="DESC")


# --- boot-path guards (the part the request-path e2e can't exercise) ---

def test_retired_auth_dev_mode_fails_boot(monkeypatch):
    """A stale AUTH_DEV_MODE must fail the boot, not silently do nothing."""
    from app.core.config import get_settings
    monkeypatch.setenv("AUTH_DEV_MODE", "true")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError):
            get_settings()
    finally:
        get_settings.cache_clear()   # drop the poisoned cache for later tests


def _staging_settings():
    return type("S", (), {"app_env": "staging", "verify_membership": False})()


def test_staging_without_active_api_client_fails_boot(monkeypatch):
    import app.db.invariants as inv
    eng = create_engine("sqlite://")
    m.API_Client.__table__.create(eng)                 # empty — no active key
    monkeypatch.setattr(inv, "get_settings", _staging_settings)
    with pytest.raises(inv.StartupInvariantError):
        inv._assert_api_client_configured(eng)


def test_staging_with_active_api_client_passes(monkeypatch):
    import app.db.invariants as inv
    from sqlalchemy.orm import sessionmaker
    eng = create_engine("sqlite://")
    m.API_Client.__table__.create(eng)
    with sessionmaker(bind=eng)() as s:
        s.add(m.API_Client(ClientID="x", KeyHash="h", Name="n",
                           Active=True, CreatedAt=datetime.now(timezone.utc)))
        s.commit()
    monkeypatch.setattr(inv, "get_settings", _staging_settings)
    inv._assert_api_client_configured(eng)              # must not raise


def test_posture_warns_when_membership_off_but_does_not_raise():
    from app.core.config import assert_security_posture
    assert_security_posture(_staging_settings())        # logs a warning; must not raise


# --- item 21: SSE graceful-shutdown startup assertion ---

def test_sse_shutdown_assertion_passes_when_uvicorn_server_is_live():
    """The live-signal-handler shape sse_starlette's own _get_uvicorn_server() looks for: a bound
    method whose __self__ has a `should_exit` attribute."""
    from app.core.config import assert_sse_graceful_shutdown_wired

    class _FakeUvicornServer:
        should_exit = False
        def handle_exit(self, sig, frame): ...

    server = _FakeUvicornServer()
    assert_sse_graceful_shutdown_wired(get_signal_handler=lambda sig: server.handle_exit)  # must not raise


def test_sse_shutdown_assertion_fails_when_no_uvicorn_server_is_wired():
    """Not "uvicorn is importable" (always true, hard dependency) — the DEFAULT handler (what a
    non-uvicorn ASGI server, or a worker class that never installs it, leaves in place) must fail
    loudly, not pass by accident."""
    import signal as _signal
    from app.core.config import assert_sse_graceful_shutdown_wired

    with pytest.raises(RuntimeError):
        assert_sse_graceful_shutdown_wired(get_signal_handler=lambda sig: _signal.SIG_DFL)

    class _NotAServer:
        def handler(self, sig, frame): ...
    with pytest.raises(RuntimeError):
        # a bound method whose __self__ has no should_exit -- e.g. some other library's own
        # SIGTERM handler -- must not be mistaken for uvicorn's.
        assert_sse_graceful_shutdown_wired(get_signal_handler=lambda sig: _NotAServer().handler)


# --- per-module key isolation ---

def test_key_is_scoped_to_its_module(db):
    """A key authenticates only for its own Module — a 'chatbot' key can't open TSG, and TSG's
    own module lookup ignores it."""
    from app.db import dal
    cb_hash = hashlib.sha256(b"chatbot-secret").hexdigest()
    with db() as s:
        # the fixture's 'shield' key defaults to Module='tsg'
        assert dal.api_client_id_for_key_hash(s, KEY_HASH, "tsg") == "shield"
        assert dal.api_client_id_for_key_hash(s, KEY_HASH, "chatbot") is None
        # a chatbot-scoped key: valid for 'chatbot', rejected for 'tsg'
        s.add(m.API_Client(ClientID="cb", KeyHash=cb_hash, Name="Chatbot",
                           Module="chatbot", Active=True, CreatedAt=datetime.now(timezone.utc)))
        s.commit()
        assert dal.api_client_id_for_key_hash(s, cb_hash, "chatbot") == "cb"
        assert dal.api_client_id_for_key_hash(s, cb_hash, "tsg") is None


# --- module identity is a deployment setting, not a source literal ---

def test_api_module_comes_from_settings():
    """The module is configurable (TSG_API_MODULE), so the same codebase runs as 'chatbot' etc.
    without a code edit. Fails if dal.API_MODULE is reverted to a hard-coded string."""
    from pydantic import ValidationError

    from app.core.config import Settings, get_settings
    from app.db import dal
    assert dal.API_MODULE == get_settings().api_module       # sourced from config, not a literal
    assert Settings(api_module="chatbot").api_module == "chatbot"
    with pytest.raises(ValidationError):                     # blank module rejected (silent-401 guard)
        Settings(api_module="")


# --- admin principal: get_principal minus the entity (app/api/deps.get_admin_principal) ---

def test_admin_principal_needs_no_entity_header(db):
    """The point of the whole thing: an admin caller authenticates WITHOUT X-Entity-Id.

    `entities` comes back empty, so require_entity denies — an admin principal can never be
    mistaken for an entity-scoped one."""
    p = deps.get_admin_principal(x_api_key=SECRET, x_user_id="1138", x_tenant_id="DESC")
    assert p.user_id == "1138"
    assert p.tenant_id == "DESC"
    assert p.client_id == "shield"
    assert p.entities == set()
    with pytest.raises(EntityForbidden):
        p.require_entity("86")


def test_admin_principal_still_requires_key_user_and_tenant(db):
    """Dropping the entity must not drop anything else: the API key still authenticates, and
    X-User-Id still gates (it is what lands in CreatedBy/UpdatedBy)."""
    for kwargs in (
        {"x_api_key": "", "x_user_id": "1138", "x_tenant_id": "DESC"},             # no key
        {"x_api_key": "not-the-key", "x_user_id": "1138", "x_tenant_id": "DESC"},  # wrong key
        {"x_api_key": SECRET, "x_user_id": "", "x_tenant_id": "DESC"},             # no audit identity
        {"x_api_key": SECRET, "x_user_id": "1138", "x_tenant_id": ""},             # no tenant
    ):
        with pytest.raises(AuthError):
            deps.get_admin_principal(**kwargs)


def test_entity_header_requirement_is_admin_only():
    """The scope guard for the 50-site dependency swap, checked BOTH ways.

    Admin routes must no longer pull in get_principal (that is what required X-Entity-Id), and
    the entity-scoped routers must still pull it in — a swap that leaked into sessions/treatment
    would silently remove an IDOR guard. Reuses route_audit's own dependency walker so this sees
    router-level dependencies too, not just per-handler ones."""
    from app.api import (admin, api_clients, control_library_crud, sessions, threat_intel,
                         threat_library_crud, threat_library_import, treatment)
    from app.api.route_audit import _all_dependency_calls

    admin_routers = [admin.router, admin.promotions_router, admin.candidates_router,
                     api_clients.router, threat_library_crud.router, control_library_crud.router,
                     threat_intel.router, threat_library_import.router]
    for router in admin_routers:
        for route in router.routes:
            calls = _all_dependency_calls(route.dependant)
            assert deps.require_admin in calls, f"{route.path} lost its admin gate"
            assert deps.get_principal not in calls, f"{route.path} still demands X-Entity-Id"

    for router in (sessions.router, treatment.router):
        for route in router.routes:
            calls = _all_dependency_calls(route.dependant)
            assert deps.get_principal in calls, f"{route.path} lost its entity scoping"
            assert deps.get_admin_principal not in calls, f"{route.path} got the admin principal"
