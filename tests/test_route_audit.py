"""[R2 remainder] app/api/route_audit.py — the boot-time check that every route
is either entity-scoped-and-authenticated, or explicitly, correctly exempt."""
from __future__ import annotations

import pytest
from fastapi import APIRouter, Depends, FastAPI

from app.api.deps import get_principal, require_admin
from app.api.route_audit import _assert_registries_disjoint, assert_routes_authenticated
from app.db.invariants import StartupInvariantError


def _app_with(router: APIRouter) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


def test_every_real_route_passes_the_audit():
    # The actual app create_app() builds — this is the regression guard: if a
    # future route (or router) is added without updating route_audit.py, THIS
    # is what starts failing, exactly matching what create_app() does at real
    # boot (it audits `app` itself now, not a hand-maintained router list).
    from app.main import create_app

    assert_routes_authenticated(create_app())


def test_unclassified_route_fails_closed():
    router = APIRouter()

    @router.get("/v1/totally-new-route")
    def _new_route():
        return {}

    with pytest.raises(StartupInvariantError, match="not classified"):
        assert_routes_authenticated(_app_with(router))


def test_entity_scoped_path_without_get_principal_fails_closed():
    # Same path as a real entry in _ENTITY_SCOPED_ROUTES, but built with no
    # Depends(get_principal) at all — simulates the exact "forgot the auth
    # dependency" mistake this check exists to catch.
    router = APIRouter()

    @router.get("/v1/sessions/{session_id}")
    def _forgot_auth(session_id: str):
        return {}

    with pytest.raises(StartupInvariantError, match="does not depend on get_principal"):
        assert_routes_authenticated(_app_with(router))


def test_entity_scoped_path_with_get_principal_passes():
    router = APIRouter()

    @router.get("/v1/sessions/{session_id}")
    def _has_auth(session_id: str, principal=Depends(get_principal)):
        return {}

    assert_routes_authenticated(_app_with(router))  # must not raise


def test_same_named_decoy_dependency_still_fails_closed():
    # [REVIEW-FIX regression] a LOCAL function also named get_principal — same
    # name, different object — must NOT satisfy the check; only the real,
    # imported app.api.deps.get_principal counts (identity, not name).
    router = APIRouter()

    def get_principal():  # shadows the real one on purpose — this is the point of the test
        return None

    @router.get("/v1/sessions/{session_id}")
    def _decoy_auth(session_id: str, principal=Depends(get_principal)):
        return {}

    with pytest.raises(StartupInvariantError, match="does not depend on get_principal"):
        assert_routes_authenticated(_app_with(router))


def test_wrapper_dependency_nesting_the_real_get_principal_passes():
    # [REVIEW-FIX regression] a route depending on a wrapper that ITSELF
    # depends on the real get_principal must pass — the check has to walk the
    # whole dependency tree, not just the route's own direct Depends(...).
    router = APIRouter()

    def get_authorized_principal(principal=Depends(get_principal)):
        return principal

    @router.get("/v1/sessions/{session_id}")
    def _wrapped_auth(session_id: str, principal=Depends(get_authorized_principal)):
        return {}

    assert_routes_authenticated(_app_with(router))  # must not raise


def test_exempt_route_with_required_dependency_missing_fails_closed():
    # Same path as a real admin route, but built without require_admin —
    # simulates someone accidentally dropping the router-level Depends.
    router = APIRouter()

    @router.post("/v1/tsg/threat-library/embeddings/create")
    def _forgot_admin_gate():
        return {}

    with pytest.raises(StartupInvariantError, match="no longer depends on it"):
        assert_routes_authenticated(_app_with(router))


def test_exempt_route_with_required_dependency_present_passes():
    router = APIRouter()

    @router.post("/v1/tsg/threat-library/embeddings/create")
    def _has_admin_gate(_admin=Depends(require_admin)):
        return {}

    assert_routes_authenticated(_app_with(router))  # must not raise


def test_exempt_route_with_no_dependency_required_passes():
    router = APIRouter()

    @router.get("/healthz")
    def _health():
        return {}

    assert_routes_authenticated(_app_with(router))  # must not raise — health has no required dep


def test_unclassified_websocket_route_fails_closed():
    # [REVIEW-FIX regression] the original isinstance(route, APIRoute) filter
    # silently skipped ANY non-APIRoute, including websocket routes — an
    # entity-scoped websocket endpoint could ship with zero auth and this
    # check would never notice. No websocket route exists in this app today;
    # this proves the audit would still catch one if it ever did.
    router = APIRouter()

    @router.websocket("/v1/sessions/{session_id}/live")
    async def _unaudited_stream(websocket):
        await websocket.accept()
        await websocket.close()

    with pytest.raises(StartupInvariantError, match="not classified"):
        assert_routes_authenticated(_app_with(router))


def test_registries_disjoint_check_raises_on_collision():
    with pytest.raises(StartupInvariantError, match="appear in BOTH"):
        _assert_registries_disjoint({("GET", "/x")}, {("GET", "/x"): None})


def test_registries_disjoint_check_passes_for_the_real_registries():
    from app.api.route_audit import _ENTITY_SCOPED_ROUTES, _EXEMPT_ROUTES

    _assert_registries_disjoint(_ENTITY_SCOPED_ROUTES, _EXEMPT_ROUTES)  # must not raise
