"""Boot-time route audit — the routing counterpart to app/db/invariants.py.

Every route on the app must be explicitly triaged into one of the two registries below, or
`create_app()` raises. This turns "a new route ships with no auth dependency wired in at all"
from a silent IDOR into a boot-time crash.

It only proves a route *declares* the right dependency; whether the body enforces the RIGHT
entity id is `get_authorized_session`/`require_entity`'s job at request time. Dependencies are
compared by callable IDENTITY, not `__name__`, and the whole nested dependency tree is walked —
a same-named decoy or a wrapper one level deeper must not satisfy the check.
"""
from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute, APIWebSocketRoute

from app.api.deps import get_principal, require_admin
from app.db.invariants import StartupInvariantError

_WEBSOCKET = "WEBSOCKET"  # synthetic method key — APIWebSocketRoute has no .methods

# FastAPI's own auto-added docs/OpenAPI routes. These are plain Starlette Routes added via
# app.add_route(), not an included APIRouter, so _iter_audit_routes cannot classify them like a
# real route — allowlisted by path rather than silently falling through unrecognized.
_FRAMEWORK_ROUTE_PATHS = {"/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}

# Every entity-scoped route (touches one entity's session/asset/scenario data) must depend on
# `get_principal`. (method, path) exactly as FastAPI resolves them, prefix included.
_ENTITY_SCOPED_ROUTES: set[tuple[str, str]] = {
    ("POST", "/v1/sessions"),
    ("GET", "/v1/sessions/{session_id}"),
    ("GET", "/v1/sessions/{session_id}/results"),
    ("POST", "/v1/sessions/{session_id}/accept"),
    ("POST", "/v1/sessions/{session_id}/regenerate/scenarios"),
    ("POST", "/v1/sessions/{session_id}/scenarios/next-set"),
    ("POST", "/v1/sessions/{session_id}/cancel"),
    ("GET", "/v1/sessions/{session_id}/events"),
    ("GET", "/v1/sessions/{session_id}/accepted-scenarios"),
    ("GET", "/v1/sessions/{session_id}/scenarios/{output_id}"),
    ("GET", "/v1/users/{user_id}/scenarios"),
    ("GET", "/v1/entities/{entity_id}/scenarios"),
    # Treatment plans (app/api/treatment.py) — mounted only when risk_module_enabled. Entries
    # for an unmounted router are inert (the audit walks LIVE app routes), so these stay
    # unconditional; when the router IS mounted, missing entries would fail the boot.
    ("POST", "/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan"),
    ("GET", "/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan"),
    ("GET", "/v1/sessions/{session_id}/treatment-plans"),
    ("POST", "/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/cancel"),
    ("POST", "/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/review"),
    ("GET", "/v1/entities/{entity_id}/treatment-plans"),
    ("GET", "/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/audit"),
    ("GET", "/v1/entities/{entity_id}/treatment-plans/audit"),
    ("GET", "/v1/sessions/{session_id}/scenarios/{output_id}/treatment-plan/evidence"),
}

# Routes deliberately outside the entity model, each mapped to the dependency CALLABLE whose
# presence keeps the exemption true (`None` = legitimately no auth at all). Re-checked every
# boot: if someone drops `require_admin`, the exemption is now a lie and this fails closed.
_EXEMPT_ROUTES: dict[tuple[str, str], Callable[..., object] | None] = {
    ("GET", "/healthz"): None,  # platform health check, no caller identity involved
    ("GET", "/readyz"): None,  # platform health check, no caller identity involved
    ("POST", "/v1/tsg/threat-library/embeddings/create"): require_admin,
    ("POST", "/v1/tsg/threat-library/embeddings/update"): require_admin,
    ("POST", "/v1/tsg/threat-library/embeddings/recreate"): require_admin,
    ("POST", "/v1/tsg/threat-library/embeddings/delete"): require_admin,
    ("GET", "/v1/tsg/threat-library/embeddings/status/{job_id}"): require_admin,
    # All 5 above: admin-key gated (router-level Depends(require_admin) in admin.py), shared
    # cross-tenant threat-library data — not one entity's data, so the per-entity JWT model
    # doesn't apply. Same rationale for every require_admin entry below.
    ("GET", "/v1/tsg/threat-library/sources"): require_admin,
    ("POST", "/v1/tsg/threat-library/sources/{source}/import"): require_admin,
    ("GET", "/v1/tsg/threat-library/imports/{job_id}"): require_admin,
    ("GET", "/v1/tsg/threat-intel/feeds"): require_admin,
    ("GET", "/v1/tsg/threat-intel/items"): require_admin,
    ("POST", "/v1/tsg/threat-intel/feeds/refresh"): require_admin,
    ("POST", "/v1/tsg/threat-intel/feeds/{feed}/refresh"): require_admin,
    # Threat-library master CRUD (routers in app/api/threat_library_crud.py; shared impl in library_crud.py). One entry PER VERB; a missing one
    # fails the boot, not a request.
    ("GET", "/v1/tsg/threat-library/threat-categories"): require_admin,
    ("POST", "/v1/tsg/threat-library/threat-categories"): require_admin,
    ("PATCH", "/v1/tsg/threat-library/threat-categories/{threat_category_id}"): require_admin,
    ("DELETE", "/v1/tsg/threat-library/threat-categories/{threat_category_id}"): require_admin,
    ("GET", "/v1/tsg/threat-library/threat-types"): require_admin,
    ("POST", "/v1/tsg/threat-library/threat-types"): require_admin,
    ("PATCH", "/v1/tsg/threat-library/threat-types/{threat_type_id}"): require_admin,
    ("DELETE", "/v1/tsg/threat-library/threat-types/{threat_type_id}"): require_admin,
    ("GET", "/v1/tsg/threat-library/threat-catalogue"): require_admin,
    ("POST", "/v1/tsg/threat-library/threat-catalogue"): require_admin,
    ("PATCH", "/v1/tsg/threat-library/threat-catalogue/{threat_catalogue_id}"): require_admin,
    ("DELETE", "/v1/tsg/threat-library/threat-catalogue/{threat_catalogue_id}"): require_admin,
    ("GET", "/v1/tsg/threat-library/threat-actors"): require_admin,
    ("POST", "/v1/tsg/threat-library/threat-actors"): require_admin,
    ("PATCH", "/v1/tsg/threat-library/threat-actors/{threat_actor_id}"): require_admin,
    ("DELETE", "/v1/tsg/threat-library/threat-actors/{threat_actor_id}"): require_admin,
    # Control-library master CRUD (routers in app/api/control_library_crud.py; shared impl in library_crud.py). The last two are the
    # control<->standard link.
    ("GET", "/v1/tsg/control-library/standards"): require_admin,
    ("POST", "/v1/tsg/control-library/standards"): require_admin,
    ("PATCH", "/v1/tsg/control-library/standards/{standard_id}"): require_admin,
    ("DELETE", "/v1/tsg/control-library/standards/{standard_id}"): require_admin,
    ("GET", "/v1/tsg/control-library/controls"): require_admin,
    ("POST", "/v1/tsg/control-library/controls"): require_admin,
    ("PATCH", "/v1/tsg/control-library/controls/{control_id}"): require_admin,
    ("DELETE", "/v1/tsg/control-library/controls/{control_id}"): require_admin,
    ("POST", "/v1/tsg/control-library/controls/{control_id}/standards/{standard_id}"): require_admin,
    ("DELETE", "/v1/tsg/control-library/controls/{control_id}/standards/{standard_id}"): require_admin,
}


def _assert_registries_disjoint(
    entity_scoped: set[tuple[str, str]], exempt: dict[tuple[str, str], Callable[..., object] | None]
) -> None:
    """A key in BOTH registries would silently skip its get_principal check — the exempt branch
    matches first and `continue`s. Fails at import time, before any route is inspected."""
    collision = entity_scoped & exempt.keys()
    if collision:
        raise StartupInvariantError(
            f"[R2] route(s) {sorted(collision)} appear in BOTH _ENTITY_SCOPED_ROUTES and "
            "_EXEMPT_ROUTES in app/api/route_audit.py — a route cannot be both. Fix the registry."
        )


_assert_registries_disjoint(_ENTITY_SCOPED_ROUTES, _EXEMPT_ROUTES)


def _all_dependency_calls(dependant: Dependant) -> set[Callable[..., object]]:
    """Every callable in the route's dependency tree. `dependant.dependencies` holds only the
    route's DIRECTLY-declared `Depends(...)`, so a route authenticated via a wrapper would look
    unauthenticated without this recursion. Returns callables, not names, for identity checks."""
    calls: set[Callable[..., object]] = set()
    for dep in dependant.dependencies:
        if dep.call is not None:  # a sub-dependant can carry sub-dependencies with no callable of its own
            calls.add(dep.call)
        calls |= _all_dependency_calls(dep)
    return calls


def _iter_audit_routes(app: FastAPI):
    """Walks the live `app` object — one source of truth, so a router registered but forgotten
    elsewhere can't ship unaudited. FastAPI (0.139) wraps each included router in a private
    `_IncludedRouter` exposing the original via `.original_router`; a plain `APIRoute`/
    `APIWebSocketRoute` sitting directly on `app.routes` is handled too."""
    for entry in app.routes:
        router = getattr(entry, "original_router", None)
        if router is not None:
            yield from router.routes
        elif isinstance(entry, (APIRoute, APIWebSocketRoute)):
            yield entry
        elif getattr(entry, "path", None) in _FRAMEWORK_ROUTE_PATHS:
            continue  # FastAPI's own docs/openapi routes — see _FRAMEWORK_ROUTE_PATHS above
        else:
            # Fail closed: a route reaching app.routes some other way (a future
            # app.add_route()/app.mount() for a REAL endpoint) must not bypass this audit.
            raise StartupInvariantError(
                f"app.routes contains an entry _iter_audit_routes doesn't recognize "
                f"(type={type(entry).__name__}, path={getattr(entry, 'path', '?')!r}) — add its "
                "path to _FRAMEWORK_ROUTE_PATHS above if it's a known-safe framework route, or "
                "register it as a real APIRoute/APIRouter so it can be triaged like every other "
                "route instead."
            )


def assert_routes_authenticated(app: FastAPI) -> None:
    """Runs at every `create_app()` (see main.py) — pure in-process introspection, no DB.

    Every route must appear in exactly one registry. Missing from both -> StartupInvariantError.
    Entity-scoped -> must depend on the real `get_principal` by identity, anywhere in its
    dependency tree. Exempt with a named dependency -> same identity check against that one.

    `APIWebSocketRoute`s are audited too: none exist today, so this only matters the day one is
    added — exactly the "future route" case this module exists for.
    """
    for route in _iter_audit_routes(app):
        dep_calls = _all_dependency_calls(route.dependant)
        methods = route.methods if isinstance(route, APIRoute) else {_WEBSOCKET}
        if not methods:
            continue  # no HTTP verb bound — nothing to audit
        for method in methods:
            key = (method, route.path)
            if key in _EXEMPT_ROUTES:
                required = _EXEMPT_ROUTES[key]
                if required is not None and required not in dep_calls:
                    raise StartupInvariantError(
                        f"[R2] route {method} {route.path} is registered exempt because of "
                        f"'{required.__name__}', but no longer depends on it — its exemption is "
                        "now false. Restore the dependency, or reclassify the route honestly."
                    )
                continue
            if key not in _ENTITY_SCOPED_ROUTES:
                raise StartupInvariantError(
                    f"[R2] route {method} {route.path} is not classified in "
                    "app/api/route_audit.py's _ENTITY_SCOPED_ROUTES/_EXEMPT_ROUTES registry — "
                    "every route must be explicitly triaged (entity-scoped, or exempt with a "
                    "reason) before it can ship, so a forgotten auth check can never silently "
                    "reach production."
                )
            if get_principal not in dep_calls:
                raise StartupInvariantError(
                    f"[R2] route {method} {route.path} is classified entity-scoped but does "
                    "not depend on get_principal (checked by identity, anywhere in its "
                    "dependency tree) — add Depends(get_principal), or move it to "
                    "route_audit.py's exempt registry with a genuine reason."
                )
