"""[R2 remainder] Boot-time route audit — a bouncer for the API surface itself,
the same idea as app/db/invariants.py but for routes instead of database schema.

WHY THIS EXISTS: `Depends(get_principal)` authenticates the caller and
`principal.require_entity(...)` (or the equivalent inline check in
sessions.py::get_authorized_session) confirms they actually own the specific
entity-scoped resource being touched. Both mechanisms already work correctly on
every route today — but nothing stops a FUTURE route from being added without
either one. Concretely: someone adds `GET /v1/sessions/{id}/export` six months
from now, copies most of an existing handler, forgets `Depends(get_principal)`
entirely. The app compiles, boots, and serves traffic fine — there is no crash,
no log line, nothing to notice — until a caller from an unrelated entity simply
requests another tenant's session id and gets back their data. This module turns
that "silently ships unsafe" failure mode into a boot-time crash instead: every
route must be explicitly triaged into one of two buckets below before the app
is allowed to start.

WHAT THIS CANNOT DO: this only proves a route *declares* the right FastAPI
dependency — it can't verify a route's body actually enforces the RIGHT entity
id (that's exactly what `get_authorized_session`/`require_entity` do at
request time, not something a static boot check can verify without full body
analysis). Closing "route has no auth wired in at all" — the actual failure
mode in the example above — is the achievable, valuable half of this problem,
and it's what `get_principal`'s absence signals.

[REVIEW-FIX] the first version of this file matched dependencies by their
`__name__` string, not by identity — a same-named decoy function (or a wrapper
dependency that nests the real one one level deeper) could silently bypass or
false-positive the whole check. This version imports the real `get_principal`/
`require_admin` and compares actual callable identity, walking the FULL nested
dependency tree (not just the route's own direct `Depends(...)`).
"""
from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from fastapi.dependencies.models import Dependant
from fastapi.routing import APIRoute, APIWebSocketRoute

from app.api.deps import get_principal, require_admin
from app.db.invariants import StartupInvariantError

_WEBSOCKET = "WEBSOCKET"  # synthetic method key — APIWebSocketRoute has no .methods

# ============================================================================
# Every entity-scoped route (touches one entity's session/asset/scenario data)
# must depend on `get_principal` — this is the mechanically-verifiable half of
# "the caller was authenticated before this route did anything." (method, path)
# exactly as FastAPI resolves them, prefix included.
# ============================================================================
_ENTITY_SCOPED_ROUTES: set[tuple[str, str]] = {
    ("POST", "/v1/sessions"),
    ("GET", "/v1/sessions/{session_id}"),
    ("GET", "/v1/sessions/{session_id}/results"),
    ("POST", "/v1/sessions/{session_id}/accept"),
    ("POST", "/v1/sessions/{session_id}/regenerate/scenarios"),
    ("POST", "/v1/sessions/{session_id}/scenarios/next-set"),
    ("POST", "/v1/sessions/{session_id}/cancel"),
    ("GET", "/v1/sessions/{session_id}/events"),
    ("GET", "/v1/assets/{asset_id}/accepted-scenarios"),
}

# ============================================================================
# Routes deliberately outside the entity model, each with the reason and (if
# any) the actual dependency CALLABLE whose presence keeps that reason true —
# not its name, its identity, so a same-named decoy can't satisfy this either.
# `None` means the route legitimately has no auth dependency at all (the
# platform health checks). A named dependency is re-checked every boot too —
# if someone later edits admin.py and drops `require_admin`, the exemption
# itself is now a lie, so this fails closed instead of quietly waving the
# route through.
# ============================================================================
_EXEMPT_ROUTES: dict[tuple[str, str], Callable[..., object] | None] = {
    ("GET", "/healthz"): None,  # platform health check, no caller identity involved
    ("GET", "/readyz"): None,  # platform health check, no caller identity involved
    ("POST", "/v1/tsg/threat-library/embeddings/create"): require_admin,
    ("POST", "/v1/tsg/threat-library/embeddings/update"): require_admin,
    ("POST", "/v1/tsg/threat-library/embeddings/recreate"): require_admin,
    ("POST", "/v1/tsg/threat-library/embeddings/delete"): require_admin,
    ("GET", "/v1/tsg/threat-library/embeddings/status/{job_id}"): require_admin,
    # All 5 above: admin-key gated (router-level Depends(require_admin) in admin.py),
    # shared cross-tenant threat-library data — not one entity's data, so the
    # per-entity JWT model doesn't apply (see admin.py's own module docstring).
}


def _assert_registries_disjoint(
    entity_scoped: set[tuple[str, str]], exempt: dict[tuple[str, str], Callable[..., object] | None]
) -> None:
    """[REVIEW-FIX] nothing previously stopped the same (method, path) key from being listed
    in BOTH registries — the exempt branch checks first and `continue`s unconditionally on a
    match, so a route accidentally added to `_EXEMPT_ROUTES` while still sitting in
    `_ENTITY_SCOPED_ROUTES` would silently skip the get_principal check it needs. Fails at
    import time, before any route is even inspected, the same "catch a registry mistake
    immediately" contract every other invariant in this file already keeps."""
    collision = entity_scoped & exempt.keys()
    if collision:
        raise StartupInvariantError(
            f"[R2] route(s) {sorted(collision)} appear in BOTH _ENTITY_SCOPED_ROUTES and "
            "_EXEMPT_ROUTES in app/api/route_audit.py — a route cannot be both. Fix the registry."
        )


_assert_registries_disjoint(_ENTITY_SCOPED_ROUTES, _EXEMPT_ROUTES)


def _all_dependency_calls(dependant: Dependant) -> set[Callable[..., object]]:
    """[REVIEW-FIX] `dependant.dependencies` is only the route's own DIRECTLY-declared
    `Depends(...)` — it does not recurse into a dependency's own nested `Depends(...)`. A
    route authenticated via a wrapper (e.g. one function that itself depends on
    `get_principal`) would otherwise look unauthenticated to this check. Recurses the whole
    tree and returns the actual callable objects (not their names) so identity comparison
    works regardless of how deep the real dependency sits."""
    calls: set[Callable[..., object]] = set()
    for dep in dependant.dependencies:
        if dep.call is not None:  # a sub-dependant can carry sub-dependencies with no callable of its own
            calls.add(dep.call)
        calls |= _all_dependency_calls(dep)
    return calls


def _iter_audit_routes(app: FastAPI):
    """[REVIEW-FIX] previously took a hand-maintained router list, kept in sync with
    `app.include_router(...)` purely by convention — a future router registered on `app` but
    never added to that list would ship completely unaudited. Walks the real, live `app`
    object instead, so there is exactly one source of truth. FastAPI (0.139, installed here)
    wraps each included router in a private `_IncludedRouter`, exposing the original
    `APIRouter` via `.original_router` — unwrapped here; a plain `APIRoute`/
    `APIWebSocketRoute` found directly on `app.routes` is also handled, so this keeps working
    if a future FastAPI version flattens routes the older, simpler way instead."""
    for entry in app.routes:
        router = getattr(entry, "original_router", None)
        if router is not None:
            yield from router.routes
        elif isinstance(entry, (APIRoute, APIWebSocketRoute)):
            yield entry


def assert_routes_authenticated(app: FastAPI) -> None:
    """Runs at every `create_app()` call (see main.py) — no DB engine involved, this is pure
    in-process introspection of the app's own registered routes.

    For every route on `app`: it must appear in exactly one of the two registries above.
    Missing from both -> `StartupInvariantError` naming the unclassified route, so a
    newly-added route can never silently ship without someone explicitly deciding which
    bucket it belongs in. Classified entity-scoped -> must depend on the real `get_principal`
    (by identity, anywhere in its dependency tree). Classified exempt with a named dependency
    -> must still depend on it, by the same identity check.

    [REVIEW-FIX] also audits `APIWebSocketRoute`s, not just plain HTTP `APIRoute`s — the
    original isinstance filter silently exempted an entire route class rather than failing
    closed on an unrecognized one. No websocket route exists in this app today, so this only
    matters the day one is added — exactly the "future route" scenario this module exists for.
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
