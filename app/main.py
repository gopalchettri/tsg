"""FastAPI application entrypoint.

Startup runs the DB invariant checks (INV-*) — the app refuses to start against a
schema missing its guards (index-existence, NOT-NULL keys, no duplicate active
rows) — and, in `create_app()`, the [R2] route audit (every route must be an
explicitly-classified, correctly-authenticated entity-scoped route or a genuine
exemption — see app/api/route_audit.py). Run with: `uvicorn app.main:app`.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.admin import candidates_router, promotions_router
from app.api.admin import router as admin_router
from app.api.api_clients import router as api_clients_router
from app.api.control_library_crud import router as control_library_crud_router
from app.api.errors import register_error_handlers
from app.api.health import router as health_router
from app.api.route_audit import assert_routes_authenticated
from app.api.sessions import router as sessions_router
from app.api.sessions import scenarios_router
from app.api.threat_intel import router as threat_intel_router
from app.api.threat_library_crud import router as threat_library_crud_router
from app.api.threat_library_import import router as threat_library_import_router
from app.api.treatment import router as treatment_router
from app.core.config import get_settings
from app.core.middleware import BodySizeLimitMiddleware, RequestIDMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown hook: enforces fail-closed boot (security posture, DB invariants,
    local-model path) before the app accepts traffic, so a broken deployment never
    silently serves requests against an unsafe config.
    """
    # Note: the `app` parameter above is required by FastAPI's lifespan signature but
    # isn't used in the body below — all the checks operate on global settings/engine.
    from app.core.config import assert_security_posture, assert_sse_graceful_shutdown_wired
    from app.core.logging import configure_logging
    from app.db.engine import get_engine
    from app.db.invariants import verify_startup
    from app.pipeline.local_models import validate_local_models

    configure_logging()
    assert_security_posture()  # header auth: warn if the (user,entity) DB check is off in prod
    verify_startup(get_engine())  # fail-fast if a required DB guard is missing (incl. >=1 API key)
    validate_local_models(warm=False)  # fail-fast on a bad local-model path (API doesn't hold the model)
    assert_sse_graceful_shutdown_wired()  # item 21: fail loudly if the worker class drifted from uvicorn
    yield


def create_app() -> FastAPI:
    """Builds the FastAPI app with error handlers and routers wired in; factored out
    from the module-level `app` so tests can construct fresh instances.
    """
    app = FastAPI(
        title="Threat Scenario Generator",
        version="1.1",
        description="AI-assisted STRIDE threat identification and scenario generation for OT/ICS assets.",
        openapi_tags=[
            {"name": "Health", "description": "Liveness/readiness probes for orchestrators. No authentication required."},
            {
                "name": "Sessions",
                "description": (
                    "Create and drive a threat-scenario-generation session: identify threats, "
                    "generate scenarios, accept/regenerate/cancel, stream live progress, and "
                    "fetch previously accepted scenarios."
                ),
            },
            {
                "name": "Scenarios",
                "description": (
                    "Cross-session scenario reads: list everything one user created, list "
                    "everything under one entity, or fetch a single scenario by id. Results "
                    "are always restricted to the caller's authorized entities."
                ),
            },
            {
                "name": "Controls Admin",
                "description": (
                    "Curate the 1,288-control library: create/update/delete controls, and link/"
                    "unlink them to the standards they satisfy (which is what fills "
                    "`standards[]` on a scenario's mapped controls). Requires the admin key. "
                    "Deletes are soft, except unlinking a control from a standard."
                ),
            },
            {
                "name": "Standards Admin",
                "description": (
                    "Curate the named standards controls are linked to (ISO, NIST, DESC ISR, "
                    "...). Requires the admin key. Deletes are soft."
                ),
            },
            {
                "name": "Threat Categories Admin",
                "description": (
                    "Curate the STRIDE threat categories. This table's PK is caller-supplied, "
                    "not auto-generated. Requires the admin key. Deletes are soft — library ids "
                    "are referenced by completed sessions."
                ),
            },
            {
                "name": "Threat Types Admin",
                "description": (
                    "Curate threat families (types). Renaming re-embeds the row for AI "
                    "matching. Requires the admin key. Deletes are soft."
                ),
            },
            {
                "name": "Threat Catalogue Admin",
                "description": (
                    "Curate exact threats under a threat-type family — creating one 404s if the "
                    "parent family doesn't exist. Renaming re-embeds the row. Requires the admin "
                    "key. Deletes are soft."
                ),
            },
            {
                "name": "Threat Actors Admin",
                "description": (
                    "Curate threat actors. Actors are not embedded, so no refresh job is ever "
                    "returned for them. Requires the admin key. Deletes are soft."
                ),
            },
            {
                "name": "Threat Rules Admin",
                "description": (
                    "Curate the scoping rules that decide which threat types apply to which "
                    "asset contexts during Stage 1 identification — tech_gate rules hard "
                    "include/exclude, relevance rules weight the score. Requires the admin key. "
                    "Deletes are soft."
                ),
            },
            {
                "name": "Embeddings Admin",
                "description": (
                    "Manage the shared embedding cache used by both the threat and control "
                    "libraries for AI matching: create/update/recreate/delete vectors, and poll "
                    "job status. Requires the admin key."
                ),
            },
            {
                "name": "Session Admin",
                "description": (
                    "Visibility and control over sessions whose library-promotion side-effect "
                    "failed after an otherwise-successful accept: list/inspect pending "
                    "failures, force an immediate retry, or dismiss one from tracking. Requires "
                    "the admin key."
                ),
            },
            {
                "name": "Threat Library Candidates",
                "description": (
                    "Curator review queue for AI-proposed threats too ambiguous to auto-file, "
                    "or routed here instead of auto-minting because "
                    "promotion_auto_approve_enabled is off: list pending candidates, approve "
                    "(mints into the shared library) or reject. Requires the admin key."
                ),
            },
            {
                "name": "Threat Library Admin",
                "description": (
                    "Bulk-import open-source threat libraries (MITRE ATT&CK/ATT&CK ICS, MISP "
                    "actors, ...): list known sources, trigger an import, and poll its job "
                    "status. Requires the admin key. For editing individual rows by hand, see "
                    "the Threat Categories/Types/Catalogue/Actors Admin groups instead."
                ),
            },
            {
                "name": "Threat Intel Admin",
                "description": (
                    "Refresh live threat-intel feeds (CISA KEV/ICS, OTX, URLhaus, ...) that "
                    "feed the threats-prompt hint. Requires the admin key."
                ),
            },
            {
                "name": "Treatment Plans",
                "description": (
                    "AI-generated Risk Treatment (Mitigate) plans for accepted scenarios. "
                    "The register's risk data (ratings, level, existing controls) is sent in "
                    "the request body. Present only when RISK_MODULE_ENABLED is on. POST to "
                    "generate/regenerate, poll the GET on the same path."
                ),
            },
        ],
        lifespan=lifespan,
    )
    app.add_middleware(RequestIDMiddleware)  # [REVIEW-FIX] request correlation ID + access logs
    # Added LAST so it runs FIRST (Starlette wraps outward): the body-size guard has to reject an
    # over-sized upload before anything buffers or json-parses it — that work happens before
    # dependencies resolve, i.e. before require_admin runs, so a per-route cap cannot prevent it.
    app.add_middleware(BodySizeLimitMiddleware)
    # Item 31: added LAST of the three, so it's outermost (Starlette wraps outward) — a CORS
    # preflight (OPTIONS) is answered before the body-size guard or request-ID logging ever run,
    # and every response, including error responses, carries the CORS headers. allow_origins is
    # empty by default (cors_allowed_origins, app/core/config.py) -- no cross-origin browser
    # access until an environment sets it. allow_headers MUST list every real auth header
    # explicitly: X-API-Key/X-User-Id/X-Entity-Id/X-Tenant-Id (app/api/deps.get_principal) and
    # X-Admin-Key (app/api/deps.require_admin) are non-simple headers that trigger a browser
    # preflight, and CORSMiddleware rejects any header not in this allowlist by default -- an
    # origin allowlist alone leaves a browser consumer blocked at the preflight stage, not
    # connected. allow_methods must be explicit too: Starlette defaults to GET-only, which would
    # silently block every POST/PATCH/DELETE from a cross-origin caller.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=get_settings().cors_allowed_origins,
        allow_headers=["X-API-Key", "X-User-Id", "X-Entity-Id", "X-Tenant-Id", "X-Admin-Key",
                       "Content-Type", "Idempotency-Key"],
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
    )
    register_error_handlers(app)
    app.include_router(health_router)
    app.include_router(sessions_router)
    app.include_router(scenarios_router)
    app.include_router(admin_router)
    app.include_router(api_clients_router)
    app.include_router(promotions_router)
    app.include_router(candidates_router)
    app.include_router(threat_library_import_router)
    app.include_router(threat_library_crud_router)
    app.include_router(control_library_crud_router)
    app.include_router(threat_intel_router)
    # Feature-flagged: flag off -> the treatment-plan paths 404 by absence (no handler code
    # runs). Flag on -> routes mount; nothing else is armed — the register's risk data arrives
    # in the request body, so no external tables are required (docs/RISK_TREATMENT_PLAN_SDD.md).
    if get_settings().risk_module_enabled:
        app.include_router(treatment_router)
    # DEV ONLY — an SSE test harness for the treatment-plan events. Gated on a local/dev APP_ENV
    # so it cannot appear on a staging/prod deployment. It has to be served BY the API rather than
    # opened from disk: there is no CORS middleware, so a file:// page could not call these
    # endpoints at all, and EventSource cannot send the auth headers the stream requires (the page
    # uses fetch + ReadableStream instead).
    if get_settings().app_env in ("local", "dev"):
        from pathlib import Path

        from fastapi.responses import FileResponse

        _sse_page = Path(__file__).parent / "static" / "sse_test.html"

        @app.get("/dev/sse-test", include_in_schema=False)
        def _dev_sse_test() -> FileResponse:  # pragma: no cover - dev tooling
            return FileResponse(_sse_page, media_type="text/html")

    # [R2 remainder] fail-closed: refuse to boot if any route is missing its entity-scoping
    # dependency, or was never triaged at all — see app/api/route_audit.py. Audits `app`
    # itself (not a hand-maintained router list) so a future router can't ship unaudited.
    assert_routes_authenticated(app)
    return app


app = create_app()
