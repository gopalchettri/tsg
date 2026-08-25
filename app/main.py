# FastAPI entrypoint. Run with: uvicorn app.main:app
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
    # Fail-closed startup: refuse to serve traffic if security posture, DB invariants,
    # or the local-model path aren't sane.
    from app.core.config import assert_security_posture, assert_sse_graceful_shutdown_wired
    from app.core.logging import configure_logging
    from app.db.engine import get_engine
    from app.db.invariants import verify_startup
    from app.pipeline.local_models import validate_local_models

    configure_logging()
    assert_security_posture()  # warn if the (user,entity) DB check is off in prod
    verify_startup(get_engine())  # fail-fast if a required DB guard is missing
    validate_local_models(warm=False)  # fail-fast on a bad local-model path
    assert_sse_graceful_shutdown_wired()  # fail loudly if the worker class drifted from uvicorn
    yield


def create_app() -> FastAPI:
    # Factored out from the module-level `app` so tests can construct fresh instances.
    app = FastAPI(
        title=get_settings().application_name,
        version=get_settings().application_version,
        description=get_settings().application_description,
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
                "name": "Remediation Plans",
                "description": (
                    "AI-generated Risk Treatment (Mitigate) plans for accepted scenarios. "
                    "The register's risk data (ratings, level, existing controls) is sent in "
                    "the request body. Present only when RISK_MODULE_ENABLED is on. POST to "
                    "generate/regenerate, poll the GET on the same path."
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
                    "Admin review queue for EVERYTHING new the AI pipeline proposes — threat "
                    "types, threat names, and actors (kind='threat' | 'actor'). With "
                    "promotion_auto_approve_enabled off (the default), nothing enters the "
                    "shared library without an approval here; approve mints the entry "
                    "(crediting the ORIGINAL proposer as CreatedBy) or reject closes the card. "
                    "Requires the admin key."
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
                "name": "API Clients Admin",
                "description": (
                    "Mint, list and revoke the API client keys callers authenticate with. "
                    "Requires the admin key alone — issuing the first key must not itself need "
                    "one. The secret is returned exactly once on create and never stored; a "
                    "lost secret is revoked and re-minted, never recovered."
                ),
            },

        ],
        lifespan=lifespan,
    )
    app.add_middleware(RequestIDMiddleware)  # request correlation ID + access logs
    # Added last so it runs first (Starlette wraps outward): reject oversized uploads
    # before anything buffers or parses the body.
    app.add_middleware(BodySizeLimitMiddleware)
    # Added last of the three so it's outermost: preflight is answered, and every
    # response carries CORS headers, before the other middleware ever runs.
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
    # Feature-flagged: routes only mount, and only 404-by-absence otherwise
    if get_settings().risk_module_enabled:
        app.include_router(treatment_router)
    # Dev-only SSE test harness, served by the API itself so auth headers/CORS work
    if get_settings().app_env in ("local", "dev"):
        from pathlib import Path

        from fastapi.responses import FileResponse

        _sse_page = Path(__file__).parent / "static" / "sse_test.html"

        @app.get("/dev/sse-test", include_in_schema=False)
        def _dev_sse_test() -> FileResponse:  # pragma: no cover - dev tooling
            return FileResponse(_sse_page, media_type="text/html")

    # Fail-closed: refuse to boot if any route is missing entity-scoping or was never audited
    assert_routes_authenticated(app)
    return app


app = create_app()
