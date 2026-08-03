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

from app.api.admin import router as admin_router
from app.api.errors import register_error_handlers
from app.api.health import router as health_router
from app.api.route_audit import assert_routes_authenticated
from app.api.sessions import router as sessions_router
from app.api.sessions import scenarios_router
from app.api.threat_intel import router as threat_intel_router
from app.api.threat_library_crud import router as threat_library_crud_router
from app.api.control_library_crud import router as control_library_crud_router
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
    from app.core.logging import configure_logging
    from app.db.engine import get_engine
    from app.db.invariants import verify_startup
    from app.pipeline.local_models import validate_local_models

    from app.core.config import assert_security_posture, get_settings
    from app.core.logging import get_logger

    configure_logging()
    assert_security_posture()  # fail-closed: refuse to boot with auth disabled in prod
    if get_settings().auth_dev_mode:
        get_logger().warning("AUTH_DEV_MODE is ON — authentication is bypassed.")
    verify_startup(get_engine())  # fail-fast if a required DB guard is missing
    validate_local_models(warm=False)  # fail-fast on a bad local-model path (API doesn't hold the model)
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
                "name": "Embeddings Admin",
                "description": (
                    "Manage the shared embedding cache used by both the threat and control "
                    "libraries for AI matching: create/update/recreate/delete vectors, and poll "
                    "job status. Requires the admin key."
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
                    "AI-generated Risk Treatment (Mitigate) plans for accepted scenarios, "
                    "joined to the CRM Risk module's risk records. Present only when "
                    "RISK_MODULE_ENABLED is on. POST to generate/regenerate, poll the GET on "
                    "the same path."
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
    register_error_handlers(app)
    app.include_router(health_router)
    app.include_router(sessions_router)
    app.include_router(scenarios_router)
    app.include_router(admin_router)
    app.include_router(threat_library_import_router)
    app.include_router(threat_library_crud_router)
    app.include_router(control_library_crud_router)
    app.include_router(threat_intel_router)
    # Feature-flagged: flag off -> the treatment-plan paths 404 by absence (no handler code
    # runs), and invariants.py skips the crm_* table check. Flag on -> routes mount AND boot
    # verifies the CRM tables exist (docs/RISK_TREATMENT_PLAN_SDD.md D3).
    if get_settings().risk_module_enabled:
        app.include_router(treatment_router)
    # [R2 remainder] fail-closed: refuse to boot if any route is missing its entity-scoping
    # dependency, or was never triaged at all — see app/api/route_audit.py. Audits `app`
    # itself (not a hand-maintained router list) so a future router can't ship unaudited.
    assert_routes_authenticated(app)
    return app


app = create_app()
