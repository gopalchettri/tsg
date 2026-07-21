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
from app.core.middleware import RequestIDMiddleware


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
        get_logger().warning("AUTH_DEV_MODE is ON — authentication is bypassed. Dev/local only.")
    verify_startup(get_engine())  # fail-fast if a required DB guard is missing
    validate_local_models(warm=False)  # fail-fast on a bad local-model path (API doesn't hold the model)
    yield


def create_app() -> FastAPI:
    """Builds the FastAPI app with error handlers and routers wired in; factored out
    from the module-level `app` so tests can construct fresh instances.
    """
    app = FastAPI(title="Threat Scenario Generator", version="1.1", lifespan=lifespan)
    app.add_middleware(RequestIDMiddleware)  # [REVIEW-FIX] request correlation ID + access logs
    register_error_handlers(app)
    app.include_router(health_router)
    app.include_router(sessions_router)
    app.include_router(admin_router)
    # [R2 remainder] fail-closed: refuse to boot if any route is missing its entity-scoping
    # dependency, or was never triaged at all — see app/api/route_audit.py. Audits `app`
    # itself (not a hand-maintained router list) so a future router can't ship unaudited.
    assert_routes_authenticated(app)
    return app


app = create_app()
