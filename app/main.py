# FastAPI entrypoint. Run with: uvicorn app.main:app
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.admin import grounding_router
from app.api.admin import router as admin_router
from app.api.api_clients import router as api_clients_router
from app.api.deps import require_admin
from app.api.errors import register_error_handlers
from app.api.health import router as health_router
from app.api.route_audit import (
    _ENTITY_SCOPED_ROUTES,
    _EXEMPT_ROUTES,
    assert_routes_authenticated,
)
from app.api.sessions import router as sessions_router
from app.api.sessions import scenarios_router
from app.api.threat_intel import router as threat_intel_router
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
                "name": "Threat Scenario Generation",
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
                    "generate/regenerate, poll the GET on the same path.\n\n"
                    "**Breaking change — the request body is now closed.** Unknown keys are "
                    "rejected with 422 `extra_forbidden` instead of being silently dropped, and "
                    "the two window fields were renamed `timeline_start_date`/`timeline_end_date` "
                    "-> `mitigation_start_date`/`mitigation_end_date`. Generate accepts exactly "
                    "these 12 keys: `existing_controls`, `likelihood_rating`, `impact_rating`, "
                    "`final_risk_rating`, `risk_level`, `risk_identification_date`, `risk_owner`, "
                    "`impacted_business_division`, `existing_controls_all_subsystems`, "
                    "`existing_controls_all_subsystems_justification`, `mitigation_start_date`, "
                    "`mitigation_end_date`. Regenerate accepts `{}` — `user_note` was removed. "
                    "Send `\"\"` for an unset optional value; it is read as absent."
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
                "name": "Grounding Admin",
                "description": (
                    "Measure the grounding match threshold — the score at or above which an "
                    "AI-proposed threat is treated as an existing library entry rather than a "
                    "new one. The right value is specific to the configured embedding+reranker "
                    "pair, so it is measured per pair and stored, not hand-tuned: read the "
                    "current one (with its provenance) and queue a re-calibration after "
                    "changing models or curating the library. Requires the admin key."
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
    app.include_router(grounding_router)
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

    _finalize_openapi(app)
    # Fail-closed: refuse to boot if any route is missing entity-scoping or was never audited
    assert_routes_authenticated(app)
    return app


_API_KEY_SCHEME = "ApiKeyAuth"
_ADMIN_KEY_SCHEME = "AdminKeyAuth"

def _finalize_openapi(app: FastAPI) -> None:
    """Make the PUBLISHED spec match what the app actually does: one error envelope, declared
    authentication, and the error statuses each route can really return.

    Four defects this closes, all of the same kind — the document promised something untrue:

    1. FastAPI auto-adds a 422 documented as `HTTPValidationError` (`{"detail": [...]}`), but this
       app registers its own RequestValidationError handler, so the real body is the
       `{error_code, message, details}` envelope. Every such route published a shape it does not
       honour, and a client generated from the spec parses the wrong one.
    2. No `securitySchemes` and no `security` anywhere, with all five auth headers published
       `required: false` — so the spec described the whole API, admin routes included, as
       unauthenticated, and a generated client simply omitted the key.
    3. 401/403/404 were returned but never declared. (503 is declared by the ROUTES
       themselves via schemas.UNAVAILABLE_RESPONSES — a central path list here went
       stale the moment a route was renamed, silently.)
    4. Every SSE route (`.../events/{job_id}` x3, `/v1/sessions/{session_id}/events`) declares its
       200 with BOTH a `"model"` and a `"content": {"text/event-stream": {}}` override — FastAPI's
       own generator adds an `application/json` sibling for the `model` regardless, so the
       published spec claims these routes can answer with JSON, which none of them ever do (they
       stream exclusively). Verified live via `app.openapi()` before this fix. Stripped below for
       any response that declares `text/event-stream` — covers today's 4 routes and any future one
       without a per-route override to forget.

    Done HERE, over the finished schema, rather than as `responses=`/`dependencies=` on each of
    the 8 routers: a per-router kwarg is one more thing a NEW router can forget, and forgetting is
    invisible. Rewriting the generated document covers every route that exists now and every route
    added later, with nothing to remember.

    The auth classification is READ FROM route_audit's registries rather than restated here.
    Those registries already map every (method, path) to its auth model and `create_app()` refuses
    to boot when a route is missing from both, so sourcing the spec from them means the document
    cannot drift from what is enforced. A second hand-maintained list in this file would
    reintroduce exactly the drift this function exists to remove.

    NOT done here: marking the auth headers `required`. `deps.py` declares them `Header(default="")`
    on purpose so the dependency runs and raises AuthError -> a clean 401; making FastAPI enforce
    them instead would turn every missing-key 401 into a 422.
    """
    schema = app.openapi()
    ref = {"$ref": "#/components/schemas/ErrorResponse"}

    def envelope(description: str) -> dict:
        return {"description": description, "content": {"application/json": {"schema": ref}}}

    schema.setdefault("components", {})["securitySchemes"] = {
        _API_KEY_SCHEME: {
            "type": "apiKey", "in": "header", "name": "X-API-Key",
            "description": "Client key. Entity-scoped routes additionally require X-User-Id and "
                        "X-Entity-Id (and X-Tenant-Id where multi-tenant).",
        },
        _ADMIN_KEY_SCHEME: {
            "type": "apiKey", "in": "header", "name": "X-Admin-Key",
            "description": "Admin key. Gates the cross-tenant admin surface on its own — minting "
                        "the first client key must not itself require a client key.",
        },
    }

    for path, methods in schema.get("paths", {}).items():
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue  # "parameters"/"summary" siblings of the verb keys, not operations
            key = (method.upper(), path)
            responses = op.setdefault("responses", {})

            r422 = responses.get("422")
            if r422 and "content" in r422:
                r422["description"] = "Validation error — the standard error envelope."
                for media in r422["content"].values():
                    media["schema"] = ref

            # Fix 4: an SSE-only response never actually answers application/json — FastAPI adds
            # it anyway whenever the response declares a "model". Drop it wherever the route also
            # declares text/event-stream, so "Try it out" and generated clients see only the
            # content-type this route can really produce.
            for resp in responses.values():
                if isinstance(resp, dict) and "text/event-stream" in resp.get("content", {}):
                    resp["content"].pop("application/json", None)

            # setdefault throughout: a route that already declares a status (accept/reject's own
            # 409, the SSE routes' 200) keeps its more specific text.
            if key in _ENTITY_SCOPED_ROUTES:
                op["security"] = [{_API_KEY_SCHEME: []}]
                responses.setdefault("401", envelope("Missing or invalid credentials."))
                responses.setdefault("403", envelope(
                    "Authenticated, but not entitled to the target entity."))
            elif key in _EXEMPT_ROUTES and _EXEMPT_ROUTES[key] is require_admin:
                op["security"] = [{_ADMIN_KEY_SCHEME: []}]
                responses.setdefault("401", envelope("Missing or invalid admin key."))

            if "{" in path:  # every route that names a resource in its path can miss it
                responses.setdefault("404", envelope(
                    "Not found, or not visible to this caller. `details` may carry a "
                    "machine-readable reason per item — accept/reject name each unusable "
                    "scenario id and why."))

    # HTTPValidationError/ValidationError become unreferenced once every 422 points at
    # ErrorResponse; leave them in components rather than deleting — a stale $ref elsewhere would
    # break the whole document, and an unused schema costs nothing.
    app.openapi_schema = schema


app = create_app()
