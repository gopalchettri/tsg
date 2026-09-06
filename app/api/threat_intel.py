"""Live threat-intel admin API — feed status and on-demand refresh.

TSG's PERISHABLE external-data channel (the durable side is curated directly in the
threat-library tables; the bulk importer is retired). These routes drive — CISA KEV, CISA ICS advisories, OTX, URLhaus and any
configured TAXII source — cached in Mongo with a TTL and injected into scenario prompts
as citable reference material.

Why these routes exist at all: until now the feature was schedule-only. An operator could
not ask "is KEV fresh?", could not re-pull a feed that failed at 03:00, and could not tell
a switched-off feed from a silently broken one — because a Celery result expires and took
the only evidence with it. `GET /feeds` answers the first two, `POST .../refresh` the
third, and fetchers._record_feed_status persists the outcome so it outlives the job.

Admin-family, same double gate as the import/embeddings routers (X-Admin-Key + a valid
principal) and cross-tenant by nature: the intel cache is shared, not entity-scoped.
"""
from __future__ import annotations

from typing import Annotated

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request

from app.api.admin import AdminValidationError
from app.api.admin_jobs import (
    FAMILY_INTEL,
    admin_job_exists,
    intel_job_channel_key,
    mark_admin_job,
)
from app.api.admin_sse import admin_job_event_stream
from app.api.deps import Principal, get_admin_principal, require_admin
from app.api.schemas import (
    UNAVAILABLE_RESPONSES,
    IntelFeedsResponse,
    IntelFeedStatus,
    IntelItem,
    IntelItemsResponse,
    IntelJobEvent,
    IntelRefreshAccepted,
    LibraryImportAccepted,
    LibraryImportBody,
    LibraryImportStatus,
    TechniqueCorpusStatus,
    TechniqueRebuildAccepted,
    TechniqueRebuildBody,
)
from app.core.enums import SSEEventType
from app.core.joblock import is_held
from app.core.logging import get_logger
from app.db import dal
from app.db.dal import NotFoundError
from app.intel.fetchers import ALL_FEEDS, enabled_feed_names, feed_status, list_intel
from app.intel.library_import import SOURCES as LIBRARY_SOURCES
from app.intel.library_import import ImportAlreadyRunning, lock_key
from app.intel.technique_reference import SOURCES as TECHNIQUE_SOURCES
from app.intel.technique_reference import stats as technique_stats
from app.pipeline.celery_app import (
    celery_app,
    dispatch_refresh,
    import_threat_library_task,
    rebuild_technique_reference_task,
)
from app.pipeline.llm import _slot_redis

router = APIRouter(
    prefix="/v1/tsg/threat-intel",
    tags=["Threat Intel Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


def _dispatch(feeds: list[str], user_id: str | None) -> IntelRefreshAccepted:
    """Queue one job per feed. The fan-out itself lives in celery_app.dispatch_refresh so the
    scheduled refresh (tsg.intel_refresh_all) and this route are one code path; this
    indirection stays so tests can run refreshes synchronously, same pattern as admin.py's
    _enqueue."""
    return IntelRefreshAccepted(jobs=dispatch_refresh(feeds, user_id))


@router.get("/feeds", response_model=IntelFeedsResponse,
            summary="Check threat-intel feed health",
            description=(
                "The operational status of every known intel feed: whether it is switched on, how many items "
                "are cached, and when it last ran, succeeded or failed.\n\n"
                "**Tell three states apart:** `enabled: false` means switched off in configuration. `enabled: "
                "true` with a null `last_success_at` means switched on but never successfully run. A non-null "
                "`last_error` means it ran and failed, with the reason.\n\n"
                "**Watch out:** a successful refresh can add zero items, because feeds only download what "
                "they do not already have. Judge health by `last_success_at` moving, not by the count "
                "changing. A `stale` flag means an enabled feed has had no success inside the configured "
                "window."
            ))
def list_feeds(_principal: Principal = Depends(get_admin_principal)) -> IntelFeedsResponse:
    """Every known feed with its cached volume, freshness and last outcome.

    Deliberately reports disabled feeds too: "switched off", "enabled but never run" and
    "ran and failed" are three different operational states, and an endpoint that only
    listed active feeds would collapse them into one silence. Note a successful refresh
    can legitimately add zero items — the incremental feeds skip what they already hold —
    so judge health by `last_success_at`, not by `item_count` moving."""
    return IntelFeedsResponse(feeds=[IntelFeedStatus(**f) for f in feed_status()])


@router.get("/items", response_model=IntelItemsResponse, responses=UNAVAILABLE_RESPONSES,
            summary="Browse cached intel items",
            description=(
                "Pages through the intel actually cached — exploited vulnerabilities, advisories, adversary "
                "reports — newest first.\n\n"
                "**Call it:** to spot-check a feed after refreshing it, or to trace a scenario's cited intel "
                "back to its source.\n\n"
                "**Filters:** `source` narrows to one feed, `limit` defaults to 50 and caps at 500, `offset` "
                "pages. A `source` TSG does not recognise is a `404`.\n\n"
                "**Watch out:** paging past the end returns `200` with an empty list and the real total. If "
                "the intel store itself is unreachable you get `503`, never an empty page standing in for an "
                "outage."
            ))
def list_items(source: str | None = None,
            limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
            _principal: Principal = Depends(get_admin_principal)) -> IntelItemsResponse:
    """Browse the cached intel items themselves, newest first — `?source=otx` lists the
    OTX pulses with their `adversary`, `?source=cisa_kev` the exploited CVEs,
    `?source=cisa_ics` the OT advisories; no filter = every feed interleaved.

    A down intel store is a 503, never an empty page — an empty `items` must mean the
    cache genuinely holds nothing for the filter."""
    if source is not None and source not in ALL_FEEDS:
        raise NotFoundError(f"unknown intel feed: {source!r} — valid: {sorted(ALL_FEEDS)}")
    got = list_intel(source=source, limit=limit, offset=offset)
    if got is None:
        raise HTTPException(status_code=503, detail="intel store unavailable")
    items, total = got
    return IntelItemsResponse(items=[IntelItem(**i) for i in items],
                            total=total, limit=limit, offset=offset)


@router.post("/feeds/refresh", response_model=IntelRefreshAccepted, status_code=202,
            summary="Refresh every enabled feed",
            description=(
                "Queues a refresh for each enabled feed, one background job per feed, so a slow feed cannot "
                "hold up the others.\n\n"
                "**What you get:** `202` with one job id per ENABLED feed — never a fixed count. If nothing "
                "is enabled you get an empty map. Watch any job with the events endpoint, or re-read the feed "
                "list.\n\n"
                "**Watch out:** there is no scheduled refresh by default; this endpoint is the only way feeds "
                "update unless an operator configures an interval."
            ))
def refresh_all_feeds(request: Request,
                    principal: Principal = Depends(get_admin_principal)) -> IntelRefreshAccepted:
    """Fetch is admin-triggered only — there is no automatic schedule. Fans out to one job
    per feed rather than one job doing all of them, so a slow or broken feed can neither
    delay nor fail the others. Returns the job id queued per feed; read the outcomes from
    GET /feeds, which survives the jobs expiring, or watch one live via
    GET /feeds/events/{job_id}.

    **No request body.** Copy-paste:
    ```
    curl -X POST "https://<host>/v1/tsg/threat-intel/feeds/refresh" \\
         -H "X-Admin-Key: <your-admin-key>"
    ```"""
    feeds = enabled_feed_names()
    accepted = _dispatch(feeds, principal.user_id)
    log.warning("admin.threat_intel_refresh", action="refresh_all", feeds=feeds,
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return accepted


@router.post("/feeds/{feed}/refresh", response_model=IntelRefreshAccepted, status_code=202,
            summary="Refresh one feed",
            description=(
                "Queues a refresh for a single named feed. This is the targeted retry after one feed fails "
                "while the others succeed.\n\n"
                "**What you get:** `202` with exactly one job id.\n\n"
                "**Watch out:** a feed name TSG does not know returns `404`, and so does a known feed that is "
                "currently switched off — the error says which."
            ))
def refresh_feed(
    feed: Annotated[str, Path(
        description="One of the known feed names. GET /feeds lists live status for all of "
                    "them, including whether each is currently enabled. A name outside this "
                    "list, or a known name that's disabled in configuration, both 404.",
        examples={
            "otx": {"summary": "AlienVault OTX", "value": "otx"},
            "cisa_kev": {"summary": "CISA Known Exploited Vulnerabilities", "value": "cisa_kev"},
            "cisa_ics": {"summary": "CISA ICS advisories", "value": "cisa_ics"},
            "urlhaus": {"summary": "URLhaus (disabled by default)", "value": "urlhaus"},
            "taxii": {"summary": "Configured TAXII source(s)", "value": "taxii"},
        },
    )],
    request: Request,
    principal: Principal = Depends(get_admin_principal),
) -> IntelRefreshAccepted:
    """Refresh ONE feed — the targeted retry after a failure, instead of re-pulling
    everything. Unknown feed → 404 (it is the addressed resource); a known but disabled
    feed → 404 as well, with a message naming it as disabled, since there is nothing to
    refresh until configuration switches it on.

    **No request body** — the feed name is the URL path segment above. Copy-paste:
    ```
    curl -X POST "https://<host>/v1/tsg/threat-intel/feeds/otx/refresh" \\
         -H "X-Admin-Key: <your-admin-key>"
    ```
    Swap `otx` for `cisa_kev`, `cisa_ics`, `urlhaus`, or `taxii` to refresh a different one."""
    if feed not in ALL_FEEDS:
        raise NotFoundError(f"unknown intel feed: {feed!r} — valid: {sorted(ALL_FEEDS)}")
    if feed not in enabled_feed_names():
        raise NotFoundError(f"intel feed {feed!r} is not enabled — switch it on in configuration first")
    accepted = _dispatch([feed], principal.user_id)
    log.warning("admin.threat_intel_refresh", action="refresh_feed", feeds=[feed],
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return accepted


def _extend_intel_terminal(result: AsyncResult) -> dict:
    """intel_refresh_feed_task returns a bare item count, not a dict (unlike import/embeddings)
    — map it to a named field instead of the shared default's dict-spread, which would do
    nothing for a plain int."""
    return {"item_count": result.result} if isinstance(result.result, int) else {}


@router.get("/feeds/events/{job_id}",
            responses={200: {"model": IntelJobEvent, "content": {"text/event-stream": {}},
                        "description": "SSE stream; each `data:` line is one IntelJobEvent."}}
                    | UNAVAILABLE_RESPONSES,
            summary="Stream a feed refresh",
            description=(
                "Pushes one feed-refresh job's progress live, instead of re-reading the feed list on a timer.\n\n"
                "**Call it:** right after either refresh endpoint, using a job id from the response.\n\n"
                "**What arrives:** a state snapshot immediately, even for a job that already finished, then "
                "live updates as the worker runs. A retry state is not terminal and keeps the stream open; "
                "success or failure closes it.\n\n"
                "**Watch out:** the connect snapshot never names the feed, because it is read from the job "
                "result rather than the worker. Only live frames carry the feed name. A browser's built-in "
                "`EventSource` cannot be used, because this needs custom headers."
            ))
async def job_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE stream for one queued per-feed refresh job (one of the ids in
    IntelRefreshAccepted.jobs): a state snapshot on connect, then the worker's live
    `intel_job_update` hints (STARTED, then either terminal SUCCESS/FAILURE or a non-terminal
    RETRY — see intel_refresh_feed_task's docstring for why RETRY must stay non-terminal here) —
    same hint-layer/AsyncResult-backstop contract as admin.py::job_events. GET /feeds (per-feed
    last_success_at/last_error) remains the durable truth; there is no separate per-job GET
    status route for intel today, so this stream reads AsyncResult directly, same as it does.
    Streaming mechanics live in admin_sse.py, shared with the embeddings and grounding-calibration
    job-events routes.

    Same header requirement as GET /v1/sessions/{session_id}/events: this is a fetch()+
    ReadableStream stream sent with the admin auth headers this API requires, so the browser's
    native `EventSource` API cannot consume it (it cannot set custom headers)."""
    return await admin_job_event_stream(
        job_id, FAMILY_INTEL, intel_job_channel_key, str(SSEEventType.intel_job_update),
        extend_terminal=_extend_intel_terminal)


# ---------------------------------------------------------------- library import
_IMPORT_DESC = (
    "Downloads one curated open-source threat library and upserts it into the Threat_Type / "
    "Threat_Catalogue master tables (or Threat_Actor, for `misp_actors`).\n\n"
    "**Sources:** `pytm`, `emb3d`, `atlas` (threats) and `misp_actors` (adversary names).\n\n"
    "**Do a dry run first.** `{\"dry_run\": true}` reports the counts and a sample of the rows it "
    "WOULD create and writes nothing - `after_count` equals `before_count`, and "
    "`new_category_links` stays null because link newness is unknowable without writing.\n\n"
    "**Re-running is safe.** The upserts are first-writer: a second import adds nothing, "
    "rewrites no provenance, and never re-publishes a row a curator has since deactivated.\n\n"
    "**Vectors are handled for you.** On a successful real import this queues an embeddings "
    "`update` and returns its id as `embedding_job_id` - imported rows stay unsearchable until "
    "they are embedded.\n\n"
    "**What you get:** `202` with a `job_id`. Poll the status endpoint or stream the events one."
)

_IMPORT_STATUS_DESC = (
    "Reports how a queued import is going.\n\n"
    "**Call it:** every few seconds until `state` stops being `PENDING`, `STARTED` or `RETRY`. "
    "`RETRY` is NOT finished - the job hit a transient problem and is queued to run again.\n\n"
    "**Reading the result:** `result` is null until the job ends. A finished import carries its "
    "counts; an invalid source or unparseable content carries `error` instead, and is terminal - "
    "retrying will not help.\n\n"
    "**Watch out:** job ids expire with the result backend, roughly an hour, after which this "
    "returns `404`."
)

_IMPORT_EVENTS_DESC = (
    "Pushes one import job's progress live instead of polling.\n\n"
    "**Call it:** right after the import endpoint, using the job id it returned.\n\n"
    "**What arrives:** a state snapshot immediately, even for a job that already finished, then "
    "live updates. `RETRY` is not terminal and keeps the stream open; success or failure closes "
    "it.\n\n"
    "**Watch out:** a browser's built-in `EventSource` cannot be used, because this needs custom "
    "auth headers."
)


@router.post("/library/import/{source}", response_model=LibraryImportAccepted, status_code=202,
            summary="Import an open-source threat library", description=_IMPORT_DESC)
def import_library(body: LibraryImportBody, request: Request,
                source: Annotated[str, Path(description="pytm | emb3d | atlas | misp_actors")],
                principal: Principal = Depends(get_admin_principal)) -> LibraryImportAccepted:
    """Queue one library import.

    Validation happens HERE, before anything reaches the broker, so a bad request fails as a 422
    on this call instead of as a failed background job the caller has to go and poll for."""
    if source not in LIBRARY_SOURCES:
        raise AdminValidationError(f"unknown source {source!r} -- valid: {list(LIBRARY_SOURCES)}")
    if source != "misp_actors" and "max_actors" in body.model_fields_set:
        raise AdminValidationError("max_actors applies to the misp_actors source only")

    # ADVISORY probe -- not the guard. It cannot be atomic with the worker's acquire, so two
    # requests can both pass it; the lock inside import_threat_library_task is what actually
    # serializes them, turning the loser into a terminal "already running" job result. This just
    # makes the common case a fast 409 rather than a 202 that quietly does nothing.
    if is_held(lock_key(source), redis_factory=_slot_redis):
        raise ImportAlreadyRunning(f"an import of {source!r} is already running")

    task = import_threat_library_task.apply_async(
        args=(source, body.dry_run, body.activate, body.max_actors, principal.user_id),
        shadow=(f"library import: {source}{' (dry run)' if body.dry_run else ''} - "
                f"by {principal.user_id} - {dal.now():%Y-%m-%d %H:%M} UTC"))
    mark_admin_job(task.id, FAMILY_INTEL, f"library import: {source}", principal.user_id)
    # Audit AFTER the enqueue confirms (the job id proves it reached the broker): logging first
    # would leave a permanent record of an import that never ran when apply_async failed.
    log.warning("admin.library_import", source=source, dry_run=body.dry_run,
                activate=body.activate, job_id=task.id, user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return LibraryImportAccepted(job_id=task.id)


@router.get("/library/import/status/{job_id}", response_model=LibraryImportStatus,
            responses=UNAVAILABLE_RESPONSES,
            summary="Check a library import", description=_IMPORT_STATUS_DESC)
def import_status(job_id: str,
                _principal: Principal = Depends(get_admin_principal)) -> LibraryImportStatus:
    """Poll one import job.

    The provenance marker is checked FIRST: this route never calls require_entity, so without it
    any caller who learned another task's id could poll ITS result here - a real authorization
    bypass. Same contract as admin.py::get_status."""
    if not admin_job_exists(job_id, FAMILY_INTEL):
        raise NotFoundError(f"unknown or expired job_id: {job_id!r}")
    result = AsyncResult(job_id, app=celery_app)
    if result.failed():
        return LibraryImportStatus(job_id=job_id, state=result.state,
                                result={"error": str(result.result)[:2000]})
    payload = result.result if isinstance(result.result, dict) else None
    return LibraryImportStatus(job_id=job_id, state=result.state, result=payload)


@router.get("/library/import/events/{job_id}",
            responses={200: {"model": IntelJobEvent, "content": {"text/event-stream": {}},
                        "description": "SSE stream; each `data:` line is one IntelJobEvent."}}
                    | UNAVAILABLE_RESPONSES,
            summary="Stream a library import", description=_IMPORT_EVENTS_DESC)
async def import_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE for one import job - same hint-layer/AsyncResult-backstop contract as job_events
    above, sharing the intel job channel and the streaming mechanics in admin_sse.py."""
    return await admin_job_event_stream(
        job_id, FAMILY_INTEL, intel_job_channel_key, str(SSEEventType.intel_job_update))


# ---------------------------------------------------------------- technique reference
_TECH_REBUILD_DESC = (
    "Rebuilds the ATT&CK / CAPEC technique corpus that scenario writing consults.\n\n"
    "**What it is for:** these describe HOW a class of attack works. They are matched to the "
    "THREAT being written about, not to the asset - which is why they cannot live in the intel "
    "feed, whose product and sector tiers a technique never matches.\n\n"
    "**When to run it:** once to populate the corpus, then again when MITRE ships a release "
    "(roughly twice a year). Not a scheduled job.\n\n"
    "**Atomic:** the new corpus is staged and renamed over the live one, so a rebuild that fails "
    "or is killed leaves the previous corpus completely intact - never a half-populated one.\n\n"
    "**Vectors are warmed before publishing**, so the first scenario after a rebuild is not the "
    "request that pays for embedding ~800 passages.\n\n"
    "**What you get:** `202` with a `job_id`; stream it, or just read GET .../techniques after."
)

_TECH_STATUS_DESC = (
    "Reports what the technique corpus currently holds.\n\n"
    "**Read `total` first.** `0` with `available: true` means no rebuild has run yet - scenarios "
    "still work, and the prompt is byte-identical to the pre-feature one, but they are written "
    "without technique grounding. `available: false` means the corpus store is unreachable, "
    "which is a fault rather than an empty state.\n\n"
    "**No request body, no parameters.**"
)


@router.post("/techniques/rebuild", response_model=TechniqueRebuildAccepted, status_code=202,
            summary="Rebuild the ATT&CK/CAPEC technique corpus", description=_TECH_REBUILD_DESC)
def rebuild_techniques(body: TechniqueRebuildBody, request: Request,
                    principal: Principal = Depends(get_admin_principal)) -> TechniqueRebuildAccepted:
    """Queue a corpus rebuild. Source names are validated HERE so a typo is a 422 on this call
    rather than a background job that fails minutes later."""
    sources = list(body.sources) if body.sources else list(TECHNIQUE_SOURCES)
    unknown = [s for s in sources if s not in TECHNIQUE_SOURCES]
    if unknown:
        raise AdminValidationError(
            f"unknown technique source(s) {unknown} -- valid: {list(TECHNIQUE_SOURCES)}")

    task = rebuild_technique_reference_task.apply_async(
        args=(sources, principal.user_id),
        shadow=(f"technique rebuild: {','.join(sources)} - by {principal.user_id} - "
                f"{dal.now():%Y-%m-%d %H:%M} UTC"))
    mark_admin_job(task.id, FAMILY_INTEL, "technique rebuild", principal.user_id)
    log.warning("admin.technique_rebuild", sources=sources, job_id=task.id,
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return TechniqueRebuildAccepted(job_id=task.id)


@router.get("/techniques", response_model=TechniqueCorpusStatus,
            responses=UNAVAILABLE_RESPONSES,
            summary="Check the technique corpus", description=_TECH_STATUS_DESC)
def technique_corpus(_principal: Principal = Depends(get_admin_principal)) -> TechniqueCorpusStatus:
    """Live corpus counts. Never raises on an unreachable store: it reports available=false, so a
    Mongo outage reads as a fault here instead of as an empty corpus."""
    return TechniqueCorpusStatus(**technique_stats())


@router.get("/techniques/events/{job_id}",
            responses={200: {"model": IntelJobEvent, "content": {"text/event-stream": {}},
                        "description": "SSE stream; each `data:` line is one IntelJobEvent."}}
                    | UNAVAILABLE_RESPONSES,
            summary="Stream a technique rebuild", description=_IMPORT_EVENTS_DESC)
async def technique_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE for one rebuild job - same contract and channel as the import and feed streams."""
    return await admin_job_event_stream(
        job_id, FAMILY_INTEL, intel_job_channel_key, str(SSEEventType.intel_job_update))
