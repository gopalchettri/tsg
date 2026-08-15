"""Live threat-intel admin API — feed status and on-demand refresh.

TSG's two external-data channels. The threat-library import
(app/api/threat_library_import.py) loads DURABLE catalogue knowledge into SQL; these
routes drive the PERISHABLE side — CISA KEV, CISA ICS advisories, OTX, URLhaus and any
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

from celery.result import AsyncResult
from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.api.admin_jobs import FAMILY_INTEL, intel_job_channel_key, mark_admin_job
from app.api.admin_sse import admin_job_event_stream
from app.api.deps import Principal, get_admin_principal, require_admin
from app.api.schemas import (
    IntelFeedsResponse,
    IntelFeedStatus,
    IntelItem,
    IntelItemsResponse,
    IntelRefreshAccepted,
)
from app.core.enums import SSEEventType
from app.core.logging import get_logger
from app.db.dal import NotFoundError
from app.intel.fetchers import ALL_FEEDS, enabled_feed_names, feed_status, list_intel
from app.pipeline.celery_app import intel_refresh_feed_task

router = APIRouter(
    prefix="/v1/tsg/threat-intel",
    tags=["Threat Intel Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


def _dispatch(feeds: list[str]) -> IntelRefreshAccepted:
    """Queue one job per feed — the fan-out. Indirection so tests can run refreshes
    synchronously, same pattern as the import router's _enqueue."""
    jobs = {}
    for feed in feeds:
        task = intel_refresh_feed_task.delay(feed)
        mark_admin_job(task.id, FAMILY_INTEL)  # best-effort — see admin_jobs.mark_admin_job
        jobs[feed] = task.id
    return IntelRefreshAccepted(jobs=jobs)


@router.get("/feeds", response_model=IntelFeedsResponse)
def list_feeds(_principal: Principal = Depends(get_admin_principal)) -> IntelFeedsResponse:
    """Every known feed with its cached volume, freshness and last outcome.

    Deliberately reports disabled feeds too: "switched off", "enabled but never run" and
    "ran and failed" are three different operational states, and an endpoint that only
    listed active feeds would collapse them into one silence. Note a successful refresh
    can legitimately add zero items — the incremental feeds skip what they already hold —
    so judge health by `last_success_at`, not by `item_count` moving."""
    return IntelFeedsResponse(feeds=[IntelFeedStatus(**f) for f in feed_status()])


@router.get("/items", response_model=IntelItemsResponse)
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


@router.post("/feeds/refresh", response_model=IntelRefreshAccepted, status_code=202)
def refresh_all_feeds(request: Request,
                    principal: Principal = Depends(get_admin_principal)) -> IntelRefreshAccepted:
    """Refresh every ENABLED feed now, without waiting for the daily schedule.

    Fans out to one job per feed rather than one job doing all of them, so a slow or
    broken feed can neither delay nor fail the others. Returns the job id queued per feed;
    read the outcomes from GET /feeds, which survives the jobs expiring."""
    feeds = enabled_feed_names()
    accepted = _dispatch(feeds)
    log.warning("admin.threat_intel_refresh", action="refresh_all", feeds=feeds,
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return accepted


@router.post("/feeds/{feed}/refresh", response_model=IntelRefreshAccepted, status_code=202)
def refresh_feed(feed: str, request: Request,
                principal: Principal = Depends(get_admin_principal)) -> IntelRefreshAccepted:
    """Refresh ONE feed — the targeted retry after a failure, instead of re-pulling
    everything. Unknown feed → 404 (it is the addressed resource); a known but disabled
    feed → 404 as well, with a message naming it as disabled, since there is nothing to
    refresh until configuration switches it on."""
    if feed not in ALL_FEEDS:
        raise NotFoundError(f"unknown intel feed: {feed!r} — valid: {sorted(ALL_FEEDS)}")
    if feed not in enabled_feed_names():
        raise NotFoundError(f"intel feed {feed!r} is not enabled — switch it on in configuration first")
    accepted = _dispatch([feed])
    log.warning("admin.threat_intel_refresh", action="refresh_feed", feeds=[feed],
                user_id=principal.user_id,
                source_ip=request.client.host if request.client else None)
    return accepted


def _extend_intel_terminal(result: AsyncResult) -> dict:
    """intel_refresh_feed_task returns a bare item count, not a dict (unlike import/embeddings)
    — map it to a named field instead of the shared default's dict-spread, which would do
    nothing for a plain int."""
    return {"item_count": result.result} if isinstance(result.result, int) else {}


@router.get("/feeds/events/{job_id}", responses={200: {"content": {"text/event-stream": {}}}})
async def job_events(job_id: str, _principal: Principal = Depends(get_admin_principal)):
    """SSE stream for one queued per-feed refresh job (one of the ids in
    IntelRefreshAccepted.jobs): a state snapshot on connect, then the worker's live
    `intel_job_update` hints (STARTED, then either terminal SUCCESS/FAILURE or a non-terminal
    RETRY — see intel_refresh_feed_task's docstring for why RETRY must stay non-terminal here) —
    same hint-layer/AsyncResult-backstop contract as admin.py::job_events. GET /feeds (per-feed
    last_success_at/last_error) remains the durable truth; there is no separate per-job GET
    status route for intel today, so this stream reads AsyncResult directly, same as it does.
    Streaming mechanics live in admin_sse.py, shared with the embeddings and import job-events
    routes."""
    return await admin_job_event_stream(
        job_id, FAMILY_INTEL, intel_job_channel_key, str(SSEEventType.intel_job_update),
        extend_terminal=_extend_intel_terminal)
