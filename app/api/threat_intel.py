"""Live threat-intel admin API — feed status and on-demand refresh.

The second of TSG's two external-data channels. The threat-library import
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

from fastapi import APIRouter, Depends, Request

from app.api.admin_jobs import FAMILY_INTEL, mark_admin_job
from app.api.deps import Principal, get_principal, require_admin
from app.api.schemas import IntelFeedsResponse, IntelFeedStatus, IntelRefreshAccepted
from app.core.logging import get_logger
from app.db.dal import NotFoundError
from app.intel.fetchers import ALL_FEEDS, enabled_feed_names, feed_status
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
def list_feeds(_principal: Principal = Depends(get_principal)) -> IntelFeedsResponse:
    """Every known feed with its cached volume, freshness and last outcome.

    Deliberately reports disabled feeds too: "switched off", "enabled but never run" and
    "ran and failed" are three different operational states, and an endpoint that only
    listed active feeds would collapse them into one silence. Note a successful refresh
    can legitimately add zero items — the incremental feeds skip what they already hold —
    so judge health by `last_success_at`, not by `item_count` moving."""
    return IntelFeedsResponse(feeds=[IntelFeedStatus(**f) for f in feed_status()])


@router.post("/feeds/refresh", response_model=IntelRefreshAccepted, status_code=202)
def refresh_all_feeds(request: Request,
                      principal: Principal = Depends(get_principal)) -> IntelRefreshAccepted:
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
                 principal: Principal = Depends(get_principal)) -> IntelRefreshAccepted:
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
