"""Generic TAXII 2.1 client — one thin wrapper so every TAXII-speaking source
(MITRE ATT&CK today; an org OpenCTI or MISP instance tomorrow) is a config entry,
never new code. Requires the small `taxii2-client` dependency; imported lazily so
the rest of the app never needs it installed.
"""
from __future__ import annotations

from typing import Any, Iterator

# MITRE's public ATT&CK TAXII 2.1 server (no auth). Collection ids are stable and
# published by MITRE; if one ever rotates, the TAXII 404 error names the bad id.
MITRE_TAXII_ROOT = "https://attack-taxii.mitre.org/api/v21/"
MITRE_COLLECTIONS = {
    "attack": "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019",      # Enterprise
    "attack_ics": "x-mitre-collection--02c3ef24-9cd4-48f3-a99f-b74ce24f1d34",  # ICS
}


# Bounds for a call into a THIRD-PARTY server. taxii2client wraps `requests`, which defaults to
# NO timeout — an unresponsive TAXII endpoint would hang the importing worker indefinitely (the
# sibling https-download path is already bounded at 180s). The page cap is the matching guard for
# the pagination loop: a server that always reports `more` would otherwise stream forever.
_TAXII_TIMEOUT_SECONDS = 180
_MAX_PAGES = 500


def _timeout_bound(request_fn):
    """taxii2client exposes no timeout setting, so bind one onto the requests.Session it uses —
    the only injection point that covers every call it makes (discovery, collections, paging)."""
    def _bounded(*args, **kwargs):
        kwargs.setdefault("timeout", _TAXII_TIMEOUT_SECONDS)
        return request_fn(*args, **kwargs)
    return _bounded


def _collection(server_url: str, collection_id: str):
    from taxii2client.v21 import ApiRoot  # lazy: optional dependency

    api_root = ApiRoot(server_url)
    api_root._conn.session.request = _timeout_bound(api_root._conn.session.request)  # noqa: SLF001
    for col in api_root.collections:
        if col.id == collection_id or collection_id in str(col.id):
            col._conn.session.request = _timeout_bound(col._conn.session.request)  # noqa: SLF001
            return col
    raise LookupError(f"collection {collection_id!r} not found at {server_url}")


def iter_objects(server_url: str, collection_id: str, added_after: str | None = None) -> Iterator[dict[str, Any]]:
    """Yield raw STIX object dicts from one TAXII collection, following pagination.
    `added_after` (ISO timestamp) makes the pull incremental. Every request is timeout-bound and
    the page walk is capped — see the constants above."""
    col = _collection(server_url, collection_id)
    kwargs = {"added_after": added_after} if added_after else {}
    envelope = col.get_objects(**kwargs)
    for _page in range(_MAX_PAGES):
        yield from envelope.get("objects", [])
        if not envelope.get("more"):
            return
        envelope = col.get_objects(next=envelope["next"], **kwargs)
    raise RuntimeError(
        f"TAXII collection {collection_id!r} at {server_url} still reported more pages after "
        f"{_MAX_PAGES} — refusing to page forever")


def fetch_collection_bundle(source: str) -> dict[str, Any]:
    """ATT&CK via live TAXII for scripts/import_threat_libraries.py --via taxii —
    returns the same {'objects': [...]} shape as the GitHub STIX bundle download,
    so the importer's adapters work identically on either path."""
    collection_id = MITRE_COLLECTIONS[source]
    return {"objects": list(iter_objects(MITRE_TAXII_ROOT, collection_id))}
