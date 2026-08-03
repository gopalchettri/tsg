"""Live threat-intel: fetcher parsing, the prompt-kind guard, fan-out isolation, and the
admin API. Closes a real gap — before this file the whole intel feature had ZERO tests, so
a feed changing its published format would have silently produced empty enrichment forever
instead of failing anything.

Fetchers are exercised against small recorded fixtures (never the network), so these tests
are hermetic and fast; what they pin is the parse contract between each external format and
`_doc`'s shape.
"""
from __future__ import annotations

import json

import pytest

from app.core.config import get_settings
from app.intel import fetchers

_KEY = "test-admin-key"

# --- fixtures: the minimum shape of each real feed ------------------------------------
_KEV = {"vulnerabilities": [
    {"cveID": "CVE-2024-1234", "vulnerabilityName": "Acme RCE", "shortDescription": "d",
     "vendorProject": "Acme", "product": "Widget", "dateAdded": "2026-07-01"}]}

_URLHAUS = [{"url": "http://bad.example/x", "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
             "threat": "malware_download"}]

_OTX = {"results": [
    {"id": "p1", "name": "Campaign X", "description": "d", "tags": ["ot"], "adversary": "Toy Ghouls"},
    {"id": "p2", "name": "Campaign Y", "description": "d", "tags": []},
]}


class _Resp:
    """Minimal stand-in for the bytes _get returns."""

    def __init__(self, payload):
        self._b = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def __call__(self, url, *a, **k):
        return self._b


class _FakeCol:
    """Just enough Mongo surface for refresh_one's upsert path."""

    def __init__(self):
        self.written = []

    @property
    def database(self):
        return {"intel_feed_status": self}

    def bulk_write(self, ops, **k):
        self.written.extend(ops)

    def update_one(self, *a, **k):
        pass


def test_fetch_kev_parses_into_doc_shape(monkeypatch):
    monkeypatch.setattr(fetchers, "_get", _Resp(_KEV))
    docs = fetchers.fetch_kev(get_settings())
    assert len(docs) == 1
    d = docs[0]
    assert d["source"] == "cisa_kev" and d["kind"] == "cve"
    assert d["external_id"] == "CVE-2024-1234" and "Acme RCE" in d["title"]


def test_fetch_urlhaus_parses_and_is_ioc_kind(monkeypatch):
    monkeypatch.setattr(fetchers, "_get", _Resp(_URLHAUS))
    docs = fetchers.fetch_urlhaus(get_settings())
    assert len(docs) == 1
    # ioc_url is deliberately NOT a PROMPT_KIND — this is the value that keeps raw
    # indicators out of the LLM context (see test_only_prompt_kinds_reach_prompts).
    assert docs[0]["kind"] == "ioc_url" and docs[0]["kind"] not in fetchers.PROMPT_KINDS


def test_fetch_otx_parses_pulses(monkeypatch):
    monkeypatch.setattr(fetchers, "_get", _Resp(_OTX))
    s = get_settings().model_copy(update={"intel_otx_api_key": "k"})
    docs = fetchers.fetch_otx(s)
    assert len(docs) == 2 and all(d["kind"] == "pulse" and d["source"] == "otx" for d in docs)
    # adversary → prepended to the title (the prompt shows only the first 140 title chars,
    # so front placement is what guarantees it survives) and inserted as the first tag
    assert docs[0]["title"] == "[Toy Ghouls] Campaign X"
    assert docs[0]["tags"][0] == "toy ghouls" and "ot" in docs[0]["tags"]
    # no adversary → title and tags untouched
    assert docs[1]["title"] == "Campaign Y" and docs[1]["tags"] == []


def test_fetch_intel_includes_library_actors(monkeypatch):
    """The threat's library actors must reach query_intel's terms — that is what lets a
    pulse tagged with its adversary (fetch_otx) surface for an actor-linked threat."""
    from app.pipeline import tasks

    captured = {}

    def fake_query(terms, prefer_kinds=("cve",), limit=5):
        captured["terms"] = list(terms)
        return []

    monkeypatch.setattr(fetchers, "query_intel", fake_query)
    tasks._fetch_intel("Ransomware", "Production server encryption", ["Toy Ghouls"])
    assert "Toy Ghouls" in captured["terms"]  # whole name, never word-split
    assert "Ransomware" in captured["terms"]


def test_only_prompt_kinds_reach_prompts():
    """The guard that keeps IOC feeds out of the LLM context. Nothing enforced this before."""
    assert "ioc_url" not in fetchers.PROMPT_KINDS
    assert set(fetchers.PROMPT_KINDS) == {"cve", "ics_advisory", "pulse"}
    assert "urlhaus" not in fetchers.PROMPTED_FEEDS
    assert set(fetchers.PROMPTED_FEEDS) <= set(fetchers.ALL_FEEDS)


def test_query_intel_fails_open_when_store_unavailable(monkeypatch):
    """Mongo down must degrade scenario generation to 'no enrichment', never raise."""
    monkeypatch.setattr(fetchers, "_store_if_healthy", lambda: None)
    assert fetchers.query_intel(["ransomware"]) == []


def test_refresh_one_rejects_unknown_and_disabled_feeds(monkeypatch):
    monkeypatch.setattr(fetchers, "_enabled_fetchers", lambda s: [("cisa_kev", fetchers.fetch_kev)])
    with pytest.raises(ValueError, match="phishtank"):
        fetchers.refresh_one("phishtank")          # never a feed at all
    with pytest.raises(ValueError, match="urlhaus"):
        fetchers.refresh_one("urlhaus")            # known, but switched off


def test_refresh_all_isolates_one_failing_feed(monkeypatch):
    """Fan-out's whole point: a broken feed must not stop the others, and its failure must
    be RECORDED rather than lost with the job result."""
    recorded = {}

    def boom(_s):
        raise RuntimeError("HTTP 403")

    monkeypatch.setattr(fetchers, "_get", _Resp(_KEV))
    monkeypatch.setattr(fetchers, "_enabled_fetchers",
                        lambda s: [("cisa_kev", fetchers.fetch_kev), ("cisa_ics", boom)])
    monkeypatch.setattr(fetchers, "_store_if_healthy", lambda: _FakeCol())
    monkeypatch.setattr(fetchers, "_record_feed_status",
                        lambda col, feed, **kw: recorded.__setitem__(feed, kw))

    results = fetchers.refresh_all()
    assert results["cisa_kev"] == 1        # healthy feed still completed
    assert results["cisa_ics"] == -1       # broken feed reported, not raised
    assert recorded["cisa_ics"]["error"].startswith("RuntimeError")   # failure persisted


def test_feed_status_reports_every_feed_including_disabled(monkeypatch):
    """'switched off', 'never run' and 'ran and failed' must be three visible states —
    an endpoint that listed only active feeds would collapse them into one silence."""
    monkeypatch.setattr(fetchers, "_enabled_fetchers", lambda s: [("cisa_kev", fetchers.fetch_kev)])
    monkeypatch.setattr(fetchers, "_store_if_healthy", lambda: None)  # no cache data at all
    rows = {f["feed"]: f for f in fetchers.feed_status()}
    assert set(rows) == set(fetchers.ALL_FEEDS)          # every known feed present
    assert rows["cisa_kev"]["enabled"] is True
    assert rows["urlhaus"]["enabled"] is False           # off, not missing
    assert rows["cisa_kev"]["last_success_at"] is None   # enabled but never ran


# --- API ------------------------------------------------------------------------------
@pytest.fixture()
def intel_client(engine, monkeypatch):
    from tests.conftest import make_client

    monkeypatch.setenv("TSG_ADMIN_API_KEY", _KEY)
    get_settings.cache_clear()
    yield make_client({"5"})
    get_settings.cache_clear()


def test_feeds_endpoint_lists_all_feeds(intel_client, monkeypatch):
    monkeypatch.setattr(fetchers, "_store_if_healthy", lambda: None)
    r = intel_client.get("/v1/tsg/threat-intel/feeds", headers={"X-Admin-Key": _KEY})
    assert r.status_code == 200
    feeds = {f["feed"]: f for f in r.json()["feeds"]}
    assert set(feeds) == set(fetchers.ALL_FEEDS)
    assert feeds["urlhaus"]["prompted"] is False   # IOC feed, cached but never prompted


def test_feeds_endpoint_requires_admin_key(intel_client):
    assert intel_client.get("/v1/tsg/threat-intel/feeds").status_code == 401


def test_refresh_unknown_or_disabled_feed_is_404(intel_client, monkeypatch):
    import app.api.threat_intel as api

    monkeypatch.setattr(api, "enabled_feed_names", lambda: ["cisa_kev"])
    h = {"X-Admin-Key": _KEY}
    assert intel_client.post("/v1/tsg/threat-intel/feeds/phishtank/refresh", headers=h).status_code == 404
    assert intel_client.post("/v1/tsg/threat-intel/feeds/urlhaus/refresh", headers=h).status_code == 404


def test_refresh_dispatches_one_job_per_feed(intel_client, monkeypatch):
    """The fan-out contract: all-feeds returns a job id PER FEED, not one job for all."""
    import app.api.threat_intel as api

    monkeypatch.setattr(api, "enabled_feed_names", lambda: ["cisa_kev", "cisa_ics"])
    monkeypatch.setattr(api.intel_refresh_feed_task, "delay",
                        lambda feed: type("T", (), {"id": f"job-{feed}"})())
    r = intel_client.post("/v1/tsg/threat-intel/feeds/refresh", headers={"X-Admin-Key": _KEY})
    assert r.status_code == 202
    assert r.json()["jobs"] == {"cisa_kev": "job-cisa_kev", "cisa_ics": "job-cisa_ics"}
