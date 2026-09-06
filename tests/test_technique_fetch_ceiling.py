"""Remote JSON is STREAMED, not loaded whole — and the guards that made whole-loading safe survive.

FOUND LIVE, in one morning:
  * POST /v1/tsg/threat-intel/techniques/rebuild failed 100% of the time — "source content
    exceeds the 25 MB ceiling" — because MITRE's ATT&CK Enterprise bundle is 51.3 MB and the
    download helper had ONE global ceiling shared with the 261 KB library feeds.
  * Raising that ceiling was a delay, not a fix: it is really a stand-in for "don't exhaust the
    worker's RAM", because the body was read whole and then parsed whole (~0.5-1 GB of Python
    objects) to produce 647 records of six short fields.

So the contract changed from "download the body" to "yield the records", and these tests pin the
PROPERTY rather than a number — a number is what rotted last time. Measured after the change:
peak 12.6 MB to build all 900 entries from that same 51.3 MB file.

No network: the helper takes any URL, so a file:// URL exercises the real code path.
"""
from __future__ import annotations

import ast
import inspect
import json
import pathlib
import tracemalloc

import pytest

from app.intel import library_import, technique_reference
from app.intel.library_import import ThreatLibraryImportError, stream_json_array


@pytest.fixture(autouse=True)
def _stub_transport(monkeypatch):
    """These tests feed fixtures through file:// URLs so the REAL streaming path runs with no
    network (see the module docstring). library_import._open now refuses any non-https URL by
    design -- source URLs are configuration, and configuration that can name file:// could read
    local files -- so the transport DOOR is stubbed here and nothing else is.

    Everything actually under test is untouched: ijson streaming, _CountingReader, the byte and
    item ceilings, and the shape guards all run exactly as in production. Only the three lines
    that open a socket are bypassed.
    """
    import urllib.request

    monkeypatch.setattr(library_import, "_open",
                        lambda url, **_kw: urllib.request.urlopen(url))


def _file_url(tmp_path: pathlib.Path, payload, name: str = "src.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p.as_uri()


# --- the property that replaces the old size constant ---------------------------------------
def test_records_are_yielded_lazily_not_materialised(tmp_path):
    """The whole point. If this ever returns a list again, memory goes back to O(file)."""
    url = _file_url(tmp_path, {"objects": [{"i": i} for i in range(5000)]})
    stream = stream_json_array(url, "objects.item")
    assert inspect.isgenerator(stream), "stream_json_array must not build the list"
    first = next(stream)
    assert first == {"i": 0}, "records arrive one at a time, in order"
    stream.close()


def test_peak_memory_stays_far_below_the_file_size(tmp_path):
    """MEASURE it, do not just assert the type.

    inspect.isgenerator only proves the function is a generator; a generator that internally
    buffered the whole document would sail past it while reintroducing exactly the memory
    profile this rewrite removed. tracemalloc is what actually pins the property.
    """
    payload = {"objects": [{"id": f"T{i:05d}", "text": "x" * 400} for i in range(6000)]}
    url = _file_url(tmp_path, payload, "big.json")
    size = (tmp_path / "big.json").stat().st_size
    assert size > 2_000_000, "fixture too small to prove anything"

    tracemalloc.start()
    count = sum(1 for _ in stream_json_array(url, "objects.item"))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert count == 6000
    assert peak < size / 4, (
        f"peak {peak/1024:.0f}KB against a {size/1024:.0f}KB file — the document is being "
        "buffered somewhere; streaming has regressed to a whole-file read")


def test_a_huge_record_count_still_completes(tmp_path):
    """Bounded memory, not a bounded file: this many dicts held at once would be the old bug."""
    url = _file_url(tmp_path, {"objects": [{"i": i} for i in range(50_000)]})
    assert sum(1 for _ in stream_json_array(url, "objects.item")) == 50_000


# --- the guards that must SURVIVE the refactor ----------------------------------------------
def test_the_byte_ceiling_still_fires_while_streaming(tmp_path):
    """Streaming must not become an unbounded read. The DoS guard is the reason the ceiling
    existed at all — losing it while 'fixing' the ceiling would be the worst outcome here."""
    url = _file_url(tmp_path, {"objects": [{"padding": "x" * 500} for _ in range(200)]})
    with pytest.raises(ThreatLibraryImportError, match="ceiling"):
        list(stream_json_array(url, "objects.item", max_bytes=2048))


def test_the_item_ceiling_fires(tmp_path):
    """A small file can still be pathologically deep in records."""
    url = _file_url(tmp_path, {"objects": [{"i": i} for i in range(500)]})
    with pytest.raises(ThreatLibraryImportError, match="more than 10 records"):
        list(stream_json_array(url, "objects.item", max_items=10))


def test_a_wrong_shape_yields_nothing_rather_than_half_parsing(tmp_path):
    """Whole-document validation is impossible on a stream; 'the path matched nothing' is what
    replaces it, and _streamed_objects turns that into the original error message."""
    url = _file_url(tmp_path, {"not_objects": [{"i": 1}]})
    assert list(stream_json_array(url, "objects.item")) == []


def test_library_imports_keep_the_tight_25mb_whole_read_ceiling():
    """Only the streamed paths get a large ceiling. atlas and emb3d are still read whole, so
    their guard must stay tight — loosening it for everyone was the wrong fix we avoided."""
    assert library_import._MAX_FETCH_BYTES == 25 * 1024 * 1024
    assert (inspect.signature(library_import._get).parameters["max_bytes"].default
            == library_import._MAX_FETCH_BYTES)
    assert library_import._MAX_STREAM_BYTES > library_import._MAX_FETCH_BYTES


# --- structural tripwire, same family as tests/test_retired_features.py ----------------------
def test_no_streamed_module_loads_a_whole_document_again():
    """A future source added the old way must fail HERE, not in production six months later when
    that file crosses the ceiling."""
    offenders = []
    for mod in (technique_reference, library_import):
        src = inspect.getsource(mod)
        for node in ast.walk(ast.parse(src)):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "loads"
                    and any(isinstance(a, ast.Call) and getattr(a.func, "id", "") == "_get"
                            for a in node.args)):
                offenders.append(f"{mod.__name__}:{node.lineno}")
    assert not offenders, (
        f"json.loads(_get(...)) is back at {offenders} — that reintroduces the whole-file "
        "memory profile streaming was added to remove")


def test_every_technique_source_is_streamed():
    """technique_reference has no whole-read path left, so a source added without one would
    break at runtime. Pin the set so that is a test failure instead."""
    assert set(technique_reference.URLS) == {"attack", "attack_ics", "capec"}
    assert "stream_json_array" in inspect.getsource(technique_reference)


def test_streamed_library_sources_are_declared_and_the_rest_are_deliberate():
    """STREAM_PATHS is the allow-list. atlas (YAML) and emb3d (ambiguous top level) are excluded
    on purpose; anything else missing means a source silently fell back to the 25 MB whole read."""
    assert set(library_import.STREAM_PATHS) == {"pytm", "misp_actors"}
    assert set(library_import.URLS) - set(library_import.STREAM_PATHS) == {"atlas", "emb3d"}


# --- the streamed entry points that actually run in production ------------------------------
# These five had NO coverage: the tests above exercised stream_json_array directly, and the
# builder/adapter tests handed over whole dicts — so every seam BETWEEN them (path resolution,
# empty-vs-wrong-shape, scalar capture, iterator-accepting adapters) was unverified in exactly
# the configuration production uses.

def test_capturing_variant_collects_scalars_and_records_in_one_pass(tmp_path):
    """CISA KEV needs its `vulnerabilities` array AND a top-level `catalogVersion`. Two passes
    would double a 2 MB download; this proves one pass yields both."""
    url = _file_url(tmp_path, {
        "title": "cat", "catalogVersion": "2026.09.04", "dateReleased": "2026-09-04T00:00:00Z",
        "vulnerabilities": [{"cveID": "CVE-1"}, {"cveID": "CVE-2"}],
    }, "kev.json")
    header: dict = {}
    items = list(library_import.stream_json_array_capturing(
        url, "vulnerabilities.item", {"catalogVersion", "dateReleased"}, header))
    assert [i["cveID"] for i in items] == ["CVE-1", "CVE-2"]
    assert header["catalogVersion"] == "2026.09.04"
    assert header["dateReleased"] == "2026-09-04T00:00:00Z"


def test_an_empty_array_is_data_but_a_missing_array_is_an_error(tmp_path, monkeypatch):
    """The distinction json.loads gave for free and streaming nearly destroyed.

    An upstream that publishes [] must reach run_import's "0 usable records" WARNING, not fail
    the job. A document with no such array at all is still a shape error.
    """
    empty = _file_url(tmp_path, {"values": []}, "empty.json")
    wrong = _file_url(tmp_path, {"nope": [{"value": "x"}]}, "wrong.json")

    monkeypatch.setitem(library_import.URLS, "misp_actors", empty)
    assert list(library_import._streamed_records("misp_actors")) == []

    monkeypatch.setitem(library_import.URLS, "misp_actors", wrong)
    with pytest.raises(ThreatLibraryImportError, match="does not match"):
        list(library_import._streamed_records("misp_actors"))


def test_load_streams_the_declared_sources_and_parses_the_rest(tmp_path, monkeypatch):
    """load() is the dispatch point: STREAM_PATHS sources come back as an iterator, others as a
    parsed document. Get this wrong and an adapter silently receives the wrong kind of thing."""
    url = _file_url(tmp_path, [{"SID": "AA01", "description": "d"}], "pytm.json")
    monkeypatch.setitem(library_import.URLS, "pytm", url)
    out = library_import.load("pytm")
    assert not isinstance(out, (list, dict)), "a STREAM_PATHS source must not be materialised"
    assert [r["SID"] for r in out] == ["AA01"]


def test_adapters_accept_a_bare_iterator_not_only_a_document():
    """Production hands these iterators; the older unit tests hand dicts. Both must work, or the
    streamed path is exercised for the first time in production."""
    from app.intel.fetchers import kev_docs

    actors, _ = library_import.adapt_misp_actors(
        iter([{"value": "Sandworm", "meta": {"cfr-suspected-state-sponsor": "Russia"}}]), 10)
    assert isinstance(actors, list)

    docs = kev_docs(iter([{"cveID": "CVE-2026-1", "vendorProject": "V", "product": "P",
                           "vulnerabilityName": "n", "shortDescription": "d",
                           "dateAdded": "2026-01-01"}]))
    assert len(docs) == 1 and docs[0]["external_id"] == "CVE-2026-1"
