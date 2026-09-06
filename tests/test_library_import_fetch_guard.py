"""Every import download goes through one checked door.

Import source URLs are configuration, and configuration that steers an outgoing fetch is a trust
boundary: a typo or a tampered env can point a worker at cloud metadata (169.254.169.254) or an
internal service. urllib also follows redirects blindly, so even a pinned https URL can be walked
elsewhere by a hijacked upstream answering 302.

The streaming work added two download sites without the guard the first one never had either.
That is why the last test here is a tripwire rather than a unit test: it is the only thing that
stops download number four shipping unguarded the same way.
"""
from __future__ import annotations

import ast
import urllib.request
from pathlib import Path

import pytest

from app.intel import library_import as li
from app.intel.library_import import ThreatLibraryImportError

_MODULE = Path(li.__file__)


@pytest.mark.parametrize("url,expected", [
    ("http://raw.githubusercontent.com/x", "non-https"),
    ("ftp://raw.githubusercontent.com/x", "non-https"),
])
def test_non_https_is_refused(url, expected):
    with pytest.raises(ThreatLibraryImportError, match=expected):
        li._open(url)


@pytest.mark.parametrize("host", [
    "169.254.169.254",   # AWS/GCP/Azure instance metadata — the classic SSRF target
    "127.0.0.1",
    "localhost",
    "[::1]",
])
def test_ip_literals_and_loopback_are_refused(host):
    with pytest.raises(ThreatLibraryImportError, match="IP-literal or loopback"):
        li._open(f"https://{host}/threats.json")


def test_a_host_outside_the_allowlist_is_refused():
    """An operator typo in TSG_LIBRARY_*_URL must fail loudly, not fetch."""
    with pytest.raises(ThreatLibraryImportError, match="not an allowed feed host"):
        li._open("https://evil.example.com/threats.json")


def test_an_allowed_host_is_accepted_and_reaches_the_hardened_opener(monkeypatch):
    """The happy path still works, and it goes through fetchers' redirect-checked opener rather
    than a bare urlopen — otherwise a 302 could still walk it anywhere."""
    seen = {}

    class _FakeOpener:
        def open(self, req, timeout=None):
            seen["url"] = req.full_url
            seen["ua"] = req.get_header("User-agent")
            seen["timeout"] = timeout
            return "response"

    monkeypatch.setattr("app.intel.fetchers._opener", lambda: _FakeOpener())
    assert li._open("https://raw.githubusercontent.com/OWASP/pytm/x.json") == "response"
    assert seen["url"].startswith("https://raw.githubusercontent.com/")
    assert seen["ua"] == "TSG-library-import/1.0"
    assert seen["timeout"] == li._FETCH_TIMEOUT_S


def test_no_download_bypasses_the_guard() -> None:
    """TRIPWIRE. A bare urlopen anywhere in this module is an unguarded download.

    Checked at the AST level so the docstrings above — which mention urlopen by name — are
    naturally exempt: only a real call counts. If this fails you have added a download; route it
    through _open() rather than calling urllib directly.
    """
    tree = ast.parse(_MODULE.read_text(encoding="utf-8"), filename=str(_MODULE))
    offenders = [
        n.lineno for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "urlopen"
    ]
    assert not offenders, (
        f"unguarded urllib urlopen at line(s) {offenders} in {_MODULE.name}. Every import "
        "download must go through _open(), which checks scheme, host and redirects. This "
        "tripwire exists because two such downloads were added without the guard already.")


# ---------------------------------------------------------------- redirects
# A pinned https URL can still be walked elsewhere by a hijacked upstream answering 302, so the
# scheme/host checks above are only half the guard. These assert BOTH halves: that _open is wired
# to fetchers' redirect handler, and that the handler actually refuses. Driven directly rather
# than over a socket -- no network in the suite.

def test_open_is_wired_to_the_redirect_checked_opener():
    """The scheme/host checks run once, on the initial URL. Everything after the first hop is the
    redirect handler's job, so being wired to it is load-bearing, not incidental."""
    from app.intel.fetchers import _opener, _RedirectPolicy

    assert any(isinstance(h, _RedirectPolicy) for h in _opener().handlers), (
        "_open() must go through the opener carrying _RedirectPolicy; without it a 302 is "
        "followed anywhere and the initial-URL checks are trivially bypassed")


def _redirect_to(newurl: str):
    from app.intel.fetchers import _RedirectPolicy
    req = urllib.request.Request("https://raw.githubusercontent.com/a.json",
                                 headers={"User-Agent": "TSG", "X-Secret": "leak-me"})
    return _RedirectPolicy().redirect_request(req, None, 302, "Found", {}, newurl)


@pytest.mark.parametrize("target", [
    "https://evil.example.com/x",     # off-allowlist
    "https://169.254.169.254/x",      # metadata
    "http://raw.githubusercontent.com/x",  # downgrade to plaintext
])
def test_a_redirect_off_the_allowlist_is_refused(target):
    with pytest.raises(ValueError, match="redirect refused"):
        _redirect_to(target)


def test_a_cross_host_redirect_drops_every_header_but_user_agent():
    """An allowed-but-different host must not receive the original request's headers -- that is
    how a credential rides along to somewhere it was never meant to go."""
    new = _redirect_to("https://www.cisa.gov/x")
    assert new is not None
    assert new.get_header("User-agent") == "TSG"
    assert new.get_header("X-secret") is None, "headers must not survive a cross-host hop"
