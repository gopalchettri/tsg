"""Which HTTP routes does no test ever enter? READ-ONLY, static, seconds.

WHY THIS EXISTS. Tests in this repo call pipeline functions directly, because that is fast and
convenient. The consequence is that ROUTE BODIES go unexecuted — their auth wiring, their
parameter handling, their response mapping, and above all the line that calls the pipeline at all.

That line is where this codebase's characteristic defect lives. app/api/sessions.py's reject route
reaches dal.decide_scenarios through accept.reject_scenarios; tests/test_scenario_reject.py calls
reject_scenarios directly. Change the route's call to `matched = 0` and the endpoint reports
success, rejects nothing, and every test still passes.

That is not hypothetical. Neutering one line in each of three routes touched in 2026-09 left the
whole 1090-test suite green, and the same shape left promote-to-library with no approval path for
a year: the caller was deleted, everything kept answering 200, and nothing failed.

Behaviour tests cannot catch it, because they ARE the thing that bypasses the route. Only asking
"does any test enter this route?" can.

TWO WAYS A TEST COUNTS, and both are required:
  1. it calls the handler function by name (AST over tests/), or
  2. it drives the route over HTTP, i.e. a URL literal in tests/ that structurally matches the
     route's path (TestClient suites do this).
Counting only (1) reports 48 uncovered routes when the true figure is 23 — the 25 difference is
entirely TestClient coverage. A screen that cries wolf gets ignored, which is worse than none.

Exit 0 when every WRITE route is reached, 1 otherwise. Read-only: it never edits a file.
"""
from __future__ import annotations

import argparse
import ast
import pathlib
import re
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = pathlib.Path(__file__).resolve().parents[1]
WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

#: FastAPI's own docs endpoints. Not ours, nothing to test — allowlisted by handler name rather
#: than silently filtered, so they stay countable.
_FRAMEWORK = {"swagger_ui_html", "swagger_ui_redirect", "redoc_html", "openapi"}

_URL = re.compile(r"""["'](/(?:v1|health|ready)[^"']*)["']""")


def _routes() -> list[tuple[str, str, str]]:
    """(method, path, handler name) for every real route on the live app."""
    from app.main import create_app

    out: list[tuple[str, str, str]] = []
    for entry in create_app().routes:
        router = getattr(entry, "original_router", None)
        for route in (router.routes if router is not None else [entry]):
            path, endpoint = getattr(route, "path", None), getattr(route, "endpoint", None)
            if not path or endpoint is None:
                continue
            for method in sorted(getattr(route, "methods", None) or ["WEBSOCKET"]):
                out.append((method, path, endpoint.__name__))
    return out


def _called_by_name(test_dir: pathlib.Path) -> set[str]:
    """Handler names a test calls directly, PROVEN by that file's own imports.

    Matching a bare call name is not good enough, and the first version of this script showed why:
    it marked `POST /v1/tsg/threat-library/embeddings/update` covered because tests call
    `dict.update(...)`, and `.../embeddings/create` covered because something calls `create(...)`.
    Thirteen of twenty-three "covered" routes were name collisions. A screen that over-reports
    coverage is worse than no screen — it is the false comfort this whole audit exists to remove.

    So provenance is required, PER FILE: either the handler was imported from an app.api module in
    this file (`from app.api.sessions import post_reject_scenarios`), or it is called qualified on
    an alias of one (`sessions_mod.post_reject_scenarios(...)`). A name imported in some other file
    does not license a call here.
    """
    names: set[str] = set()
    for path in sorted(test_dir.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported: set[str] = set()   # handler names bound by `from app.api.x import handler`
        aliases: set[str] = set()    # local names bound to an app.api MODULE
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("app.api"):
                    for a in node.names:
                        # `from app.api import sessions as sessions_mod` binds a module, not a
                        # handler; `from app.api.sessions import post_x` binds the handler.
                        (aliases if node.module == "app.api" else imported).add(a.asname or a.name)
            elif isinstance(node, ast.Import):
                for a in node.names:
                    if a.name.startswith("app.api"):
                        aliases.add(a.asname or a.name.split(".")[-1])
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in imported:
                names.add(func.id)
            elif (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                    and func.value.id in aliases):
                names.add(func.attr)
    return names


_VERBS = {"get", "post", "put", "patch", "delete", "head", "options"}


def _url_literals(test_dir: pathlib.Path) -> set[tuple[str, str]]:
    """(METHOD, path) pairs a test actually REQUESTS — not every path-shaped string in the file.

    Two ways a looser version lies:

      * a docstring mentioning a route ("POST /v1/sessions/{id}/scenarios/reject now ...") is an
        ast.Constant like any other, so scanning raw text or bare constants grants coverage to a
        route nobody calls. Several test modules in this repo discuss routes in prose.
      * matching a path without its VERB lets a GET test vouch for the POST on the same path — and
        several paths here carry both (the treatment-plan path, the intel paths).

    So: only strings passed to `client.post(...)`-shaped calls count, and the verb comes from the
    method name (or from the first argument of `.request("POST", url)`).
    """
    out: set[tuple[str, str]] = set()
    for path in sorted(test_dir.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            attr, args = node.func.attr.lower(), node.args
            if attr in _VERBS and args:
                url = args[0]
                if isinstance(url, ast.Constant) and isinstance(url.value, str):
                    out.add((attr.upper(), url.value))
                elif isinstance(url, ast.JoinedStr):
                    # An f-string URL. Each interpolation becomes a PLACEHOLDER, never nothing:
                    # dropping it turns f"/v1/sessions/{sid}/accept" into "/v1/sessions//accept",
                    # which loses a segment and then matches no route at all. That mistake cut the
                    # HTTP-detected count from 16 to 2 — a false FAIL on fourteen tested routes,
                    # which is how a guard gets deleted in its second week.
                    lit = "".join(
                        v.value if isinstance(v, ast.Constant) and isinstance(v.value, str)
                        else "{x}"
                        for v in url.values)
                    out.add((attr.upper(), lit or "/"))
            elif attr == "request" and len(args) >= 2:
                meth, url = args[0], args[1]
                if (isinstance(meth, ast.Constant) and isinstance(url, ast.Constant)
                        and isinstance(url.value, str)):
                    out.add((str(meth.value).upper(), url.value))
    return {(m, u) for m, u in out if _URL.fullmatch(f'"{u}"') or u.startswith("/")}


def _segments(url: str) -> list[str]:
    return [s for s in url.split("?")[0].strip("/").split("/") if s]


def _hit_over_http(method: str, route_path: str, requests: set[tuple[str, str]]) -> bool:
    """Does any test REQUEST match this route's method and path?

    Structural on the path, exact on the verb. A test writes "/v1/sessions/{sid}/accept" (an
    f-string) or a real uuid where the route declares "{session_id}", so segments compare as
    equal-or-placeholder — but the SEGMENT COUNT must match, which is what keeps
    "/v1/sessions/{id}/accept" from crediting "/v1/sessions/{id}/accepted-scenarios" and
    "/feeds/refresh" from crediting "/feeds/{feed}/refresh".
    """
    want = _segments(route_path)
    for got_method, lit in requests:
        if got_method != method:
            continue
        got = _segments(lit)
        if len(want) != len(got):
            continue
        if all(w.startswith("{") or g.startswith("{") or w == g for w, g in zip(want, got)):
            return True
    return False


def audit(test_dir: pathlib.Path | None = None) -> dict[str, list[tuple[str, str, str]]]:
    """{'direct'|'http'|'unreached'|'framework': [(method, path, handler), ...]}."""
    test_dir = test_dir or ROOT / "tests"
    by_name, requests = _called_by_name(test_dir), _url_literals(test_dir)
    buckets: dict[str, list[tuple[str, str, str]]] = {
        "direct": [], "http": [], "unreached": [], "framework": []}
    for method, path, name in _routes():
        if name in _FRAMEWORK:
            buckets["framework"].append((method, path, name))
        elif name in by_name:
            buckets["direct"].append((method, path, name))
        elif _hit_over_http(method, path, requests):
            buckets["http"].append((method, path, name))
        else:
            buckets["unreached"].append((method, path, name))
    return buckets


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--all", action="store_true",
                    help="list reached routes too, not just the gaps")
    args = ap.parse_args()

    b = audit()
    total = sum(len(v) for v in b.values())
    print(f"{total} routes: {len(b['direct'])} entered by a direct call, "
        f"{len(b['http'])} driven over HTTP, {len(b['framework'])} framework, "
        f"{len(b['unreached'])} UNREACHED")

    writes = [r for r in b["unreached"] if r[0] in WRITE_METHODS]
    reads = [r for r in b["unreached"] if r[0] not in WRITE_METHODS]

    print(f"\n=== UNREACHED WRITE routes ({len(writes)}) — these can change or lose data ===")
    for method, path, name in sorted(writes, key=lambda r: r[1]):
        print(f"  {method:6} {path:62} {name}")
    print(f"\n=== UNREACHED read routes ({len(reads)}) — wrong data, not lost data ===")
    for method, path, name in sorted(reads, key=lambda r: r[1]):
        print(f"  {method:6} {path:62} {name}")

    if args.all:
        for bucket in ("direct", "http"):
            print(f"\n=== reached: {bucket} ({len(b[bucket])}) ===")
            for method, path, name in sorted(b[bucket], key=lambda r: r[1]):
                print(f"  {method:6} {path:62} {name}")

    if writes:
        print(f"\n{len(writes)} write route(s) that no test enters. Break the line where one of "
            "them calls the pipeline and the suite stays green.")
        return 1
    print("\nEvery write route is entered by at least one test.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
