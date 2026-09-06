"""LIVE end-to-end smoke test of the TSG HTTP API — real server, real broker, real MSSQL/Mongo.

WHY THIS EXISTS: tests/ proves handler logic against in-process SQLite with Celery stubbed out
(tests/test_e2e_full_flow.py says so in its own docstring). Nothing in the repo had ever driven
these routes over a socket against the real stack, so FastAPI request parsing, the auth
dependencies, response-model serialization, the Celery round trip and the SSE framing were
collectively unverified in the shape production actually runs them. scripts/uat_preflight.py is
adjacent but exercises the dependencies THROUGH app code — it never calls TSG's own API.

SAFETY, because several of these routes are destructive:
  * The run MINTS ITS OWN API CLIENT from the admin key and uses it throughout, so the operator's
    real key is never in the blast radius and `revoke` can be tested honestly. Every revoke is
    guarded by a `qa-smoke-` prefix assert — that one line is the difference between a test and
    an outage, because a revoked sole client 401s every route in the app.
  * Embedding delete/recreate are scoped to ONE named row in the smallest group and restored on
    the next call. A bare {} recreate would wipe every group and leave grounding matching nothing.
  * Grounding calibration is only ever called UNFORCED. A forced sweep is ~12 minutes of billed
    calls AND silently overwrites the live match threshold with no undo route.

Run:  .venv/Scripts/python.exe scripts/live_smoke.py [--base-url URL] [--out DIR]
Exit: 0 = every check passed, 1 = at least one FAIL/ERROR, 2 = could not start.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import httpx

ROOT = Path(__file__).resolve().parents[1]
USER_ID = os.environ.get("TSG_SMOKE_USER_ID", "gopal")
TENANT_ID = os.environ.get("TSG_SMOKE_TENANT_ID", "desc")


def env_value(key: str) -> str:
    """Read one key from tsg/.env WITHOUT importing app.core.config.

    Deliberate: get_settings() is lru_cached and importing litellm anywhere in that chain calls
    load_dotenv(), which would mutate os.environ for the rest of the process. This runner must
    observe the server's configuration, never influence it.
    """
    override = os.environ.get(key)
    if override:
        return override
    path = ROOT / ".env"
    if path.exists():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(rf"^\s*{re.escape(key)}\s*=\s*(.*)$", line)
            if m:
                return m.group(1).strip().strip('"').strip("'")
    return ""


@dataclass
class Result:
    phase: str
    name: str
    status: str            # PASS | FAIL | ERROR | SKIP
    detail: str = ""
    request_id: str | None = None
    body: str = ""
    seconds: float = 0.0


@dataclass
class Runner:
    client: httpx.Client
    api_key: str = ""
    admin_key: str = ""
    results: list[Result] = field(default_factory=list)
    failed_gates: set[str] = field(default_factory=set)
    hit: set[tuple[str, str]] = field(default_factory=set)
    last: httpx.Response | None = None

    # --- header builders -------------------------------------------------------------------
    def admin_headers(self, **over: str) -> dict[str, str]:
        h = {"X-Admin-Key": self.admin_key, "X-API-Key": self.api_key, "X-User-Id": USER_ID}
        h.update(over)
        return {k: v for k, v in h.items() if v is not None}

    def entity_headers(self, entity: str = "78", **over: str) -> dict[str, str]:
        h = {"X-API-Key": self.api_key, "X-User-Id": USER_ID,
             "X-Entity-Id": entity, "X-Tenant-Id": TENANT_ID}
        h.update(over)
        return {k: v for k, v in h.items() if v is not None}

    # --- request + assertion helpers -------------------------------------------------------
    def req(self, method: str, path: str, **kw: Any) -> httpx.Response:
        self.hit.add((method.upper(), path.split("?")[0]))
        r = self.client.request(method, path, **kw)
        self.last = r
        return r

    def expect(self, r: httpx.Response, code: int, why: str = "") -> Any:
        if r.status_code != code:
            raise AssertionError(
                f"expected {code}, got {r.status_code}{' (' + why + ')' if why else ''} "
                f":: {r.text[:300]}")
        return r.json() if r.headers.get("content-type", "").startswith("application/json") \
            else r.text

    # --- the check harness -----------------------------------------------------------------
    def check(self, phase: str, name: str, fn: Callable[[], Any], *,
              gate: str | None = None, needs: str | None = None) -> Any:
        """Run one check. A failure is RECORDED, never raised — one broken route must not hide
        the other 46. `needs` names a gate that must have passed, otherwise this is SKIP: that
        distinction is what stops a single infra hiccup manufacturing 40 bogus failures."""
        if needs and needs in self.failed_gates:
            self.results.append(Result(phase, name, "SKIP", f"blocked by gate '{needs}'"))
            # A skipped check never ran, so it cannot have produced the gate it declares either.
            # Without this, dependents of THAT gate run against state the skipped check was
            # supposed to create and die with a KeyError -- which reads as four fresh bugs
            # instead of one upstream skip.
            if gate:
                self.failed_gates.add(gate)
            return None
        self.last = None
        t0 = time.time()
        try:
            out = fn()
            self.results.append(Result(phase, name, "PASS", seconds=time.time() - t0,
                                       request_id=self._rid()))
            return out
        except AssertionError as exc:
            self._fail(phase, name, "FAIL", str(exc), t0, gate)
        except Exception as exc:  # noqa: BLE001 — a crashed check is a result, not a crashed run
            self._fail(phase, name, "ERROR", f"{type(exc).__name__}: {exc}", t0, gate)
        return None

    def _fail(self, phase: str, name: str, status: str, detail: str,
              t0: float, gate: str | None) -> None:
        if gate:
            self.failed_gates.add(gate)
        self.results.append(Result(
            phase, name, status, detail, self._rid(),
            (self.last.text[:500] if self.last is not None else ""), time.time() - t0))

    def _rid(self) -> str | None:
        # APP_ENV=staging returns "an unexpected error occurred" with no detail, so the request
        # id is the ONLY thread back to the cause in logs/.
        return self.last.headers.get("X-Request-Id") if self.last is not None else None


# ============================================================================================
# Phase 0 — the stack is actually up, and every route is accounted for
# ============================================================================================
def phase0(r: Runner) -> set[tuple[str, str]]:
    P = "0-health"

    def health() -> None:
        assert r.expect(r.req("GET", "/health"), 200) == {"status": "ok"}

    def health_is_unauthenticated() -> None:
        # Proves /health is genuinely open, not passing only because we send good headers.
        r.expect(r.req("GET", "/health", headers={"X-API-Key": "garbage", "X-Admin-Key": "x"}), 200)

    def ready() -> None:
        checks = r.expect(r.req("GET", "/ready", timeout=30), 200)["checks"]
        for dep in ("database", "redis", "mongo"):
            assert checks.get(dep) == "ok", f"{dep} = {checks.get(dep)!r}"

    def workers_up() -> None:
        """Assert EVERY queue has a consumer, not the `workers` aggregate.

        The aggregate is an any() across queues, so a healthy pipeline worker makes it "ok"
        while the admin worker is dead — and then every rebuild, import, embedding action and
        calibration this suite triggers returns 202 and silently never runs. This check looked
        straight past the exact failure /ready gained workers_<queue> keys to expose.

        A GATE, not an ordinary check: phases 3/3b/5/6/7 all queue work.
        """
        checks = r.expect(r.req("GET", "/ready", timeout=30), 200)["checks"]
        per_queue = {k: v for k, v in checks.items() if k.startswith("workers_")}
        assert per_queue, (
            "/ready publishes no workers_<queue> keys — either the server predates the queue "
            "split or health.py regressed to the any() aggregate")
        bad = {k: v for k, v in per_queue.items() if v != "ok"}
        assert not bad, f"queue(s) with no consumer: {bad} — jobs would be accepted and vanish"

    r.check(P, "GET /health -> 200 ok", health)
    r.check(P, "GET /health needs no auth", health_is_unauthenticated)
    r.check(P, "GET /ready -> db/redis/mongo ok", ready)
    r.check(P, "GET /ready -> workers ok", workers_up, gate="workers")

    routes: set[tuple[str, str]] = set()

    def coverage() -> None:
        spec = r.expect(r.req("GET", "/openapi.json"), 200)
        for path, ops in spec["paths"].items():
            for m in ops:
                if m.upper() in ("GET", "POST", "PATCH", "PUT", "DELETE"):
                    routes.add((m.upper(), path))
        assert routes, "the schema declares no routes at all"

    r.check(P, "GET /openapi.json enumerates the route set", coverage)
    return routes


# ============================================================================================
# Phase 1 — mint throwaway credentials (never touch the operator's real client)
# ============================================================================================
def phase1(r: Runner, run_id: str) -> dict[str, str]:
    P = "1-api-clients"
    minted: dict[str, str] = {}
    qa_id, other_id = f"qa-smoke-{run_id}", f"qa-nomodule-{run_id}"
    admin_only = {"X-Admin-Key": r.admin_key, "X-User-Id": USER_ID}

    def create() -> None:
        body = r.expect(r.req("POST", "/v1/tsg/api-clients", headers=admin_only,
                              json={"client_id": qa_id, "name": "QA live smoke",
                                    "module": "tsg"}), 201)
        assert body["client_id"] == qa_id and body["module"] == "tsg"
        assert re.fullmatch(r"[0-9a-f]{64}", body["secret"]), "secret is not 32 bytes of hex"
        minted["qa"] = body["secret"]

    def create_wrong_module() -> None:
        # A structurally valid key whose module != 'tsg'. dal.api_client_id_for_key_hash filters
        # on Module, so this must fail on entity routes — the only proof module scoping is live.
        body = r.expect(r.req("POST", "/v1/tsg/api-clients", headers=admin_only,
                              json={"client_id": other_id, "name": "QA wrong module",
                                    "module": "qa-smoke"}), 201)
        minted["other"] = body["secret"]

    def duplicate_is_409() -> None:
        r.expect(r.req("POST", "/v1/tsg/api-clients", headers=admin_only,
                       json={"client_id": qa_id, "name": "dupe", "module": "tsg"}), 409)

    def missing_user_is_400() -> None:
        # Documented edge: 400, NOT 401 — attribution is a validation failure, not an auth one.
        r.expect(r.req("POST", "/v1/tsg/api-clients", headers={"X-Admin-Key": r.admin_key},
                       json={"client_id": f"x-{run_id}", "name": "n", "module": "tsg"}), 400)

    def bad_admin_key_is_401() -> None:
        r.expect(r.req("POST", "/v1/tsg/api-clients",
                       headers={"X-Admin-Key": "wrong", "X-User-Id": USER_ID},
                       json={"client_id": f"y-{run_id}", "name": "n", "module": "tsg"}), 401)

    def non_ascii_admin_key_is_401() -> None:
        # Regression: secrets.compare_digest raises on a non-ASCII str, which turned a failed
        # auth check into an unauthenticated 500. The header value MUST be sent as raw bytes:
        # httpx encodes str headers as ASCII and would refuse client-side, so a str here tests
        # httpx, not the server. Starlette decodes header bytes as latin-1, so UTF-8 "café"
        # arrives as the non-ASCII str "cafÃ©" — exactly the shape that used to raise.
        r.expect(r.req("GET", "/v1/tsg/api-clients",
                       headers={"X-Admin-Key": "café".encode()}), 401, "non-ASCII admin key")

    def oversized_client_id_is_422() -> None:
        r.expect(r.req("POST", "/v1/tsg/api-clients", headers=admin_only,
                       json={"client_id": "z" * 101, "name": "n", "module": "tsg"}), 422)

    def listing_never_leaks_secrets() -> None:
        raw = r.req("GET", "/v1/tsg/api-clients", headers={"X-Admin-Key": r.admin_key})
        body = r.expect(raw, 200)
        assert any(c["client_id"] == qa_id for c in body), "minted client missing from listing"
        for banned in ("secret", "key_hash", "keyhash"):
            assert banned not in raw.text.lower(), f"listing leaked {banned!r}"
        if "qa" in minted:
            assert minted["qa"] not in raw.text, "listing echoed the plaintext secret"

    def listing_filters_by_module() -> None:
        body = r.expect(r.req("GET", "/v1/tsg/api-clients", params={"module": "qa-smoke"},
                              headers={"X-Admin-Key": r.admin_key}), 200)
        assert all(c["module"] == "qa-smoke" for c in body), "module filter leaked other modules"

    r.check(P, "POST /api-clients -> 201 + one-time secret", create, gate="apikey")
    r.check(P, "POST /api-clients (module!=tsg) -> 201", create_wrong_module)
    r.check(P, "POST /api-clients duplicate id -> 409", duplicate_is_409)
    r.check(P, "POST /api-clients without X-User-Id -> 400 (not 401)", missing_user_is_400)
    r.check(P, "POST /api-clients bad admin key -> 401", bad_admin_key_is_401)
    r.check(P, "admin key with non-ASCII char -> 401 (not 500)", non_ascii_admin_key_is_401)
    r.check(P, "POST /api-clients client_id 101 chars -> 422", oversized_client_id_is_422)
    r.check(P, "GET /api-clients never returns secret/hash", listing_never_leaks_secrets)
    r.check(P, "GET /api-clients?module= filters", listing_filters_by_module)

    if "qa" in minted:
        r.api_key = minted["qa"]
    return {"qa_id": qa_id, "other_id": other_id, **minted}


# ============================================================================================
# Phase 2 — admin reads: threat intel + grounding
# ============================================================================================
def phase2(r: Runner, other_key: str = "") -> dict[str, Any]:
    P = "2-admin-read"
    state: dict[str, Any] = {"other_key": other_key}
    TI = "/v1/tsg/threat-intel"

    def feeds() -> None:
        body = r.expect(r.req("GET", f"{TI}/feeds", headers=r.admin_headers()), 200)
        by = {f["feed"]: f for f in body["feeds"]}
        state["feeds"] = by
        for name in ("cisa_kev", "cisa_ics", "otx", "urlhaus", "taxii"):
            assert name in by, f"feed {name} missing — disabled feeds must still be listed"
        for f in by.values():
            assert isinstance(f["enabled"], bool) and isinstance(f["item_count"], int)
            # stale is only meaningful for an enabled feed; a disabled one must never read stale
            if not f["enabled"]:
                assert f["stale"] is False, f"{f['feed']} is disabled but reports stale=true"

    def feeds_need_api_key_too() -> None:
        # Router-level require_admin AND per-route get_admin_principal: the admin key alone
        # must not be enough.
        r.expect(r.req("GET", f"{TI}/feeds",
                       headers={"X-Admin-Key": r.admin_key, "X-User-Id": USER_ID}), 401)

    def feeds_need_user_id() -> None:
        r.expect(r.req("GET", f"{TI}/feeds",
                       headers={"X-Admin-Key": r.admin_key, "X-API-Key": r.api_key}), 401)

    def feeds_reject_wrong_module_key() -> None:
        r.expect(r.req("GET", f"{TI}/feeds",
                       headers={"X-Admin-Key": r.admin_key, "X-API-Key": other_key,
                                "X-User-Id": USER_ID}), 401, "module-scoped key accepted")

    def items_default_page() -> None:
        body = r.expect(r.req("GET", f"{TI}/items", headers=r.admin_headers()), 200)
        assert body["limit"] == 50 and body["offset"] == 0
        assert len(body["items"]) <= 50 and body["total"] >= len(body["items"])
        state["total_items"] = body["total"]

    def items_source_filter() -> None:
        body = r.expect(r.req("GET", f"{TI}/items", params={"source": "cisa_kev", "limit": 5},
                              headers=r.admin_headers()), 200)
        assert all(i["source"] == "cisa_kev" for i in body["items"]), "source filter leaked"

    def items_paging_is_disjoint() -> None:
        a = r.expect(r.req("GET", f"{TI}/items", params={"limit": 1, "offset": 0},
                           headers=r.admin_headers()), 200)
        b = r.expect(r.req("GET", f"{TI}/items", params={"limit": 1, "offset": 1},
                           headers=r.admin_headers()), 200)
        if a["items"] and b["items"]:
            assert a["items"][0] != b["items"][0], "offset did not move the window"

    def items_past_end_is_empty_not_404() -> None:
        body = r.expect(r.req("GET", f"{TI}/items", params={"offset": 999999},
                              headers=r.admin_headers()), 200, "paging past the end")
        assert body["items"] == [] and body["total"] > 0, "empty page lost the real total"

    def items_unknown_source_is_404() -> None:
        r.expect(r.req("GET", f"{TI}/items", params={"source": "nope"},
                       headers=r.admin_headers()), 404)

    def items_disabled_source_is_not_404() -> None:
        # urlhaus is KNOWN but switched off. /items filters, it does not validate enablement —
        # so this must be an empty 200, unlike the refresh route where a disabled feed is a 404.
        body = r.expect(r.req("GET", f"{TI}/items", params={"source": "urlhaus"},
                              headers=r.admin_headers()), 200, "known-but-disabled source")
        assert body["items"] == []

    def items_bounds() -> None:
        for params in ({"limit": 0}, {"limit": 501}, {"offset": -1}):
            r.expect(r.req("GET", f"{TI}/items", params=params, headers=r.admin_headers()), 422,
                     f"bounds {params}")

    def threshold() -> None:
        body = r.expect(r.req("GET", "/v1/tsg/grounding/threshold", headers=r.admin_headers()), 200)
        assert body["origin"] in ("calibrated", "env_pinned", "static_default"), body["origin"]
        state["threshold"] = body

    def calibrations() -> None:
        body = r.expect(r.req("GET", "/v1/tsg/grounding/calibrations", params={"limit": 5},
                              headers=r.admin_headers()), 200)
        rows = body if isinstance(body, list) else body.get("calibrations", [])
        assert isinstance(rows, list), f"unexpected shape: {type(body)}"
        state["calibrations"] = rows

    def calibrations_bounds() -> None:
        for lim in (0, 201):
            r.expect(r.req("GET", "/v1/tsg/grounding/calibrations", params={"limit": lim},
                           headers=r.admin_headers()), 422, f"limit={lim}")

    r.check(P, "GET /threat-intel/feeds -> all 5 feeds incl. disabled", feeds, gate="feeds")
    r.check(P, "GET /threat-intel/feeds admin key alone -> 401", feeds_need_api_key_too)
    r.check(P, "GET /threat-intel/feeds without X-User-Id -> 401", feeds_need_user_id)
    if other_key:
        r.check(P, "GET /threat-intel/feeds wrong-module key -> 401", feeds_reject_wrong_module_key)
    r.check(P, "GET /threat-intel/items default page", items_default_page)
    r.check(P, "GET /threat-intel/items?source= filters", items_source_filter)
    r.check(P, "GET /threat-intel/items paging is disjoint", items_paging_is_disjoint)
    r.check(P, "GET /threat-intel/items past end -> 200 empty + real total",
            items_past_end_is_empty_not_404)
    r.check(P, "GET /threat-intel/items?source=unknown -> 404", items_unknown_source_is_404)
    r.check(P, "GET /threat-intel/items?source=urlhaus (disabled) -> 200 empty",
            items_disabled_source_is_not_404)
    r.check(P, "GET /threat-intel/items limit/offset bounds -> 422", items_bounds)
    r.check(P, "GET /grounding/threshold -> origin present", threshold)
    r.check(P, "GET /grounding/calibrations -> history", calibrations)
    r.check(P, "GET /grounding/calibrations limit bounds -> 422", calibrations_bounds)
    return state


_TERMINAL = {"SUCCESS", "FAILURE", "REVOKED"}
_EMB_NAME = os.environ.get("TSG_SMOKE_EMB_NAME", "")

# The five fields TreatmentPlanBody actually requires. Kept in one place so a negative test can
# vary ONE field and still be a valid request in every other respect.
_PLAN_BODY: dict[str, Any] = {
    "existing_controls": ["network segmentation"],
    "likelihood_rating": 3,
    "impact_rating": 4,
    "final_risk_rating": 12,
    "risk_level": "High",
}


# ============================================================================================
# SSE helper — EventSource is unusable here (these routes need custom auth headers), so every
# stream is read with httpx.stream + iter_lines. sse_starlette emits "event:"/"data:"/"" lines.
# ============================================================================================
def read_sse(r: Runner, path: str, headers: dict[str, Any], *,
             cap: float = 45.0, max_frames: int = 40) -> tuple[list[dict], str]:
    frames: list[dict] = []
    t0 = time.time()
    r.hit.add(("GET", path.split("?")[0]))
    with r.client.stream("GET", path, headers=headers,
                         timeout=httpx.Timeout(10.0, read=cap)) as resp:
        if resp.status_code != 200:
            resp.read()
            raise AssertionError(f"stream returned {resp.status_code}: {resp.text[:200]}")
        ctype = resp.headers.get("content-type", "")
        for line in resp.iter_lines():
            if line.startswith("data:"):
                payload = line[5:].strip()
                if payload:
                    try:
                        frames.append(json.loads(payload))
                    except json.JSONDecodeError:
                        frames.append({"_raw": payload})
                if len(frames) >= max_frames:
                    break
                if frames and str(frames[-1].get("state", "")).upper() in _TERMINAL:
                    break
            if time.time() - t0 > cap:
                break
    return frames, ctype


def poll_job(r: Runner, path: str, headers: dict[str, str], *,
             cap: float = 120.0, every: float = 2.0) -> dict:
    """Poll an admin job status endpoint until terminal. Returns the last body."""
    t0 = time.time()
    body: dict = {}
    while time.time() - t0 < cap:
        body = r.expect(r.req("GET", path, headers=headers), 200)
        if str(body.get("state", "")).upper() in _TERMINAL:
            return body
        time.sleep(every)
    raise AssertionError(f"job did not reach a terminal state in {cap}s (last={body.get('state')})")


# ============================================================================================
# Phase 3 — admin jobs: intel refresh, embeddings, calibration, and their SSE streams
# ============================================================================================
def phase3(r: Runner, feeds_before: dict[str, Any]) -> dict[str, str]:
    P = "3-admin-jobs"
    TI = "/v1/tsg/threat-intel"
    EMB = "/v1/tsg/threat-library/embeddings"
    GR = "/v1/tsg/grounding"
    jobs: dict[str, str] = {}

    # --- threat intel refresh -----------------------------------------------------------
    def refresh_one() -> None:
        body = r.expect(r.req("POST", f"{TI}/feeds/cisa_kev/refresh",
                              headers=r.admin_headers()), 202)
        assert list(body["jobs"]) == ["cisa_kev"], f"expected exactly one job, got {body['jobs']}"
        jobs["intel"] = body["jobs"]["cisa_kev"]

    def refresh_unknown_is_404() -> None:
        r.expect(r.req("POST", f"{TI}/feeds/bogus/refresh", headers=r.admin_headers()), 404)

    def refresh_disabled_is_404_with_its_own_message() -> None:
        resp = r.req("POST", f"{TI}/feeds/urlhaus/refresh", headers=r.admin_headers())
        r.expect(resp, 404, "known-but-disabled feed")
        # Same status as an unknown feed, but it MUST say something different — otherwise an
        # operator cannot tell "typo" from "switched off", which is the point of the split.
        assert "enabled" in resp.text.lower(), (
            f"disabled-feed 404 is indistinguishable from unknown-feed 404: {resp.text[:200]}")

    def refresh_all_only_enabled() -> None:
        body = r.expect(r.req("POST", f"{TI}/feeds/refresh", headers=r.admin_headers()), 202)
        enabled = {n for n, f in feeds_before.items() if f["enabled"]}
        assert set(body["jobs"]) == enabled, (
            f"refresh-all queued {set(body['jobs'])}, enabled feeds are {enabled}")

    def intel_sse() -> None:
        frames, ctype = read_sse(r, f"{TI}/feeds/events/{jobs['intel']}", r.admin_headers(), cap=60)
        assert "text/event-stream" in ctype, f"content-type is {ctype!r}"
        assert frames, "no frames — not even the connect snapshot"
        assert frames[0].get("type") == "intel_job_update", frames[0]
        assert frames[0].get("job_id") == jobs["intel"]

    def intel_sse_unknown_job_is_404() -> None:
        try:
            read_sse(r, f"{TI}/feeds/events/00000000-0000-0000-0000-000000000000",
                     r.admin_headers(), cap=8)
        except AssertionError as exc:
            assert "404" in str(exc), f"expected 404, got: {exc}"
            return
        raise AssertionError("unknown job id opened a stream instead of returning 404")

    def refresh_moved_last_success() -> None:
        # The health signal is last_success_at MOVING, never item_count changing: KEV only
        # downloads what it does not already have, so a perfect refresh often adds zero.
        body = r.expect(r.req("GET", f"{TI}/feeds", headers=r.admin_headers()), 200)
        after = {f["feed"]: f for f in body["feeds"]}["cisa_kev"]
        before = feeds_before["cisa_kev"]
        assert after["last_attempt_at"] is not None
        if before.get("last_success_at") and after.get("last_success_at"):
            assert after["last_success_at"] >= before["last_success_at"], \
                "last_success_at went backwards"

    r.check(P, "POST /threat-intel/feeds/cisa_kev/refresh -> 202 one job", refresh_one,
            gate="intel_job")
    r.check(P, "POST /threat-intel/feeds/bogus/refresh -> 404", refresh_unknown_is_404)
    r.check(P, "POST /threat-intel/feeds/urlhaus/refresh -> 404 saying 'not enabled'",
            refresh_disabled_is_404_with_its_own_message)
    r.check(P, "POST /threat-intel/feeds/refresh -> one job per ENABLED feed",
            refresh_all_only_enabled)
    r.check(P, "GET /threat-intel/feeds/events/{job} -> SSE frames", intel_sse, needs="intel_job")
    r.check(P, "GET /threat-intel/feeds/events/{unknown} -> 404", intel_sse_unknown_job_is_404)
    r.check(P, "refresh moved last_success_at (not item_count)", refresh_moved_last_success,
            needs="intel_job")

    # --- embeddings ---------------------------------------------------------------------
    def emb_update() -> None:
        body = r.expect(r.req("POST", f"{EMB}/update", headers=r.admin_headers(),
                              json={"group": "threat_type"}), 202)
        jobs["emb"] = body["job_id"]

    def emb_status() -> None:
        body = poll_job(r, f"{EMB}/status/{jobs['emb']}", r.admin_headers(), cap=240)
        assert body["state"] == "SUCCESS", body

    def emb_events_terminal_frame() -> None:
        frames, ctype = read_sse(r, f"{EMB}/events/{jobs['emb']}", r.admin_headers(), cap=20)
        assert "text/event-stream" in ctype
        assert frames, "an already-finished job must still yield its terminal snapshot"

    def emb_cross_family_is_404() -> None:
        # A VALID Celery id from the intel family must not resolve here — without the family
        # marker a bare AsyncResult lookup would hand back another job's result.
        r.expect(r.req("GET", f"{EMB}/status/{jobs['intel']}", headers=r.admin_headers()), 404,
                 "cross-family job id leaked")

    def emb_status_unknown_is_404() -> None:
        r.expect(r.req("GET", f"{EMB}/status/00000000-0000-0000-0000-000000000000",
                       headers=r.admin_headers()), 404)

    def emb_create_empty_is_422() -> None:
        r.expect(r.req("POST", f"{EMB}/create", headers=r.admin_headers(), json={}), 422)

    def emb_delete_empty_is_422() -> None:
        # A bare {} would wipe the entire cross-tenant cache — it must be refused outright.
        r.expect(r.req("POST", f"{EMB}/delete", headers=r.admin_headers(), json={}), 422)

    def emb_names_without_group_is_422() -> None:
        for action in ("delete", "recreate", "create"):
            r.expect(r.req("POST", f"{EMB}/{action}", headers=r.admin_headers(),
                           json={"names": ["x"]}), 422, f"{action} names-without-group")

    def emb_bad_group_is_422() -> None:
        r.expect(r.req("POST", f"{EMB}/update", headers=r.admin_headers(),
                       json={"group": "not_a_group"}), 422)

    def emb_recreate_one_name_roundtrip() -> None:
        # Scoped to ONE name in the smallest group, and recreate is self-restoring by
        # construction (delete-then-embed inside a single job). Never a bare {}.
        assert _EMB_NAME, "no embedding name supplied"
        body = r.expect(r.req("POST", f"{EMB}/recreate", headers=r.admin_headers(),
                              json={"group": "threat_type", "names": [_EMB_NAME]}), 202)
        out = poll_job(r, f"{EMB}/status/{body['job_id']}", r.admin_headers(), cap=240)
        assert out["state"] == "SUCCESS", out

    r.check(P, "POST /embeddings/update -> 202", emb_update, gate="emb_job")
    r.check(P, "GET /embeddings/status/{job} -> SUCCESS", emb_status, needs="emb_job")
    r.check(P, "GET /embeddings/events/{job} -> terminal snapshot", emb_events_terminal_frame,
            needs="emb_job")
    if "intel" in jobs:
        r.check(P, "GET /embeddings/status/{intel job} -> 404 (cross-family)",
                emb_cross_family_is_404, needs="emb_job")
    r.check(P, "GET /embeddings/status/{unknown} -> 404", emb_status_unknown_is_404)
    r.check(P, "POST /embeddings/create {} -> 422", emb_create_empty_is_422)
    r.check(P, "POST /embeddings/delete {} -> 422 (refuses to wipe the cache)",
            emb_delete_empty_is_422)
    r.check(P, "POST /embeddings/* names without group -> 422", emb_names_without_group_is_422)
    r.check(P, "POST /embeddings/update bad group -> 422", emb_bad_group_is_422)
    if _EMB_NAME:
        r.check(P, "POST /embeddings/recreate one name -> SUCCESS (self-restoring)",
                emb_recreate_one_name_roundtrip)

    # --- grounding calibration (UNFORCED ONLY) ------------------------------------------
    def calibrate_unforced() -> None:
        body = r.expect(r.req("POST", f"{GR}/calibrate", headers=r.admin_headers(), json={}), 202)
        assert body.get("job_id") and body.get("run_id"), body
        jobs["cal"] = body["job_id"]

    def calibrate_status_is_skipped() -> None:
        body = poll_job(r, f"{GR}/calibrate/status/{jobs['cal']}", r.admin_headers(), cap=90)
        assert body["state"] == "SUCCESS", body
        # Unforced + an existing successful run for this model pair == no sweep, no LLM calls.
        assert body.get("skipped") == "already_calibrated", (
            f"unforced calibrate RAN A REAL SWEEP (skipped={body.get('skipped')!r}) — that is "
            "~12 min of billed calls and it overwrites the live threshold")

    def calibrate_events() -> None:
        frames, ctype = read_sse(r, f"{GR}/calibrate/events/{jobs['cal']}", r.admin_headers(),
                                 cap=20)
        assert "text/event-stream" in ctype
        assert frames, "no terminal snapshot for a finished calibration job"

    def calibrate_cross_family_is_404() -> None:
        r.expect(r.req("GET", f"{GR}/calibrate/status/{jobs['emb']}",
                       headers=r.admin_headers()), 404, "embeddings job resolved as calibration")

    def calibrate_bad_force_is_422() -> None:
        r.expect(r.req("POST", f"{GR}/calibrate", headers=r.admin_headers(),
                       json={"force": "maybe"}), 422)

    r.check(P, "POST /grounding/calibrate {} -> 202 job_id+run_id", calibrate_unforced,
            gate="cal_job")
    r.check(P, "calibrate status -> already_calibrated (no sweep, no spend)",
            calibrate_status_is_skipped, needs="cal_job")
    r.check(P, "GET /grounding/calibrate/events/{job} -> terminal snapshot", calibrate_events,
            needs="cal_job")
    if "emb" in jobs:
        r.check(P, "GET /grounding/calibrate/status/{emb job} -> 404 (cross-family)",
                calibrate_cross_family_is_404, needs="cal_job")
    r.check(P, "POST /grounding/calibrate {force:'maybe'} -> 422", calibrate_bad_force_is_422)
    return jobs


# ============================================================================================
# Phase 3b — the threat-library importer and the ATT&CK/CAPEC technique corpus
#
# CONTAINMENT: the import route is only ever called with `dry_run: true`. A real import upserts
# into the SQL threat library (Threat_Type / Threat_Catalogue), which is shared master data --
# not something a smoke test gets to rewrite. app/intel/library_import.py::run_import gates
# every write on `not dry_run`, and the result echoes `dry_run` back, so the run can PROVE it
# stayed read-only rather than assuming it.
#
# The technique rebuild IS run for real, and that is safe by construction: it builds into a
# staging collection and publishes with `staging.rename(COLLECTION, dropTarget=True)`, a single
# metadata operation, so a reader sees either the old corpus or the new one and never a gap.
# ============================================================================================
def phase3b(r: Runner, emb_job: str = "") -> None:
    P = "3b-library+techniques"
    TI = "/v1/tsg/threat-intel"
    st: dict[str, Any] = {}

    # --- technique corpus ---------------------------------------------------------------
    def techniques_status() -> None:
        body = r.expect(r.req("GET", f"{TI}/techniques", headers=r.admin_headers()), 200)
        for k in ("total", "available", "by_source", "by_stride"):
            assert k in body, f"{k} missing from the corpus status"
        assert isinstance(body["available"], bool)
        # `available` means the STORE is reachable, deliberately distinct from an empty corpus:
        # both report total 0, only one is a fault. So an unreachable store must never claim a
        # non-zero total, and that is the invariant worth pinning.
        if not body["available"]:
            assert body["total"] == 0, "corpus store unreachable but reporting documents"
        st["total_before"] = body["total"]
        st["built_before"] = body.get("built_at")

    def rebuild_unknown_source_is_422() -> None:
        r.expect(r.req("POST", f"{TI}/techniques/rebuild", headers=r.admin_headers(),
                       json={"sources": ["not_a_source"]}), 422)

    def rebuild_mixed_sources_is_422() -> None:
        # One bad name among good ones must still be refused up front, not silently dropped:
        # a typo'd source would otherwise produce a smaller corpus and no error anywhere.
        r.expect(r.req("POST", f"{TI}/techniques/rebuild", headers=r.admin_headers(),
                       json={"sources": ["capec", "not_a_source"]}), 422)

    def rebuild() -> None:
        body = r.expect(r.req("POST", f"{TI}/techniques/rebuild", headers=r.admin_headers(),
                              json={}), 202)
        assert body.get("job_id"), body
        st["tech_job"] = body["job_id"]

    def rebuild_events() -> None:
        frames, ctype = read_sse(r, f"{TI}/techniques/events/{st['tech_job']}",
                                 r.admin_headers(), cap=600)
        assert "text/event-stream" in ctype, f"content-type is {ctype!r}"
        assert frames, "no frames — not even the connect snapshot"
        st["tech_frames"] = frames
        # The job's own verdict, not just "some frames arrived". A rebuild that dies on a
        # download ceiling still streams PENDING -> STARTED -> FAILURE perfectly happily.
        terminal = [f for f in frames if str(f.get("state", "")).upper() in _TERMINAL]
        assert terminal, f"stream ended with no terminal state: {frames[-1] if frames else None}"
        assert terminal[-1]["state"] == "SUCCESS", (
            f"rebuild FAILED: {terminal[-1].get('error')}")

    def rebuild_events_unknown_job_is_404() -> None:
        try:
            read_sse(r, f"{TI}/techniques/events/00000000-0000-0000-0000-000000000000",
                     r.admin_headers(), cap=8)
        except AssertionError as exc:
            assert "404" in str(exc), f"expected 404, got: {exc}"
            return
        raise AssertionError("unknown job id opened a stream instead of returning 404")

    def corpus_is_republished_after_the_rebuild() -> None:
        body = r.expect(r.req("GET", f"{TI}/techniques", headers=r.admin_headers()), 200)
        assert body["available"] is True, "corpus store unreachable after a rebuild"
        assert body["total"] > 0, (
            f"rebuild finished but the corpus still holds {body['total']} documents")
        assert body["by_source"], "documents exist but none carry a source tag"
        assert body["built_at"], "corpus populated but built_at is null"
        # THE assertion. `total > 0` alone is a false pass once the corpus has ever been built:
        # a rebuild that fails leaves the previous corpus in place and the count unchanged.
        # Freshness is built_at MOVING -- the same reason feed health is judged on
        # last_success_at rather than item_count.
        assert body["built_at"] != st.get("built_before"), (
            f"built_at did not advance ({body['built_at']}) — the corpus was not republished")

    # --- library import (DRY RUN ONLY) ---------------------------------------------------
    def import_unknown_source_is_422() -> None:
        r.expect(r.req("POST", f"{TI}/library/import/not_a_source", headers=r.admin_headers(),
                       json={}), 422)

    def import_max_actors_on_the_wrong_source_is_422() -> None:
        # max_actors belongs to misp_actors alone. Accepting it elsewhere would silently ignore
        # a caller's explicit cap, which is worse than refusing it.
        r.expect(r.req("POST", f"{TI}/library/import/pytm", headers=r.admin_headers(),
                       json={"max_actors": 5}), 422)

    def import_dry_run() -> None:
        body = r.expect(r.req("POST", f"{TI}/library/import/pytm", headers=r.admin_headers(),
                              json={"dry_run": True}), 202)
        st["imp_job"] = body["job_id"]

    def import_status_proves_it_stayed_dry() -> None:
        body = poll_job(r, f"{TI}/library/import/status/{st['imp_job']}", r.admin_headers(),
                        cap=420)
        assert body["state"] == "SUCCESS", body
        result = body.get("result") or {}
        assert result.get("dry_run") is True, (
            f"dry_run did not survive into the result: {result}")
        # Black-box proof that nothing was written: every write counter must be zero. Asserted
        # generically so a NEW counter added later is covered without editing this test.
        wrote = {k: v for k, v in result.items()
                 if isinstance(v, int) and v
                 and k.endswith(("_upserted", "_created", "_inserted", "_written", "_activated"))}
        assert not wrote, f"dry_run reported writes: {wrote}"
        st["imp_result"] = result

    def import_events() -> None:
        frames, ctype = read_sse(r, f"{TI}/library/import/events/{st['imp_job']}",
                                 r.admin_headers(), cap=60)
        assert "text/event-stream" in ctype
        assert frames, "an already-finished import must still yield its terminal snapshot"

    def import_status_unknown_job_is_404() -> None:
        r.expect(r.req("GET", f"{TI}/library/import/status/"
                              f"00000000-0000-0000-0000-000000000000",
                       headers=r.admin_headers()), 404)

    def import_status_rejects_another_family() -> None:
        # The provenance marker is the ONLY thing between this route and any other task's
        # result: it never calls require_entity, so a caller who learned an embeddings job id
        # could otherwise poll it here. An authorization bypass, not a cosmetic mismatch.
        r.expect(r.req("GET", f"{TI}/library/import/status/{emb_job}",
                       headers=r.admin_headers()), 404, "cross-family job id leaked")

    r.check(P, "GET /threat-intel/techniques -> corpus status", techniques_status)
    r.check(P, "POST /techniques/rebuild unknown source -> 422", rebuild_unknown_source_is_422)
    r.check(P, "POST /techniques/rebuild one bad among good -> 422", rebuild_mixed_sources_is_422)
    r.check(P, "POST /techniques/rebuild -> 202", rebuild, gate="tech_job")
    r.check(P, "GET /techniques/events/{job} -> SSE frames", rebuild_events, needs="tech_job")
    r.check(P, "GET /techniques/events/{unknown} -> 404", rebuild_events_unknown_job_is_404)
    r.check(P, "corpus is REPUBLISHED (built_at advanced), not merely non-empty",
            corpus_is_republished_after_the_rebuild, needs="tech_job")

    r.check(P, "POST /library/import/{unknown} -> 422", import_unknown_source_is_422)
    r.check(P, "POST /library/import/pytm with max_actors -> 422",
            import_max_actors_on_the_wrong_source_is_422)
    r.check(P, "POST /library/import/pytm {dry_run:true} -> 202", import_dry_run, gate="imp_job")
    r.check(P, "import status: SUCCESS, dry_run echoed, zero writes",
            import_status_proves_it_stayed_dry, needs="imp_job")
    r.check(P, "GET /library/import/events/{job} -> terminal snapshot", import_events,
            needs="imp_job")
    r.check(P, "GET /library/import/status/{unknown} -> 404", import_status_unknown_job_is_404)
    if emb_job:
        r.check(P, "GET /library/import/status/{embeddings job} -> 404 (cross-family)",
                import_status_rejects_another_family)


# ============================================================================================
# Phase 4 — warm reads against sessions that already exist, plus the entity negative matrix
# ============================================================================================
def phase4(r: Runner, other_key: str) -> dict[str, Any]:
    P = "4-warm-reads"
    fx: dict[str, Any] = {}

    def discover() -> None:
        rows = r.expect(r.req("GET", f"/v1/users/{USER_ID}/scenarios", params={"limit": 50},
                              headers=r.entity_headers()), 200)
        assert rows, "no scenarios visible for this user — cannot drive the warm-read phase"
        done = [x for x in rows if x.get("session_status") == "completed"]
        pick = (done or rows)[0]
        fx["session_id"] = pick["session_id"]
        fx["scenario_id"] = pick["scenario_id"]
        fx["entity_id"] = str(pick["entity_id"])

    r.check(P, "GET /v1/users/{id}/scenarios -> fixtures discovered", discover, gate="fixtures")
    if "fixtures" in r.failed_gates:
        return fx
    sid, scid = fx["session_id"], fx["scenario_id"]

    # --- the session board --------------------------------------------------------------
    def board() -> None:
        body = r.expect(r.req("GET", f"/v1/sessions/{sid}", headers=r.entity_headers()), 200)
        prog = body["progress"]
        # Declared breaking change: error_message is a MAP of stage -> message, not a string.
        assert isinstance(prog.get("error_message"), dict), (
            f"progress.error_message is {type(prog.get('error_message')).__name__}, expected dict")
        # The stage fields must publish COMPLETE, never the internal awaiting-decision label.
        assert prog.get("scenarios") != "SCENARIOS_AWAITING_DECISION", (
            "internal StageStatus leaked into the published progress.scenarios field")
        fx["overall"] = prog.get("overall")
        fx["session_status"] = body["session_status"]

    def completed_can_still_await_review() -> None:
        # The flagship "the obvious field lies" case: session_status says the AI finished;
        # progress.overall says a human has not decided. A UI reading only the first is wrong.
        assert fx.get("overall") is not None, "progress.overall missing"

    def missing_tenant_is_401() -> None:
        h = r.entity_headers()
        h.pop("X-Tenant-Id")
        r.expect(r.req("GET", f"/v1/sessions/{sid}", headers=h), 401, "X-Tenant-Id not required")

    def missing_entity_is_401() -> None:
        h = r.entity_headers()
        h.pop("X-Entity-Id")
        r.expect(r.req("GET", f"/v1/sessions/{sid}", headers=h), 401)

    def wrong_entity_is_403() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}", headers=r.entity_headers(entity="79")), 403)

    def wrong_module_key_is_401() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}",
                       headers=r.entity_headers(**{"X-API-Key": other_key})), 401)

    def non_guid_session_is_404_not_500() -> None:
        r.expect(r.req("GET", "/v1/sessions/not-a-guid", headers=r.entity_headers()), 404,
                 "a malformed id must not reach the DB layer as a 500")

    def unknown_session_is_404() -> None:
        r.expect(r.req("GET", "/v1/sessions/00000000-0000-0000-0000-000000000000",
                       headers=r.entity_headers()), 404)

    r.check(P, "GET /v1/sessions/{id} -> board shape", board, gate="board")
    r.check(P, "progress.overall is published", completed_can_still_await_review, needs="board")
    r.check(P, "GET /v1/sessions/{id} without X-Tenant-Id -> 401", missing_tenant_is_401)
    r.check(P, "GET /v1/sessions/{id} without X-Entity-Id -> 401", missing_entity_is_401)
    r.check(P, "GET /v1/sessions/{id} wrong entity -> 403", wrong_entity_is_403)
    if other_key:
        r.check(P, "GET /v1/sessions/{id} wrong-module key -> 401", wrong_module_key_is_401)
    r.check(P, "GET /v1/sessions/not-a-guid -> 404 (not 500)", non_guid_session_is_404_not_500)
    r.check(P, "GET /v1/sessions/{unknown guid} -> 404", unknown_session_is_404)

    # --- results / accepted / audit -----------------------------------------------------
    def results() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/results", headers=r.entity_headers()), 200)

    def results_ordering_is_stable() -> None:
        a = r.expect(r.req("GET", f"/v1/sessions/{sid}/results", headers=r.entity_headers()), 200)
        b = r.expect(r.req("GET", f"/v1/sessions/{sid}/results", headers=r.entity_headers()), 200)
        assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True), \
            "two identical reads of /results disagreed — ordering is not stable"

    def results_include_replaced() -> None:
        body = r.expect(r.req("GET", f"/v1/sessions/{sid}/results",
                              params={"include_replaced": "true"},
                              headers=r.entity_headers()), 200)
        for c in (body.get("scenarios") or []) if isinstance(body, dict) else []:
            for rep in (c.get("replaced_scenarios") or []):
                assert rep.get("scenario_id") != c.get("scenario_id"), "a card contains itself"
                assert not rep.get("replaced_scenarios"), "replacement nesting deeper than one"

    def accepted_scenarios() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/accepted-scenarios",
                       headers=r.entity_headers()), 200)

    def audit() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/audit", params={"limit": 5},
                       headers=r.entity_headers()), 200)

    def audit_bad_event_is_422() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/audit", params={"event": "bogus"},
                       headers=r.entity_headers()), 422)

    def audit_bounds() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/audit", params={"limit": 501},
                       headers=r.entity_headers()), 422)

    r.check(P, "GET /v1/sessions/{id}/results -> 200", results)
    r.check(P, "GET /results ordering is stable across reads", results_ordering_is_stable)
    r.check(P, "GET /results?include_replaced nests exactly one level", results_include_replaced)
    r.check(P, "GET /v1/sessions/{id}/accepted-scenarios -> 200", accepted_scenarios)
    r.check(P, "GET /v1/sessions/{id}/audit -> 200", audit)
    r.check(P, "GET /audit?event=bogus -> 422", audit_bad_event_is_422)
    r.check(P, "GET /audit?limit=501 -> 422", audit_bounds)

    # --- cross-session scenario reads ---------------------------------------------------
    def user_scenarios_bad_status_is_422() -> None:
        r.expect(r.req("GET", f"/v1/users/{USER_ID}/scenarios", params={"status": "bogus"},
                       headers=r.entity_headers()), 422)

    def unknown_user_is_empty_not_403() -> None:
        # This route filters by user, it does not assert identity — an unknown user is an empty
        # list, never a 403. Contrast with the entity route below.
        body = r.expect(r.req("GET", "/v1/users/no-such-user-xyz/scenarios",
                              headers=r.entity_headers()), 200)
        assert body == [], f"expected an empty list, got {len(body)} rows"

    def entity_scenarios() -> None:
        r.expect(r.req("GET", f"/v1/entities/{fx['entity_id']}/scenarios",
                       headers=r.entity_headers(entity=fx["entity_id"])), 200)

    def entity_path_header_mismatch_is_403() -> None:
        # require_entity compares the PATH entity against the caller's authorized set, and that
        # set is exactly what X-Entity-Id declared. So the 403 needs a MISMATCH: asking for 79
        # while declaring 78. Sending entity=79 in both places is a legitimate 200 (empty) --
        # asserting 403 there would be testing a rule the design does not have.
        r.expect(r.req("GET", "/v1/entities/79/scenarios",
                       headers=r.entity_headers(entity=fx["entity_id"])), 403)

    def entity_self_declared_is_allowed() -> None:
        # The flip side, recorded deliberately: any valid key may declare ANY entity in the
        # header and read it. verify_membership is off by design (deps.py) -- X-API-Key is the
        # whole security boundary. This asserts the CURRENT posture so a change to it is visible.
        r.expect(r.req("GET", "/v1/entities/79/scenarios",
                       headers=r.entity_headers(entity="79")), 200)

    def one_scenario() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/scenarios/{scid}",
                       params={"user_id": USER_ID}, headers=r.entity_headers()), 200)

    def one_scenario_without_user_id_is_422() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/scenarios/{scid}",
                       headers=r.entity_headers()), 422)

    def one_scenario_wrong_user_is_404_not_403() -> None:
        # Deliberate no-existence-leak: a scenario you may not see is indistinguishable from
        # one that does not exist.
        r.expect(r.req("GET", f"/v1/sessions/{sid}/scenarios/{scid}",
                       params={"user_id": "someone-else"}, headers=r.entity_headers()), 404)

    def one_scenario_non_guid_is_404() -> None:
        r.expect(r.req("GET", f"/v1/sessions/{sid}/scenarios/not-a-guid",
                       params={"user_id": USER_ID}, headers=r.entity_headers()), 404)

    r.check(P, "GET /v1/users/{id}/scenarios?status=bogus -> 422", user_scenarios_bad_status_is_422)
    r.check(P, "GET /v1/users/{unknown}/scenarios -> 200 empty (not 403)",
            unknown_user_is_empty_not_403)
    r.check(P, "GET /v1/entities/{id}/scenarios -> 200", entity_scenarios)
    r.check(P, "GET /v1/entities/79 with X-Entity-Id 78 -> 403", entity_path_header_mismatch_is_403)
    r.check(P, "GET /v1/entities/79 with X-Entity-Id 79 -> 200 (self-declared entity is allowed)",
            entity_self_declared_is_allowed)
    r.check(P, "GET /v1/sessions/{sid}/scenarios/{scid}?user_id -> 200", one_scenario)
    r.check(P, "GET /v1/sessions/{sid}/scenarios/{scid} without user_id -> 422",
            one_scenario_without_user_id_is_422)
    r.check(P, "GET .../scenarios/{scid}?user_id=wrong -> 404 (not 403)",
            one_scenario_wrong_user_is_404_not_403)
    r.check(P, "GET .../scenarios/not-a-guid -> 404", one_scenario_non_guid_is_404)

    # --- conflict states on a finished session ------------------------------------------
    def cancel_completed_is_409() -> None:
        r.expect(r.req("POST", f"/v1/sessions/{sid}/cancel", headers=r.entity_headers()), 409)

    def accept_malformed_is_422() -> None:
        for body in ({"mode": "all", "scenario_ids": []}, {"mode": "subset"}, {"mode": "bogus"}):
            r.expect(r.req("POST", f"/v1/sessions/{sid}/accept", headers=r.entity_headers(),
                           json=body), 422, f"accept {body}")

    def accept_non_guid_id_is_422_not_500() -> None:
        r.expect(r.req("POST", f"/v1/sessions/{sid}/accept", headers=r.entity_headers(),
                       json={"mode": "subset", "scenario_ids": ["not-a-guid"]}), 422)

    def accept_over_batch_is_422() -> None:
        r.expect(r.req("POST", f"/v1/sessions/{sid}/accept", headers=r.entity_headers(),
                       json={"mode": "subset", "scenario_ids": [scid] * 51}), 422, "batch cap 50")

    r.check(P, "POST /v1/sessions/{completed}/cancel -> 409", cancel_completed_is_409)
    r.check(P, "POST /accept malformed mode/ids -> 422", accept_malformed_is_422)
    r.check(P, "POST /accept non-GUID id -> 422 (not 500)", accept_non_guid_id_is_422_not_500)
    r.check(P, "POST /accept 51 ids -> 422", accept_over_batch_is_422)

    # --- treatment plan reads -----------------------------------------------------------
    def plan_board() -> None:
        body = r.expect(r.req("GET", f"/v1/sessions/{sid}/treatment-plans",
                              headers=r.entity_headers()), 200)
        rows = body.get("scenarios", []) if isinstance(body, dict) else body
        for row in rows:
            # A scenario with no plan must have the whole plan block null TOGETHER — a half-null
            # row is what makes a UI render "status: null" as an error state.
            if row.get("plan_id") is None:
                assert row.get("status") is None and row.get("review_status") is None, row
            else:
                fx.setdefault("plan_scenario_id", row.get("scenario_id"))
                fx.setdefault("plan_id", row.get("plan_id"))

    def entity_plan_register() -> None:
        r.expect(r.req("GET", f"/v1/entities/{fx['entity_id']}/treatment-plans",
                       params={"limit": 5},
                       headers=r.entity_headers(entity=fx["entity_id"])), 200)

    def entity_plan_register_bad_status_is_422() -> None:
        # An unrecognized status used to silently return an empty page, which reads as
        # "no plans" rather than "you asked a nonsense question".
        r.expect(r.req("GET", f"/v1/entities/{fx['entity_id']}/treatment-plans",
                       params={"status": "PENDING"},
                       headers=r.entity_headers(entity=fx["entity_id"])), 422)

    def entity_plan_audit_tz_offset() -> None:
        r.expect(r.req("GET", f"/v1/entities/{fx['entity_id']}/treatment-plans/audit",
                       params={"from": "2026-01-01T00:00:00+05:30", "limit": 5},
                       headers=r.entity_headers(entity=fx["entity_id"])), 200,
                 "a tz-aware bound must be accepted and normalised")

    def discover_plan_fixture() -> None:
        """Find a scenario that ACTUALLY has a plan, from the entity-wide register.

        The session picked for the read phase often has no treatment plan at all, and the
        earlier version silently skipped all seven plan routes when that happened — 7 untested
        routes reported as a clean run, which is worse than a failure.
        """
        rows = r.expect(r.req("GET", f"/v1/entities/{fx['entity_id']}/treatment-plans",
                              params={"limit": 50},
                              headers=r.entity_headers(entity=fx["entity_id"])), 200)
        rows = rows if isinstance(rows, list) else rows.get("plans", rows.get("items", []))
        row = next((x for x in rows if x.get("plan_id") and x.get("scenario_id")), None)
        assert row is not None, "no treatment plan exists anywhere for this entity"
        fx["plan_session_id"] = row.get("session_id", sid)
        fx["plan_scenario_id"] = row["scenario_id"]
        fx["plan_id"] = row["plan_id"]

    r.check(P, "GET /v1/sessions/{id}/treatment-plans -> board", plan_board, gate="plan_board")
    r.check(P, "a scenario with a plan is discoverable", discover_plan_fixture, gate="plan_fx")
    r.check(P, "GET /v1/entities/{id}/treatment-plans -> register", entity_plan_register)
    r.check(P, "GET /entities/{id}/treatment-plans?status=PENDING -> 422",
            entity_plan_register_bad_status_is_422)
    r.check(P, "GET /entities/{id}/treatment-plans/audit with +05:30 offset -> 200",
            entity_plan_audit_tz_offset)

    psc = fx.get("plan_scenario_id")
    psid = fx.get("plan_session_id", sid)
    if psc:
        def plan_get() -> None:
            r.expect(r.req("GET", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan",
                           headers=r.entity_headers()), 200)

        def plan_status() -> None:
            r.expect(r.req("GET", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan/status",
                           headers=r.entity_headers()), 200)

        def plan_audit() -> None:
            r.expect(r.req("GET", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan/audit",
                           headers=r.entity_headers()), 200)

        def plan_evidence_needs_version() -> None:
            r.expect(r.req("GET", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan/evidence",
                           headers=r.entity_headers()), 422)

        def plan_evidence() -> None:
            r.expect(r.req("GET", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan/evidence",
                           params={"version": fx["plan_id"]}, headers=r.entity_headers()), 200)

        def plan_duplicate_is_409() -> None:
            # A COMPLETE, valid body on purpose: with a body that fails validation this would
            # 422 first and the 409 would never be reached, so the check would pass while
            # proving nothing about the conflict it claims to test.
            r.expect(r.req("POST", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan",
                           headers=r.entity_headers(), json=dict(_PLAN_BODY)), 409)

        def plan_body_bounds_are_422() -> None:
            for bad in ({**_PLAN_BODY, "likelihood_rating": 6},
                        {**_PLAN_BODY, "impact_rating": 0},
                        {**_PLAN_BODY, "final_risk_rating": 26},
                        {**_PLAN_BODY, "strategy": "avoid"},          # extra="forbid"
                        {k: v for k, v in _PLAN_BODY.items() if k != "risk_level"}):
                r.expect(r.req("POST", f"/v1/sessions/{psid}/scenarios/{psc}/treatment-plan",
                               headers=r.entity_headers(), json=bad), 422,
                         f"body {sorted(bad)}")

        r.check(P, "GET .../treatment-plan -> 200", plan_get, needs="plan_board")
        r.check(P, "GET .../treatment-plan/status -> 200", plan_status, needs="plan_board")
        r.check(P, "GET .../treatment-plan/audit -> 200", plan_audit, needs="plan_board")
        r.check(P, "GET .../treatment-plan/evidence without version -> 422",
                plan_evidence_needs_version, needs="plan_board")
        r.check(P, "GET .../treatment-plan/evidence?version -> 200", plan_evidence,
                needs="plan_board")
        r.check(P, "POST .../treatment-plan where one exists -> 409", plan_duplicate_is_409,
                needs="plan_board")
        r.check(P, "POST .../treatment-plan out-of-range / extra fields -> 422",
                plan_body_bounds_are_422, needs="plan_board")
    return fx


# Assets confirmed present for entity 78 — read back from Scenario_Session rows this DB already
# holds, not guessed. A fixture drift therefore shows up as a 403 "asset not owned by entity"
# rather than a mystery failure three checks later.
_ASSETS = {
    99: {"subsystems": [306, 307, 308], "subsector": 110},   # Power Generation System
    100: {"subsystems": [309, 310, 311], "subsector": 110},  # Smart Grid Infrastructure
}


def _create_body(asset: int, entity: str) -> dict[str, Any]:
    a = _ASSETS[asset]
    return {"entity_id": entity, "asset_id": asset,
            "subsector_id": a["subsector"], "supporting_system_id": list(a["subsystems"])}


def poll_board(r: Runner, sid: str, want: Callable[[dict], bool], *,
               cap: float, every: float = 8.0) -> dict:
    """Poll GET /v1/sessions/{id} until `want(body)` holds or the budget expires."""
    t0 = time.time()
    body: dict = {}
    while time.time() - t0 < cap:
        body = r.expect(r.req("GET", f"/v1/sessions/{sid}", headers=r.entity_headers()), 200)
        if want(body):
            return body
        time.sleep(every)
    raise AssertionError(
        f"budget {cap}s expired; last overall="
        f"{body.get('progress', {}).get('overall')!r} status={body.get('session_status')!r}")



def post_past_the_lock(r: Runner, path: str, headers: dict[str, str], *, cap: float = 180.0,
                       json_body: Any = None, expect: int = 202) -> dict:
    """POST, retrying while the subsystem lock is still held.

    THE CONTRACT GAP THIS PAPERS OVER: the regenerate route tells clients to confirm completion
    by polling until `progress.last_regen.epoch` matches. But cascade.py commits the
    `regeneration_completed` audit row (which is what that field reads) INSIDE the
    `with _subsystem_lock(...)` block, so the epoch is visible to a poller while the lock is
    still held. A client that follows the documented protocol exactly and then issues its next
    call can get `409 regenerate_conflict: subsystem N is locked`. This run hit it on the first
    attempt, on both next-set and accept. There is no public field a client could poll instead,
    so retrying is the only thing a real client could do either.
    """
    t0 = time.time()
    last = None
    while time.time() - t0 < cap:
        resp = r.req("POST", path, headers=headers, **({"json": json_body} if json_body is not None else {}))
        if resp.status_code != 409 or ("locked" not in resp.text and "lock held" not in resp.text):
            return r.expect(resp, expect)
        last = resp.text[:160]
        time.sleep(5)
    raise AssertionError(f"still lock-conflicted after {cap}s: {last}")


# ============================================================================================
# Phase 5 — create -> cancel lifecycle, the SSE close guarantee, and the create negatives
# ============================================================================================
def phase5(r: Runner, entity: str, run_id: str) -> None:
    P = "5-create-cancel"
    st: dict[str, Any] = {}
    H = r.entity_headers(entity=entity)

    def create() -> None:
        body = r.expect(r.req("POST", "/v1/sessions",
                              headers={**H, "Idempotency-Key": f"{run_id}-cx"},
                              json=_create_body(99, entity)), 202)
        st["sid"] = body["session_id"]

    def is_active() -> None:
        body = r.expect(r.req("GET", f"/v1/sessions/{st['sid']}", headers=H), 200)
        assert body["session_status"] == "active", body["session_status"]

    def idempotent_replay_returns_the_same_session() -> None:
        # Same key, same asset -> 200 (not a second 202) with the ORIGINAL id. A retry after a
        # dropped response must never start a second generation run.
        body = r.expect(r.req("POST", "/v1/sessions",
                              headers={**H, "Idempotency-Key": f"{run_id}-cx"},
                              json=_create_body(99, entity)), 200, "idempotent replay")
        assert body["session_id"] == st["sid"], "replay returned a DIFFERENT session"

    def idempotency_conflict_is_409() -> None:
        r.expect(r.req("POST", "/v1/sessions",
                       headers={**H, "Idempotency-Key": f"{run_id}-cx"},
                       json=_create_body(100, entity)), 409, "same key, different asset")

    def active_asset_conflict_is_409() -> None:
        r.expect(r.req("POST", "/v1/sessions",
                       headers={**H, "Idempotency-Key": f"{run_id}-cx2"},
                       json=_create_body(99, entity)), 409, "asset already has an active session")

    def cancel() -> None:
        body = r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/cancel", headers=H), 200)
        assert body.get("status") == "cancelled", body

    def cancel_again_is_409() -> None:
        r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/cancel", headers=H), 409)

    def cancelled_stream_closes() -> None:
        # The close guarantee: a cancelled session has nothing left to report, so the stream
        # must end on its own. One that never closes leaks a connection per viewer until the
        # process hits its SSE cap and every later stream is refused.
        t0 = time.time()
        read_sse(r, f"/v1/sessions/{st['sid']}/events", H, cap=20, max_frames=200)
        assert time.time() - t0 < 19, "stream did not close by itself within the budget"

    def board_reads_cancelled() -> None:
        body = r.expect(r.req("GET", f"/v1/sessions/{st['sid']}", headers=H), 200)
        assert body["progress"]["overall"] == "cancelled", body["progress"]["overall"]

    # --- create negatives (all rejected before any row is written) ----------------------
    def body_entity_mismatch_is_403() -> None:
        r.expect(r.req("POST", "/v1/sessions", headers=H,
                       json=_create_body(99, "79")), 403, "body entity != header entity")

    def unowned_asset_is_403() -> None:
        # 403, not 404: the asset may well exist, it is simply not this entity's.
        r.expect(r.req("POST", "/v1/sessions", headers=H,
                       json={**_create_body(99, entity), "asset_id": 999999}), 403)

    def duplicate_subsystems_is_422() -> None:
        r.expect(r.req("POST", "/v1/sessions", headers=H,
                       json={**_create_body(99, entity),
                             "supporting_system_id": [306, 306]}), 422)

    def empty_subsystems_is_422() -> None:
        r.expect(r.req("POST", "/v1/sessions", headers=H,
                       json={**_create_body(99, entity), "supporting_system_id": []}), 422)

    def too_many_subsystems_is_422() -> None:
        r.expect(r.req("POST", "/v1/sessions", headers=H,
                       json={**_create_body(99, entity),
                             "supporting_system_id": list(range(1, 60))}), 422)

    def oversized_idempotency_key_is_422() -> None:
        r.expect(r.req("POST", "/v1/sessions", headers={**H, "Idempotency-Key": "k" * 201},
                       json=_create_body(99, entity)), 422, "201-char key must not 500")

    r.check(P, "POST /v1/sessions (asset 99) -> 202", create, gate="cancel_session")
    r.check(P, "new session reads active", is_active, needs="cancel_session")
    r.check(P, "same Idempotency-Key + same asset -> 200 same session",
            idempotent_replay_returns_the_same_session, needs="cancel_session")
    r.check(P, "same Idempotency-Key + different asset -> 409", idempotency_conflict_is_409,
            needs="cancel_session")
    r.check(P, "second session on a busy asset -> 409", active_asset_conflict_is_409,
            needs="cancel_session")
    r.check(P, "POST /cancel -> 200 cancelled", cancel, needs="cancel_session")
    r.check(P, "POST /cancel again -> 409", cancel_again_is_409, needs="cancel_session")
    r.check(P, "SSE on a cancelled session closes itself", cancelled_stream_closes,
            needs="cancel_session")
    r.check(P, "board reads cancelled", board_reads_cancelled, needs="cancel_session")
    r.check(P, "POST /v1/sessions body entity != header -> 403", body_entity_mismatch_is_403)
    r.check(P, "POST /v1/sessions unowned asset -> 403 (not 404)", unowned_asset_is_403)
    r.check(P, "POST /v1/sessions duplicate subsystem ids -> 422", duplicate_subsystems_is_422)
    r.check(P, "POST /v1/sessions empty subsystem list -> 422", empty_subsystems_is_422)
    r.check(P, "POST /v1/sessions 59 subsystem ids -> 422", too_many_subsystems_is_422)
    r.check(P, "POST /v1/sessions 201-char Idempotency-Key -> 422 (not 500)",
            oversized_idempotency_key_is_422)


# ============================================================================================
# Phase 6 — one REAL generation, then every decision route against it
# ============================================================================================
def phase6(r: Runner, entity: str, run_id: str, budget: float) -> dict[str, Any]:
    P = "6-generation"
    st: dict[str, Any] = {}
    H = r.entity_headers(entity=entity)

    def create() -> None:
        # Try each known asset: `active_session_exists` is a legitimate state (a colleague, or
        # an earlier run whose generation is still finishing), not a defect. Hardcoding one
        # asset turns somebody else's in-flight work into a red suite.
        errors = []
        for asset in (100, 99):
            resp = r.req("POST", "/v1/sessions",
                         headers={**H, "Idempotency-Key": f"{run_id}-hot{asset}"},
                         json=_create_body(asset, entity))
            if resp.status_code == 202:
                st["sid"] = resp.json()["session_id"]
                st["asset"] = asset
                return
            errors.append(f"asset {asset}: {resp.status_code} {resp.text[:90]}")
        raise AssertionError("no free asset to generate against — " + "; ".join(errors))

    def reaches_review() -> None:
        body = poll_board(r, st["sid"], lambda b: b["progress"]["overall"] in
                          ("awaiting_review", "complete", "error"), cap=budget)
        assert body["progress"]["overall"] != "error", \
            f"generation failed: {body['progress'].get('error_message')}"
        st["board"] = body

    def results_have_cards() -> None:
        body = r.expect(r.req("GET", f"/v1/sessions/{st['sid']}/results", headers=H), 200)
        cards = body.get("scenarios") or []
        assert cards, "no scenario cards after generation"
        # A card whose `scenario` is null is a FAILURE card — it can never be accepted, so
        # grabbing cards[0] blindly 404s later and the accept route takes the blame.
        good = [c for c in cards if c.get("scenario")]
        assert good, f"all {len(cards)} cards are failure cards"
        st["ids"] = [c["scenario_id"] for c in good]

    def accept_none_decides_nothing() -> None:
        body = r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/accept", headers=H,
                              json={"mode": "none"}), 200)
        assert body.get("accepted_count") == 0, body
        after = r.expect(r.req("GET", f"/v1/sessions/{st['sid']}", headers=H), 200)
        assert after["progress"]["overall"] == "awaiting_review", "mode=none advanced the session"

    def reject_one() -> None:
        body = r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/scenarios/reject", headers=H,
                              json={"scenario_ids": [st["ids"][-1]]}), 200)
        assert body.get("rejected_count") == 1, body
        st["rejected"] = st["ids"][-1]

    def accepting_a_rejected_one_is_404() -> None:
        r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/accept", headers=H,
                       json={"mode": "subset", "scenario_ids": [st["rejected"]]}), 404,
                 "already_rejected")

    def accept_subset_is_repeatable() -> None:
        target = st["ids"][0]
        first = r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/accept", headers=H,
                               json={"mode": "subset", "scenario_ids": [target]}), 200)
        assert first.get("accepted_count") == 1, first
        # Repeating the same decision must be a no-op, never a re-stamp of accepted_by/at.
        r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/accept", headers=H,
                       json={"mode": "subset", "scenario_ids": [target]}), 200, "repeat accept")
        st["accepted"] = target

    def regenerate_one() -> None:
        keep = [i for i in st["ids"] if i not in (st.get("accepted"), st.get("rejected"))]
        assert keep, "no undecided scenario left to regenerate"
        body = r.expect(r.req("POST", f"/v1/sessions/{st['sid']}/regenerate/scenarios",
                              headers=H, json={"scenario_ids": [keep[0]]}), 202)
        epoch = body.get("epoch")
        # The SSE regen_result frame carries no epoch, so the board is the durable confirmation.
        poll_board(r, st["sid"], lambda b: (b["progress"].get("last_regen") or {}).get("epoch")
                   == epoch, cap=300, every=10)

    def regenerate_foreign_scenario_is_409_with_a_reason() -> None:
        # NOT a 404, deliberately: an id that never existed and one that has been superseded are
        # indistinguishable to this route, and both mean "not a current regeneration target".
        # The reason code is what makes them actionable, so assert that, not just the status.
        resp = r.req("POST", f"/v1/sessions/{st['sid']}/regenerate/scenarios", headers=H,
                     json={"scenario_ids": ["00000000-0000-0000-0000-000000000000"]})
        body = r.expect(resp, 409, "unknown scenario id")
        assert body.get("details", {}).get("reason") == "output_not_found_or_superseded", body

    def next_set() -> None:
        body = post_past_the_lock(r, f"/v1/sessions/{st['sid']}/scenarios/next-set", H)
        epoch = body.get("epoch")
        board = poll_board(r, st["sid"],
                           lambda b: (b["progress"].get("last_next_set") or {}).get("epoch")
                           == epoch, cap=420, every=10)
        outcome = (board["progress"].get("last_next_set") or {}).get("outcome")
        # `exhausted` is a CORRECT final answer on an asset whose pool is drained, not a failure.
        assert outcome in ("complete", "partial_retryable", "exhausted"), outcome

    def accept_all() -> None:
        post_past_the_lock(r, f"/v1/sessions/{st['sid']}/accept", H,
                           json_body={"mode": "all"}, expect=200)

    def promote_to_library() -> None:
        st["promoted"] = r.expect(r.req(
            "POST", f"/v1/sessions/{st['sid']}/scenarios/{st['accepted']}/promote-to-library",
            headers=H), 200)

    def promote_is_idempotent() -> None:
        body = r.expect(r.req(
            "POST", f"/v1/sessions/{st['sid']}/scenarios/{st['accepted']}/promote-to-library",
            headers=H), 200)
        assert body.get("created_count") == 0, f"a second promote created rows again: {body}"

    def promote_a_rejected_one_is_409() -> None:
        r.expect(r.req(
            "POST", f"/v1/sessions/{st['sid']}/scenarios/{st['rejected']}/promote-to-library",
            headers=H), 409)

    def accepted_scenarios_and_audit() -> None:
        acc = r.expect(r.req("GET", f"/v1/sessions/{st['sid']}/accepted-scenarios",
                             headers=H), 200)
        rows = acc.get("scenarios", []) if isinstance(acc, dict) else acc
        assert rows, "accept succeeded but accepted-scenarios is empty"
        for row in rows:
            assert row.get("accepted_by") and row.get("accepted_at"), row
        r.expect(r.req("GET", f"/v1/sessions/{st['sid']}/audit",
                       params={"event": "scenario_accepted"}, headers=H), 200)

    r.check(P, "POST /v1/sessions on a free asset -> 202", create, gate="hot")
    r.check(P, f"generation reaches the review barrier (<={int(budget)}s)", reaches_review,
            gate="hot", needs="hot")
    r.check(P, "GET /results has a non-failure card", results_have_cards, gate="hot", needs="hot")
    r.check(P, "POST /accept {mode:none} -> 200, decides nothing", accept_none_decides_nothing,
            needs="hot")
    r.check(P, "POST /scenarios/reject -> 200", reject_one, gate="rejected", needs="hot")
    r.check(P, "accepting a rejected scenario -> 404", accepting_a_rejected_one_is_404,
            needs="rejected")
    r.check(P, "POST /accept subset -> 200 and repeatable", accept_subset_is_repeatable,
            gate="accepted", needs="hot")
    r.check(P, "POST /regenerate/scenarios -> epoch lands on the board", regenerate_one,
            needs="hot")
    r.check(P, "POST /regenerate/scenarios unknown id -> 409 + reason code",
            regenerate_foreign_scenario_is_409_with_a_reason, needs="hot")
    r.check(P, "POST /scenarios/next-set -> a valid outcome", next_set, needs="hot")
    r.check(P, "POST /accept {mode:all} -> 200", accept_all, needs="hot")
    r.check(P, "POST /promote-to-library -> 200", promote_to_library, gate="promoted",
            needs="accepted")
    r.check(P, "POST /promote-to-library twice -> created_count 0", promote_is_idempotent,
            needs="promoted")
    r.check(P, "promote a REJECTED scenario -> 409", promote_a_rejected_one_is_409,
            needs="rejected")
    r.check(P, "accepted-scenarios + audit record the decision", accepted_scenarios_and_audit,
            needs="accepted")
    return st


# ============================================================================================
# Phase 7 — treatment plan write side, against the scenario accepted in phase 6
# ============================================================================================
def phase7(r: Runner, entity: str, sid: str, scid: str) -> None:
    P = "7-treatment-write"
    st: dict[str, Any] = {}
    H = r.entity_headers(entity=entity)
    base = f"/v1/sessions/{sid}/scenarios/{scid}/treatment-plan"

    def wait_until_settled(cap: float = 240.0) -> str:
        t0 = time.time()
        while time.time() - t0 < cap:
            body = r.expect(r.req("GET", f"{base}/status", headers=H), 200)
            overall = body["progress"]["overall"]
            if overall not in ("generating", "pending"):
                return overall
            time.sleep(4)
        raise AssertionError(f"plan did not leave 'generating' within {cap}s")

    def create_plan() -> None:
        body = r.expect(r.req("POST", base, headers=H, json=dict(_PLAN_BODY)), 202)
        st["plan_id"] = body.get("plan_id")

    def completes() -> None:
        st["overall"] = wait_until_settled()

    def plan_is_readable_with_warnings_surfaced() -> None:
        body = r.expect(r.req("GET", base, headers=H), 200)
        assert body.get("status") in ("COMPLETE", "ERROR"), body.get("status")
        if body.get("status") == "COMPLETE":
            # A plan can complete with an EMPTY action list plus a warning. Treating COMPLETE
            # alone as "ready" is how an empty plan reaches a reviewer looking finished.
            assert "warnings" in body, "COMPLETE plan does not surface a warnings field"

    def duplicate_is_409() -> None:
        r.expect(r.req("POST", base, headers=H, json=dict(_PLAN_BODY)), 409)

    def regenerate() -> None:
        body = r.expect(r.req("POST", f"{base}/regenerate", headers=H, json={}), 202)
        new_id = body.get("plan_id")
        assert new_id and new_id != st.get("plan_id"), "regenerate reused the same plan_id"
        st["v2"] = new_id

    def regenerate_rejects_extra_fields() -> None:
        r.expect(r.req("POST", f"{base}/regenerate", headers=H, json={"user_note": "x"}), 422)

    def cancel_in_flight() -> None:
        # A race by nature: the worker may finish first. BOTH answers are correct — what must
        # never happen is a 500, or a silent success against an already-finished plan.
        resp = r.req("POST", f"{base}/cancel", headers=H)
        assert resp.status_code in (200, 409), f"got {resp.status_code}: {resp.text[:200]}"
        st["cancel_status"] = resp.status_code

    def settle_after_cancel() -> None:
        if st.get("cancel_status") == 200:
            r.expect(r.req("POST", f"{base}/regenerate", headers=H, json={}), 202)
        wait_until_settled()

    def cancel_completed_is_409() -> None:
        r.expect(r.req("POST", f"{base}/cancel", headers=H), 409, "cancel on a finished plan")

    def review_needs_plan_id() -> None:
        r.expect(r.req("POST", f"{base}/review", headers=H, json={"decision": "approved"}), 422)

    def review_unknown_plan_is_404() -> None:
        r.expect(r.req("POST", f"{base}/review", headers=H,
                       json={"decision": "approved",
                             "plan_id": "00000000-0000-0000-0000-000000000000"}), 404)

    def approve() -> None:
        current = r.expect(r.req("GET", base, headers=H), 200)
        pid = current.get("plan_id") or st.get("v2") or st.get("plan_id")
        body = r.expect(r.req("POST", f"{base}/review", headers=H,
                              json={"decision": "approved", "plan_id": pid}), 200)
        assert body.get("reviewed_by") == USER_ID, body

    def audit_records_the_review() -> None:
        r.expect(r.req("GET", f"{base}/audit", headers=H), 200)

    r.check(P, "POST .../treatment-plan -> 202", create_plan, gate="plan")
    r.check(P, "plan leaves 'generating'", completes, gate="plan", needs="plan")
    r.check(P, "GET .../treatment-plan surfaces status + warnings",
            plan_is_readable_with_warnings_surfaced, needs="plan")
    r.check(P, "POST .../treatment-plan again -> 409", duplicate_is_409, needs="plan")
    r.check(P, "POST .../regenerate -> a NEW plan_id", regenerate, needs="plan")
    r.check(P, "POST .../regenerate with an extra field -> 422", regenerate_rejects_extra_fields,
            needs="plan")
    r.check(P, "POST .../cancel mid-flight -> 200 or 409, never 500", cancel_in_flight,
            needs="plan")
    r.check(P, "plan settles after the cancel race", settle_after_cancel, needs="plan")
    r.check(P, "POST .../cancel on a finished plan -> 409", cancel_completed_is_409, needs="plan")
    r.check(P, "POST .../review without plan_id -> 422", review_needs_plan_id, needs="plan")
    r.check(P, "POST .../review unknown plan_id -> 404", review_unknown_plan_is_404, needs="plan")
    r.check(P, "POST .../review approved -> 200, attributed", approve, needs="plan")
    r.check(P, "GET .../treatment-plan/audit after review -> 200", audit_records_the_review,
            needs="plan")


# ============================================================================================
# Phase 8 — teardown. Runs in a finally, so a crash still revokes the minted clients.
# ============================================================================================
def phase8(r: Runner, minted: dict[str, str]) -> None:
    P = "8-teardown"
    qa_id, other_id = minted.get("qa_id", ""), minted.get("other_id", "")
    admin_only = {"X-Admin-Key": r.admin_key, "X-User-Id": USER_ID}

    def revoke_qa() -> None:
        # THE guard. Revoking the operator's sole client 401s the entire API.
        assert qa_id.startswith("qa-smoke-"), f"refusing to revoke {qa_id!r}"
        r.expect(r.req("POST", f"/v1/tsg/api-clients/{qa_id}/revoke", headers=admin_only), 200)

    def revoked_key_is_401() -> None:
        r.expect(r.req("GET", "/v1/tsg/threat-intel/feeds",
                       headers={"X-Admin-Key": r.admin_key, "X-API-Key": minted["qa"],
                                "X-User-Id": USER_ID}), 401, "revoked key still works")

    def double_revoke_is_404() -> None:
        assert qa_id.startswith("qa-smoke-")
        r.expect(r.req("POST", f"/v1/tsg/api-clients/{qa_id}/revoke", headers=admin_only), 404)

    def revoke_without_user_is_400() -> None:
        assert other_id.startswith("qa-nomodule-")
        r.expect(r.req("POST", f"/v1/tsg/api-clients/{other_id}/revoke",
                       headers={"X-Admin-Key": r.admin_key}), 400)

    def revoke_other() -> None:
        assert other_id.startswith("qa-nomodule-")
        r.expect(r.req("POST", f"/v1/tsg/api-clients/{other_id}/revoke", headers=admin_only), 200)

    def listing_shows_revoked() -> None:
        body = r.expect(r.req("GET", "/v1/tsg/api-clients",
                              headers={"X-Admin-Key": r.admin_key}), 200)
        for cid in [c for c in (qa_id, other_id) if c]:
            row = next((c for c in body if c["client_id"] == cid), None)
            assert row is not None and row["active"] is False, f"{cid} not shown revoked"
            assert row["revoked_by"] and row["revoked_at"], f"{cid} missing revoke attribution"

    if "qa" in minted:
        r.check(P, "POST /api-clients/{qa}/revoke -> 200", revoke_qa)
        r.check(P, "revoked key -> 401 on a real route", revoked_key_is_401)
        r.check(P, "POST /api-clients/{qa}/revoke again -> 404", double_revoke_is_404)
    if "other" in minted:
        r.check(P, "revoke without X-User-Id -> 400", revoke_without_user_is_400)
        r.check(P, "POST /api-clients/{other}/revoke -> 200", revoke_other)
    r.check(P, "GET /api-clients shows both revoked with attribution", listing_shows_revoked)


# ============================================================================================
def _template_rx(template: str) -> re.Pattern[str]:
    """`/v1/sessions/{session_id}/results` -> a regex matching one concrete path."""
    parts = ["[^/]+" if seg.startswith("{") and seg.endswith("}") else re.escape(seg)
             for seg in template.split("/")]
    return re.compile("^" + "/".join(parts) + "$")


def coverage_gap(routes: set[tuple[str, str]],
                 hit: set[tuple[str, str]]) -> list[tuple[str, str]]:
    """Routes in the live schema that this run never called.

    THE POINT: the previous version of this check only asserted "at least 45 routes exist",
    which is a count, not coverage. Six new routes were added to the app and the suite stayed
    green while testing none of them. A route nobody exercises must turn the run RED, or the
    suite quietly measures its own past instead of the app's present.

    Literal templates are matched before parameterised ones so `/feeds/refresh` is never
    credited to `/feeds/{feed}/refresh`.
    """
    patterns = sorted(((m, t, _template_rx(t)) for m, t in routes),
                      key=lambda x: x[1].count("{"))
    exercised: set[tuple[str, str]] = set()
    for method, concrete in hit:
        for m, template, rx in patterns:
            if m == method and rx.match(concrete):
                exercised.add((m, template))
                break
    return sorted(routes - exercised)


def report(r: Runner, out_dir: Path, routes: set[tuple[str, str]], *,
           partial: bool = False) -> int:
    # Coverage is a RESULT, not a footnote: an untested route is recorded as a failure so it
    # shows up in the same place as every other defect. On a deliberately partial run
    # (--skip-hot) it is a SKIP instead -- flagging routes the operator chose not to run would
    # train them to ignore this line, which is how the gap got in.
    for method, template in coverage_gap(routes, r.hit):
        r.results.append(Result(
            "9-coverage", f"{method} {template}", "SKIP" if partial else "FAIL",
            "route exists in /openapi.json but this run never called it"))
    out_dir.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for res in r.results:
        counts[res.status] = counts.get(res.status, 0) + 1

    (out_dir / "live_smoke_report.json").write_text(
        json.dumps({"summary": counts,
                    "routes_in_schema": sorted(f"{m} {p}" for m, p in routes),
                    "results": [asdict(x) for x in r.results]}, indent=2), encoding="utf-8")

    bad = [x for x in r.results if x.status in ("FAIL", "ERROR")]
    lines = ["# Live smoke failures", ""]
    for x in bad:
        lines += [f"## [{x.phase}] {x.name}",
                  f"- status: **{x.status}**",
                  f"- detail: {x.detail}",
                  f"- X-Request-Id: `{x.request_id}`" if x.request_id else "- X-Request-Id: none",
                  f"- body: `{x.body[:300]}`" if x.body else "", ""]
    (out_dir / "live_smoke_failures.md").write_text("\n".join(lines), encoding="utf-8")

    width = max((len(x.name) for x in r.results), default=10)
    cur = None
    for x in r.results:
        if x.phase != cur:
            cur = x.phase
            print(f"\n--- {cur} ---")
        mark = {"PASS": "ok  ", "FAIL": "FAIL", "ERROR": "ERR ", "SKIP": "skip"}[x.status]
        print(f"  {mark} {x.name:<{width}}  {x.detail[:110]}")
    print(f"\n{counts}\nreports -> {out_dir}")
    return 1 if bad else 0


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # harness stdout is cp1252
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url",
                    default=os.environ.get("TSG_SMOKE_BASE_URL", "http://localhost:8000"))
    ap.add_argument("--out", default=str(ROOT / "logs" / "live_smoke"))
    ap.add_argument("--skip-hot", action="store_true",
                    help="skip phases 6-7 (the live generation and plan writes) — the rest of "
                         "the suite covers 39 of 47 routes in ~2.5 min")
    ap.add_argument("--gen-budget", type=float, default=900.0,
                    help="seconds to allow the generation to reach the review barrier")
    args = ap.parse_args()

    admin_key = env_value("TSG_ADMIN_API_KEY") or env_value("ADMIN_API_KEY")
    if not admin_key:
        print("TSG_ADMIN_API_KEY not found in tsg/.env or the environment", file=sys.stderr)
        return 2

    run_id = str(int(time.time()))
    minted: dict[str, str] = {}
    routes: set[tuple[str, str]] = set()
    with httpx.Client(base_url=args.base_url, timeout=httpx.Timeout(30.0)) as c:
        r = Runner(client=c, admin_key=admin_key)
        try:
            r.req("GET", "/health", timeout=5)
        except Exception as exc:  # noqa: BLE001
            print(f"cannot reach {args.base_url}: {exc}", file=sys.stderr)
            return 2
        try:
            routes = phase0(r)
            minted = phase1(r, run_id)
            if r.api_key:
                st = phase2(r, minted.get("other", ""))
                jobs = phase3(r, st.get("feeds", {}))
                phase3b(r, jobs.get("emb", ""))
                fx = phase4(r, minted.get("other", ""))
                entity = fx.get("entity_id", "78")
                phase5(r, entity, run_id)
                if not args.skip_hot:
                    hot = phase6(r, entity, run_id, args.gen_budget)
                    if hot.get("sid") and hot.get("accepted"):
                        phase7(r, entity, hot["sid"], hot["accepted"])
                    else:
                        r.results.append(Result(
                            "7-treatment-write", "all", "SKIP",
                            "phase 6 produced no accepted scenario to plan against"))
            else:
                r.results.append(Result("2-admin-read", "all", "SKIP", "no API key was minted"))
        finally:
            try:
                phase8(r, minted)
            except Exception as exc:  # noqa: BLE001 — teardown must never mask the real result
                r.results.append(Result("8-teardown", "teardown", "ERROR", repr(exc)))
        return report(r, Path(args.out), routes, partial=args.skip_hot)


if __name__ == "__main__":
    raise SystemExit(main())
