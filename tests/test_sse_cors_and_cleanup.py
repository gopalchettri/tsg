"""Two more plan items that are testable without a live Redis/MSSQL/Celery stack, bundled here
since each is a single, self-contained check:

- Item 31 / verification 12: a CORS preflight from a non-allowlisted origin is rejected; from an
  allowlisted origin, it succeeds AND the three custom auth headers are accepted (not just the
  origin). Mirrors app/main.py's own CORSMiddleware call, not the full app (no DB/lifespan
  needed for a preflight -- Starlette's CORSMiddleware answers OPTIONS itself, before any route).
- Item 15 / part of verification 6: `bus.subscribe()`'s cleanup (`pub.aclose()`/`r.aclose()`)
  must complete even when the consuming task is cancelled mid-wait -- the whole reason the fix is
  `anyio.CancelScope(shield=True)` and not a plain `finally`. redis.asyncio is mocked out
  entirely, so this needs no live Redis.
"""
from __future__ import annotations

import asyncio

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app.sse import bus

_AUTH_HEADERS = ["X-API-Key", "X-User-Id", "X-Entity-Id"]  # app/api/deps.py's three headers


def _cors_app(allowed_origins: list[str]) -> FastAPI:
    app = FastAPI()
    app.add_middleware(CORSMiddleware, allow_origins=allowed_origins, allow_headers=_AUTH_HEADERS)

    @app.get("/v1/sessions/x/events")
    def _stub():  # pragma: no cover - never reached by a preflight
        return {}

    return app


def test_cors_preflight_rejected_for_non_allowlisted_origin():
    client = TestClient(_cors_app(["https://allowed.example"]))
    resp = client.options("/v1/sessions/x/events", headers={
        "Origin": "https://evil.example",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-API-Key",
    })
    assert "access-control-allow-origin" not in resp.headers


def test_cors_preflight_allows_allowlisted_origin_and_auth_headers():
    client = TestClient(_cors_app(["https://allowed.example"]))
    resp = client.options("/v1/sessions/x/events", headers={
        "Origin": "https://allowed.example",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "X-API-Key, X-User-Id, X-Entity-Id",
    })
    assert resp.headers.get("access-control-allow-origin") == "https://allowed.example"
    allowed = resp.headers.get("access-control-allow-headers", "")
    for header in _AUTH_HEADERS:
        assert header.lower() in allowed.lower()


class _FakePubSub:
    def __init__(self):
        self.closed = False
        self.calls = 0

    async def subscribe(self, channel):
        pass

    async def get_message(self, ignore_subscribe_messages=True, timeout=None):
        self.calls += 1
        if self.calls == 1:
            return  # first call: immediate tick, so the test can get past __anext__() #1
        await asyncio.sleep(1000)  # second call: never resolves on its own -- must be cancelled

    async def aclose(self):
        self.closed = True


class _FakeRedis:
    def __init__(self, connection_pool=None):
        self.closed = False
        self.pubsub_obj = _FakePubSub()

    def pubsub(self):
        return self.pubsub_obj

    async def aclose(self):
        self.closed = True


def test_subscribe_cleanup_completes_under_task_cancellation(monkeypatch):
    """Item 15: cancel the task mid-`get_message` wait -- the finally block's two `aclose()`
    calls must still both complete, proving the shield actually protects them."""
    import redis.asyncio as aioredis

    fake = _FakeRedis()
    monkeypatch.setattr(aioredis, "Redis", lambda connection_pool=None: fake)
    monkeypatch.setattr(bus, "_subscriber_pool", lambda: None)

    async def run():
        gen = bus.subscribe("s1")
        await gen.__anext__()  # first get_message() call resolves immediately (a tick)
        task = asyncio.ensure_future(gen.__anext__())  # second call parks in asyncio.sleep(1000)
        await asyncio.sleep(0)  # let it start and suspend inside get_message
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(run())
    assert fake.pubsub_obj.closed
    assert fake.closed


if __name__ == "__main__":
    print("run via pytest")
