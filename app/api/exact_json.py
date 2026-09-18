"""A route class that reads JSON numbers exactly as the client wrote them.

FastAPI parses a body with `request.json()` — stdlib `json.loads` — which turns every decimal into
a binary float BEFORE any schema sees it. A float holds 15 significant digits exactly and no more,
so `999999999999.9997` arrived as `999999999999.9998` and `4.1234000000000000001` as `4.1234` —
accepted and stored as a number the client never sent. `parse_float=Decimal` keeps the literal
text, so the schema judges what was actually sent (and 422s what it cannot keep exactly).
Integers are unaffected: `json.loads` already parses them exactly.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Coroutine
from decimal import Decimal
from typing import Any

from fastapi import Request, Response
from fastapi.routing import APIRoute


class _ExactNumberRequest(Request):
    async def json(self) -> Any:
        if not hasattr(self, "_json"):
            self._json = json.loads(await self.body(), parse_float=Decimal)
        return self._json


class ExactNumberRoute(APIRoute):
    """`APIRouter(route_class=ExactNumberRoute)` — every route on that router reads decimals exactly.
    float-typed fields still validate (pydantic's lax mode takes a Decimal for a float)."""

    def get_route_handler(self) -> Callable[[Request], Coroutine[Any, Any, Response]]:
        handler = super().get_route_handler()

        async def exact_handler(request: Request) -> Response:
            return await handler(_ExactNumberRequest(request.scope, request.receive))

        return exact_handler
