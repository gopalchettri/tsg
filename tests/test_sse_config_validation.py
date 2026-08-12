"""Item 16 / verification 7: `sse_ping_seconds` must be rejected at CONFIG LOAD (`Field(gt=0)`),
never at connect time -- 0 would flood pings, a negative value 500s every SSE connect attempt.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_sse_ping_seconds_zero_rejected(monkeypatch):
    monkeypatch.setenv("TSG_SSE_PING_SECONDS", "0")
    with pytest.raises(ValidationError):
        Settings()


def test_sse_ping_seconds_negative_rejected(monkeypatch):
    monkeypatch.setenv("TSG_SSE_PING_SECONDS", "-1")
    with pytest.raises(ValidationError):
        Settings()


def test_sse_ping_seconds_positive_accepted(monkeypatch):
    monkeypatch.setenv("TSG_SSE_PING_SECONDS", "5")
    assert Settings().sse_ping_seconds == 5


if __name__ == "__main__":
    print("run via pytest")
