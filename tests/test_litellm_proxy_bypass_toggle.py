"""litellm_bypass_proxy toggle -- see app/pipeline/llm.py::_ensure_litellm_proxy_bypassed."""
from __future__ import annotations

import os

from app.core.config import Settings
from app.pipeline.llm import _ensure_litellm_proxy_bypassed


def test_bypass_disabled_leaves_no_proxy_untouched(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setenv("TSG_LITELLM_BYPASS_PROXY", "false")
    monkeypatch.setenv("TSG_LLM_PROVIDER", "litellm_proxy")
    _ensure_litellm_proxy_bypassed(Settings())
    assert "NO_PROXY" not in os.environ


def test_bypass_enabled_by_default(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.setenv("TSG_LLM_PROVIDER", "litellm_proxy")
    monkeypatch.setenv("TSG_LITELLM_BASE_URL", "https://llmapi.govai.ae")
    _ensure_litellm_proxy_bypassed(Settings())
    assert "llmapi.govai.ae" in os.environ.get("NO_PROXY", "")


if __name__ == "__main__":
    print("run via pytest")
