"""Unit tests for pure helpers in the pipeline orchestrator (`tasks.py`).

Orchestration flow (write_profile/find_threats/write_scenarios) is covered end-to-end in
`test_slice.py` / `test_cascade.py`; this file pins the small, pure boundaries.
"""
from __future__ import annotations

from app.pipeline.tasks import _safe_text


def test_safe_text_coerces_untrusted_model_fields():
    # A proposal's fields are untrusted model JSON. A real string passes through; null / non-string
    # collapse to the column default — so a dict can't crash the pyodbc bind and the nullable
    # ThreatName stays NULL rather than becoming "".
    assert _safe_text("Phishing", "") == "Phishing"
    assert _safe_text(None, "") == ""
    assert _safe_text({"name": "x"}, "") == ""
    assert _safe_text(123, "") == ""
    assert _safe_text(None, None) is None
    assert _safe_text(["nested"], None) is None
