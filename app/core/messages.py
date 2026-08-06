"""User-facing API message templates — maintained in ONE place.

Every message a CLIENT can see (HTTP error detail, response prose) is a member here, so
wording changes never require hunting call sites and a message can never drift between the
place that raises it and the place that documents it. Members are `.format()` templates;
call sites fill the placeholders and never compose free-hand prose.

Scope is deliberate: OPERATOR-facing diagnostics stay where they are raised — config
validator messages (config.py) explain arithmetic to whoever edits .env and read best beside
the invariant they enforce, and structured log event names (log.warning("accept.…")) are a
separate machine-readable namespace. This module owns what goes over the wire to API callers.
"""
from __future__ import annotations

from enum import StrEnum


class ApiMessage(StrEnum):
    """HTTP-visible message templates. `.format()` placeholders are part of the contract."""

    #: 422 on session creation when active Config_Tuning rows break validation. `detail` is
    #: loc+msg pairs ONLY — never pydantic's str(exc), whose model-level failures embed
    #: `input=<the whole settings dict>` (DSNs, API keys) into the body.
    CONFIG_TUNING_INVALID = "Config_Tuning: {detail}"
