"""AuthN/AuthZ + model-boundary input handling.

AuthN is the header model: app/api/deps.get_principal verifies X-API-Key against API_Client and
(optionally) the (X-User-Id, X-Entity-Id) pair against user_scope_assignment. This module keeps
only the shared AuthError type and the data-plane redaction below.

Data plane: free text runs through a secret/PII redaction pass before any model call, so
secrets and other entities' data are structurally excluded rather than assumed absent.
"""
from __future__ import annotations

import re
from typing import Any

# No-value tokens that reach us as curator-dropdown labels ("NA" is a real option in the
# multiselect lookup tables — context._resolve_multiselect hands it over as a display name)
# or as free-text filler. The same class of non-value as ""/[] in scrub_context below.
_PLACEHOLDER_VALUES = frozenset({
    "na", "n/a", "n.a.", "n.a", "not applicable", "none", "nil", "null",
    "-", "--", "tbd", "to be determined", "unknown", "not available"})

_SECRET_PATTERNS = [
    # PEM private-key block FIRST: match the whole BEGIN..END span as one unit before any other
    # pattern can fragment its base64 body ([\s\S] spans newlines; non-greedy stops at the first END).
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT-like
    # name=value / name: free-text creds. `key`/`api_key` keep a strict word boundary
    # (so e.g. `primary_key`/`cache_key` aren't swept up); secret/password/passwd/token
    # additionally tolerate a snake_case/kebab-case prefix (db_password, access_token,
    # client_secret, api_secret) since '_'/'-' are \w chars and never form a \b on their
    # own. `=value` still stops at the next token (machine-generated values never have
    # embedded spaces); `: value` runs to end of line, since colon-labelled values are
    # free text that CAN contain spaces (e.g. a human-chosen passphrase).
    re.compile(
        r"(?i)\b(?:api[_-]?key|key|(?:\w+[_-])?(?:secret|password|passwd|token))\b"
        r"\s*(?:=\s*\S+|:\s*.+)"
    ),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),        # access key id (near-zero false positives)
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),                 # long hex (keys/hashes)
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),         # email (PII)
    # Internal hostnames (.local/.internal TLD convention only — no org domains hardcoded).
    # Secret-shaped patterns above can't catch these, yet they're the most realistic echo of
    # infrastructure detail into model output [gap-8]. Shared list, so inbound context stops
    # leaking them to the provider too.
    re.compile(r"(?i)\b[\w][\w-]*(?:\.[\w-]+)*\.(?:local|internal)\b"),
]
REDACTED = "[REDACTED]"


class AuthError(Exception):
    """Invalid/absent token or failed API-key/identity check (→ 401)."""


def redact(text: str | None) -> str | None:
    """Strip secrets/PII from free text before it reaches a model (§10.3). Accepts and returns
    None, so callers with optional free-text fields need no guard of their own."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub(REDACTED, text)
    return text

def _redact_value(val: Any) -> Any:
    """Redact strings, recurse into lists/dicts, pass other scalars through. Depth-recursive so
    nested free text can't carry a secret past a boundary that stops top-level strings."""
    if isinstance(val, str):
        return redact(val)
    if isinstance(val, list):
        return [_redact_value(v) for v in val]
    if isinstance(val, dict):
        return {k: _redact_value(v) for k, v in val.items()}
    return val

def is_placeholder(value: Any) -> bool:
    """True when a string carries no real information (a placeholder label, not data)."""
    return isinstance(value, str) and value.strip().casefold() in _PLACEHOLDER_VALUES

def _has_value(item: Any) -> bool:
    """List-item test: a blank/whitespace or placeholder string is noise, everything else is data."""
    return not (isinstance(item, str) and (not item.strip() or is_placeholder(item)))

def scrub_context(fields: dict[str, Any]) -> dict[str, Any]:
    """Build model context from EVERY supplied field, redacting strings recursively. No
    field-name allowlist — whatever the caller assembles reaches the model, so the caller owns
    that decision.

    Drops fields with no real value: None, empty/whitespace string, empty list/dict, and
    placeholder labels ("NA"/"N/A"/"Not Applicable" — see _PLACEHOLDER_VALUES), alone or as list
    items. A no-value field reads to the model as "this asset has no critical service" rather
    than "we don't know". Numeric 0 and boolean False ARE real values and are kept.
    """
    out: dict[str, Any] = {}
    for name, val in fields.items():
        if val is None:
            continue
        if isinstance(val, (str, list, dict, tuple, set)) and not val:
            continue
        if isinstance(val, str) and not _has_value(val):
            continue
        if isinstance(val, (list, tuple)):
            val = [v for v in val if _has_value(v)]
            if not val:
                continue
        out[name] = _redact_value(val)
    return out
