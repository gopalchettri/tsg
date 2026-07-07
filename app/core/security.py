"""AuthN/AuthZ + model-boundary input handling (SDD §10).

Resource server only: we VALIDATE the platform/SSO JWT (signature + exp/iss/aud)
and read its claims — we never issue tokens (§10.1). The set of entities the
caller may act on comes from the JWT `entities[]` claim ([R2]); a missing/empty
set is a hard deny, never allow-all.

Data plane (§10.2/§10.3): prompts are built from an allowlist of named context
fields, and free text is run through a secret/PII redaction pass before any
model call — secrets/other entities' data are structurally excluded, not assumed
absent.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any

import jwt
from jwt import PyJWKClient

from app.core.config import Settings, get_settings


class AuthError(Exception):
    """Invalid/absent token or failed claim check (→ 401)."""


@lru_cache
def _jwks_client(url: str) -> PyJWKClient:
    """Cached per JWKS URL so each validation doesn't refetch the issuer's key set."""
    return PyJWKClient(url)


def validate_jwt(token: str, settings: Settings | None = None) -> dict[str, Any]:
    """Verify signature + exp/iss/aud against the issuer's JWKS; return claims."""
    settings = settings or get_settings()
    if not token:
        raise AuthError("missing bearer token")
    try:
        key = _jwks_client(settings.jwt_jwks_url).get_signing_key_from_jwt(token)
        return jwt.decode(
            token,
            key.key,
            algorithms=list(settings.jwt_algorithms),
            audience=settings.jwt_audience or None,
            issuer=settings.jwt_issuer or None,
            options={"require": ["exp"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid token: {exc}") from exc


def allowed_entities(claims: dict[str, Any], settings: Settings | None = None) -> set[str]:
    """[R2] The `group.id` set the caller may act on, read from the JWT claim.

    Empty/missing → empty set → every object-level check must then deny.
    """
    settings = settings or get_settings()
    raw = claims.get(settings.jwt_entities_claim) or []
    if isinstance(raw, (str, int)):
        raw = [raw]
    return {str(e) for e in raw}


# --- Data-plane input handling (§10.2 / §10.3) ---

_SECRET_PATTERNS = [
    # PEM private-key block FIRST: match the whole BEGIN..END span as one unit before any other
    # pattern can fragment its base64 body ([\s\S] spans newlines; non-greedy stops at the first END).
    re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"),
    re.compile(r"[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),  # JWT-like
    re.compile(r"(?i)\b(?:api[_-]?key|key|secret|password|passwd|token)\b\s*[:=]\s*\S+"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),        # AWS access key id (near-zero false positives)
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),                 # long hex (keys/hashes)
    re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"),         # email (PII)
]
REDACTED = "[REDACTED]"


def redact(text: str | None) -> str | None:
    """Strip secrets/PII from free text before it reaches a model (§10.3). Accepts (and
    returns) None so callers with optional free-text fields (e.g. scenario_prompt's
    threat_type/threat_name) need no guard of their own."""
    if not text:
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub(REDACTED, text)
    return text


def _redact_value(val: Any) -> Any:
    """Redact strings; recurse into lists/dicts; pass other scalars unchanged.
    Depth-recursive so nested free-text (e.g. a populated `interfaces` list)
    can never carry a secret past the boundary that top-level strings can't."""
    if isinstance(val, str):
        return redact(val)
    if isinstance(val, list):
        return [_redact_value(v) for v in val]
    if isinstance(val, dict):
        return {k: _redact_value(v) for k, v in val.items()}
    return val


def allowlist_context(fields: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    """Build model context from ONLY the named allowlisted fields (§10.3);
    redact string values recursively (nested lists/dicts included). Anything
    not on the allowlist never reaches the model.
    """
    out: dict[str, Any] = {}
    for name in allowed:
        val = fields.get(name)
        if val is not None:
            out[name] = _redact_value(val)
    return out


if __name__ == "__main__":  # tiny self-check (no framework)
    assert redact("key=abcdef1234567890 contact a@b.com") == "[REDACTED] contact [REDACTED]"
    assert redact("cred AKIAIOSFODNN7EXAMPLE end") == "cred [REDACTED] end"  # AWS access key id
    assert redact("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----") == "[REDACTED]"
    assert redact(None) is None  # optional free-text field passes through unchanged
    assert allowlist_context({"name": "CAD", "secret": "x", "url": None}, {"name", "url"}) == {"name": "CAD"}
    assert allowlist_context(  # nested structures are redacted too, not just top-level strings
        {"name": "CAD", "interfaces": [{"note": "password=hunter2secret"}]}, {"name", "interfaces"},
    ) == {"name": "CAD", "interfaces": [{"note": "[REDACTED]"}]}
    assert allowed_entities({"entities": [5, 8]}) == {"5", "8"}
    assert allowed_entities({}) == set()
    print("security self-check ok")
