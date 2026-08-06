"""AuthN/AuthZ + model-boundary input handling.

Resource server only: we VALIDATE the platform/SSO JWT (signature + exp/iss/aud)
and read its claims — we never issue tokens. The set of entities the
caller may act on comes from the JWT `entities[]` claim; a missing/empty
set is a hard deny, never allow-all.

Data plane: prompts are built from an allowlist of named context
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
    if not settings.jwt_issuer:
        # PyJWT's issuer check no-ops entirely when issuer=None (it won't even require
        # an 'iss' claim to be present, let alone match) -- unlike audience, which still
        # rejects a token whose 'aud' claim is present when audience=None. Fail closed
        # instead of silently accepting a token meant for some other issuer/app.
        raise AuthError("TSG_JWT_ISSUER is not configured; refusing to skip issuer verification")
    if not settings.jwt_audience:
        # Same asymmetry as issuer above, other direction: audience=None only rejects a
        # token that HAPPENS to carry an 'aud' claim -- one minted for a different
        # first-party app that omits 'aud' would sail through unscoped. Fail closed.
        raise AuthError("TSG_JWT_AUDIENCE is not configured; refusing to skip audience verification")
    try:
        if settings.jwt_secret:
            # Shared-secret mode (HS256): the same key signs and verifies, no JWKS fetch.
            key_material: Any = settings.jwt_secret
        else:
            # Find the public key (by "kid" in the token header) from the issuer's published key
            # set, then verify the token's signature and required claims against it.
            key_material = _jwks_client(settings.jwt_jwks_url).get_signing_key_from_jwt(token).key
        return jwt.decode(
            token,
            key_material,
            algorithms=list(settings.jwt_algorithms),
            audience=settings.jwt_audience or None,
            issuer=settings.jwt_issuer,
            # Issuer tokens live ~5 minutes; a small clock difference between the issuing
            # server and this one must not read as "expired"/"not yet valid".
            leeway=30,
            options={"require": ["exp"]},
        )
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid token: {exc}") from exc


def allowed_entities(claims: dict[str, Any], settings: Settings | None = None) -> set[str]:
    """The `group.id` set the caller may act on, read from the JWT claim.

    Empty/missing → empty set → every object-level check must then deny.
    """
    settings = settings or get_settings()
    raw = claims.get(settings.jwt_entities_claim) or []
    # The claim may come in as a single value instead of a list; wrap it so the
    # rest of this function can treat it uniformly as a collection.
    if isinstance(raw, (str, int)):
        raw = [raw]
    return {str(e) for e in raw}


# --- Data-plane input handling (§10.2 / §10.3) ---

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
    """Build model context from ONLY the named allowlisted fields;
    redact string values recursively (nested lists/dicts included). Anything
    not on the allowlist never reaches the model.

    A field with no real value never reaches the model either — not just None, but also an
    empty string/list/dict (e.g. "" or []). Sending an empty field wastes prompt space and can
    read to the AI as "this asset has no critical service" instead of "we don't know" — dropping
    it means the model sees only what's actually filled in. A numeric 0 or boolean False is a
    real value (e.g. target_rto_hours=0), so those are kept.
    """
    out: dict[str, Any] = {}
    for name in allowed:
        val = fields.get(name)
        if val is None:
            continue
        if isinstance(val, (str, list, dict, tuple, set)) and not val:
            continue
        out[name] = _redact_value(val)
    return out

