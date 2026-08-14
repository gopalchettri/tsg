"""API dependencies — header-model authentication + object-level authorization ([R2], §10.1).

`get_principal` verifies `X-API-Key` against a stored client-secret hash and takes the caller's
identity from `X-User-Id`/`X-Entity-Id`/`X-Tenant-Id` — see docs/TSG_API_AUTHENTICATION_GUIDE.md
for the full contract. Tests override `get_principal` via `app.dependency_overrides` to inject a
Principal directly.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

import structlog
from fastapi import Header

from app.core.config import get_settings
from app.core.logging import get_logger
from app.core.security import AuthError
from app.db import dal
from app.db.dal import EntityForbidden
from app.db.engine import db_session

_log = get_logger(__name__)


@dataclass
class Principal:
    """The authenticated caller: the acting user's id (as `sub`), the single verified entity
    they act on, the tenant (customer org), and the API client that presented the request."""
    claims: dict
    entities: set[str]
    client_id: str | None = None
    tenant_id: str | None = None

    @property
    def user_id(self) -> str | None:
        """The acting user id Shield sent in `X-User-Id`, carried as the `sub` claim."""
        uid = self.claims.get("sub")
        return str(uid) if uid is not None else None

    def require_entity(self, entity_id) -> None:
        """ Deny unless the target entity is in the caller's authorized set."""
        # str(): entity_id may arrive as an int/UUID while self.entities holds strings
        if str(entity_id) not in self.entities:
            raise EntityForbidden(f"entity {entity_id} not authorized for caller")


# One opaque message for every auth failure — never leak which check failed (config oracle).
_UNAUTHORIZED = "unauthorized"


def verify_api_key(presented: str) -> str:
    """Return the ClientID of the active API_Client whose secret hashes to `presented`, or raise
    AuthError (-> 401). The stored value is a SHA-256 hex; we hash the presented secret and match.
    A blank key, an unknown key, or a revoked key all raise the SAME message."""
    key = presented.strip()
    if not key:
        raise AuthError(_UNAUTHORIZED)
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    with db_session() as sess:
        client_id = dal.api_client_id_for_key_hash(sess, key_hash)
    if client_id is None:
        raise AuthError(_UNAUTHORIZED)
    return client_id


def get_principal(
    x_api_key: str = Header(default="", alias="X-API-Key"),
    x_user_id: str = Header(default="", alias="X-User-Id"),
    x_entity_id: str = Header(default="", alias="X-Entity-Id"),
    x_tenant_id: str = Header(default="", alias="X-Tenant-Id"),
) -> Principal:
    """Resolve the caller's `Principal` from the request headers (header auth model):

      1. `X-API-Key` authenticates the caller (Shield) — bad/absent -> 401.
      2. `X-User-Id` + `X-Entity-Id` carry the acting identity — absent -> 401.
      3. If `verify_membership` is on, the (user, entity) pair is checked against
         `user_scope_assignment` — not a real active Entity assignment -> 403. Default OFF:
         the pair is taken on trust (Phase A), the API key is the security boundary.

    downstream handlers still owe `require_entity`. AuthError/EntityForbidden propagate to
    the [R9] envelope handler in app/api/errors.py."""
    client_id = verify_api_key(x_api_key)
    # X-User-Id, X-Entity-Id and X-Tenant-Id are all REQUIRED — absent/blank → 401. isinstance
    # guard: on a real request these are str; when this dependency is called directly (tests)
    # an unpassed Header param is FastAPI's sentinel, not a str.
    tenant_id = x_tenant_id.strip() if isinstance(x_tenant_id, str) else ""
    if not (x_user_id.strip() and x_entity_id.strip() and tenant_id):
        raise AuthError(_UNAUTHORIZED)
    user_id, entity_id = x_user_id.strip(), x_entity_id.strip()

    if get_settings().verify_membership:
        try:
            with db_session() as sess:
                allowed = dal.user_has_entity(sess, user_id, entity_id)
        except Exception:  # noqa: BLE001 — fail CLOSED: any lookup error is a deny, not an allow
            _log.warning("auth.membership_check_failed", user_id=user_id, entity_id=entity_id)
            allowed = False
        if not allowed:
            raise EntityForbidden(f"user {user_id} is not authorized for entity {entity_id}")

    structlog.contextvars.bind_contextvars(
        sub=user_id, entity=entity_id, tenant=tenant_id, client_id=client_id)
    return Principal(claims={"sub": user_id}, entities={entity_id},
                    client_id=client_id, tenant_id=tenant_id)


def get_admin_principal(
    x_api_key: str = Header(default="", alias="X-API-Key"),
    x_user_id: str = Header(default="", alias="X-User-Id"),
    x_tenant_id: str = Header(default="", alias="X-Tenant-Id"),
) -> Principal:
    """The admin routers' principal — `get_principal` minus the entity.

    Admin routes touch shared cross-tenant master data (threat/control libraries, intel feeds),
    so there is no entity to scope to and no admin handler reads `entities`. Requiring
    `X-Entity-Id` there only forced callers to invent a value that was then discarded.

    `X-User-Id` is still REQUIRED: it is the acting identity that lands in CreatedBy/UpdatedBy,
    so dropping it would silently blank the library audit trail. `entities` is empty, so
    `require_entity` DENIES on an admin principal — fail-closed if an entity-scoped route ever
    mounts this by mistake. `verify_membership` is skipped: it validates a (user, entity) pair
    and there is no entity."""
    client_id = verify_api_key(x_api_key)
    # isinstance guards mirror get_principal: called directly (tests), an unpassed Header param
    # is FastAPI's sentinel, not a str.
    user_id = x_user_id.strip() if isinstance(x_user_id, str) else ""
    tenant_id = x_tenant_id.strip() if isinstance(x_tenant_id, str) else ""
    if not (user_id and tenant_id):
        raise AuthError(_UNAUTHORIZED)

    structlog.contextvars.bind_contextvars(sub=user_id, tenant=tenant_id, client_id=client_id)
    return Principal(claims={"sub": user_id}, entities=set(),
                    client_id=client_id, tenant_id=tenant_id)


def require_admin(x_admin_key: str = Header(default="", alias="X-Admin-Key")) -> None:
    """Gates the admin-only library/embedding endpoints. Deliberately NOT part of the JWT/entity
    model: TSG has no admin role, and these routes touch shared cross-tenant master data.

    An unconfigured `admin_api_key` ALWAYS denies — it must never become "open to everyone"
    because both sides of a naive equality check happen to be empty. `compare_digest` keeps the
    comparison constant-time."""
    key = get_settings().admin_api_key
    # Compare as BYTES: secrets.compare_digest raises TypeError on a non-ASCII str operand, so a
    # header like `X-Admin-Key: café` turned a failed auth check into an unauthenticated 500 (a
    # log-flood vector and a config oracle). The bytes overload has no ASCII restriction and
    # keeps the constant-time property.
    if not key or not secrets.compare_digest(x_admin_key.encode("utf-8"), key.encode("utf-8")):
        raise AuthError("invalid or missing X-Admin-Key")
