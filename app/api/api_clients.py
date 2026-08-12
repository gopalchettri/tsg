"""Admin API-key management — create / list / revoke `API_Client` rows so keys can be issued
from a UI instead of hand-written SQL.

Gated by `X-Admin-Key` ALONE (router-level `require_admin`). Deliberately NOT `get_principal`:
minting a client key must not itself require already having one, and this manages cross-tenant
client keys, not one entity's data. The acting admin's id is taken from `X-User-Id` (trusted via
the admin key) and written to `CreatedBy`/`RevokedBy` for the audit trail.

The secret is generated server-side, returned exactly ONCE in the create response, and never
stored — only its SHA-256 hash. Lost secret → revoke + create a new key, never recover.
"""
from __future__ import annotations

import hashlib
import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.exc import IntegrityError

from app.api.deps import require_admin
from app.api.schemas import ApiClientCreated, ApiClientInfo, CreateApiClientBody
from app.core.logging import get_logger
from app.db import dal
from app.db.engine import db_session

router = APIRouter(
    prefix="/v1/tsg/api-clients",
    tags=["API Clients Admin"],
    dependencies=[Depends(require_admin)],
)
log = get_logger(__name__)


@router.post("", status_code=201, response_model=ApiClientCreated)
def create_api_client(
    body: CreateApiClientBody,
    x_user_id: str = Header(default="", alias="X-User-Id"),
) -> ApiClientCreated:
    """Provision a new API client. Generates a 32-byte secret, stores ONLY its SHA-256 hash, and
    returns the secret ONCE (201). Duplicate `client_id` -> 409. `module` is free-text: an admin
    may create a key for any module (`tsg`, `chatbot`, ...)."""
    created_by = x_user_id.strip()
    if not created_by:  # required — every key must be attributed to a person for the audit trail
        raise HTTPException(status_code=400, detail="X-User-Id header is required")
    secret = secrets.token_hex(32)
    key_hash = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    with db_session() as sess:
        try:
            dal.create_api_client(sess, body.client_id, body.name, body.module, key_hash, created_by)
        except IntegrityError as exc:
            raise HTTPException(status_code=409,
                                detail=f"client_id '{body.client_id}' already exists") from exc
    # Log the creation WITHOUT the secret — the secret exists only in the response body.
    log.warning("api_client.created", client_id=body.client_id, module=body.module, created_by=created_by)
    return ApiClientCreated(client_id=body.client_id, module=body.module, secret=secret)


@router.get("", response_model=list[ApiClientInfo])
def list_api_clients(module: str | None = Query(default=None)) -> list[ApiClientInfo]:
    """List API clients — metadata only, never the hash or secret. Optional `?module=` filter."""
    with db_session() as sess:
        return [ApiClientInfo(**row) for row in dal.list_api_clients(sess, module)]


@router.post("/{client_id}/revoke", status_code=200)
def revoke_api_client(
    client_id: str,
    x_user_id: str = Header(default="", alias="X-User-Id"),
) -> dict:
    """Deactivate a key; it stops authenticating on its next use. 404 if not an active client."""
    revoked_by = x_user_id.strip()
    if not revoked_by:  # required — every revocation must be attributed for the audit trail
        raise HTTPException(status_code=400, detail="X-User-Id header is required")
    with db_session() as sess:
        if not dal.revoke_api_client(sess, client_id, revoked_by):
            raise HTTPException(status_code=404, detail=f"no active API client '{client_id}'")
    log.warning("api_client.revoked", client_id=client_id, revoked_by=revoked_by)
    return {"client_id": client_id, "status": "revoked"}
