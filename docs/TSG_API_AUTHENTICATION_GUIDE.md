# TSG API Authentication — Implementation Guide

## 1. What Is TSG API Authentication?

TSG authenticates every API request from a calling application (e.g. Shield). Each request proves **which application** is calling (via a secret API key), and carries **which user** is acting and **which entity** they are accessing. The API key is mandatory authentication; verifying the user↔entity relationship is an optional, configurable check on top.

| Header | Purpose |
|---|---|
| `X-API-Key` | Authenticates the calling application |
| `X-User-Id` | Identifies the acting user |
| `X-Entity-Id` | Identifies the entity being accessed |
| `X-Tenant-Id` | Identifies the tenant (customer org) |

---

## 2. How It Works

```text
Request
  ↓
Validate X-API-Key ──► invalid/absent → 401
  ↓
Validate X-User-Id + X-Entity-Id + X-Tenant-Id ──► missing → 401
  ↓
TSG_VERIFY_MEMBERSHIP enabled?
  ├─ No  → process request
  └─ Yes → check user/entity assignment
             ├─ invalid → 403
             └─ valid   → process request
```

- TSG stores only the **SHA-256 hash** of the key; the calling application keeps the plaintext secret.
- `TSG_VERIFY_MEMBERSHIP=false` is the default — the key authenticates and the identity headers are trusted.
- When enabled, TSG verifies the user is actively assigned to the entity.

---

## 3. Why This Approach?

- Authenticates the calling application on every request.
- Carries user + entity context with every call.
- Protects the secret — only its hash is stored.
- Per-module key isolation via `Module`.
- Optional membership validation as defence-in-depth.
- Rotate/revoke keys with no restart (takes effect on the next request).

---

## 4. What Is Required?

| Component | Purpose |
|---|---|
| `API_Client` | Stores API-client metadata and key hash |
| `X-API-Key` | Application authentication |
| `X-User-Id` | User identity |
| `X-Entity-Id` | Entity context |
| `X-Tenant-Id` | Tenant (customer org) |
| `Module` | Restricts a key to one module |
| `TSG_VERIFY_MEMBERSHIP` | Enables optional membership validation |
| `TSG_ADMIN_API_KEY` | Additional credential for admin/library routes |
| `user_scope_assignment` | Source table for membership validation |

---

## 5. Database Structure

| Field | Purpose |
|---|---|
| `ClientID` | Client/key identifier |
| `KeyHash` | SHA-256 hash of the secret |
| `Name` | Client name |
| `Module` | Module scope (`tsg`, `chatbot`, …) |
| `Active` | Key status (1 = valid) |
| `CreatedAt` / `CreatedBy` | Provisioning audit |
| `RevokedAt` / `RevokedBy` | Revocation audit |

> Generate the SHA-256 hash in **Python (UTF-8)**, the same representation TSG uses. Do **not** substitute SQL `HASHBYTES` on a parameter or `N'…'` literal — it hashes UTF-16 and never matches, causing silent `401`s.

---

## 6. Setup and Configuration *(Operator)*

**1. Create the table**
```bash
sqlcmd -S <server> -d <database> -E -i scripts/TSG_Core.sql
```

**2. Generate secret + hash**
```bash
python -c "import hashlib, secrets; s = secrets.token_hex(32); print('SECRET:', s); print('KEYHASH:', hashlib.sha256(s.encode()).hexdigest())"
```
- `SECRET` → give securely to the calling application.
- `KEYHASH` → store in TSG.

**3. Register the client**
```sql
INSERT INTO API_Client (ClientID, KeyHash, Name, Module, CreatedBy)
VALUES ('shield-prod', '<KEYHASH>', 'Shield production', 'tsg', '<your-name>');
```

**4. Configure TSG**
```ini
APP_ENV=prod                 # local | dev | staging | prod
TSG_VERIFY_MEMBERSHIP=false  # true = also verify user↔entity in the DB
TSG_ADMIN_API_KEY=<secret>   # for admin/library routes
```
> Staging/prod refuses to start unless at least one **active** `API_Client` key exists for the module.

**5. Provide the secret securely** — store it in the calling application's secret manager, and use a **different key per environment** (UAT ≠ prod).

---

## 7. How to Use the Authentication *(Calling-App Developer)*

Send all four headers on every request:
```bash
curl https://tsg.example.com/v1/entities/86/scenarios \
  -H "X-API-Key: <SECRET>" \
  -H "X-User-Id: 1138" \
  -H "X-Entity-Id: 86" \
  -H "X-Tenant-Id: DESC"
```

| Code | Meaning |
|---|---|
| `200` / `202` | Successful / accepted |
| `401` | Invalid/missing/revoked key, or a missing identity header |
| `403` | Entity mismatch, or failed membership validation |

> Never hard-code or log `X-API-Key`.

---

## 8. Admin / Library APIs

Admin/library routes require the admin key **in addition to** the standard headers:
```text
X-Admin-Key   +   X-API-Key   +   X-User-Id   +   X-Tenant-Id
```
`X-Admin-Key` is **additional** — it does not replace `X-API-Key`.

**No `X-Entity-Id`.** Admin routes operate on shared cross-tenant master data (threat library,
control library, intel feeds), so there is no single entity to scope to — they resolve
`get_admin_principal` instead of `get_principal` (`app/api/deps.py`). `X-User-Id` is still
required: it is the identity recorded in `CreatedBy`/`UpdatedBy`. Sending `X-Entity-Id` anyway is
harmless; it is ignored.

---

## 9. Verify the Setup

```bash
# No key → 401
curl -s -o /dev/null -w "%{http_code}\n" https://tsg.example.com/v1/entities/86/scenarios
# Valid key + headers → 200
curl -s -o /dev/null -w "%{http_code}\n" https://tsg.example.com/v1/entities/86/scenarios \
  -H "X-API-Key: <SECRET>" -H "X-User-Id: 1138" -H "X-Entity-Id: 86"
# Health probe (no auth) → 200
curl -s -o /dev/null -w "%{http_code}\n" https://tsg.example.com/healthz
```

---

## 10. Key Management *(Operator)*

**Routine rotation** (no downtime):
```text
Create new key → activate (insert) → switch caller → revoke old key
```
```sql
INSERT INTO API_Client (ClientID, KeyHash, Name, Module, CreatedBy)
VALUES ('shield-prod-2', '<new-KEYHASH>', 'Shield production', 'tsg', '<your-name>');
```
Both keys work during the switch; revocation applies on the **next request**.

**Emergency revocation:**
```sql
UPDATE API_Client SET Active = 0, RevokedAt = SYSUTCDATETIME(), RevokedBy = '<your-name>'
WHERE ClientID = 'shield-prod';
```
Requests using the revoked key return `401`.

### Admin API (alternative to SQL — issue keys from a UI)

Instead of the SQL above, an admin can manage keys over HTTP. **Gated by `X-Admin-Key` only**; the
secret is generated server-side, returned **once**, and never stored (lost → revoke + create new).
Works for any module (`module` in the body).

```bash
# Create — returns the secret ONCE (copy it now):
curl -X POST https://tsg.example.com/v1/tsg/api-clients \
  -H "X-Admin-Key: <TSG_ADMIN_API_KEY>" -H "X-User-Id: <admin>" -H "Content-Type: application/json" \
  -d '{"client_id":"shield-chatbot-prod","name":"Shield → Chatbot","module":"chatbot"}'
# -> 201 {"client_id":"shield-chatbot-prod","module":"chatbot","secret":"<store this now>"}

# List — metadata only, never the secret or hash:
curl https://tsg.example.com/v1/tsg/api-clients -H "X-Admin-Key: <TSG_ADMIN_API_KEY>"

# Revoke:
curl -X POST https://tsg.example.com/v1/tsg/api-clients/shield-chatbot-prod/revoke \
  -H "X-Admin-Key: <TSG_ADMIN_API_KEY>" -H "X-User-Id: <admin>"
```

`CreatedBy`/`RevokedBy` are recorded from `X-User-Id`. Rotation = create a new key, then revoke the old.

---

## 11. Optional Membership Validation

```ini
TSG_VERIFY_MEMBERSHIP=true
```
When enabled, TSG verifies against `user_scope_assignment`:
```text
user_id = X-User-Id   AND   ref_id = X-Entity-Id   AND   scope_type = 4   AND   is_active = 1
```
If the user is not actively assigned to the entity → `403`.

> This is a configuration switch — no code change is required.

---

## 12. Reuse Across Modules

Every DESC module (TSG, Chatbot, …) uses this same mechanism. The `Module` field isolates keys: a key authenticates **only** for its own module, so one leaked key is contained to a single module.

**How the module is identified — in two places, never sent in the request:**

1. **Each app declares its own module**, fixed for that deployment: TSG = `tsg`, the Chatbot app = `chatbot`. An app only ever checks a key against its **own** module.
2. **Each key carries its module** — set when the key is created (the `Module` column).

A request never sends the module; it's implied by **which app** receives it.

**Steps to configure a new module (e.g. Chatbot):**

1. Deploy the module's app with its own module identity (`chatbot`).
2. Generate a secret + hash (§6, Step 2), then register a key **scoped to that module**:
   ```sql
   INSERT INTO API_Client (ClientID, KeyHash, Name, Module, CreatedBy)
   VALUES ('shield-chatbot-prod', '<KEYHASH>', 'Shield → Chatbot', 'chatbot', '<your-name>');
   ```
3. Give that secret to the team; they call the Chatbot with the **same four headers** (§7).

**Isolation — why a chatbot key can't open TSG:**

| Request to | Key's `Module` | Result |
|---|---|---|
| TSG | `tsg` | ✅ 200 |
| TSG | `chatbot` | ❌ 401 — TSG only accepts `tsg` keys |
| Chatbot | `chatbot` | ✅ 200 |

**Membership is global:** a user authorized for entity 86 is authorized in **every** module — `user_scope_assignment` has no module dimension, so the split is on the **key**, not on the user's entity access.

---

## 13. Browser Traffic

- Never expose `X-API-Key` to browser code.
- Browser calls must go through the module backend / BFF.
- The backend holds the key and adds the headers.

```text
Browser → Backend/BFF → TSG API
                  X-API-Key
                  X-User-Id
                  X-Entity-Id
```

---

## 14. Security Checklist

- HTTPS/TLS is required.
- Never log `X-API-Key`.
- Never expose the key to browsers.
- Store secrets in a secret manager.
- Use separate keys per environment and per module.
- Rotate immediately if a key may be compromised.
- Store only the SHA-256 hash in TSG.
