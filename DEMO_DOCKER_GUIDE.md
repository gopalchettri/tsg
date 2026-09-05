# TSG — Local Docker Demo Guide (Windows)

Runs the TSG API + Celery worker + beat (+ optional Flower dashboard) in
Docker on this laptop, while SQL Server, Redis, and MongoDB stay as native
Windows installs. The only outbound network call the whole system makes is
to your external LLM/embedding/rerank endpoint. A separate UI application
consumes the API over HTTP once it's up — nobody needs shell access to the
containers.

The three files this guide assumes already exist (created earlier in this
project):
- [`Dockerfile`](Dockerfile) — builds the image, compiles the app to
  bytecode and removes the `.py` source before the final layer.
- [`docker/compose.demo.yml`](docker/compose.demo.yml) — the four services
  (`api`, `worker`, `beat`, `flower`), no database containers.
- [`.env.demo`](.env.demo) — the settings file for this deployment, with
  `<placeholder>` values you'll fill in at step 6.

You don't need to touch any of these three files' structure — just fill in
`.env.demo`'s placeholders.

All commands below are **Windows PowerShell**, run from the `tsg` folder
unless a step says otherwise.

---

## 1. Prerequisites checklist

- Docker Desktop installed **and running** (check for its icon in the
  system tray — `docker build` fails with a `dockerDesktopLinuxEngine`
  connection error if it isn't open, not because of anything in this repo).
- SQL Server, Redis, and MongoDB already installed natively on this laptop.
- The base URL, API key, and model names for your litellm-proxy-shaped
  endpoint (serves chat + embeddings + reranking) — get these from
  whoever manages that endpoint if you don't already have them.
- SSMS (SQL Server Management Studio) or `sqlcmd` available, for the
  one-time schema setup in step 7.

---

## 2. One-time SQL Server setup

A Docker container has no Windows security context, so it can't use
`Trusted_Connection=yes` (Windows Integrated Auth) — SQL Server needs to
accept a **username + password** login instead.

**2a. Enable TCP/IP on a fixed port.**
1. Open **SQL Server Configuration Manager** (search for it in the Start
   menu — the exe name is version-suffixed, e.g. `SQLServerManager16.msc`
   for SQL Server 2022; searching avoids guessing the wrong version).
2. **SQL Server Network Configuration → Protocols for `<your instance>`**
   → right-click **TCP/IP** → **Enable**.
3. Double-click **TCP/IP** → **IP Addresses** tab → scroll to **IPAll** →
   set **TCP Port** to `1433` and clear **TCP Dynamic Ports** (this pins a
   fixed port regardless of whether you have a default or named instance,
   so later steps never need to guess an instance name).
4. Restart the SQL Server service so the change takes effect:
   ```powershell
   # Replace with your actual service name if it differs — check with:
   #   Get-Service *SQL*
   Restart-Service -Name 'MSSQLSERVER'          # default instance
   # Restart-Service -Name 'MSSQL$SQLEXPRESS'   # named instance, e.g. Express
   ```

**2b. Enable SQL Server Authentication (Mixed Mode).**
In SSMS: right-click the server instance in Object Explorer → **Properties**
→ **Security** page → select **"SQL Server and Windows Authentication
mode"** → OK → then restart the service again (same command as 2a.4) —
this setting only takes effect after a restart.

**2c. Create the demo database, login, and grant.**
Run in SSMS (or via `sqlcmd`, see step 7's syntax) connected to your SQL
Server instance:
```sql
-- Creates an empty TSG database.
CREATE DATABASE TSG;
GO
USE TSG;
GO
-- A plain alphanumeric password on purpose: it goes straight into a
-- connection-string URL later (.env.demo's TSG_DB_DSN), and special
-- characters there would need percent-encoding. Skipping that entirely
-- is simpler than getting the encoding right for a one-off demo password.
CREATE LOGIN tsg_demo WITH PASSWORD = 'TsgDemo2026Pass';
CREATE USER tsg_demo FOR LOGIN tsg_demo;
-- db_owner is broad, deliberately: the schema-bootstrap scripts in step 7
-- create tables and flip a database-level setting, and this is a
-- throwaway demo database, not something to fuss over least-privilege for.
ALTER ROLE db_owner ADD MEMBER tsg_demo;
GO
```

---

## 3. One-time Windows Firewall rules

Docker's virtual network is a separate, routed network as far as Windows
Firewall is concerned — even though everything is on one laptop, these
ports need explicit inbound rules or the containers can't reach them.

```powershell
# One rule per native service the containers need to reach. Scoped to the
# "Private" network profile (the usual profile for an off-domain laptop's
# active network) rather than a specific remote address, since Docker
# Desktop's internal subnet can change across reboots/updates — fine for a
# throwaway demo box; tighten with -RemoteAddress if this ever needs to be
# more locked down.
New-NetFirewallRule -DisplayName "TSG demo - SQL Server 1433" -Direction Inbound -Protocol TCP -LocalPort 1433 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "TSG demo - Redis 6379"      -Direction Inbound -Protocol TCP -LocalPort 6379 -Action Allow -Profile Private
New-NetFirewallRule -DisplayName "TSG demo - MongoDB 27017"   -Direction Inbound -Protocol TCP -LocalPort 27017 -Action Allow -Profile Private
```

---

## 4. One-time Redis / MongoDB bind-address check

Both need to be listening on more than just loopback, or the containers
(which reach them as a "different machine" over `host.docker.internal`)
will get connection-refused even with the firewall rules above in place.

- **Redis**: open your install's `redis.windows.conf`, find the `bind`
  line, and make sure it's either commented out or set to `bind 0.0.0.0`
  (not left at a loopback-only default). Restart the Redis Windows service
  after editing.
- **MongoDB**: open `mongod.cfg`, under the `net:` section set
  `bindIp: 0.0.0.0` (Community Edition installs often default to
  `127.0.0.1` only, which would block the container). Restart the MongoDB
  Windows service after editing.

---

## 5. Fill in `tsg/.env.demo`

Open [`tsg/.env.demo`](.env.demo) and replace every `<placeholder>`:

| Placeholder | What to put there |
|---|---|
| `<SQL_LOGIN_PASSWORD>` in `TSG_DB_DSN` | `TsgDemo2026Pass` (or whatever you actually used in step 2c) |
| `TSG_ADMIN_API_KEY` | Output of the command below |
| `TSG_FLOWER_BASIC_AUTH` | `demo:<a password you pick>` — literal `user:password` text, not hashed |
| `TSG_LITELLM_BASE_URL` / `TSG_LITELLM_API_KEY` | Your litellm-proxy endpoint's URL and key |
| `TSG_INFERENCE_MODEL` / `TSG_EMBEDDING_MODEL` / `TSG_RERANKER_MODEL` | The model names your endpoint serves |
| `TSG_EMBEDDING_DIMENSIONS` | The embedding model's real output width — ask whoever runs the endpoint if unsure. Getting this wrong isn't silent: the worker refuses to boot with a clear dimension-mismatch error rather than corrupting data. |

Generate the admin key (run from any PowerShell with `python` on PATH —
this doesn't need to run inside a container):
```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 6. Schema bootstrap (once, against the native SQL Server)

**Important — this step runs `sqlcmd` directly on this Windows laptop**,
where SQL Server actually lives, so it connects via `localhost`, **not**
`host.docker.internal`. (`host.docker.internal` only resolves *from inside
a container* — that's the hostname `.env.demo` uses instead, later, for
the app running in Docker. Same server, two different hostnames depending
on which side of the container boundary you're on.)

If `sqlcmd` isn't installed: `winget install sqlcmd`, or open each of the
six files below in SSMS's Query window (connected to `localhost,1433`)
and execute them in order instead.

Run these **in this exact order** — they build on each other:
```powershell
# -S localhost,1433 : connect to this machine, the fixed port from step 2a
#                      (the explicit port means it works whether SQL Server
#                      is a default or named instance).
# -d TSG             : the database created in step 2c.
# -I                 : forces QUOTED_IDENTIFIER ON — sqlcmd defaults this
#                      OFF, which is the most common cause of these scripts
#                      failing partway through.
# -i "<file>"        : the script to run. Filenames contain spaces/periods,
#                      hence the quotes.
sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/0. TSG_Preflight.sql"
# READ-ONLY health check. Any row reporting FAIL means stop and fix that
# first — don't continue to the next file.

sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/1. TSG_Core.sql"
# Creates the baseline tables and turns on READ_COMMITTED_SNAPSHOT, which
# the app asserts is on at every boot (app/db/invariants.py) and refuses
# to start without.

sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/2. Threat_library.sql"
sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/3. Seed_to_Threat_library.sql"
sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/4. Control_library.sql"

sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/5. Seed_to_Control_library.sql"
# The slow one: ~30 standards, ~1,288 controls, ~6,105 links. Let it finish.

sqlcmd -S localhost,1433 -d TSG -U tsg_demo -P "TsgDemo2026Pass" -I -i "scripts/eyshield_handoff/6. TSG_Verify.sql"
# READ-ONLY final check. Any FAIL row means something above didn't take —
# don't proceed to step 8 until this is clean.
```

**Seed one API client** — required because `.env.demo` sets
`APP_ENV=staging`, which hard-requires at least one active row here, or
every single API call returns 401:
```powershell
# Prints a real key (give this to whoever/whatever calls the API — save
# it now, it is shown exactly once and never stored anywhere) and its
# SHA-256 hash (goes into the database instead of the real key).
python -c "import hashlib,secrets; s=secrets.token_hex(32); print('X-API-Key:', s); print('KeyHash:', hashlib.sha256(s.encode()).hexdigest())"
```
Then, in SSMS or `sqlcmd`, paste the printed `KeyHash` in:
```sql
INSERT INTO API_Client (ClientID, KeyHash, Name, Module)
VALUES ('shield-demo', '<paste KeyHash here>', 'Demo Caller', 'tsg');
-- Module defaults to 'tsg' and Active defaults to 1 in the schema, but
-- naming Module explicitly here keeps the row self-documenting.
```

**Note**: `TSG_Preflight.sql` also reports on a handful of platform tables
(asset/onboarding data) that TSG reads but never creates itself. If you
want a full end-to-end session to run — not just a healthy, empty API —
that data has to come from wherever your platform's onboarding system
normally populates it. Out of scope for this Docker setup.

---

## 7. Build and run

```powershell
# Run from the tsg folder (where the Dockerfile lives).
docker build -t tsg:latest .
# No --build-arg needed — the default build (no local embedding/reranker
# models) is already the right one, since everything routes through your
# external endpoint.

docker compose -f docker/compose.demo.yml up -d
# Starts api, worker, beat, and flower, reading tsg/.env.demo.

docker compose -f docker/compose.demo.yml ps
# Watch the STATUS column — worker can take a few minutes to reach
# "healthy" on its first boot.

docker compose -f docker/compose.demo.yml logs -f api worker beat
# Live logs from all three — Ctrl+C to stop watching (the containers keep
# running).
```

---

## 8. Verify it worked

Windows PowerShell aliases plain `curl` to `Invoke-WebRequest`, which
takes different flags than real curl — the commands below use `curl.exe`
explicitly to reach the actual curl binary Windows already ships.

**8a. Liveness and readiness** (no auth needed):
```powershell
curl.exe http://localhost:8000/health
# Expect: {"status":"ok"}

curl.exe http://localhost:8000/ready
# Expect: 200, with checks.database / checks.redis / checks.mongo all "ok".
# Any of those NOT "ok" points at step 2-4 (SQL/Redis/Mongo reachability).
```

**8b. Container health:**
```powershell
docker compose -f docker/compose.demo.yml ps
# All four services should show "healthy".
```

**8c. Full smoke test through the app's real code paths** — this is the
strongest single check, since it also exercises a real chat + embed +
rerank call through your configured endpoint:
```powershell
docker compose -f docker/compose.demo.yml exec api python scripts/uat_preflight.py
```

**8d. Header auth check** — proves the API key seeded in step 6 actually
works. Uses a made-up (but well-formed) session id on purpose, since a
fresh demo database has no real sessions yet:
```powershell
curl.exe -i -H "X-API-Key: <the key printed in step 6>" -H "X-User-Id: 1" -H "X-Entity-Id: 1" http://localhost:8000/v1/sessions/00000000-0000-0000-0000-000000000000
# Read the FIRST line of the response:
#   HTTP/1.1 401 Unauthorized  -> auth is broken, recheck step 6's INSERT
#   HTTP/1.1 404 ...           -> auth PASSED — request reached real
#                                 business logic and correctly reported
#                                 "no such session", which is expected
#                                 since none exist yet. This is success.
```

**8e. Flower** (if you kept that service): open `http://localhost:5555`
in a browser, log in with the `user:password` you set in `.env.demo`'s
`TSG_FLOWER_BASIC_AUTH`, and confirm the worker shows as registered.

---

## 9. Troubleshooting

**`docker build` fails: `failed to connect to the docker API at
npipe:////./pipe/dockerDesktopLinuxEngine`** — Docker Desktop isn't
running. Start it from the Start menu, wait for its tray icon to show
"running", then retry.

**`sqlcmd` fails to log in / "Login failed for user 'tsg_demo'"** — Mixed
Mode authentication (step 2b) wasn't actually enabled, or the service
wasn't restarted after enabling it. Re-check SSMS → server Properties →
Security, and restart the SQL Server service again.

**`/ready` shows `checks.database`, `checks.redis`, or `checks.mongo` as
anything other than `"ok"`** — almost always one of: the matching Windows
Firewall rule (step 3) is missing, the service is bound to loopback-only
(step 4), or the corresponding native Windows service isn't actually
running (`Get-Service` to check).

**`docker compose ps` shows `worker` stuck at "starting" for several
minutes** — expected on the very first boot; its healthcheck has a 240
second grace period. If it's still unhealthy well past that, check
`docker compose -f docker/compose.demo.yml logs worker` for the actual
error (usually a DB/Redis/endpoint reachability issue caught during boot).

**`TSG_Preflight.sql` or a later script reports missing platform tables**
— expected, and harmless for getting the app itself running; see the note
at the end of step 6. It only matters if you need a real end-to-end
session, not just a healthy API.
