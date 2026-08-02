# TSG on OpenShift — deployment + CI/CD

One image, three workloads (translated from `docker/compose.prod.yml`):

| Deployment | Command | Notes |
|---|---|---|
| `tsg-api` | gunicorn (4 uvicorn workers, :8000) | probes `/healthz` + `/readyz`; scale freely |
| `tsg-worker` | `celery -A app.pipeline.celery_worker.celery_app worker -P gevent -c 50` | 300s termination grace; ~240s cold start |
| `tsg-beat` | `celery -A app.pipeline.celery_app.celery_app beat -s /tmp/celerybeat-schedule` | **exactly 1 replica** |

Layout: `deploy/base` + `deploy/overlays/{dev,uat,prod}` (Kustomize), `deploy/tekton` (CI),
`deploy/argocd` (CD). Namespaces: `ai-threatgen-ci` (pipeline + image) and
`ai-threatgen-dev` / `ai-threatgen-uat` / `ai-threatgen-prod` (apps).

## Why this needs no Docker anywhere

Historically the plan was "`docker build` on the jump server, `docker push` to Quay, deploy" —
blocked because Docker isn't installed on the jump server, and Quay's hostname doesn't even
resolve from there (see `documents/openshift-access-test-steps.md`). This design never touches
Docker at all:

- **Build**: the Tekton `build-push` task runs the `buildah` ClusterTask **in a pod inside the
  cluster** and pushes straight to the internal OpenShift registry
  (`image-registry.openshift-image-registry.svc:5000/ai-threatgen-ci/tsg`) — Quay isn't used.
- **Deploy**: ArgoCD's controller (also in-cluster) applies the manifests — no `oc apply` runs
  from any pipeline task or from the jump server.
- **Jump server**: only ever needs the `oc` CLI (already installed and confirmed working,
  v4.22.2) to log in and apply the one-time bootstrap manifests below, plus optionally `tkn`
  (manual PipelineRun triggers) and `argocd` (manual sync for uat/prod). All three are static
  Go binaries — no daemon, no socket, nothing Docker/Podman-related.

## Prerequisites (one-time)

1. **Operator**: OpenShift Pipelines installed (Tekton) **and** OpenShift GitOps installed
   (ArgoCD) — see step 9 for the GitOps operator manifest if it isn't installed yet.
2. **Namespaces**: `oc new-project ai-threatgen-ci ai-threatgen-dev ai-threatgen-uat ai-threatgen-prod`
   (one at a time).
3. **MSSQL** (external): DB `TSG` created, reachable from the cluster, and — mandatory, the
   app refuses to boot otherwise (`app/db/invariants.py`):
   `ALTER DATABASE TSG SET READ_COMMITTED_SNAPSHOT ON;`
4. **Redis**: dev uses the in-cluster `tsg-redis` from the dev overlay; uat/prod need an
   external/managed Redis (`rediss://` with password).
5. **MongoDB**: NOT required — overlays set `EMBEDDING_STORE=memory`. Only deploy Mongo if
   you switch that to `mongo` and set `TSG_MONGO_URL`.
6. **litellm proxy** reachable; set `TSG_LITELLM_BASE_URL` in `base/configmap.yaml`.
7. **IdP**: fill `TSG_JWT_ISSUER/AUDIENCE/JWKS_URL` in the uat/prod configmap patches.
   Until an IdP exists, only dev (AUTH_DEV_MODE) can run — staging/prod fail-closed on boot.
8. **Secrets** — per app namespace (values from your vault, never committed):

   ```
   oc -n ai-threatgen-<env> create secret generic tsg-secrets \
     --from-literal=TSG_DB_DSN='mssql+pyodbc://<user>:<pass>@<host>:1433/TSG?driver=ODBC+Driver+17+for+SQL+Server&Encrypt=yes&TrustServerCertificate=no' \
     --from-literal=TSG_REDIS_URL='rediss://:<pass>@<redis-host>:6380/0' \
     --from-literal=TSG_LITELLM_API_KEY='<key>' \
     --from-literal=TSG_ADMIN_API_KEY='<key>'
   ```

   **uat only** — Celery Flower (`deploy/overlays/uat/flower-deployment.yaml`) is wired to the
   same `tsg-secrets`, so it also needs:

   ```
   oc -n ai-threatgen-uat patch secret tsg-secrets --type=merge \
     -p '{"stringData":{"TSG_FLOWER_BASIC_AUTH":"<flower-ui-user>:<flower-ui-pass>"}}'
   ```

   Flower's dashboard is then reachable at the `tsg-flower` Route
   (`oc -n ai-threatgen-uat get route tsg-flower`), guarded by that basic-auth pair — pick a
   password here, don't reuse another credential.

   And per env in the CI namespace, discrete creds for the `sqlcmd` schema task
   (the SQLAlchemy DSN above is not parseable by sqlcmd):

   ```
   oc -n ai-threatgen-ci create secret generic tsg-db-<env> \
     --from-literal=DB_HOST='<host>,1433' \
     --from-literal=DB_NAME='TSG' \
     --from-literal=DB_USER='<user>' \
     --from-literal=DB_PASSWORD='<pass>'
   ```

9. **CI wiring** (Tekton — build, test, commit the new image tag; no deploy step anymore):

   ```
   oc apply -f deploy/tekton/rbac.yaml
   oc -n ai-threatgen-ci apply -f deploy/tekton/pipeline.yaml
   # only if the EventListener Route is reachable from github.com:
   oc -n ai-threatgen-ci create secret generic github-webhook-secret --from-literal=secretToken=<random>
   oc -n ai-threatgen-ci apply -f deploy/tekton/triggers.yaml
   ```

   Then add the webhook in GitHub (repo → Settings → Webhooks): the `tsg-webhook` Route URL,
   content type `application/json`, the same secret, push events.

   **Git push credential** — the pipeline's `update-manifest` task commits the new image tag
   back to `deploy/overlays/<env>/kustomization.yaml` and pushes it, so the `pipeline`
   ServiceAccount needs push rights on the repo:

   ```
   oc -n ai-threatgen-ci create secret generic tsg-git-push \
     --type=kubernetes.io/basic-auth \
     --from-literal=username='<github-username>' \
     --from-literal=password='<github-PAT-with-repo-push-rights>'
   oc -n ai-threatgen-ci annotate secret tsg-git-push tekton.dev/git-0=https://github.com
   oc -n ai-threatgen-ci secrets link pipeline tsg-git-push
   ```

10. **CD wiring** (ArgoCD — one-time, installs the operator if missing and points it at this repo):

    ```
    oc apply -f deploy/argocd/operator-subscription.yaml   # skip if OpenShift GitOps is already installed
    # wait for the operator: oc get pods -n openshift-gitops
    oc apply -f deploy/argocd/rbac.yaml
    oc apply -f deploy/argocd/dev-application.yaml
    oc apply -f deploy/argocd/uat-application.yaml
    oc apply -f deploy/argocd/prod-application.yaml
    ```

## Deploying

- **CI+CD (dev)**: push to the pipeline branch → webhook (loop-guarded — see
  `deploy/tekton/triggers.yaml`) → test → build (`EXTRAS=prod`, slim image, tag = commit SHA)
  → idempotent SQL schema apply → commit the new tag to `deploy/overlays/dev/kustomization.yaml`
  → ArgoCD detects the commit and **auto-syncs** `ai-threatgen-dev`.
- **CI (uat/prod)**: manual build+tag-commit —
  `oc create -f deploy/tekton/pipelinerun-example.yaml -n ai-threatgen-ci` (edit `env`) — then
  **manual CD**: review the diff and run `argocd app sync tsg-uat` / `tsg-prod` (or click Sync
  in the ArgoCD UI). This two-step gate is deliberate: nothing reaches uat/prod without a human
  starting the build *and* a human approving the sync.
- **Without CI/CD**: `oc apply -k deploy/overlays/dev` (image tag in the overlay's
  `kustomization.yaml`; schema scripts run manually via sqlcmd in the order in
  `scripts/readme.txt`).

## Operational notes

- **Connection budget**: each api pod = 4 gunicorn workers × (`TSG_DB_POOL_SIZE` +
  `TSG_DB_MAX_OVERFLOW`) = 40 MSSQL connections at the configured 5/5. Total across api +
  worker pods must stay under the SQL Server cap.
- **`TSG_MAX_CONCURRENT_LLM_CALLS`** (Redis-backed global semaphore) is the guard against a
  scaled-out worker fleet stampeding the model cluster — raise it deliberately.
- **Route timeout** is 300s for SSE; sse-starlette keepalives (15s) keep streams alive.
- **TLS**: DSN uses `Encrypt=yes&TrustServerCertificate=no` — if MSSQL/Redis/IdP use an
  internal CA, add its bundle to the image (`update-ca-certificates`) or mount it.
- **Image contents**: built with `--build-arg EXTRAS=prod` — no torch, no local models. To
  run in-process models instead, build with `EXTRAS=prod,local`, provide model files on a
  PVC at `/models/...`, and set `EMBEDDING_PROVIDER=local`.
- **Logs**: structlog JSON on stdout. Alert on `readyz.not_ready`, `readyz.*_unreachable`,
  `selfcheck.*`, `stage_error`.
- **GitOps drift**: `deploy/overlays/*/kustomization.yaml`'s `newTag` is now committed by CI,
  not hand-edited — don't "fix" a stale tag by editing it locally without also letting ArgoCD
  sync, or the next pipeline run's commit will just overwrite your edit anyway.
