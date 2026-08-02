# Production image for the TSG service (API + Celery worker + beat share this image).
# Build:  docker build -t tsg:latest .
#   DEFAULT is the slim proxy-path image (EMBEDDING/RERANKER_PROVIDER=litellm_proxy).
#   For local in-process models (pulls torch, large):  --build-arg EXTRAS=prod,local
FROM python:3.12-slim AS base

ARG EXTRAS=prod

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# ODBC Driver 17 for SQL Server (for pyodbc) + build tools for wheels.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl gnupg ca-certificates gcc g++ unixodbc-dev \
 && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc \
        | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" \
        > /etc/apt/sources.list.d/mssql-release.list \
 && apt-get update \
 && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql17 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
# requirements.lock pins the prod dependency set (regenerate with:
#   uv pip compile pyproject.toml --extra prod -o requirements.lock --python-platform linux --python-version 3.12
# ) so two builds of the same commit install identical versions. pyproject.toml stays canonical.
COPY pyproject.toml requirements.lock ./
COPY app ./app
# scripts/ carries the schema: database-first, TSG_Core.sql is the only thing that
# creates the baseline tables (see scripts/readme.txt). No migration tool in the image.
COPY scripts ./scripts
RUN pip install -r requirements.lock && pip install -e ".[${EXTRAS}]"

# Run as a non-root user. OpenShift's restricted-v2 SCC assigns a RANDOM uid in group 0,
# so /app must be group-0 writable (chmod g=u) — uid 10001 is only the non-OpenShift default.
RUN useradd -u 10001 -m appuser && chown -R appuser:0 /app && chmod -R g=u /app
USER 10001

EXPOSE 8000
# Default command runs the API; the worker/beat override this in compose/OpenShift.
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", \
     "-w", "4", "-b", "0.0.0.0:8000", "--timeout", "120", "--graceful-timeout", "30"]
