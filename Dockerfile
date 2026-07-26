# Production image for the TSG service (API + Celery worker + beat share this image).
# Build:  docker build -t tsg:latest .
#   DEFAULT includes local in-process models (matches EMBEDDING/RERANKER_PROVIDER=local); pulls torch (large).
#   Slim image for the proxy path instead:  --build-arg EXTRAS=prod
FROM python:3.12-slim AS base

ARG EXTRAS=prod,local

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
COPY pyproject.toml ./
COPY app ./app
# scripts/ carries the schema: database-first, TSG_Core.sql is the only thing that
# creates the baseline tables (see scripts/readme.txt). No migration tool in the image.
COPY scripts ./scripts
RUN pip install -e ".[${EXTRAS}]"

# Run as a non-root user (OpenShift-friendly).
RUN useradd -u 10001 -m appuser && chown -R appuser /app
USER 10001

EXPOSE 8000
# Default command runs the API; the worker/beat override this in compose/OpenShift.
CMD ["gunicorn", "app.main:app", "-k", "uvicorn.workers.UvicornWorker", \
     "-w", "4", "-b", "0.0.0.0:8000", "--timeout", "120", "--graceful-timeout", "30"]
