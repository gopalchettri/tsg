# FINAL ONE
# NOTE: run every command below from the "tsg" folder (the one with pyproject.toml).
cd "C:\Chettri_World\IT World\Development\DESC\TSG\tsg"

# The env MUST be named .venv (dot-prefixed) -- start.ps1, README.md and
# SETUP_AND_RUN_GUIDE.md all activate ".venv\Scripts\Activate.ps1" by that exact
# name. A plain "venv" is not picked up by any of them.

# 1. Create the virtual environment (Python 3.12)
py -3.12 -m venv .venv

# 2. Activate it
# On Windows (PowerShell):
.venv\Scripts\Activate.ps1

# On Windows (CMD):
.venv\Scripts\activate.bat

# On Git Bash / WSL:
source .venv/Scripts/activate

# 3. Upgrade pip
python -m pip install --upgrade pip

# 4. Install all dependencies. pyproject.toml is canonical; requirements.txt
#    exists too, but only for tooling that can't read pyproject.toml (e.g. Docker)
pip install -e ".[dev]"

# EMBEDDING_PROVIDER/RERANKER_PROVIDER default to "local" (see .env.example) -- that
# needs sentence-transformers, which is NOT part of [dev]. Without this, the Celery
# worker fails fast at boot with "sentence-transformers is not installed".
pip install -e ".[local]"

# 5. Verify no dependency conflicts
pip check

# run (needs Redis running; pyodbc needs "ODBC Driver 17 for SQL Server")
# Easiest: .\start.ps1  -- brings up docker deps + worker + beat + API.
#   No Docker? .\run.ps1 checks the native deps and passes -SkipDocker for you.
#   Both AUTO-RELOAD when the env file is .env, so a code edit takes effect without
#   restarting the stack. Any other env file (-EnvFile .env.uat) gets a plain server;
#   -NoReload turns it off for .env too.
#   The reload is `watchfiles` supervising uvicorn, NOT `uvicorn --reload`: uvicorn's own
#   in-process reloader dies on its first restart here and takes the console with it
#   (measured 2026-09-24 -- see start.ps1's -NoReload help).
# By hand, the API only -- same supervisor, so an edit restarts it:
python -m watchfiles --filter python "python -m uvicorn app.main:app --port 8000" app

# The Celery worker needs the venv ACTIVATED first. Without it a bare `celery`
# resolves to whatever global Python is on PATH -- which has celery but no gevent,
# and dies with "ModuleNotFoundError: No module named 'gevent'" in celery_worker.py.
# Activate (step 2) first, or call the venv's own exe explicitly:
.venv\Scripts\celery.exe -A app.pipeline.celery_worker.celery_app worker -Q celery -P gevent -c 50 -l info

# Second worker, for the `admin` queue (technique rebuild / library import / embeddings /
# grounding calibration). Without -Q above, the pipeline worker drains this queue too.
# -A celery_app, NOT celery_worker: gevent monkey-patching hangs a solo pool at boot.
.venv\Scripts\celery.exe -A app.pipeline.celery_app.celery_app worker -Q admin -P solo -l info


.\start.ps1 -SkipDocker -EnvFile .env