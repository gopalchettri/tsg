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
#    exists too, but only for tooling that can't read pyproject.toml (e.g. Docker).
pip install -e ".[dev]"

# 5. Verify no dependency conflicts
pip check

# run (needs Redis running; pyodbc needs "ODBC Driver 17 for SQL Server")
# Easiest: .\start.ps1  -- brings up docker deps + worker + beat + API.
# By hand, the API only:
uvicorn app.main:app --reload --port 8000

# The Celery worker needs the venv ACTIVATED first. Without it a bare `celery`
# resolves to whatever global Python is on PATH -- which has celery but no gevent,
# and dies with "ModuleNotFoundError: No module named 'gevent'" in celery_worker.py.
# Activate (step 2) first, or call the venv's own exe explicitly:
.venv\Scripts\celery.exe -A app.pipeline.celery_worker.celery_app worker -P gevent -c 50 -l info
