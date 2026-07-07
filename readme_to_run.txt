# FINAL ONE
# NOTE: run every command below from the "tsg" folder (the one with pyproject.toml).
cd "C:\Chettri_World\IT World\Development\DESC\TSG\tsg"

# 1. Create the virtual environment (Python 3.11+)
py -3.12 -m venv venv

# 2. Activate it
# On Windows (PowerShell):
venv\Scripts\Activate.ps1

# On Windows (CMD):
venv\Scripts\activate.bat

# On Git Bash / WSL:
source venv/Scripts/activate

# 3. Upgrade pip
python -m pip install --upgrade pip

# 4. Install all dependencies (from pyproject.toml — there is no requirements.txt)
pip install -e ".[dev]"

# 5. Verify no dependency conflicts
pip check

# run (needs Redis running; pyodbc needs "ODBC Driver 17 for SQL Server")
uvicorn app.main:app --reload --port 8000
