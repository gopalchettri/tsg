1. once the database is created. run the following command-
ALTER DATABASE <database_name> SET READ_COMMITTED_SNAPSHOT ON;

(If you forget this step, the app will refuse to start and tell you to run it —
app/db/invariants.py checks RCSI is on every time the API or a Celery worker boots.)