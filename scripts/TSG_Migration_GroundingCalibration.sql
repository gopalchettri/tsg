/* ===========================================================================================
   TSG — admin-triggered grounding calibration: copy-paste migration
   ===========================================================================================
   Paste this whole file into SSMS / Azure Data Studio against the TSG database and run it.

   scripts/eyshield_handoff/"1. TSG_Core.sql" REMAINS CANONICAL and already contains every
   statement below (as does TSG_Core_UAT.sql). This file exists only so you do not have to run the
   full schema script to apply one release to a database that is already up.

   Every statement is guarded and idempotent: re-running changes nothing.

   WHAT IT DOES
     1. Grounding_Calibration_Run                  — one row per calibration sweep. This is BOTH
                                                     the audit trail (who ran it, when, pass or
                                                     fail) AND the threshold store: MatchTh on
                                                     the latest successful row is what the
                                                     pipeline reads.
     2. UX_GroundingCalibration_Running            — filtered UNIQUE index that makes two
                                                     concurrent sweeps impossible. Asserted at
                                                     boot; the app will NOT start without it.
     3. Identified_Threat.GroundingThresholdOrigin — which cutoff judged each threat
                                                     ('calibrated' | 'static_default' | 'env_pinned')

   WHY (the short version)
     The grounding threshold used to live in MongoDB, written by a best-effort call that swallowed
     its own failures — so a finished 15-minute sweep could lose its answer to a Mongo blip and
     leave nothing but a log line. And the sweep ran during WORKER BOOT, before the worker
     registered on the broker, which pushed cold starts past their readiness window. It is now an
     explicit admin action (POST /v1/tsg/grounding/calibrate) whose result is a column of the row
     that records it, so "measured but not saved" is no longer a reachable state.

   ORDER: run this BEFORE deploying the new application code. The app asserts its indexes at
   startup and will refuse to boot against an un-migrated database — by design, so the failure
   lands at deploy time rather than at runtime.

   AFTER: the MongoDB collection `grounding_thresholds` (in TSG_MONGO_DB, default
   `tsg_embeddings`) is no longer read or written. CONFIRM IT IS EMPTY OR STALE, then drop it:
       use tsg_embeddings
       db.grounding_thresholds.find()      // expect 0 docs, or values you no longer need
       db.grounding_thresholds.drop()
   Nothing migrates from it: any value there was produced by the old code path and is superseded
   by the first run of the new one. The `embeddings` collection is UNRELATED — leave it alone.
   =========================================================================================== */

SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;
GO

/* -- 1. The calibration ledger ------------------------------------------------------------- */
IF OBJECT_ID('dbo.Grounding_Calibration_Run', 'U') IS NULL
CREATE TABLE Grounding_Calibration_Run (
    RunID              uniqueidentifier NOT NULL CONSTRAINT PK_Grounding_Calibration_Run PRIMARY KEY,
    JobID              nvarchar(100) NULL,        -- Celery task id
    Status             nvarchar(100) NOT NULL,    -- running | success | no_signal | failed
    StartedBy          nvarchar(200) NULL,        -- X-User-Id: CLAIMED, never verified on admin routes
    StartedByClient    nvarchar(200) NULL,        -- API_Client.ClientID: VERIFIED
    StartedAt          datetime2     NULL,
    FinishedAt         datetime2     NULL,
    EmbeddingModel     nvarchar(500) NULL,
    RerankerModel      nvarchar(500) NULL,
    Forced             bit           NOT NULL CONSTRAINT DF_GroundingCalibration_Forced DEFAULT 0,
    MatchTh            float         NULL,        -- the cutoff; NULL unless Status='success'
    Quality            float         NULL,        -- Youden's J at MatchTh, 0-1
    NegativesCount     int           NULL,
    PositivesCount     int           NULL,
    HighestNegative    float         NULL,
    LowestPositive     float         NULL,
    NearDuplicatesJSON nvarchar(max) NULL,        -- curation to-do list, not an error
    ErrorMessage       nvarchar(max) NULL
);
GO

/* -- 2. One in-flight calibration per model pair -------------------------------------------
   A CORRECTNESS index, not a performance one. A sweep costs 10-15 minutes and ~100 billed LLM
   calls, and the API route cannot prevent a double-start by itself: two requests arriving
   together both read "nothing running" before either writes. The database refusing the second
   INSERT is the only thing that closes that window, which is why the application asserts this
   index at boot and refuses to start without it.

   An abandoned 'running' row (worker killed mid-sweep) would block every future run, so the
   route settles rows older than TSG_CALIBRATION_STALE_AFTER_SECONDS to 'failed' before
   inserting. Do NOT "fix" a stuck calibration by dropping this index.                        */
IF NOT EXISTS (SELECT 1 FROM sys.indexes WHERE name = 'UX_GroundingCalibration_Running' AND object_id = OBJECT_ID('dbo.Grounding_Calibration_Run'))
    EXEC('CREATE UNIQUE INDEX UX_GroundingCalibration_Running ON Grounding_Calibration_Run(EmbeddingModel, RerankerModel) WHERE Status = ''running''');
GO

/* -- 3. Which cutoff judged each identified threat ------------------------------------------
   'calibrated' | 'static_default' | 'env_pinned'. The three collide numerically — a calibrated
   75.0 and the untuned default 75.0 are the same float — so without this column there is no way
   to find the threats graded on a default meant for a DIFFERENT model pair once a deployment
   finally calibrates. Nullable and never backfilled: on older rows it was genuinely unknown, and
   inventing a value would falsify records that were correct when written.                    */
IF COL_LENGTH('dbo.Identified_Threat', 'GroundingThresholdOrigin') IS NULL
    ALTER TABLE Identified_Threat ADD GroundingThresholdOrigin nvarchar(100) NULL;
GO

PRINT 'TSG grounding-calibration migration applied.';
PRINT 'Next: deploy the application, then POST /v1/tsg/grounding/calibrate to measure the';
PRINT 'threshold for this deployment''s embedding+reranker pair. Until then grounding runs on';
PRINT 'the static default, which was tuned for a DIFFERENT model pair.';
GO
