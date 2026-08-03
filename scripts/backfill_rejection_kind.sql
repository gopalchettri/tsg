-- ============================================================================
-- ONE-SHOT backfill: Scoped_Threat.RejectionKind from the legacy Reason prose.
--
-- Run ONCE per database that existed before 2026-08-03 (the column ships NULL on those rows,
-- and next_unserved_unique_threats treats NULL as NOT re-servable -- so without this, every
-- top-N casualty already on disk becomes invisible to "generate next set" forever).
-- A database created fresh from TSG_Core.sql after that date needs nothing here.
--
-- Idempotent: the WHERE clause only ever touches rows still NULL, so re-running is a no-op.
--
-- Yes, this parses the Reason sentence -- the exact thing RejectionKind exists to stop. That is
-- fine HERE and nowhere else: this reads history that is already written and then never runs
-- again. The bug was never "matching a string"; it was matching a string in a LIVE code path,
-- where the writer drifts and the reader silently stops finding anything. A one-shot has no
-- future writer to drift from.
--
-- Prose written by app/pipeline/scoping.py and app/pipeline/tasks.py as of 2026-08-03:
--   'beyond top-<N> cutoff'              -> top_n_cutoff     (RE-SERVABLE)
--   'duplicate of higher-ranked threat'  -> duplicate
--   'tech_gate:<keys> failed'            -> tech_gate
--   'below score threshold (<x>)'        -> below_threshold
-- Selected=1 rows are left NULL on purpose: nothing rejected them.
-- ============================================================================

SET NOCOUNT ON;

IF COL_LENGTH('dbo.Scoped_Threat', 'RejectionKind') IS NULL
BEGIN
    RAISERROR('Scoped_Threat.RejectionKind does not exist -- run TSG_Core.sql first.', 16, 1);
    RETURN;
END

UPDATE Scoped_Threat
SET RejectionKind = CASE
        WHEN Reason LIKE 'beyond top-%'                  THEN 'top_n_cutoff'
        WHEN Reason = 'duplicate of higher-ranked threat' THEN 'duplicate'
        WHEN Reason LIKE 'tech_gate:%'                   THEN 'tech_gate'
        WHEN Reason LIKE 'below score threshold%'        THEN 'below_threshold'
    END
WHERE Selected = 0
  AND RejectionKind IS NULL
  AND (Reason LIKE 'beyond top-%'
    OR Reason = 'duplicate of higher-ranked threat'
    OR Reason LIKE 'tech_gate:%'
    OR Reason LIKE 'below score threshold%');

PRINT CONCAT('Backfilled ', @@ROWCOUNT, ' Scoped_Threat row(s).');

-- Anything left is a rejected row this script could not classify: an older wording, or a
-- hand-edited row. Report it rather than guessing -- guessing 'top_n_cutoff' would re-serve a
-- permanently-rejected threat and wedge the session on "no new threats".
SELECT Reason AS UnclassifiedReason, COUNT(*) AS RowsAffected
FROM Scoped_Threat
WHERE Selected = 0 AND RejectionKind IS NULL
GROUP BY Reason
ORDER BY COUNT(*) DESC;
