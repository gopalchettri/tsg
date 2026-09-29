/*==============================================================================
  SCHEMA VERDICT  (READ ONLY)

  Script:      002_schema_verdict.sql
  Order:       99_validation / 002   (run LAST, after 001)
  Purpose:     Verify all 296 columns and all 32 indexes, down to index key columns and filters.
  Depends on:  99_validation/001_post_deployment_validation.sql
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    NOTHING. Catalog views only.

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '==============================================================';
PRINT ' TSG COLUMN VERDICT   (296 columns across 22 tables)';
PRINT ' Database: ' + DB_NAME();
PRINT '==============================================================';
GO

DECLARE @expected TABLE (
    tbl sysname, col sysname, base_type sysname, full_type nvarchar(100), is_nullable bit);
INSERT INTO @expected (tbl, col, base_type, full_type, is_nullable) VALUES
    (N'Threat_Category', N'ThreatCategoryID', N'int', N'INT', 0),
    (N'Threat_Category', N'ThreatCategoryName', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Threat_Category', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Category', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Category', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Category', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Category', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Category', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Type', N'ThreatTypeID', N'int', N'INT', 0),
    (N'Threat_Type', N'ThreatTypeName', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Threat_Type', N'ThreatCategoryID', N'int', N'INT', 1),
    (N'Threat_Type', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Type', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Type', N'Source', N'nvarchar', N'NVARCHAR(50)', 1),
    (N'Threat_Type', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Type', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Type', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Type', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Catalogue', N'ThreatCatalogueID', N'int', N'INT', 0),
    (N'Threat_Catalogue', N'ThreatTypeID', N'int', N'INT', 0),
    (N'Threat_Catalogue', N'ThreatName', N'nvarchar', N'NVARCHAR(500)', 0),
    (N'Threat_Catalogue', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Catalogue', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Catalogue', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Catalogue', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Catalogue', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Catalogue', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Catalogue', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Actor', N'ThreatActorID', N'int', N'INT', 0),
    (N'Threat_Actor', N'ThreatActorName', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Threat_Actor', N'IsCapable', N'int', N'INT', 0),
    (N'Threat_Actor', N'IsActive', N'bit', N'BIT', 0),
    (N'Threat_Actor', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Threat_Actor', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Actor', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Actor', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Actor', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Actor', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Catalogue_Category_Map', N'ThreatCategoryID', N'int', N'INT', 0),
    (N'Threat_Catalogue_Category_Map', N'ThreatCatalogueID', N'int', N'INT', 0),
    (N'Threat_Catalogue_Category_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'ThreatType_ThreatActor_Map', N'ThreatTypeID', N'int', N'INT', 0),
    (N'ThreatType_ThreatActor_Map', N'ThreatActorID', N'int', N'INT', 0),
    (N'ThreatType_ThreatActor_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Control_Standard', N'StandardID', N'int', N'INT', 0),
    (N'Control_Standard', N'StandardName', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Control_Standard', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Control_Standard', N'CreatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Standard', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Standard', N'UpdatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Standard', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Standard', N'IsActive', N'bit', N'BIT', 0),
    (N'Control_Standard', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Control_Library', N'ControlLibraryID', N'int', N'INT', 0),
    (N'Control_Library', N'ControlCode', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Control_Library', N'ITOT', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Control_Library', N'Domain', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Control_Library', N'ControlName', N'nvarchar', N'NVARCHAR(500)', 0),
    (N'Control_Library', N'ControlDescription', N'nvarchar', N'NVARCHAR(max)', 0),
    (N'Control_Library', N'SampleEvidence', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Control_Library', N'Source', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Control_Library', N'CreatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Library', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Library', N'UpdatedAt', N'datetime', N'DATETIME', 1),
    (N'Control_Library', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Control_Library', N'IsActive', N'bit', N'BIT', 0),
    (N'Control_Library', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Control_Library_Standard_Map', N'ControlLibraryID', N'int', N'INT', 0),
    (N'Control_Library_Standard_Map', N'StandardID', N'int', N'INT', 0),
    (N'Control_Library_Standard_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'API_Client', N'ClientID', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'API_Client', N'KeyHash', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'API_Client', N'Name', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'API_Client', N'Module', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'API_Client', N'Active', N'bit', N'BIT', 0),
    (N'API_Client', N'CreatedAt', N'datetime2', N'DATETIME2(3)', 0),
    (N'API_Client', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'API_Client', N'RevokedAt', N'datetime2', N'DATETIME2(3)', 1),
    (N'API_Client', N'RevokedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'TuningID', N'int', N'INT', 0),
    (N'Config_Tuning', N'TuningKey', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Config_Tuning', N'TuningValue', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Config_Tuning', N'ValueType', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Config_Tuning', N'EmbeddingModel', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'CreateDate', N'datetime2', N'DATETIME2(7)', 1),
    (N'Config_Tuning', N'CreatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'UpdateDate', N'datetime2', N'DATETIME2(7)', 1),
    (N'Config_Tuning', N'UpdatedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Config_Tuning', N'IsActive', N'bit', N'BIT', 0),
    (N'Config_Tuning', N'IsDeleted', N'bit', N'BIT', 0),
    (N'Grounding_Calibration_Run', N'RunID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Grounding_Calibration_Run', N'JobID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Grounding_Calibration_Run', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Grounding_Calibration_Run', N'StartedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Grounding_Calibration_Run', N'StartedByClient', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Grounding_Calibration_Run', N'StartedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Grounding_Calibration_Run', N'FinishedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Grounding_Calibration_Run', N'EmbeddingModel', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Grounding_Calibration_Run', N'RerankerModel', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Grounding_Calibration_Run', N'Forced', N'bit', N'BIT', 0),
    (N'Grounding_Calibration_Run', N'MatchTh', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'ControlMapTh', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'Quality', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'NegativesCount', N'int', N'INT', 1),
    (N'Grounding_Calibration_Run', N'PositivesCount', N'int', N'INT', 1),
    (N'Grounding_Calibration_Run', N'HighestNegative', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'LowestPositive', N'float', N'FLOAT', 1),
    (N'Grounding_Calibration_Run', N'NearDuplicatesJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Grounding_Calibration_Run', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scenario_Session', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Scenario_Session', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Scenario_Session', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Session', N'AssetName', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Scenario_Session', N'AssetID', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Scenario_Session', N'SessionStatus', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'CurrentStage', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'StageStatus', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'Mode', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Session', N'CurrentSubsystemIndex', N'int', N'INT', 1),
    (N'Scenario_Session', N'SubsystemsJSON', N'nvarchar', N'NVARCHAR(max)', 0),
    (N'Scenario_Session', N'IdempotencyKey', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Session', N'SectorIDsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'AssetContextJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'ScoringRulesSnapshotJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Session', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'CompletedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'CancelledAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scenario_Session', N'CancelledBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Session', N'ControlMapSeconds', N'float', N'FLOAT', 1),
    (N'Subsystem_Stage_State', N'StateID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Subsystem_Stage_State', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Subsystem_Stage_State', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Subsystem_Stage_State', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Subsystem_Stage_State', N'SubsystemID', N'int', N'INT', 0),
    (N'Subsystem_Stage_State', N'Level', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Subsystem_Stage_State', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Subsystem_Stage_State', N'GenerationEpoch', N'int', N'INT', 0),
    (N'Subsystem_Stage_State', N'ActiveTaskID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Subsystem_Stage_State', N'LeaseExpiresAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'HeartbeatAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'AttemptCount', N'int', N'INT', 0),
    (N'Subsystem_Stage_State', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Subsystem_Stage_State', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Subsystem_Stage_State', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'StartedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Subsystem_Stage_State', N'FinishedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Identified_Threat', N'ThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Threat', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Threat', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Threat', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Threat', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Threat', N'SubsystemID', N'int', N'INT', 0),
    (N'Identified_Threat', N'ThreatCategory', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Identified_Threat', N'ThreatType', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Identified_Threat', N'ThreatName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Threat', N'GenericName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Threat', N'ThreatCategoryID', N'int', N'INT', 1),
    (N'Identified_Threat', N'ThreatActorsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Identified_Threat', N'LibraryThreatType', N'nvarchar', N'NVARCHAR(300)', 1),
    (N'Identified_Threat', N'LibraryThreatName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Threat', N'ThreatTypeID', N'int', N'INT', 1),
    (N'Identified_Threat', N'ThreatCatalogueID', N'int', N'INT', 1),
    (N'Identified_Threat', N'IsThreatAIGenerated', N'bit', N'BIT', 0),
    (N'Identified_Threat', N'IsThreatTypeAIGenerated', N'bit', N'BIT', 0),
    (N'Identified_Threat', N'GroundingStatus', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Identified_Threat', N'GroundingScore', N'float', N'FLOAT', 1),
    (N'Identified_Threat', N'GroundingThresholdOrigin', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Identified_Threat', N'Superseded', N'int', N'INT', 0),
    (N'Identified_Threat', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Identified_Duplicate_Threat', N'DuplicateThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Duplicate_Threat', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Identified_Duplicate_Threat', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Duplicate_Threat', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Duplicate_Threat', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Identified_Duplicate_Threat', N'SubsystemID', N'int', N'INT', 0),
    (N'Identified_Duplicate_Threat', N'ThreatCategory', N'nvarchar', N'NVARCHAR(200)', 0),
    (N'Identified_Duplicate_Threat', N'ThreatType', N'nvarchar', N'NVARCHAR(300)', 0),
    (N'Identified_Duplicate_Threat', N'ThreatName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Duplicate_Threat', N'GenericName', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Identified_Duplicate_Threat', N'ThreatActorsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Identified_Duplicate_Threat', N'DuplicateOfThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Identified_Duplicate_Threat', N'DuplicateReason', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Identified_Duplicate_Threat', N'SimilarityScore', N'float', N'FLOAT', 1),
    (N'Identified_Duplicate_Threat', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Scoped_Threat', N'ScopedThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scoped_Threat', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scoped_Threat', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scoped_Threat', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scoped_Threat', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scoped_Threat', N'SubsystemID', N'int', N'INT', 0),
    (N'Scoped_Threat', N'ThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scoped_Threat', N'Score', N'float', N'FLOAT', 0),
    (N'Scoped_Threat', N'ScopeRank', N'int', N'INT', 0),
    (N'Scoped_Threat', N'Selected', N'int', N'INT', 0),
    (N'Scoped_Threat', N'Reason', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Scoped_Threat', N'RejectionKind', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scoped_Threat', N'SelectionKind', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scoped_Threat', N'FactorsJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scoped_Threat', N'Superseded', N'int', N'INT', 0),
    (N'Scoped_Threat', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'SubsystemID', N'int', N'INT', 0),
    (N'Threat_Scenario', N'ScopedThreatID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Threat_Scenario', N'ScenarioJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'ValidationJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'AcceptedSubsetJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'Accepted', N'int', N'INT', 0),
    (N'Threat_Scenario', N'Superseded', N'int', N'INT', 0),
    (N'Threat_Scenario', N'IdentityHash', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Scenario', N'ScenarioNumber', N'int', N'INT', 0),
    (N'Threat_Scenario', N'ReplacesScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Threat_Scenario', N'GenerationEpoch', N'int', N'INT', 0),
    (N'Threat_Scenario', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Threat_Scenario', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ControlsMappedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ControlMapAttempts', N'int', N'INT', 0),
    (N'Threat_Scenario', N'GenStartedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'GenFinishedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'ScenarioSource', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Threat_Scenario', N'RejectedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'RejectedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario', N'AcceptedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Threat_Scenario', N'AcceptedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Threat_Scenario_Control_Map', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario_Control_Map', N'ControlLibraryID', N'int', N'INT', 0),
    (N'Threat_Scenario_Control_Map', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Threat_Scenario_Control_Map', N'MapRank', N'int', N'INT', 0),
    (N'Threat_Scenario_Control_Map', N'Score', N'float', N'FLOAT', 1),
    (N'Threat_Scenario_Control_Map', N'SuggestedControl', N'nvarchar', N'NVARCHAR(500)', 1),
    (N'Threat_Scenario_Control_Map', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'PlanID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Risk_Treatment_Plan', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Risk_Treatment_Plan', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Risk_Treatment_Plan', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'CrmRiskIdentificationID', N'int', N'INT', 1),
    (N'Risk_Treatment_Plan', N'TreatmentStrategy', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Risk_Treatment_Plan', N'Status', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Risk_Treatment_Plan', N'ActiveTaskID', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Risk_Treatment_Plan', N'RiskIdentificationDate', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'InputSnapshotJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'PlanJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'ValidationJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'ErrorMessage', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'Superseded', N'int', N'INT', 0),
    (N'Risk_Treatment_Plan', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'UpdatedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'CompletedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'RiskLevel', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Risk_Treatment_Plan', N'ReviewStatus', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Risk_Treatment_Plan', N'ReviewComment', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Risk_Treatment_Plan', N'ReviewedBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'ReviewedAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'CancelledAt', N'datetime2', N'DATETIME2(7)', 1),
    (N'Risk_Treatment_Plan', N'CancelledBy', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Risk_Treatment_Plan', N'ErrorReason', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Audit', N'AuditID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scenario_Audit', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Scenario_Audit', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Audit', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Audit', N'Stage', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'SubsystemID', N'int', N'INT', 1),
    (N'Scenario_Audit', N'EventType', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Scenario_Audit', N'ScenarioID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Scenario_Audit', N'PlanID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1),
    (N'Scenario_Audit', N'Decision', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'Granularity', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'ThreatTypeRefID', N'int', N'INT', 1),
    (N'Scenario_Audit', N'ActorUserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Scenario_Audit', N'ActorType', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Scenario_Audit', N'DetailJSON', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Scenario_Audit', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Prompt_Log', N'LogID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Prompt_Log', N'SessionID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 0),
    (N'Prompt_Log', N'TenantID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'EntityID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'UserID', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'SubsystemID', N'int', N'INT', 0),
    (N'Prompt_Log', N'Stage', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Prompt_Log', N'PromptVersion', N'nvarchar', N'NVARCHAR(100)', 0),
    (N'Prompt_Log', N'Messages', N'nvarchar', N'NVARCHAR(max)', 0),
    (N'Prompt_Log', N'Prompt', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Prompt_Log', N'ResponseText', N'nvarchar', N'NVARCHAR(max)', 1),
    (N'Prompt_Log', N'Model', N'nvarchar', N'NVARCHAR(200)', 1),
    (N'Prompt_Log', N'ModelVersion', N'nvarchar', N'NVARCHAR(100)', 1),
    (N'Prompt_Log', N'ParseSucceeded', N'bit', N'BIT', 0),
    (N'Prompt_Log', N'CreatedAt', N'datetime2', N'DATETIME2(7)', 0),
    (N'Prompt_Log', N'CorrelationID', N'uniqueidentifier', N'UNIQUEIDENTIFIER', 1);

DECLARE @missing int = 0, @wrong_type int = 0, @wrong_null int = 0;

/* A column the application reads that the database does not have. The app breaks on first use. */
SELECT @missing = COUNT(*)
FROM   @expected e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.columns c
                   WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @missing > 0
    SELECT '[FAIL] missing column: ' + e.tbl + '.' + e.col +
           '  (expected ' + e.full_type + ')' AS Problem
    FROM   @expected e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.columns c
                       WHERE c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

/* A different type FAMILY. Not a widening, not recoverable by re-running the deployment. */
SELECT @wrong_type = COUNT(*)
FROM   @expected e
JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
WHERE  TYPE_NAME(c.user_type_id) <> e.base_type;

IF @wrong_type > 0
    SELECT '[FAIL] wrong type: ' + e.tbl + '.' + e.col +
           '  is ' + TYPE_NAME(c.user_type_id) + ', expected ' + e.base_type AS Problem
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  TYPE_NAME(c.user_type_id) <> e.base_type;

/* NULLABILITY, and only the DANGEROUS direction fails.

   A column the application requires that the database lets be NULL is a real failure: it is
   exactly what the deployment DELIBERATELY creates when it adds a NOT NULL column to a table
   that already has rows, printing a [WARNING] and the ALTER to run after backfilling. That
   warning scrolls past; this does not.

   The OPPOSITE - database NOT NULL where the ORM says nullable - is reported but not failed.
   It is the safe direction (the database is stricter), it is what the reviewed script already
   declares for the library tables' CreatedAt columns, and those carry a DEFAULT so an insert
   that omits the value still succeeds. Failing it would refuse sign-off on the schema this
   package itself deploys. */
SELECT @wrong_null = COUNT(*)
FROM   @expected e
JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
WHERE  c.is_nullable = 1 AND e.is_nullable = 0;

IF @wrong_null > 0
    SELECT '[FAIL] nullability: ' + e.tbl + '.' + e.col +
           '  allows NULL but the application requires NOT NULL'
           + '  -> backfill, then: ALTER TABLE dbo.' + QUOTENAME(e.tbl)
           + ' ALTER COLUMN ' + QUOTENAME(e.col) + ' ' + e.full_type + ' NOT NULL;' AS Problem
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  c.is_nullable = 1 AND e.is_nullable = 0;

IF EXISTS (SELECT 1 FROM @expected e
           JOIN sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                             AND c.name = e.col
           WHERE c.is_nullable = 0 AND e.is_nullable = 1)
    SELECT '[INFO] stricter than the application: ' + e.tbl + '.' + e.col +
           ' is NOT NULL where the model allows NULL (safe; inserts rely on its DEFAULT)'
           AS Note
    FROM   @expected e
    JOIN   sys.columns c ON c.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl)) AND c.name = e.col
    WHERE  c.is_nullable = 0 AND e.is_nullable = 1;

/*============================ INDEXES ============================
  001 matches indexes by NAME and TABLE only, so an index carrying the right name over the WRONG
  COLUMNS, or with its WHERE filter dropped, signs off clean. Every one of these is a uniqueness
  guard the application leans on for a race it cannot otherwise win - one active session per
  asset, one accepted version per scenario, one running calibration. A filtered unique index
  whose predicate went missing enforces something quite different from what the code assumes.

  Key columns are compared BY NAME AND ORDER (key_ordinal), which is what decides whether the
  index can serve the query and what the uniqueness actually spans. Included columns are not
  compared: they change only cost, never correctness.
==================================================================*/
DECLARE @ix TABLE (name sysname, tbl sysname, is_unique bit, is_filtered bit, cols nvarchar(900));
INSERT INTO @ix (name, tbl, is_unique, is_filtered, cols) VALUES
    (N'UX_Session_ActiveAsset', N'Scenario_Session', 1, 1, N'EntityID,AssetID'),
    (N'UX_Session_IdempotencyKey', N'Scenario_Session', 1, 1, N'EntityID,IdempotencyKey'),
    (N'UX_Scenario_ActiveIdentity', N'Threat_Scenario', 1, 1, N'SessionID,IdentityHash,ScenarioNumber'),
    (N'UX_Scenario_ActiveScoped', N'Threat_Scenario', 1, 1, N'SessionID,ScopedThreatID'),
    (N'UX_Scenario_ActiveAccepted', N'Threat_Scenario', 1, 1, N'SessionID,IdentityHash,ScenarioNumber'),
    (N'UX_SubsystemStageState_SessionSubLevel', N'Subsystem_Stage_State', 1, 0, N'SessionID,SubsystemID,Level'),
    (N'UX_TreatmentPlan_ActiveScenario', N'Risk_Treatment_Plan', 1, 1, N'ScenarioID'),
    (N'UX_GroundingCalibration_Running', N'Grounding_Calibration_Run', 1, 1, N'EmbeddingModel,RerankerModel'),
    (N'UX_ThreatType_NaturalKey', N'Threat_Type', 1, 1, N'ThreatTypeName'),
    (N'UX_ThreatCatalogue_NaturalKey', N'Threat_Catalogue', 1, 1, N'ThreatName'),
    (N'UX_ThreatActor_NaturalKey', N'Threat_Actor', 1, 1, N'ThreatActorName'),
    (N'UX_ThreatCategory_NaturalKey', N'Threat_Category', 1, 1, N'ThreatCategoryName'),
    (N'UX_Control_Standard_Name', N'Control_Standard', 1, 1, N'StandardName'),
    (N'UX_Control_Library_Code', N'Control_Library', 1, 1, N'ControlCode'),
    (N'IX_Session_Active', N'Scenario_Session', 0, 1, N'SessionStatus'),
    (N'UX_API_Client_KeyHash', N'API_Client', 1, 1, N'KeyHash'),
    (N'IX_IdentifiedThreat_SessionSubActive', N'Identified_Threat', 0, 1, N'SessionID,SubsystemID'),
    (N'IX_ScopedThreat_SessionSubActive', N'Scoped_Threat', 0, 1, N'SessionID,SubsystemID'),
    (N'IX_ScopedThreat_SessionActiveScores', N'Scoped_Threat', 0, 0, N'SessionID,Superseded'),
    (N'IX_Scenario_SessionSubActive', N'Threat_Scenario', 0, 1, N'SessionID,SubsystemID'),
    (N'IX_Scenario_RejectedDecision', N'Threat_Scenario', 0, 1, N'SessionID'),
    (N'IX_Session_EntityUser', N'Scenario_Session', 0, 0, N'EntityID,UserID'),
    (N'IX_TreatmentPlan_SessionActive', N'Risk_Treatment_Plan', 0, 1, N'SessionID'),
    (N'IX_TreatmentPlan_SessionHistory', N'Risk_Treatment_Plan', 0, 1, N'SessionID,ScenarioID,CreatedAt'),
    (N'IX_ScenarioAudit_SessionSubEvent', N'Scenario_Audit', 0, 0, N'SessionID,SubsystemID,EventType,CreatedAt'),
    (N'IX_ScenarioAudit_Scenario', N'Scenario_Audit', 0, 1, N'ScenarioID,CreatedAt'),
    (N'IX_ThreatType_Category_Active', N'Threat_Type', 0, 1, N'ThreatCategoryID'),
    (N'IX_PromptLog_Correlation', N'Prompt_Log', 0, 1, N'CorrelationID,CreatedAt'),
    (N'IX_IdentifiedDuplicateThreat_Session', N'Identified_Duplicate_Threat', 0, 0, N'SessionID'),
    (N'IX_PromptLog_Session', N'Prompt_Log', 0, 0, N'SessionID,SubsystemID'),
    (N'IX_ScenarioAudit_Plan', N'Scenario_Audit', 0, 1, N'PlanID,CreatedAt'),
    (N'UQ_Config_Tuning_Key', N'Config_Tuning', 1, 0, N'TuningKey');

DECLARE @ix_missing int = 0, @ix_shape int = 0;

SELECT @ix_missing = COUNT(*)
FROM   @ix e
WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                   WHERE i.name = e.name
                     AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND i.is_disabled = 0);

IF @ix_missing > 0
    SELECT '[FAIL] index missing or disabled: ' + e.name + ' on ' + e.tbl AS Problem
    FROM   @ix e
    WHERE  NOT EXISTS (SELECT 1 FROM sys.indexes i
                       WHERE i.name = e.name
                         AND i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND i.is_disabled = 0);

/* Shape: uniqueness, filtered-ness, and the key column list in order. */
DECLARE @actual TABLE (name sysname, tbl sysname, is_unique bit, is_filtered bit,
                       cols nvarchar(900));
INSERT INTO @actual (name, tbl, is_unique, is_filtered, cols)
SELECT i.name, t.name, i.is_unique, i.has_filter,
       STUFF((SELECT ',' + c.name
              FROM   sys.index_columns ic
              JOIN   sys.columns c ON c.object_id = ic.object_id
                                  AND c.column_id = ic.column_id
              WHERE  ic.object_id = i.object_id AND ic.index_id = i.index_id
                AND  ic.is_included_column = 0
              ORDER BY ic.key_ordinal
              FOR XML PATH('')), 1, 1, '')
FROM   sys.indexes i
JOIN   sys.tables  t ON t.object_id = i.object_id
WHERE  i.name IN (SELECT name FROM @ix);

SELECT @ix_shape = COUNT(*)
FROM   @ix e JOIN @actual a ON a.name = e.name AND a.tbl = e.tbl
WHERE  a.is_unique <> e.is_unique OR a.is_filtered <> e.is_filtered
   OR  ISNULL(a.cols, '') <> e.cols;

IF @ix_shape > 0
    SELECT '[FAIL] index shape: ' + e.name + ' on ' + e.tbl +
           CASE WHEN a.is_unique   <> e.is_unique   THEN '  UNIQUE differs;' ELSE '' END +
           CASE WHEN a.is_filtered <> e.is_filtered THEN '  filter differs;' ELSE '' END +
           CASE WHEN ISNULL(a.cols, '') <> e.cols
                THEN '  keys are (' + ISNULL(a.cols, '<none>') + '), expected (' + e.cols + ')'
                ELSE '' END AS Problem
    FROM   @ix e JOIN @actual a ON a.name = e.name AND a.tbl = e.tbl
    WHERE  a.is_unique <> e.is_unique OR a.is_filtered <> e.is_filtered
       OR  ISNULL(a.cols, '') <> e.cols;

/*========================== PRIMARY KEYS ==========================
  The key COLUMNS, in order. 001 only asks whether a table HAS a primary key, so an older
  Threat_Scenario_Control_Map keyed on (OutputID, ControlLibraryID) passed it - and every insert
  failed, because the application writes ScenarioID and never supplies OutputID.
==================================================================*/
DECLARE @pk TABLE (tbl sysname, cols nvarchar(900));
INSERT INTO @pk (tbl, cols) VALUES
    (N'Threat_Category', N'ThreatCategoryID'),
    (N'Threat_Type', N'ThreatTypeID'),
    (N'Threat_Catalogue', N'ThreatCatalogueID'),
    (N'Threat_Actor', N'ThreatActorID'),
    (N'Threat_Catalogue_Category_Map', N'ThreatCategoryID,ThreatCatalogueID'),
    (N'ThreatType_ThreatActor_Map', N'ThreatTypeID,ThreatActorID'),
    (N'Control_Standard', N'StandardID'),
    (N'Control_Library', N'ControlLibraryID'),
    (N'Control_Library_Standard_Map', N'ControlLibraryID,StandardID'),
    (N'API_Client', N'ClientID'),
    (N'Config_Tuning', N'TuningID'),
    (N'Grounding_Calibration_Run', N'RunID'),
    (N'Scenario_Session', N'SessionID'),
    (N'Subsystem_Stage_State', N'StateID'),
    (N'Identified_Threat', N'ThreatID'),
    (N'Identified_Duplicate_Threat', N'DuplicateThreatID'),
    (N'Scoped_Threat', N'ScopedThreatID'),
    (N'Threat_Scenario', N'ScenarioID'),
    (N'Threat_Scenario_Control_Map', N'ScenarioID,ControlLibraryID'),
    (N'Risk_Treatment_Plan', N'PlanID'),
    (N'Scenario_Audit', N'AuditID'),
    (N'Prompt_Log', N'LogID');

DECLARE @pk_wrong int = 0;
DECLARE @pk_actual TABLE (tbl sysname, cols nvarchar(900));
INSERT INTO @pk_actual (tbl, cols)
SELECT e.tbl,
       STUFF((SELECT ',' + c.name
              FROM   sys.indexes i
              JOIN   sys.index_columns ic ON ic.object_id = i.object_id AND ic.index_id = i.index_id
              JOIN   sys.columns c        ON c.object_id = ic.object_id AND c.column_id = ic.column_id
              WHERE  i.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                AND  i.is_primary_key = 1 AND ic.key_ordinal > 0
              ORDER BY ic.key_ordinal
              FOR XML PATH('')), 1, 1, '')
FROM   @pk e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL;

SELECT @pk_wrong = COUNT(*)
FROM   @pk e JOIN @pk_actual a ON a.tbl = e.tbl
WHERE  ISNULL(a.cols, '') <> e.cols;

IF @pk_wrong > 0
    SELECT '[FAIL] primary key: ' + e.tbl + '  keys are (' + ISNULL(a.cols, '<none>') +
           '), expected (' + e.cols + ')' AS Problem
    FROM   @pk e JOIN @pk_actual a ON a.tbl = e.tbl
    WHERE  ISNULL(a.cols, '') <> e.cols;

/*============================ DEFAULTS ============================
  Checked BY COLUMN, not by constraint name. SQL Server permits one default per column, and a
  database may legitimately carry it under an auto-generated name
  (DF__Identifie__IsAIG__7954A4F6) — the column still has its default, which is what the
  application depends on. Demanding our name would fail a correct database and tempt someone to
  drop and recreate a constraint for cosmetics.

  Nothing verified these before: 001 prints a count as [INFO] and never fails on it. A column
  that loses its default does not error — it silently stores whatever the insert left out.
==================================================================*/
DECLARE @df TABLE (name sysname, tbl sysname, col sysname);
INSERT INTO @df (name, tbl, col) VALUES
    (N'DF_API_Client_Module', N'API_Client', N'Module'),
    (N'DF_API_Client_Active', N'API_Client', N'Active'),
    (N'DF_API_Client_CreatedAt', N'API_Client', N'CreatedAt'),
    (N'DF_Config_Tuning_IsActive', N'Config_Tuning', N'IsActive'),
    (N'DF_Config_Tuning_IsDeleted', N'Config_Tuning', N'IsDeleted'),
    (N'DF_Control_Library_CreatedAt', N'Control_Library', N'CreatedAt'),
    (N'DF_Control_Library_IsActive', N'Control_Library', N'IsActive'),
    (N'DF_Control_Library_IsDeleted', N'Control_Library', N'IsDeleted'),
    (N'DF_ControlStdMap_CreatedAt', N'Control_Library_Standard_Map', N'CreatedAt'),
    (N'DF_Control_Standard_CreatedAt', N'Control_Standard', N'CreatedAt'),
    (N'DF_Control_Standard_IsActive', N'Control_Standard', N'IsActive'),
    (N'DF_Control_Standard_IsDeleted', N'Control_Standard', N'IsDeleted'),
    (N'DF_GroundingCalibration_Forced', N'Grounding_Calibration_Run', N'Forced'),
    (N'DF_IdentifiedThreat_IsThreatAIGenerated', N'Identified_Threat', N'IsThreatAIGenerated'),
    (N'DF_IdentifiedThreat_IsThreatTypeAIGenerated', N'Identified_Threat', N'IsThreatTypeAIGenerated'),
    (N'DF_TreatmentPlan_Superseded', N'Risk_Treatment_Plan', N'Superseded'),
    (N'DF_SSS_AttemptCount', N'Subsystem_Stage_State', N'AttemptCount'),
    (N'DF_StageState_CreatedAt', N'Subsystem_Stage_State', N'CreatedAt'),
    (N'DF_CatCategoryMap_CreatedAt', N'Threat_Catalogue_Category_Map', N'CreatedAt'),
    (N'DF_Scenario_ScenarioNumber', N'Threat_Scenario', N'ScenarioNumber'),
    (N'DF_ThreatScenario_ControlMapAttempts', N'Threat_Scenario', N'ControlMapAttempts'),
    (N'DF_TypeActorMap_CreatedAt', N'ThreatType_ThreatActor_Map', N'CreatedAt');

DECLARE @df_missing int = 0;
SELECT @df_missing = COUNT(*)
FROM   @df e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
                   JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                     AND c.column_id = dc.parent_column_id
                   WHERE dc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @df_missing > 0
    SELECT '[FAIL] no DEFAULT on ' + e.tbl + '.' + e.col +
           '  (expected ' + e.name + ') -> inserts omitting it store no value' AS Problem
    FROM   @df e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
                       JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                         AND c.column_id = dc.parent_column_id
                       WHERE dc.parent_object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

/*=================== IDENTITY and COLLATION ===================
  IDENTITY: the application NEVER supplies these ids — dal.upsert_threat_type and its siblings
  insert without the key and read the generated value back. A table created without identity
  therefore passes every other check here and then fails on the first library insert with
  "Cannot insert the value NULL". It cannot be repaired by ALTER (SQL Server needs a table
  rebuild), so this reports it rather than pretending a re-run fixes it.

  COLLATION: the natural-key unique indexes are the database half of the library's dedup
  guarantee. Under a case-SENSITIVE collation 'Ransomware' and 'ransomware' are different keys,
  so both insert and the library quietly accumulates duplicates that normalize_name() in Python
  already treats as one row. Checked as a FAMILY (_CI_), not an exact string, because the
  accent and locale parts are a deployment choice and only case-insensitivity is relied upon.
==============================================================*/
DECLARE @ident TABLE (tbl sysname, col sysname);
INSERT INTO @ident (tbl, col) VALUES
    (N'Config_Tuning', N'TuningID'),
    (N'Control_Library', N'ControlLibraryID'),
    (N'Control_Standard', N'StandardID'),
    (N'Threat_Actor', N'ThreatActorID'),
    (N'Threat_Catalogue', N'ThreatCatalogueID'),
    (N'Threat_Type', N'ThreatTypeID');

DECLARE @id_missing int = 0, @fail_collation int = 0;

SELECT @id_missing = COUNT(*)
FROM   @ident e
WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
  AND  NOT EXISTS (SELECT 1 FROM sys.identity_columns ic
                   JOIN sys.columns c ON c.object_id = ic.object_id
                                     AND c.column_id = ic.column_id
                   WHERE ic.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                     AND c.name = e.col);

IF @id_missing > 0
    SELECT '[FAIL] ' + e.tbl + '.' + e.col + ' is not an IDENTITY column. The application '
           + 'inserts without this id, so the first write to ' + e.tbl + ' will fail. '
           + 'IDENTITY cannot be added by ALTER - the table must be rebuilt.' AS Problem
    FROM   @ident e
    WHERE  OBJECT_ID('dbo.' + QUOTENAME(e.tbl), 'U') IS NOT NULL
      AND  NOT EXISTS (SELECT 1 FROM sys.identity_columns ic
                       JOIN sys.columns c ON c.object_id = ic.object_id
                                         AND c.column_id = ic.column_id
                       WHERE ic.object_id = OBJECT_ID('dbo.' + QUOTENAME(e.tbl))
                         AND c.name = e.col);

DECLARE @collation nvarchar(128) = CAST(DATABASEPROPERTYEX(DB_NAME(), 'Collation') AS nvarchar(128));
IF @collation IS NULL OR @collation NOT LIKE '%_CI_%'
BEGIN
    SET @fail_collation = 1;
    PRINT ' [FAIL] Database collation is ' + ISNULL(@collation, '<unreadable>') + '.';
    PRINT '       A case-INSENSITIVE collation is required: the natural-key unique indexes';
    PRINT '       are what stop the threat library holding ''Ransomware'' and ''ransomware''';
    PRINT '       as two rows, and normalize_name() in the application already treats them';
    PRINT '       as one. Case-sensitive here means silent duplicate library entries.';
END;

PRINT '';
PRINT 'SCHEMA VERDICT';
PRINT '--------------';
PRINT ' [INFO]    Columns expected:   296';
PRINT ' [INFO]    Missing:            ' + CAST(@missing    AS varchar(10));
PRINT ' [INFO]    Wrong type:         ' + CAST(@wrong_type AS varchar(10));
PRINT ' [INFO]    Wrong nullability:  ' + CAST(@wrong_null AS varchar(10));
PRINT ' [INFO]    Indexes expected:   32';
PRINT ' [INFO]    Missing/disabled:   ' + CAST(@ix_missing AS varchar(10));
PRINT ' [INFO]    Wrong shape:        ' + CAST(@ix_shape   AS varchar(10));
PRINT ' [INFO]    Primary keys wrong: ' + CAST(@pk_wrong   AS varchar(10));
PRINT ' [INFO]    Defaults expected:  22';
PRINT ' [INFO]    Missing defaults:   ' + CAST(@df_missing AS varchar(10));
PRINT ' [INFO]    Identity expected:  6';
PRINT ' [INFO]    Missing identity:   ' + CAST(@id_missing AS varchar(10));
PRINT ' [INFO]    Collation:          ' + ISNULL(@collation, '<unreadable>');
PRINT '';
PRINT 'Columns:   ' + CASE WHEN (@missing + @wrong_type + @wrong_null) = 0
                           THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Indexes:   ' + CASE WHEN (@ix_missing + @ix_shape) = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Keys:      ' + CASE WHEN @pk_wrong = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Defaults:  ' + CASE WHEN @df_missing = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Identity:  ' + CASE WHEN @id_missing = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT 'Collation: ' + CASE WHEN @fail_collation = 0 THEN 'PASS' ELSE 'FAILED' END;
PRINT '';

IF (@missing + @wrong_type + @wrong_null + @ix_missing + @ix_shape + @pk_wrong + @df_missing
    + @id_missing + @fail_collation) = 0
BEGIN
    PRINT 'FINAL SIGN-OFF: this script and 001 have both passed. The application may start.';
END
ELSE
BEGIN
    PRINT 'FINAL SIGN-OFF: REFUSED. The failing rows are in the RESULTS tab in SSMS (listed';
    PRINT 'above in sqlcmd). A column [FAIL] usually means the deployment left work for a human -';
    PRINT 'a NOT NULL column added as NULL because the table already had rows - and re-running';
    PRINT 'will NOT clear it. An index [FAIL] should not survive a run: 03_indexes rebuilds a';
    PRINT 'wrong-shaped index, so check the output for an [ERROR] on that index.';
    EXEC sp_set_session_context N'tsg_deploy_failed', 1;
    RAISERROR('FINAL SIGN-OFF REFUSED - see the rows in the Results tab.', 16, 1);
END;
GO
