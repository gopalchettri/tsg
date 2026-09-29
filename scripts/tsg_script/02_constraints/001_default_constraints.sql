/*==============================================================================
  DEFAULT CONSTRAINTS

  Script:      001_default_constraints.sql
  Order:       02_constraints / 001
  Purpose:     21 default constraints.
  Depends on:  01_tables/ *
  Re-runnable: YES. Every statement checks first; a second run reports [EXISTS].
  Modifies:    default constraints

  GENERATED FILE - do not edit by hand.
  Regenerate:  python scripts/tsg_script/_generate.py
  Sources:     app/db/models.py (columns), tsg_remediation_tables.sql (indexes, constraints)
==============================================================================*/
SET NOCOUNT ON;
SET QUOTED_IDENTIFIER ON;   -- required: several indexes are filtered
GO

PRINT '';
PRINT '--- default constraints ---';
GO

/*==============================================================================
  SECTION 4 — Default constraints

  Named so a later script can reference or replace them. Every one is guarded,
  so this section is a no-op on a database that already has them.
==============================================================================*/
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.API_Client')
                 AND c.name = 'Module')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_Module] DEFAULT ('tsg') FOR [Module];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.API_Client')
                 AND c.name = 'Active')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_Active] DEFAULT ((1)) FOR [Active];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.API_Client')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[API_Client] ADD CONSTRAINT [DF_API_Client_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Config_Tuning')
                 AND c.name = 'IsActive')
    ALTER TABLE [dbo].[Config_Tuning] ADD CONSTRAINT [DF_Config_Tuning_IsActive] DEFAULT ((1)) FOR [IsActive];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Config_Tuning')
                 AND c.name = 'IsDeleted')
    ALTER TABLE [dbo].[Config_Tuning] ADD CONSTRAINT [DF_Config_Tuning_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library')
                 AND c.name = 'IsActive')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_IsActive] DEFAULT ((1)) FOR [IsActive];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library')
                 AND c.name = 'IsDeleted')
    ALTER TABLE [dbo].[Control_Library] ADD CONSTRAINT [DF_Control_Library_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Library_Standard_Map')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Control_Library_Standard_Map] ADD CONSTRAINT [DF_ControlStdMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Standard')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Standard')
                 AND c.name = 'IsActive')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_IsActive] DEFAULT ((1)) FOR [IsActive];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Control_Standard')
                 AND c.name = 'IsDeleted')
    ALTER TABLE [dbo].[Control_Standard] ADD CONSTRAINT [DF_Control_Standard_IsDeleted] DEFAULT ((0)) FOR [IsDeleted];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Grounding_Calibration_Run')
                 AND c.name = 'Forced')
    ALTER TABLE [dbo].[Grounding_Calibration_Run] ADD CONSTRAINT [DF_GroundingCalibration_Forced] DEFAULT ((0)) FOR [Forced];
GO

/* Named, unlike the SSMS default. A system-generated name differs per database
   and cannot be scripted against later. */
IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Identified_Threat')
                 AND c.name = 'IsThreatAIGenerated')
    ALTER TABLE [dbo].[Identified_Threat] ADD CONSTRAINT [DF_IdentifiedThreat_IsThreatAIGenerated] DEFAULT ((0)) FOR [IsThreatAIGenerated];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Identified_Threat')
                 AND c.name = 'IsThreatTypeAIGenerated')
    ALTER TABLE [dbo].[Identified_Threat] ADD CONSTRAINT [DF_IdentifiedThreat_IsThreatTypeAIGenerated] DEFAULT ((0)) FOR [IsThreatTypeAIGenerated];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Risk_Treatment_Plan')
                 AND c.name = 'Superseded')
    ALTER TABLE [dbo].[Risk_Treatment_Plan] ADD CONSTRAINT [DF_TreatmentPlan_Superseded] DEFAULT ((0)) FOR [Superseded];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Subsystem_Stage_State')
                 AND c.name = 'AttemptCount')
    ALTER TABLE [dbo].[Subsystem_Stage_State] ADD CONSTRAINT [DF_SSS_AttemptCount] DEFAULT ((0)) FOR [AttemptCount];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Threat_Catalogue_Category_Map')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[Threat_Catalogue_Category_Map] ADD CONSTRAINT [DF_CatCategoryMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Threat_Scenario')
                 AND c.name = 'ScenarioNumber')
    ALTER TABLE [dbo].[Threat_Scenario] ADD CONSTRAINT [DF_Scenario_ScenarioNumber] DEFAULT ((1)) FOR [ScenarioNumber];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.Threat_Scenario')
                 AND c.name = 'ControlMapAttempts')
    ALTER TABLE [dbo].[Threat_Scenario] ADD CONSTRAINT [DF_ThreatScenario_ControlMapAttempts] DEFAULT ((0)) FOR [ControlMapAttempts];
GO

IF NOT EXISTS (SELECT 1 FROM sys.default_constraints dc
               JOIN sys.columns c ON c.object_id = dc.parent_object_id
                                 AND c.column_id = dc.parent_column_id
               WHERE dc.parent_object_id = OBJECT_ID('dbo.ThreatType_ThreatActor_Map')
                 AND c.name = 'CreatedAt')
    ALTER TABLE [dbo].[ThreatType_ThreatActor_Map] ADD CONSTRAINT [DF_TypeActorMap_CreatedAt] DEFAULT (sysutcdatetime()) FOR [CreatedAt];
GO
